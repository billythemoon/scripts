#!/bin/bash
#
# password.sh -- reset passwords + apply a full password policy
#
# Usage:  sudo ./password.sh <protected-user> [another-user ...]
#         (no argument = it asks you)
#
# Runs in four phases:
#   1. Every user's password -> NEW_PASSWORD, EXCEPT the protected user(s)
#   2. Full password policy: login.defs, pwquality (complexity),
#      pam_pwhistory (no reusing old passwords), defaults for new users
#   3. Aging policy applied to EVERY user, INCLUDING the protected user(s)
#   4. Every user's password -> NEW_PASSWORD again, EXCEPT the protected user(s)
#
# The protected user's password is never touched.
# NOTE: the password is in plaintext below -- delete this script when done.

set -uo pipefail

# ----- edit deez -----
NEW_PASSWORD='Qwertyuiop-01'
PASS_MAX_DAYS=90       # password must be changed every N days
PASS_MIN_DAYS=7        # can't change it again for N days
PASS_WARN_AGE=14       # warn N days before it expires
INACTIVE_DAYS=30       # lock the account N days after the password expires
UID_MIN=1000
CHANGE_ROOT=0          # 1 = include root (root's password is normally locked on Ubuntu)

# complexity (pwquality)
PWQ_MINLEN=12; PWQ_MINCLASS=3
PWQ_DCREDIT=-1; PWQ_UCREDIT=-1; PWQ_LCREDIT=-1; PWQ_OCREDIT=-1   # need 1 of each
PWQ_MAXREPEAT=3; PWQ_MAXSEQUENCE=4; PWQ_DIFOK=3; PWQ_RETRY=3
PWHISTORY_REMEMBER=5   # can't reuse the last N passwords
# ---------------------

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0 <protected-user>" >&2; exit 1; fi

STAMP=$(date +%Y%m%d%H%M%S)
backup() { [[ -f $1 ]] && cp -a "$1" "$1.bak.$STAMP" && echo "  backed up $1"; }

# ----- protected user(s) -----
PROTECTED=("$@")
if (( ${#PROTECTED[@]} == 0 )); then
    read -rp "User whose password should NOT be changed (e.g. your own account): " p
    [[ -n $p ]] && PROTECTED=($p)
fi
for p in "${PROTECTED[@]}"; do
    getent passwd "$p" >/dev/null || { echo "Error: user '$p' doesn't exist. Nothing changed." >&2; exit 1; }
done
if (( ${#PROTECTED[@]} == 0 )); then
    read -rp "No protected user given -- EVERY password will be reset. Continue? [y/N] " a
    [[ $a == [yY]* ]] || exit 1
fi
is_protected() { local p; for p in "${PROTECTED[@]}"; do [[ $p == "$1" ]] && return 0; done; return 1; }

# ----- which users -----
# UID >= UID_MIN, plus anything listed after the first UID_MIN account in
# /etc/passwd (catches low-UID accounts added later). Only login-capable
# accounts are touched.
is_login_shell() {
    case "$(getent passwd "$1" | cut -d: -f7)" in
        ""|*nologin|*/false|*/sync|*/shutdown|*/halt) return 1 ;; *) return 0 ;;
    esac
}
mapfile -t ALL < <(awk -F: -v a="$UID_MIN" '
    $3 == a { after = 1 }
    $1 != "nobody" && $1 != "nogroup" && ($3+0 >= a || after) { print $1 }' /etc/passwd)
(( CHANGE_ROOT )) && ALL=(root "${ALL[@]}")
USERS=()
for u in "${ALL[@]}"; do is_login_shell "$u" && USERS+=("$u"); done
for p in "${PROTECTED[@]}"; do
    is_login_shell "$p" || echo "Note: protected user '$p' has no login shell, so it isn't in the list anyway."
done

echo "Protected (password untouched): ${PROTECTED[*]:-none}"
echo "Users: ${#USERS[@]} -> ${USERS[*]}"

PW_FAILED=()
reset_passwords() {   # $1 = phase label
    local u n=0
    for u in "${USERS[@]}"; do
        if is_protected "$u"; then echo "  $u: skipped (protected)"; continue; fi
        if echo "$u:$NEW_PASSWORD" | chpasswd >/dev/null 2>&1; then
            n=$((n+1))
        else
            echo "  $u: PASSWORD NOT CHANGED"; PW_FAILED+=("$u ($1)")
        fi
    done
    echo "  $n password(s) set"
}

# =====================================================================
echo; echo "== Phase 1: reset passwords (except protected) =="
reset_passwords "phase 1"

# =====================================================================
echo; echo "== Phase 2: password policy =="
# --- /etc/login.defs ---
LOGIN_DEFS=/etc/login.defs
backup "$LOGIN_DEFS"
set_def() {
    if grep -qE "^[[:space:]]*$1[[:space:]]" "$LOGIN_DEFS"; then
        sed -i -E "s|^[[:space:]]*$1[[:space:]].*|$1\t\t$2|" "$LOGIN_DEFS"
    elif grep -qE "^#[[:space:]]*$1[[:space:]]" "$LOGIN_DEFS"; then
        sed -i -E "0,/^#[[:space:]]*$1[[:space:]]/s|^#[[:space:]]*$1[[:space:]].*|$1\t\t$2|" "$LOGIN_DEFS"
    else
        printf '%s\t\t%s\n' "$1" "$2" >> "$LOGIN_DEFS"
    fi
}
set_def PASS_MAX_DAYS  "$PASS_MAX_DAYS"
set_def PASS_MIN_DAYS  "$PASS_MIN_DAYS"
set_def PASS_WARN_AGE  "$PASS_WARN_AGE"
set_def LOGIN_RETRIES  5
set_def LOGIN_TIMEOUT  60
set_def FAILLOG_ENAB   yes
set_def LOG_OK_LOGINS  yes
set_def ENCRYPT_METHOD "$(grep -qE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+YESCRYPT' "$LOGIN_DEFS" && echo YESCRYPT || echo SHA512)"
echo "  login.defs: max $PASS_MAX_DAYS / min $PASS_MIN_DAYS / warn $PASS_WARN_AGE days, strong hashing, login logging"

# --- defaults for accounts created later ---
useradd -D -f "$INACTIVE_DAYS" >/dev/null && echo "  new accounts lock $INACTIVE_DAYS days after their password expires"

# --- pwquality (complexity) ---
COMMON_PW=/etc/pam.d/common-password
if ! grep -q pam_pwquality.so "$COMMON_PW" 2>/dev/null; then
    echo "  installing libpam-pwquality..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libpam-pwquality >/dev/null 2>&1 \
        || echo "  could not install libpam-pwquality (no internet?) -- complexity rules won't be enforced"
fi
PWQ=/etc/security/pwquality.conf
if [[ -f $PWQ ]]; then
    backup "$PWQ"
    set_pwq() {
        if grep -qE "^[[:space:]]*$1[[:space:]]*=" "$PWQ"; then
            sed -i -E "s|^[[:space:]]*$1[[:space:]]*=.*|$1 = $2|" "$PWQ"
        elif grep -qE "^#[[:space:]]*$1[[:space:]]*=" "$PWQ"; then
            sed -i -E "s|^#[[:space:]]*$1[[:space:]]*=.*|$1 = $2|" "$PWQ"
        else
            echo "$1 = $2" >> "$PWQ"
        fi
    }
    set_flag() {
        grep -qE "^[[:space:]]*$1[[:space:]]*$" "$PWQ" && return
        grep -qE "^#[[:space:]]*$1[[:space:]]*$" "$PWQ" \
            && sed -i -E "s|^#[[:space:]]*$1[[:space:]]*$|$1|" "$PWQ" \
            || echo "$1" >> "$PWQ"
    }
    set_pwq minlen "$PWQ_MINLEN";   set_pwq minclass "$PWQ_MINCLASS"
    set_pwq dcredit "$PWQ_DCREDIT"; set_pwq ucredit "$PWQ_UCREDIT"
    set_pwq lcredit "$PWQ_LCREDIT"; set_pwq ocredit "$PWQ_OCREDIT"
    set_pwq maxrepeat "$PWQ_MAXREPEAT"; set_pwq maxsequence "$PWQ_MAXSEQUENCE"
    set_pwq difok "$PWQ_DIFOK";     set_pwq retry "$PWQ_RETRY"
    set_pwq dictcheck 1;            set_pwq usercheck 1
    set_flag enforce_for_root
    echo "  pwquality: $PWQ_MINLEN+ chars, upper+lower+digit+symbol, dictionary/username checks, applies to root"
fi

# --- common-password: history + strong hashing, no empty passwords ---
if [[ -f $COMMON_PW ]]; then
    backup "$COMMON_PW"
    # remove 'nullok' (allows empty passwords) from pam_unix
    sed -i -E '/pam_unix\.so/ s/[[:space:]]+nullok(_secure)?//g' "$COMMON_PW"
    # make sure pam_unix hashes strongly
    if grep -qE '^password.*pam_unix\.so' "$COMMON_PW" && ! grep -qE '^password.*pam_unix\.so.*(sha512|yescrypt)' "$COMMON_PW"; then
        sed -i -E '/^password.*pam_unix\.so/ s/$/ sha512/' "$COMMON_PW"
    fi
    # password history, inserted just before pam_unix (only if not already there)
    if grep -q pam_pwhistory.so "$COMMON_PW"; then
        sed -i -E "/pam_pwhistory\.so/ { s/remember=[0-9]+/remember=$PWHISTORY_REMEMBER/; /remember=/!s/$/ remember=$PWHISTORY_REMEMBER/ }" "$COMMON_PW"
    else
        # use_authtok means "reuse the password pam_pwquality already asked for".
        # Only valid when pwquality is in the stack -- without it, use_authtok
        # makes EVERY password change fail.
        if grep -qE '^password.*pam_pwquality\.so' "$COMMON_PW"; then
            sed -i -E "0,/^password.*pam_pwquality\.so/ s|^(password.*pam_pwquality\.so.*)$|\1\npassword\trequisite\t\t\tpam_pwhistory.so remember=$PWHISTORY_REMEMBER use_authtok|" "$COMMON_PW"
        else
            sed -i -E "0,/^password.*pam_unix\.so/ s|^(password.*pam_unix\.so.*)$|password\trequisite\t\t\tpam_pwhistory.so remember=$PWHISTORY_REMEMBER\n\1|" "$COMMON_PW"
        fi
    fi
    # safety check: a password change must still work, or the PAM edit is undone
    tu="pwtest$$"
    useradd -M -s /usr/sbin/nologin "$tu" 2>/dev/null
    if echo "$tu:$NEW_PASSWORD" | chpasswd 2>/dev/null; then
        echo "  verified: password changes still work"
    else
        cp -a "$COMMON_PW.bak.$STAMP" "$COMMON_PW"
        echo "  !! password changes broke with the new common-password -- restored the backup"
    fi
    userdel "$tu" 2>/dev/null
    echo "  common-password: remembers last $PWHISTORY_REMEMBER passwords, nullok removed, strong hashing"
fi

# =====================================================================
echo; echo "== Phase 3: aging policy for EVERYONE (protected included) =="
for u in "${USERS[@]}"; do
    chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" -I "$INACTIVE_DAYS" "$u" \
        && echo "  $u$(is_protected "$u" && echo ' (protected)')" \
        || echo "  $u: chage FAILED"
done

# =====================================================================
echo; echo "== Phase 4: reset passwords again (except protected) =="
reset_passwords "phase 4"

# =====================================================================
echo; echo "== Result =="
printf "  %-16s %-26s %-14s %s\n" USER "LAST CHANGED" EXPIRES MIN/MAX/WARN  INACTIVE
for u in "${USERS[@]}"; do
    info=$(chage -l "$u")
    get() { awk -F': ' -v k="$1" 'index($0,k)==1{print $2}' <<<"$info"; }
    printf "  %-16s %-26s %-14s %s/%s/%s %s%s\n" "$u" "$(get 'Last password change')" "$(get 'Password expires')" \
        "$(get 'Minimum number')" "$(get 'Maximum number')" "$(get 'Number of days of warning')" "$(get 'Password inactive')" \
        "$(is_protected "$u" && echo '   <- protected')"
done
if (( ${#PW_FAILED[@]} )); then
    echo; echo "WARNING: password not set for: ${PW_FAILED[*]}"
fi
echo; echo "Done. Delete this script when finished (it contains the password in plaintext)."
