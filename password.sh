#!/bin/bash
#
set -euo pipefail

#edit deez
PASS_MAX_DAYS=90     
PASS_MIN_DAYS=7      
PASS_WARN_AGE=14     
UID_MIN=1000         

# Password reset: sets every targeted user's password to NEW_PASSWORD.
# NOTE: this is stored in plaintext in this file -- delete the script when done.
CHANGE_PASSWORDS=1                # 1 = reset passwords, 0 = only apply the aging policy
NEW_PASSWORD='Qwertyuiop-01'
CHANGE_ROOT=0                     # 1 = also set root's password + policy (off by default: root's
                                  #     password is normally locked, and setting one enables password login)

# pwquality (password complexity) settings
PWQ_MINLEN=12          # minimum password length
PWQ_MINCLASS=3         # min character classes required (upper/lower/digit/special)
PWQ_DCREDIT=-1         # require at least 1 digit
PWQ_UCREDIT=-1         # require at least 1 uppercase letter
PWQ_LCREDIT=-1         # require at least 1 lowercase letter
PWQ_OCREDIT=-1         # require at least 1 special/"other" character
PWQ_MAXREPEAT=3        # max identical chars in a row
PWQ_RETRY=3            # attempts before the password prompt fails
PWQ_ENFORCE_FOR_ROOT=1 # 1 = also enforce these rules on root's password

LOGIN_DEFS="/etc/login.defs"
BACKUP="/etc/login.defs.bak.$(date +%Y%m%d%H%M%S)"

echo "Backing up $LOGIN_DEFS to $BACKUP"
cp "$LOGIN_DEFS" "$BACKUP"

update_login_defs() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}[[:space:]]+" "$LOGIN_DEFS"; then
        sed -i "s/^${key}[[:space:]].*/${key}   ${value}/" "$LOGIN_DEFS"
    else
        echo "${key}   ${value}" >> "$LOGIN_DEFS"
    fi
}

echo "Updating $LOGIN_DEFS (applies to newly created users)..."
update_login_defs "PASS_MAX_DAYS" "$PASS_MAX_DAYS"
update_login_defs "PASS_MIN_DAYS" "$PASS_MIN_DAYS"
update_login_defs "PASS_WARN_AGE" "$PASS_WARN_AGE"

# ----- pwquality (password complexity) -----
PWQUALITY_CONF="/etc/security/pwquality.conf"

if [[ -f "$PWQUALITY_CONF" ]]; then
    PWQ_BACKUP="${PWQUALITY_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    echo "Backing up $PWQUALITY_CONF to $PWQ_BACKUP"
    cp "$PWQUALITY_CONF" "$PWQ_BACKUP"

    update_pwquality() {
        local key="$1"
        local value="$2"
        if grep -qE "^${key}[[:space:]]*=" "$PWQUALITY_CONF"; then
            sed -i "s/^${key}[[:space:]]*=.*/${key} = ${value}/" "$PWQUALITY_CONF"
        elif grep -qE "^#[[:space:]]*${key}[[:space:]]*=" "$PWQUALITY_CONF"; then
            sed -i "s/^#[[:space:]]*${key}[[:space:]]*=.*/${key} = ${value}/" "$PWQUALITY_CONF"
        else
            echo "${key} = ${value}" >> "$PWQUALITY_CONF"
        fi
    }

    echo "Updating $PWQUALITY_CONF (password complexity rules for future password changes)..."
    update_pwquality "minlen" "$PWQ_MINLEN"
    update_pwquality "minclass" "$PWQ_MINCLASS"
    update_pwquality "dcredit" "$PWQ_DCREDIT"
    update_pwquality "ucredit" "$PWQ_UCREDIT"
    update_pwquality "lcredit" "$PWQ_LCREDIT"
    update_pwquality "ocredit" "$PWQ_OCREDIT"
    update_pwquality "maxrepeat" "$PWQ_MAXREPEAT"
    update_pwquality "retry" "$PWQ_RETRY"
    # enforce_for_root is a bare flag (no "=value"), so it needs its own
    # handling rather than the generic key=value function above.
    if [[ "$PWQ_ENFORCE_FOR_ROOT" -eq 1 ]]; then
        if grep -qE "^[[:space:]]*enforce_for_root[[:space:]]*$" "$PWQUALITY_CONF"; then
            : # already active, nothing to do
        elif grep -qE "^#[[:space:]]*enforce_for_root[[:space:]]*$" "$PWQUALITY_CONF"; then
            sed -i "s/^#[[:space:]]*enforce_for_root[[:space:]]*$/enforce_for_root/" "$PWQUALITY_CONF"
        else
            echo "enforce_for_root" >> "$PWQUALITY_CONF"
        fi
    fi

    echo "Note: pwquality only affects passwords set/changed AFTER this point --"
    echo "existing passwords can't be retroactively checked for complexity since"
    echo "only their hashes are stored, not the plaintext."
else
    echo "$PWQUALITY_CONF not found -- is libpam-pwquality (Debian/Ubuntu) or"
    echo "pam_pwquality / pam-pwquality (RHEL/Fedora) installed? Skipping"
    echo "complexity settings."
fi

# ----- Pick the users to apply this to -----
# Every account with UID >= UID_MIN, PLUS every account listed after the first
# UID_MIN account in /etc/passwd (useradd appends, so this catches accounts added
# later even if they were given a low, service-looking UID). "nobody"/"nogroup"
# are excluded. Accounts with a non-login shell are skipped below.
mapfile -t USERS < <(awk -F: -v anchor="$UID_MIN" '
    $3 == anchor { after = 1 }
    ($1 != "nobody" && $1 != "nogroup" && ($3 + 0 >= anchor || after)) { print $1 }
' /etc/passwd)

if [[ "$CHANGE_ROOT" -eq 1 ]]; then
    USERS=(root "${USERS[@]}")
fi

is_login_shell() {
    local shell
    shell=$(getent passwd "$1" | cut -d: -f7)
    case "$shell" in
        *nologin|*/false|*/sync|*/shutdown|*/halt) return 1 ;;
        *) return 0 ;;
    esac
}

echo "Applying aging policy$([[ "$CHANGE_PASSWORDS" -eq 1 ]] && echo " and resetting passwords") for existing users..."

TARGETS=()
PW_FAILED=()

if [[ ${#USERS[@]} -eq 0 ]]; then
    echo "No matching users found."
else
    for user in "${USERS[@]}"; do
        if ! is_login_shell "$user"; then
            echo "  Skipping $user (non-login shell: $(getent passwd "$user" | cut -d: -f7))"
            continue
        fi
        TARGETS+=("$user")

        # Reset the password first. chpasswd also stamps today as the "last
        # changed" date, which clears any "password must be changed" flag.
        # It goes through PAM, so the pwquality rules above are enforced; a
        # rejection is recorded and the script carries on with the next user.
        if [[ "$CHANGE_PASSWORDS" -eq 1 ]]; then
            if echo "${user}:${NEW_PASSWORD}" | chpasswd 2>/dev/null; then
                pw_status="password reset"
            else
                pw_status="PASSWORD NOT CHANGED"
                PW_FAILED+=("$user")
            fi
        else
            pw_status="password untouched"
        fi

        chage --maxdays "$PASS_MAX_DAYS" \
              --mindays "$PASS_MIN_DAYS" \
              --warndays "$PASS_WARN_AGE" \
              "$user"
        echo "  $user: aging policy applied, $pw_status"
    done
fi

echo ""
echo "Done. Policy summary for the ${#TARGETS[@]} affected user(s):"
printf "  %-16s %-14s %-14s %s\n" "USER" "LAST CHANGED" "EXPIRES" "MIN/MAX/WARN"
for user in "${TARGETS[@]}"; do
    info=$(chage -l "$user")
    last=$(echo "$info"  | awk -F': ' '/Last password change/ {print $2}')
    exp=$(echo "$info"   | awk -F': ' '/^Password expires/ {print $2}')
    min=$(echo "$info"   | awk -F': ' '/Minimum number/ {print $2}')
    max=$(echo "$info"   | awk -F': ' '/Maximum number/ {print $2}')
    warn=$(echo "$info"  | awk -F': ' '/Number of days of warning/ {print $2}')
    printf "  %-16s %-14s %-14s %s/%s/%s\n" "$user" "$last" "$exp" "$min" "$max" "$warn"
done

if [[ ${#PW_FAILED[@]} -gt 0 ]]; then
    echo ""
    echo "WARNING: the password could not be set for: ${PW_FAILED[*]}"
    echo "(Most likely it was rejected by the pwquality rules, or the account is locked/special.)"
fi

if [[ "$CHANGE_PASSWORDS" -eq 1 && ${#PW_FAILED[@]} -lt ${#TARGETS[@]} ]]; then
    echo ""
    echo "Every account not listed above now has the same password. Delete this script when"
    echo "done (it contains that password in plaintext)."
fi
