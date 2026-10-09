#!/bin/bash
#
# list_users_and_admins.sh  (v2) -- READ-ONLY user & privilege audit
#
# Nothing on the system is changed. It prints findings and a summary of
# everything that needs a look, marked:
#   [CRIT]  almost certainly a planted problem (extra UID 0, empty password...)
#   [WARN]  probably wrong, check it against the README
#   [INFO]  context
#
# Run as root:  sudo ./list_users_and_admins.sh
#
# OPTIONAL: paste the README's lists below (space-separated usernames).
# If filled in, the script compares the system against them. If left
# empty, it just reports what's there.

AUTHORIZED_ADMINS=()   # e.g. (king james mary)
AUTHORIZED_USERS=()    # regular (non-admin) users, e.g. (john patricia robert)

UID_ANCHOR=1000
EXCLUDE_NAMES=(nobody nogroup)
# Groups that give admin-level power. docker/lxd = root-equivalent.
ADMIN_GROUPS=(sudo wheel admin root adm lpadmin docker lxd shadow disk)

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (sudo) -- /etc/shadow and home dirs can't be checked otherwise." >&2
    exit 1
fi

if [[ -t 1 ]]; then
    RED=$'\e[31m'; YEL=$'\e[33m'; BLU=$'\e[34m'; GRN=$'\e[32m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
    RED=""; YEL=""; BLU=""; GRN=""; BLD=""; RST=""
fi
FINDINGS=()
crit()    { printf '  %s[CRIT]%s %s\n' "$RED" "$RST" "$1"; FINDINGS+=("CRIT|$1"); }
warn()    { printf '  %s[WARN]%s %s\n' "$YEL" "$RST" "$1"; FINDINGS+=("WARN|$1"); }
info()    { printf '  %s[INFO]%s %s\n' "$BLU" "$RST" "$1"; }
ok()      { printf '  %s[ OK ]%s %s\n' "$GRN" "$RST" "$1"; }
section() { printf '\n%s== %s ==%s\n' "$BLD" "$1" "$RST"; }

in_list() { local x=$1; shift; local i; for i in "$@"; do [[ $i == "$x" ]] && return 0; done; return 1; }
HAVE_README=0
(( ${#AUTHORIZED_ADMINS[@]} + ${#AUTHORIZED_USERS[@]} > 0 )) && HAVE_README=1
ALL_AUTH=("${AUTHORIZED_ADMINS[@]}" "${AUTHORIZED_USERS[@]}")

is_login_shell() {
    case "$1" in
        ""|*nologin|*/false|*/sync|*/shutdown|*/halt) return 1 ;;
        *) return 0 ;;
    esac
}

# Can the account actually be used to log in? (login shell AND not locked)
can_login() {
    local shell hash
    shell=$(getent passwd "$1" | cut -d: -f7)
    hash=$(awk -F: -v u="$1" '$1==u{print $2}' /etc/shadow)
    is_login_shell "$shell" && [[ $hash != "!"* && $hash != "*"* ]]
}

# admin groups a user is in: secondary (group member list) + primary (GID)
admin_groups_of() {
    local u=$1 pgid pgroup g members out=()
    pgid=$(awk -F: -v u="$u" '$1==u{print $4}' /etc/passwd)
    pgroup=$(awk -F: -v g="$pgid" '$3==g{print $1}' /etc/group)
    for g in "${ADMIN_GROUPS[@]}"; do
        [[ $pgroup == "$g" ]] && out+=("$g(primary)")
        members=$(awk -F: -v g="$g" '$1==g{print $4}' /etc/group)
        [[ ",$members," == *",$u,"* ]] && out+=("$g")
    done
    printf '%s\n' "${out[@]}" | awk 'NF && !s[$0]++' | paste -sd, -
}

# users granted root by a sudoers rule directly (not through a group)
SUDOERS_FILES=(/etc/sudoers)
for f in /etc/sudoers.d/*; do [[ -f $f ]] && SUDOERS_FILES+=("$f"); done
sudoers_direct() {
    grep -hvE '^\s*(#|$|Defaults|%|@include|Cmnd_Alias|Host_Alias|Runas_Alias|User_Alias)' "${SUDOERS_FILES[@]}" 2>/dev/null \
        | awk -v u="$1" '$1==u' | head -n1
}

printf '%sUser & privilege audit%s  %s on %s\n' "$BLD" "$RST" "$(date '+%F %H:%M')" "$(hostname)"
(( HAVE_README )) && info "Comparing against ${#AUTHORIZED_ADMINS[@]} admin(s) and ${#AUTHORIZED_USERS[@]} user(s) from the README lists" \
                  || info "README lists are empty -- reporting only (fill AUTHORIZED_ADMINS / AUTHORIZED_USERS at the top to compare)"

# =====================================================================
section "Which accounts are checked"
# =====================================================================
# (a) UID >= 1000  (b) anything at/after the UID-1000 line  (c) UID 0
mapfile -t AUDIT_USERS < <(awk -F: -v a="$UID_ANCHOR" '
    BEGIN { split("'"${EXCLUDE_NAMES[*]}"'", ex, " "); for (i in ex) skip[ex[i]]=1 }
    $3 == a && !anchor { anchor = 1 }
    !($1 in skip) && ($3+0 >= a || anchor || $3 == 0) && !seen[$1]++ { print $1 }
' /etc/passwd)
anchor_line=$(awk -F: -v a="$UID_ANCHOR" '$3==a{print NR": "$1; exit}' /etc/passwd)
info "Anchor (first UID $UID_ANCHOR): ${anchor_line:-none found}"
info "${#AUDIT_USERS[@]} account(s): UID >= $UID_ANCHOR, everything listed after the anchor, and UID 0"

# =====================================================================
section "Account table"
# =====================================================================
printf '  %-14s %-6s %-7s %-6s %-20s %-18s %s\n' USER UID PASS ADMIN SHELL "LAST LOGIN" "ADMIN VIA"
SERVICE=()
for u in "${AUDIT_USERS[@]}"; do
    via=$(admin_groups_of "$u")
    if ! can_login "$u" && [[ -z $via && -z $(sudoers_direct "$u") ]] && [[ $(id -u "$u") != 0 ]]; then
        SERVICE+=("$u"); continue
    fi
    IFS=: read -r _ _ uid _ _ _ shell < <(getent passwd "$u")
    hash=$(awk -F: -v u="$u" '$1==u{print $2}' /etc/shadow)
    case "$hash" in
        "")        pst="EMPTY" ;;
        "!"*|"*"*) pst="locked" ;;
        *)         pst="set" ;;
    esac
    via=$(admin_groups_of "$u"); sd=$(sudoers_direct "$u")
    [[ -n $sd ]] && via="${via:+$via,}sudoers"
    adm=$([[ -n $via || $uid == 0 ]] && echo yes || echo no)
    last=$(lastlog -u "$u" 2>/dev/null | awk 'NR==2{ if ($0 ~ /Never logged in/) print "never"; else print $(NF-5),$(NF-4),$(NF-1) }')
    printf '  %-14s %-6s %-7s %-6s %-20s %-18s %s\n' "$u" "$uid" "$pst" "$adm" "${shell:0:20}" "${last:-?}" "${via:--}"
done
(( ${#SERVICE[@]} )) && info "${#SERVICE[@]} locked/no-login service account(s) not shown: ${SERVICE[*]}"

# =====================================================================
section "Root-level accounts"
# =====================================================================
uid0=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | paste -sd' ')
[[ -n $uid0 ]] && crit "Non-root account(s) with UID 0 (full root): $uid0" || ok "Only root has UID 0"
gid0=$(awk -F: '$4==0 && $1!="root"{print $1}' /etc/passwd | paste -sd' ')
[[ -n $gid0 ]] && warn "Account(s) with root as primary group (GID 0): $gid0"
roothash=$(awk -F: '$1=="root"{print $2}' /etc/shadow)
[[ -z $roothash ]] && crit "root has an EMPTY password"
[[ $roothash != "!"* && $roothash != "*"* && -n $roothash ]] && info "root has a password set (normal on some images; Ubuntu default is locked)"

# =====================================================================
section "Password problems"
# =====================================================================
found=0
while IFS=: read -r name hash _; do
    [[ -z $hash ]] && { crit "$name has an EMPTY password (anyone can log in)"; found=1; }
done < /etc/shadow
while IFS=: read -r name pw _; do
    [[ $pw != x ]] && { crit "$name has a password field in /etc/passwd ('$pw') instead of 'x' -- bypasses /etc/shadow"; found=1; }
done < /etc/passwd
while IFS=: read -r name hash _; do
    case "$hash" in
        '$1$'*) warn "$name uses a weak MD5 password hash -- reset the password"; found=1 ;;
        [a-zA-Z0-9./][a-zA-Z0-9./]?????????) warn "$name uses an ancient DES password hash -- reset the password"; found=1 ;;
    esac
done < /etc/shadow
grep -qE '\bnullok\b' /etc/pam.d/common-auth 2>/dev/null && { warn "'nullok' in /etc/pam.d/common-auth lets empty passwords log in"; found=1; }
(( found )) || ok "No empty, misplaced or weak password hashes"

# =====================================================================
section "Duplicates and odd names"
# =====================================================================
found=0
d=$(cut -d: -f3 /etc/passwd | sort | uniq -d | grep -vx 0 | paste -sd' ');  [[ -n $d ]] && { crit "Duplicate UID(s): $d -- accounts sharing a UID are the same user"; found=1; }
d=$(cut -d: -f1 /etc/passwd | sort | uniq -d | paste -sd' ');  [[ -n $d ]] && { crit "Duplicate username(s) in /etc/passwd: $d"; found=1; }
d=$(cut -d: -f3 /etc/group  | sort | uniq -d | paste -sd' ');  [[ -n $d ]] && { warn "Duplicate GID(s) in /etc/group: $d"; found=1; }
d=$(cut -d: -f1 /etc/group  | sort | uniq -d | paste -sd' ');  [[ -n $d ]] && { warn "Duplicate group name(s): $d"; found=1; }
d=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/group | paste -sd' '); [[ -n $d ]] && { crit "Group(s) with GID 0 besides root: $d"; found=1; }
d=$(awk -F: '$1 !~ /^[a-z_][a-z0-9_-]*\$?$/ {print $1}' /etc/passwd | paste -sd' '); [[ -n $d ]] && { warn "Unusual username(s) (hidden/uppercase/odd characters): $d"; found=1; }
d=$(cut -d: -f1 /etc/passwd | sort > "${TMPDIR:-/tmp}/.pw$$"; cut -d: -f1 /etc/shadow | sort | comm -3 "${TMPDIR:-/tmp}/.pw$$" - | tr -d '\t' | paste -sd' '; rm -f "${TMPDIR:-/tmp}/.pw$$")
[[ -n $d ]] && { warn "Accounts in only one of /etc/passwd and /etc/shadow: $d (run 'pwck -r')"; found=1; }
(( found )) || ok "No duplicate or odd accounts"

# =====================================================================
section "System accounts that can log in"
# =====================================================================
# UID 1-999 accounts normally have nologin/false. A real shell on one of
# them (especially with a password) is a common hidden backdoor.
found=0
while IFS=: read -r name _ uid _ _ _ shell; do
    (( uid > 0 && uid < UID_ANCHOR )) || continue
    in_list "$name" "${EXCLUDE_NAMES[@]}" && continue
    is_login_shell "$shell" || continue
    hash=$(awk -F: -v u="$name" '$1==u{print $2}' /etc/shadow)
    if [[ -n $hash && $hash != "!"* && $hash != "*"* ]]; then
        crit "System account $name (UID $uid) has a login shell ($shell) AND a password"
    else
        warn "System account $name (UID $uid) has a login shell ($shell)"
    fi
    found=1
done < /etc/passwd
(( found )) || ok "No system accounts with login shells"

# =====================================================================
section "Admin rights"
# =====================================================================
for g in "${ADMIN_GROUPS[@]}"; do
    line=$(awk -F: -v g="$g" '$1==g' /etc/group); [[ -z $line ]] && continue
    gid=$(cut -d: -f3 <<<"$line"); mem=$(cut -d: -f4 <<<"$line")
    prim=$(awk -F: -v g="$gid" '$4==g{print $1}' /etc/passwd | paste -sd, -)
    printf '  %-8s members: %-30s primary: %s\n' "$g" "${mem:-none}" "${prim:-none}"
done

echo
echo "  Active sudoers lines:"
for f in "${SUDOERS_FILES[@]}"; do
    grep -nvE '^\s*(#[^i]|#$|$)' "$f" 2>/dev/null | sed "s|^|    ${f##*/}:|"
done
found=0
while read -r line; do
    [[ -z $line ]] && continue
    warn "NOPASSWD sudo rule (no password needed for root): $line"; found=1
done < <(grep -hvE '^\s*#' "${SUDOERS_FILES[@]}" 2>/dev/null | grep -E 'NOPASSWD')
while read -r line; do
    [[ -z $line ]] && continue
    warn "Authentication disabled for sudo: $line"; found=1
done < <(grep -hvE '^\s*#' "${SUDOERS_FILES[@]}" 2>/dev/null | grep -E '!authenticate')
for f in "${SUDOERS_FILES[@]}"; do
    p=$(stat -c '%a %U' "$f")
    [[ $p != "440 root" && $p != "400 root" ]] && { warn "$f permissions are $p (should be 440 root)"; found=1; }
done
(( found )) || ok "No NOPASSWD / !authenticate rules, sudoers permissions OK"

# =====================================================================
section "Home directories and SSH keys"
# =====================================================================
found=0
for u in "${AUDIT_USERS[@]}"; do
    IFS=: read -r _ _ uid _ _ home shell < <(getent passwd "$u")
    [[ -d $home ]] || { is_login_shell "$shell" && [[ $home != / ]] && { info "$u: home $home doesn't exist"; }; continue; }
    [[ $home == / ]] && continue
    owner=$(stat -c '%U' "$home"); mode=$(stat -c '%a' "$home")
    [[ $owner != "$u" ]] && { warn "$u's home $home is owned by $owner"; found=1; }
    (( 8#$mode & 8#002 )) && { warn "$u's home $home is world-writable ($mode)"; found=1; }
    for k in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
        [[ -s $k ]] && { warn "$u has SSH keys in $k ($(grep -cvE '^\s*(#|$)' "$k") key(s)) -- verify they're legit"; found=1; }
    done
    [[ -e $home/.rhosts || -e $home/.shosts ]] && { crit "$u has a .rhosts/.shosts file (passwordless remote login)"; found=1; }
done
[[ -e /etc/hosts.equiv ]] && { crit "/etc/hosts.equiv exists (passwordless remote login)"; found=1; }
(( found )) || ok "Home directories and SSH keys look normal"

# =====================================================================
section "Password aging"
# =====================================================================
nochg=(); for u in "${AUDIT_USERS[@]}"; do
    can_login "$u" || continue
    IFS=: read -r _ _ last min max warnd inact _ < <(grep "^$u:" /etc/shadow)
    [[ -z ${max:-} || $max == 99999 ]] && nochg+=("$u")
done
(( ${#nochg[@]} )) && info "No password expiry set for: ${nochg[*]} (password.sh fixes this)" || ok "All login-capable accounts have a max password age"

# =====================================================================
if (( HAVE_README )); then
section "README comparison"
# =====================================================================
    svc_skip=()
    for u in "${AUDIT_USERS[@]}"; do
        [[ $u == root ]] && continue
        IFS=: read -r _ _ uid _ _ _ shell < <(getent passwd "$u")
        if ! in_list "$u" "${ALL_AUTH[@]}"; then
            if can_login "$u" || [[ -n $(admin_groups_of "$u") || -n $(sudoers_direct "$u") ]]; then
                crit "$u is NOT in the README but can log in -- unauthorized user? (sudo deluser $u)"
            else
                svc_skip+=("$u")
            fi
            continue
        fi
        via=$(admin_groups_of "$u"); sd=$(sudoers_direct "$u")
        if in_list "$u" "${AUTHORIZED_ADMINS[@]}"; then
            [[ -z $via && -z $sd ]] && warn "$u should be an admin but has no admin rights (sudo gpasswd -a $u sudo)"
        else
            [[ -n $via ]] && crit "$u is NOT an admin in the README but has admin rights via: $via"
            [[ -n $sd ]] && crit "$u is NOT an admin in the README but has a sudoers rule: $sd"
        fi
    done
    (( ${#svc_skip[@]} )) && info "Not in the README but locked/no-login (likely package accounts): ${svc_skip[*]}"
    for u in "${ALL_AUTH[@]}"; do
        getent passwd "$u" >/dev/null || warn "$u is in the README but doesn't exist (sudo adduser $u)"
    done
fi

# =====================================================================
section "Summary"
# =====================================================================
nc=0; nw=0
for f in "${FINDINGS[@]}"; do [[ $f == CRIT* ]] && nc=$((nc+1)) || nw=$((nw+1)); done
printf '  %s%d critical%s, %s%d warnings%s\n' "$RED" "$nc" "$RST" "$YEL" "$nw" "$RST"
for f in "${FINDINGS[@]}"; do [[ $f == CRIT* ]] && printf '  %s!%s %s\n' "$RED" "$RST" "${f#*|}"; done
for f in "${FINDINGS[@]}"; do [[ $f == WARN* ]] && printf '  %s-%s %s\n' "$YEL" "$RST" "${f#*|}"; done
echo
echo "  Nothing was changed. Fix what's flagged after checking it against the README."
