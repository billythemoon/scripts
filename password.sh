#!/bin/bash
#
set -euo pipefail

#edit deez
PASS_MAX_DAYS=90     
PASS_MIN_DAYS=7      
PASS_WARN_AGE=14     
UID_MIN=1000         

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

echo "Applying policy retroactively to existing users (UID >= $UID_MIN)..."


mapfile -t USERS < <(awk -F: -v minuid="$UID_MIN" '($3 >= minuid) && ($1 != "nobody") {print $1}' /etc/passwd)

if [[ ${#USERS[@]} -eq 0 ]]; then
    echo "No matching users found."
else
    for user in "${USERS[@]}"; do
        shell=$(getent passwd "$user" | cut -d: -f7)
        if [[ "$shell" == *"nologin"* || "$shell" == *"/false" ]]; then
            echo "  Skipping $user (non-login shell: $shell)"
            continue
        fi

        echo "  Updating $user"
        chage --maxdays "$PASS_MAX_DAYS" \
              --mindays "$PASS_MIN_DAYS" \
              --warndays "$PASS_WARN_AGE" \
              "$user"
    done
fi

echo ""
echo "Done. Current policy summary for affected users:"
for user in "${USERS[@]}"; do
    shell=$(getent passwd "$user" | cut -d: -f7)
    [[ "$shell" == *"nologin"* || "$shell" == *"/false" ]] && continue
    echo "--- $user ---"
    chage -l "$user"
    echo ""
done
