#!/bin/bash

set -euo pipefail


LOCKOUT_DENY=5
LOCKOUT_UNLOCK_TIME=60
LOCKOUT_FAIL_INTERVAL=900

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d%H%M%S)

backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        cp "$f" "${f}.bak.${TIMESTAMP}"
        echo "  Backed up $f -> ${f}.bak.${TIMESTAMP}"
    fi
}

if ! find / -xdev -name "pam_faillock.so" 2>/dev/null | grep -q .; then
    echo "pam_faillock.so not found on this system." >&2
    echo "Install it first: 'apt install libpam-modules' (Debian/Ubuntu) or it should already ship with pam on RHEL/Fedora." >&2
    exit 1
fi


FAILLOCK_CONF="/etc/security/faillock.conf"
echo "Configuring $FAILLOCK_CONF..."
backup_file "$FAILLOCK_CONF"
touch "$FAILLOCK_CONF"

set_faillock_option() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}[[:space:]]*=" "$FAILLOCK_CONF" 2>/dev/null; then
        sed -i "s/^${key}[[:space:]]*=.*/${key} = ${value}/" "$FAILLOCK_CONF"
    elif grep -qE "^#[[:space:]]*${key}[[:space:]]*=" "$FAILLOCK_CONF" 2>/dev/null; then
        sed -i "s/^#[[:space:]]*${key}[[:space:]]*=.*/${key} = ${value}/" "$FAILLOCK_CONF"
    else
        echo "${key} = ${value}" >> "$FAILLOCK_CONF"
    fi
}

set_faillock_option "deny" "$LOCKOUT_DENY"
set_faillock_option "unlock_time" "$LOCKOUT_UNLOCK_TIME"
set_faillock_option "fail_interval" "$LOCKOUT_FAIL_INTERVAL"

detect_pam_family() {
    if command -v authselect >/dev/null 2>&1; then
        echo "authselect"
    elif [[ -f /etc/pam.d/common-auth ]]; then
        echo "debian"
    elif [[ -f /etc/pam.d/system-auth ]]; then
        echo "rhel-manual"
    else
        echo "unknown"
    fi
}

FAMILY=$(detect_pam_family)
echo "Detected PAM family: $FAMILY"

case "$FAMILY" in
    authselect)
        echo "This system uses authselect (RHEL/CentOS/Fedora 8+)."
        if authselect current 2>/dev/null | grep -q "with-faillock"; then
            echo "  pam_faillock is already enabled via authselect."
        else
            echo "  pam_faillock is NOT yet enabled via authselect."
            echo "  Enable it with (example, adjust profile name as needed):"
            echo "    authselect select sssd with-faillock --force"
            echo "  Run 'authselect current' to see your active profile first."
        fi
        ;;
    debian)
        AUTH_FILE="/etc/pam.d/common-auth"
        ACCOUNT_FILE="/etc/pam.d/common-account"

        if grep -qE "pam_faillock\.so[[:space:]]+preauth" "$AUTH_FILE" 2>/dev/null \
           && grep -qE "pam_faillock\.so[[:space:]]+authfail" "$AUTH_FILE" 2>/dev/null \
           && grep -qE "pam_faillock\.so[[:space:]]+authsucc" "$AUTH_FILE" 2>/dev/null; then
            echo "  pam_faillock already fully wired into $AUTH_FILE (preauth/authfail/authsucc present)."
        else
            echo "  Rebuilding the Primary block in $AUTH_FILE to use pam_faillock..."
            backup_file "$AUTH_FILE"
            backup_file "$ACCOUNT_FILE"

            if ! grep -qF '# here are the per-package modules (the "Primary" block)' "$AUTH_FILE" \
               || ! grep -qF '# and here are more per-package modules (the "Additional" block)' "$AUTH_FILE"; then
                echo "  $AUTH_FILE doesn't match the expected pam-auth-update layout" >&2
                echo "  (missing the Primary/Additional block markers). Not touching it" >&2
                echo "  automatically -- please wire in pam_faillock manually. The backup" >&2
                echo "  taken above is unmodified." >&2
            else

                unix_opts=$(sed -n '/# here are the per-package modules (the "Primary" block)/,/# and here are more per-package modules/p' "$AUTH_FILE" \
                    | grep -oP '(?<=pam_unix\.so)[^$]*' | head -1 | xargs)
                if [[ -z "$unix_opts" ]]; then
                    unix_opts="try_first_pass"
                elif [[ "$unix_opts" != *"try_first_pass"* ]]; then
                    unix_opts="try_first_pass ${unix_opts}"
                fi

                awk -v unix_opts="$unix_opts" '
                    BEGIN { in_primary = 0; printed = 0 }
                    /# here are the per-package modules \(the "Primary" block\)/ {
                        print
                        print "auth\trequired\t\t\tpam_faillock.so preauth"
                        print "auth\t[success=2 default=ignore]\tpam_unix.so " unix_opts
                        print "# here'\''s the fallback if no module succeeds"
                        print "auth\t[default=die]\t\t\tpam_faillock.so authfail"
                        print "auth\trequisite\t\t\tpam_deny.so"
                        print "# prime the stack with a positive return value if there isn'\''t one already;"
                        print "# this avoids us returning an error just because nothing sets a success code"
                        print "# since the modules above will each just jump around"
                        print "auth\tsufficient\t\t\tpam_faillock.so authsucc"
                        print "auth\trequired\t\t\tpam_permit.so"
                        in_primary = 1
                        printed = 1
                        next
                    }
                    /# and here are more per-package modules \(the "Additional" block\)/ {
                        in_primary = 0
                        print
                        next
                    }
                    in_primary { next }
                    { print }
                ' "$AUTH_FILE" > "${AUTH_FILE}.new"

                mv "${AUTH_FILE}.new" "$AUTH_FILE"
                echo "  Rebuilt Primary block in $AUTH_FILE (preserved pam_unix.so options: ${unix_opts})."
            fi

            if ! grep -q "pam_faillock.so" "$ACCOUNT_FILE" 2>/dev/null; then
                echo "account     required      pam_faillock.so" >> "$ACCOUNT_FILE"
                echo "  Added pam_faillock line to $ACCOUNT_FILE."
            fi
            echo "  Review $AUTH_FILE manually with 'cat -A' or a diff against the backup before trusting it in production."
        fi
        ;;
    rhel-manual)
        echo "  This looks like an older RHEL-family system without authselect."
        echo "  Manual /etc/pam.d/system-auth and password-auth edits are needed;"
        echo "  this script won't auto-edit those files since they're often"
        echo "  symlinked/managed by authconfig. Please configure pam_faillock"
        echo "  manually or install authselect."
        ;;
    *)
        echo "  Could not detect a known PAM family. faillock.conf has been"
        echo "  written, but you'll need to manually ensure pam_faillock.so is"
        echo "  referenced in your PAM auth stack for it to take effect."
        ;;
esac

echo ""
echo "Done. Current faillock configuration:"
grep -E "^(deny|unlock_time|fail_interval)" "$FAILLOCK_CONF" || true
echo ""
echo "To check a user's lockout status:  faillock --user <username>"
echo "To manually unlock a user:         faillock --user <username> --reset"
echo ""
echo "IMPORTANT: Test with a non-root, non-sudo test account in a new SSH"
echo "session before relying on this in production, and keep your current"
echo "session open until you've confirmed logins still work."
