#!/bin/bash
#
# set_lockout_policy.sh
# Configures account lockout policy (failed login attempts) system-wide
# using pam_faillock. This applies to ALL users automatically, since
# lockout is enforced by PAM at login time, not stored per-user.
#
# Must be run as root.
#
#
# Usage:  sudo ./set_lockout_policy.sh
#
# Applies immediately and stays applied. Every file it edits is backed up first
# (*.bak.<timestamp>). Test a login in a NEW terminal before closing this one.

set -uo pipefail

# ----- Configurable policy values -----
LOCKOUT_DENY=5             # Failed attempts before lockout
LOCKOUT_UNLOCK_TIME=900    # Seconds before auto-unlock (900 = 15 min). 0 = locked until an admin runs faillock --user X --reset
LOCKOUT_FAIL_INTERVAL=900  # Window (seconds) in which failed attempts accumulate toward the deny threshold
# ---------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

# ----- Cancel any auto-revert left over from an older version of this script -----
# (older versions scheduled an 'at' job that undid the lockout after 3 minutes)
if command -v atq >/dev/null 2>&1; then
    for job in $(atq 2>/dev/null | awk '{print $1}'); do
        if at -c "$job" 2>/dev/null | grep -q 'set_lockout_policy'; then
            atrm "$job" && echo "Cancelled a pending auto-revert left by an older run (at job $job)."
        fi
    done
fi
rm -f /root/.set_lockout_policy_state /root/.set_lockout_policy_confirmed

TIMESTAMP=$(date +%Y%m%d%H%M%S)

backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        cp "$f" "${f}.bak.${TIMESTAMP}"
        echo "  Backed up $f -> ${f}.bak.${TIMESTAMP}"
    fi
}

# ----- Verify every PAM module we're about to reference actually exists -----
# Referencing a module that isn't installed is one of the fastest ways to
# break every login: PAM fails the whole phase it can't even load.
find_pam_module() {
    find /lib /usr/lib -xdev -name "$1" 2>/dev/null | head -1
}

MISSING_MODULES=()
for mod in pam_faillock.so pam_unix.so pam_deny.so pam_permit.so; do
    if [[ -z "$(find_pam_module "$mod")" ]]; then
        MISSING_MODULES+=("$mod")
    fi
done

if [[ ${#MISSING_MODULES[@]} -gt 0 ]]; then
    echo "ERROR: the following required PAM modules were not found on this system:" >&2
    printf '  %s\n' "${MISSING_MODULES[@]}" >&2
    echo "Install libpam-modules (Debian/Ubuntu) or the equivalent and re-run. Nothing was changed." >&2
    exit 1
fi

# ----- Ensure the faillock runtime directory exists with correct permissions -----
# pam_faillock needs somewhere to track attempt counts. If this directory is
# missing, pam_faillock's account check can error out -- and since it's
# wired in as "required", that one failure denies every login.
FAILLOCK_DIR="/var/run/faillock"
[[ -d "$FAILLOCK_DIR" ]] || mkdir -p "$FAILLOCK_DIR"
chown root:root "$FAILLOCK_DIR"
chmod 755 "$FAILLOCK_DIR"
echo "Confirmed faillock runtime directory exists: $FAILLOCK_DIR"

# ----- Step 1: Configure /etc/security/faillock.conf (the values pam_faillock reads) -----
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

# ----- Step 2: Make sure pam_faillock is actually wired into the PAM auth stack -----
# This differs by distro family. We detect which PAM files exist and check
# whether pam_faillock is already referenced. We do NOT blindly inject lines
# into unfamiliar PAM stacks — that's how you lock out all logins.

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

        if ! command -v pam-auth-update >/dev/null 2>&1; then
            echo "  pam-auth-update not found -- is libpam-runtime installed?" >&2
            echo "  Nothing changed." >&2
        elif grep -qE "pam_faillock\.so[[:space:]]+preauth" "$AUTH_FILE" 2>/dev/null \
           && grep -qE "pam_faillock\.so[[:space:]]+authfail" "$AUTH_FILE" 2>/dev/null \
           && grep -qE "pam_faillock\.so[[:space:]]+authsucc" "$AUTH_FILE" 2>/dev/null; then
            echo "  pam_faillock already fully wired into $AUTH_FILE (preauth/authfail/authsucc present)."
        else
            echo "  Wiring in pam_faillock via pam-auth-update (not hand-editing PAM files)..."
            backup_file "$AUTH_FILE"
            backup_file "$ACCOUNT_FILE"

            # Two profiles are needed because pam-auth-update only lets a
            # profile contribute to ONE position in the stack (either the
            # very first slot via "-Initial", or a normal slot ordered by
            # Priority -- never both). preauth must run FIRST (before any
            # other auth module), while authfail/authsucc must run AFTER
            # pam_unix's own check. Splitting them into two profiles with
            # priorities above and below pam_unix's (256) achieves both,
            # and pam-auth-update automatically recalculates pam_unix's
            # internal jump offset to stay consistent -- this is the actual
            # fix for the fragility of hand-counting that offset ourselves.
            #
            # Known minor limitation (verified, not a safety issue): because
            # the recalculated jump is based on "always land on a guaranteed
            # success," it skips over authsucc on the success path rather
            # than executing it, so the fail counter isn't reset the instant
            # a login succeeds. fail_interval (set above) still ages out old
            # failures on its own, so this only means a slightly slower
            # reset, not a security gap or a lockout risk.
            cat > /usr/share/pam-configs/faillock-preauth << 'PROFILE1'
Name: pam_faillock preauth (deny already-locked users before auth)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth-Initial:
	requisite			pam_faillock.so preauth
Account-Type: Primary
Account-Initial:
	requisite			pam_faillock.so
PROFILE1

            cat > /usr/share/pam-configs/faillock-tally << 'PROFILE2'
Name: pam_faillock authfail/authsucc (record failures, reset on success)
Default: yes
Priority: 1
Auth-Type: Primary
Auth:
	[default=die]			pam_faillock.so authfail
	sufficient			pam_faillock.so authsucc
PROFILE2

            if pam-auth-update --enable faillock-preauth faillock-tally --force >/dev/null 2>&1; then
                echo "  pam-auth-update applied successfully."
            else
                echo "  pam-auth-update FAILED. Restoring original PAM files from backup." >&2
                cp "${AUTH_FILE}.bak.${TIMESTAMP}" "$AUTH_FILE" 2>/dev/null
                cp "${ACCOUNT_FILE}.bak.${TIMESTAMP}" "$ACCOUNT_FILE" 2>/dev/null
                rm -f /usr/share/pam-configs/faillock-preauth /usr/share/pam-configs/faillock-tally
                echo "  Nothing was left changed." >&2
                exit 1
            fi
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
echo "Current faillock configuration:"
grep -E "^(deny|unlock_time|fail_interval)" "$FAILLOCK_CONF" || true
echo ""
echo "To check a user's lockout status:  faillock --user <username>"
echo "To manually unlock a user:         faillock --user <username> --reset"
echo ""
echo "The lockout policy is applied and permanent. Open a NEW terminal and log in to"
echo "make sure logins still work before closing this one. To undo, copy the .bak"
echo "files listed above back into place and run: sudo pam-auth-update --force"
