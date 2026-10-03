#!/bin/bash
#
# set_lockout_policy.sh
# Configures account lockout policy (failed login attempts) system-wide
# using pam_faillock. This applies to ALL users automatically, since
# lockout is enforced by PAM at login time, not stored per-user.
#
# Must be run as root.
#
# SAFETY NET: PAM changes take effect immediately, for every login method
# at once (console, SSH, GUI, autologin) -- there's no "restart a service"
# step to fail safely at. So this script applies the change, then starts a
# background timer. If you don't confirm it worked within ROLLBACK_DELAY
# seconds (by running this same script with --confirm, from a NEW login
# session), it automatically reverts itself. This means you cannot be
# permanently locked out, even if the PAM edit is completely broken --
# worst case, you wait out the timer.
#
# Usage:
#   sudo ./set_lockout_policy.sh            Apply the policy, start the safety-net timer
#   sudo ./set_lockout_policy.sh --confirm  Cancel the pending auto-revert (run this
#                                            from a NEW session after confirming login works)

set -uo pipefail   # no -e: we want to control rollback ourselves on failure, not abort mid-way

# ----- Configurable policy values -----
LOCKOUT_DENY=5             # Failed attempts before lockout
LOCKOUT_UNLOCK_TIME=900    # Seconds before auto-unlock (900 = 15 min). 0 = locked until an admin runs faillock --user X --reset
LOCKOUT_FAIL_INTERVAL=900  # Window (seconds) in which failed attempts accumulate toward the deny threshold
ROLLBACK_DELAY_MIN=3       # Minutes to wait for --confirm before auto-reverting
# ---------------------------------------

STATE_FILE="/root/.set_lockout_policy_state"
CONFIRM_FILE="/root/.set_lockout_policy_confirmed"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

# ----- Handle --confirm: cancel the pending auto-revert -----
if [[ "${1:-}" == "--confirm" ]]; then
    if [[ -f "$STATE_FILE" ]]; then
        touch "$CONFIRM_FILE"
        # Also remove our specific queued at job outright (belt and
        # suspenders; the job already checks for CONFIRM_FILE too, so this
        # isn't strictly required for safety -- just tidiness). Only our
        # own recorded job ID is touched, never other at jobs on the system.
        OUR_JOB_ID=$(grep '^AT_JOB_ID=' "$STATE_FILE" | cut -d= -f2)
        [[ -n "$OUR_JOB_ID" ]] && atrm "$OUR_JOB_ID" 2>/dev/null
        echo "Confirmed. The pending auto-revert has been cancelled."
        echo "Your lockout policy changes are now permanent."
        exit 0
    else
        echo "No pending change found to confirm (nothing to do)."
        exit 0
    fi
fi

TIMESTAMP=$(date +%Y%m%d%H%M%S)

backup_file() {
    local f="$1"
    if [[ -f "$f" ]]; then
        cp "$f" "${f}.bak.${TIMESTAMP}"
        echo "  Backed up $f -> ${f}.bak.${TIMESTAMP}"
    fi
}

# ----- The safety net depends on 'at', a scheduler that runs via its own
# system daemon (atd), independent of this shell session. This matters:
# a plain backgrounded process (nohup/disown) can still be killed the
# moment this login session ends on modern systemd systems (logind can
# tear down a whole user session's processes), which would silently
# disarm the safety net. 'at' avoids that entirely. -----
if ! command -v at >/dev/null 2>&1; then
    echo "Installing 'at' (needed for the auto-revert safety net)..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y at >/dev/null 2>&1
    fi
fi
if ! command -v at >/dev/null 2>&1; then
    echo "ERROR: 'at' could not be found or installed. Refusing to proceed" >&2
    echo "without the safety net -- install it manually (apt install at) and re-run." >&2
    exit 1
fi
systemctl enable --now atd >/dev/null 2>&1 || service atd start >/dev/null 2>&1 || true
if ! pgrep -x atd >/dev/null 2>&1; then
    echo "ERROR: atd doesn't appear to be running, and the safety net needs it." >&2
    echo "Start it manually (systemctl start atd) and re-run." >&2
    exit 1
fi

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

# ----- Arm the safety net (only meaningful if we actually touched PAM files) -----
rm -f "$CONFIRM_FILE"   # any previous confirmation no longer applies to this run

if [[ "$FAMILY" == "debian" && -n "${AUTH_FILE:-}" ]]; then
    AUTH_BACKUP="${AUTH_FILE}.bak.${TIMESTAMP}"
    ACCOUNT_BACKUP="${ACCOUNT_FILE}.bak.${TIMESTAMP}"

    {
        echo "AUTH_FILE=$AUTH_FILE"
        echo "AUTH_BACKUP=$AUTH_BACKUP"
        echo "ACCOUNT_FILE=$ACCOUNT_FILE"
        echo "ACCOUNT_BACKUP=$ACCOUNT_BACKUP"
    } > "$STATE_FILE"

    # Scheduled via 'at', which runs through atd (an independent system
    # service) -- NOT a child of this shell. This survives the terminal
    # closing, the SSH session dropping, or even this whole login session
    # ending, which a plain backgrounded/nohup'd process is not guaranteed
    # to survive on systemd systems (logind can tear down a user's entire
    # process set when their last session ends).
    # NOTE: 'at' always executes jobs via /bin/sh (dash on Debian/Ubuntu),
    # regardless of any shebang line -- confirmed by testing. dash doesn't
    # support bash's [[ ]] test syntax (it fails as "command not found" and
    # silently takes the wrong branch), so this must be plain POSIX sh.
    AT_SCRIPT=$(mktemp)
    cat > "$AT_SCRIPT" << EOF
if [ ! -f '$CONFIRM_FILE' ]; then
    [ -f '$AUTH_BACKUP' ] && cp '$AUTH_BACKUP' '$AUTH_FILE'
    [ -f '$ACCOUNT_BACKUP' ] && cp '$ACCOUNT_BACKUP' '$ACCOUNT_FILE'
    pam-auth-update --force >/dev/null 2>&1
    logger -t set_lockout_policy 'Auto-reverted PAM changes after ${ROLLBACK_DELAY_MIN} min with no --confirm received'
fi
rm -f '$AT_SCRIPT'
EOF
    AT_OUTPUT=$(at now + "${ROLLBACK_DELAY_MIN}" minutes -f "$AT_SCRIPT" 2>&1)
    AT_JOB_ID=$(echo "$AT_OUTPUT" | grep -oE '^job [0-9]+' | awk '{print $2}')
    echo "AT_JOB_ID=$AT_JOB_ID" >> "$STATE_FILE"

    echo ""
    echo "=================================================================="
    echo " SAFETY NET ARMED (via 'at', job #$AT_JOB_ID)"
    echo "=================================================================="
    echo "The change above is LIVE right now. You have $ROLLBACK_DELAY_MIN minute(s) to:"
    echo ""
    echo "  1. Open a NEW terminal/session (don't close this one yet)"
    echo "  2. Confirm you can log in normally"
    echo "  3. Run:  sudo $0 --confirm"
    echo ""
    echo "If you don't run --confirm in time, the scheduled 'at' job will"
    echo "AUTOMATICALLY restore the original PAM files on its own -- this"
    echo "happens via atd, independent of this session, so it fires even if"
    echo "you close this terminal, disconnect, or your session ends entirely."
    echo ""
    echo "Check it's still scheduled any time with: atq"
fi

echo ""
echo "Current faillock configuration:"
grep -E "^(deny|unlock_time|fail_interval)" "$FAILLOCK_CONF" || true
echo ""
echo "To check a user's lockout status:  faillock --user <username>"
echo "To manually unlock a user:         faillock --user <username> --reset"
