#!/bin/bash
#
# ssh_defense.sh
# Hardens sshd_config against brute-force and common misconfigurations.
#
# SAFETY NOTE: disabling password authentication will lock you out if no
# user has SSH key-based access set up. This script checks for that first
# and will refuse to disable password auth unless it finds at least one
# authorized_keys file, so you don't get bricked. It also validates the
# new config with `sshd -t` before restarting the service, and rolls back
# automatically if the config is invalid.
#
# Must be run as root.

set -uo pipefail   # no -e: we want to control our own rollback logic on failure

# ----- Configurable policy values -----
PERMIT_ROOT_LOGIN="no"          # no | yes | prohibit-password
PASSWORD_AUTH="no"              # will be auto-forced to "yes" if no SSH keys are found (see safety check below)
PERMIT_EMPTY_PASSWORDS="no"
MAX_AUTH_TRIES=3                # attempts per connection before disconnect
LOGIN_GRACE_TIME=30             # seconds allowed to authenticate before disconnect
CLIENT_ALIVE_INTERVAL=300       # seconds between keepalive checks
CLIENT_ALIVE_COUNT_MAX=0        # disconnect idle sessions after ClientAliveInterval * this (0 = disconnect after first missed check)
X11_FORWARDING="no"
ALLOW_TCP_FORWARDING="no"
PERMIT_USER_ENVIRONMENT="no"
MAX_SESSIONS=2
UID_MIN=1000                    # used only for the authorized_keys safety scan
# ---------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "$SSHD_CONFIG not found. Is OpenSSH server installed?" >&2
    exit 1
fi

BACKUP="${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
echo "Backing up $SSHD_CONFIG to $BACKUP"
cp "$SSHD_CONFIG" "$BACKUP"

# ----- Safety check: don't disable password auth if nobody has a key set up -----
if [[ "$PASSWORD_AUTH" == "no" ]]; then
    echo "Checking for existing SSH key-based access before disabling password auth..."
    KEY_FOUND=0

    if [[ -s /root/.ssh/authorized_keys ]]; then
        KEY_FOUND=1
    fi

    mapfile -t CHECK_USERS < <(awk -F: -v minuid="$UID_MIN" '($3 >= minuid) {print $1}' /etc/passwd)
    for u in "${CHECK_USERS[@]}"; do
        home=$(getent passwd "$u" | cut -d: -f6)
        if [[ -s "${home}/.ssh/authorized_keys" ]]; then
            KEY_FOUND=1
            break
        fi
    done

    if [[ "$KEY_FOUND" -eq 0 ]]; then
        echo "  WARNING: No authorized_keys found for root or any user (UID >= $UID_MIN)."
        echo "  Disabling password authentication now would lock everyone out over SSH."
        echo "  Forcing PasswordAuthentication to 'yes' instead. Set up key-based login"
        echo "  first, then re-run this script to safely switch it to 'no'."
        PASSWORD_AUTH="yes"
    else
        echo "  Found at least one authorized_keys file -- safe to disable password auth."
    fi
fi

# ----- Update sshd_config -----
update_sshd_config() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}[[:space:]]+" "$SSHD_CONFIG"; then
        sed -i "s/^${key}[[:space:]].*/${key} ${value}/" "$SSHD_CONFIG"
    elif grep -qiE "^#[[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG"; then
        sed -i "s/^#[[:space:]]*${key}[[:space:]].*/${key} ${value}/i" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

echo "Applying SSH hardening settings..."
update_sshd_config "PermitRootLogin" "$PERMIT_ROOT_LOGIN"
update_sshd_config "PasswordAuthentication" "$PASSWORD_AUTH"
update_sshd_config "PermitEmptyPasswords" "$PERMIT_EMPTY_PASSWORDS"
update_sshd_config "MaxAuthTries" "$MAX_AUTH_TRIES"
update_sshd_config "LoginGraceTime" "$LOGIN_GRACE_TIME"
update_sshd_config "ClientAliveInterval" "$CLIENT_ALIVE_INTERVAL"
update_sshd_config "ClientAliveCountMax" "$CLIENT_ALIVE_COUNT_MAX"
update_sshd_config "X11Forwarding" "$X11_FORWARDING"
update_sshd_config "AllowTcpForwarding" "$ALLOW_TCP_FORWARDING"
update_sshd_config "PermitUserEnvironment" "$PERMIT_USER_ENVIRONMENT"
update_sshd_config "MaxSessions" "$MAX_SESSIONS"

# ----- Validate before restarting -----
echo "Validating new config with 'sshd -t'..."
if ! sshd -t 2>/tmp/sshd_test_err; then
    echo "ERROR: new sshd_config failed validation:" >&2
    cat /tmp/sshd_test_err >&2
    echo "Rolling back to the backup..." >&2
    cp "$BACKUP" "$SSHD_CONFIG"
    rm -f /tmp/sshd_test_err
    exit 1
fi
rm -f /tmp/sshd_test_err
echo "Config is valid."

# ----- Restart the service (name differs by distro) -----
SERVICE=""
for candidate in sshd ssh; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${candidate}\.service"; then
        SERVICE="$candidate"
        break
    fi
done

if [[ -z "$SERVICE" ]]; then
    echo "Couldn't determine the SSH service name (sshd vs ssh)." >&2
    echo "Config has been updated and validated, but you'll need to restart" >&2
    echo "the SSH service manually, e.g.: systemctl restart ssh" >&2
else
    echo "Restarting $SERVICE..."
    systemctl restart "$SERVICE"
    echo "Done. $SERVICE restarted with hardened config."
fi

echo ""
echo "Summary of applied settings:"
grep -E "^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|MaxAuthTries|LoginGraceTime|ClientAliveInterval|ClientAliveCountMax|X11Forwarding|AllowTcpForwarding|PermitUserEnvironment|MaxSessions)" "$SSHD_CONFIG"

if [[ "$PASSWORD_AUTH" == "yes" ]]; then
    echo ""
    echo "NOTE: PasswordAuthentication is still 'yes' because no SSH keys were"
    echo "found. Set up key-based auth, then re-run this script to disable it."
fi

echo ""
echo "IMPORTANT: keep your current terminal/SSH session open until you've"
echo "confirmed you can open a NEW connection successfully -- don't close"
echo "this session first, in case something needs to be rolled back."
