#!/bin/bash
#
# fix_permissions.sh
# Resets permissions/ownership on well-known sensitive system files to their
# standard secure values, then scans (and optionally fixes) world-writable
# files and reports SUID/SGID binaries for manual review.
#
# SAFETY NOTE: SUID/SGID binaries are reported, not auto-stripped -- removing
# the bit from something like /usr/bin/sudo or /usr/bin/passwd would break
# the system. Review the SUID list by hand before changing anything there.
#
# Must be run as root.

set -uo pipefail

# ----- Known critical files: "path:perm:owner:group" -----
# Standard, widely-used values. Adjust if your distro/policy differs.
CRITICAL_FILES=(
    "/etc/shadow:640:root:shadow"
    "/etc/gshadow:640:root:shadow"
    "/etc/passwd:644:root:root"
    "/etc/group:644:root:root"
    "/etc/sudoers:440:root:root"
    "/etc/ssh/sshd_config:600:root:root"
    "/etc/crontab:600:root:root"
    "/etc/hosts.allow:644:root:root"
    "/etc/hosts.deny:644:root:root"
    "/boot/grub/grub.cfg:600:root:root"
)

CRITICAL_DIRS=(
    "/etc/cron.d:700:root:root"
    "/etc/cron.daily:700:root:root"
    "/etc/cron.hourly:700:root:root"
    "/etc/cron.weekly:700:root:root"
    "/etc/cron.monthly:700:root:root"
    "/etc/sudoers.d:750:root:root"
)

FIX_WORLD_WRITABLE=1     # 1 = actually strip world-write bit on found files, 0 = report only
SCAN_PATHS=("/etc" "/usr" "/bin" "/sbin" "/opt" "/home" "/root")  # kept off /proc,/sys,/dev,/run automatically
# ---------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

LOGFILE="/root/fix_permissions_before_state.$(date +%Y%m%d%H%M%S).log"
echo "Recording current state of critical files to $LOGFILE before changing anything..."
{
    for entry in "${CRITICAL_FILES[@]}"; do
        path="${entry%%:*}"
        [[ -e "$path" ]] && stat -c '%n %a %U:%G' "$path"
    done
    for entry in "${CRITICAL_DIRS[@]}"; do
        path="${entry%%:*}"
        [[ -e "$path" ]] && stat -c '%n %a %U:%G' "$path"
    done
} > "$LOGFILE"

# =====================================================================
# Part 1: Fix known critical files
# =====================================================================
echo ""
echo "=== Fixing critical system files ==="
for entry in "${CRITICAL_FILES[@]}"; do
    IFS=':' read -r path perm owner group <<< "$entry"
    if [[ -e "$path" ]]; then
        current=$(stat -c '%a %U:%G' "$path")
        chmod "$perm" "$path"
        chown "${owner}:${group}" "$path"
        new=$(stat -c '%a %U:%G' "$path")
        if [[ "$current" != "$new" ]]; then
            echo "  $path: $current -> $new"
        else
            echo "  $path: already correct ($new)"
        fi
    else
        echo "  $path: not found, skipping"
    fi
done

echo ""
echo "=== Fixing critical directories ==="
for entry in "${CRITICAL_DIRS[@]}"; do
    IFS=':' read -r path perm owner group <<< "$entry"
    if [[ -e "$path" ]]; then
        current=$(stat -c '%a %U:%G' "$path")
        chmod "$perm" "$path"
        chown "${owner}:${group}" "$path"
        new=$(stat -c '%a %U:%G' "$path")
        if [[ "$current" != "$new" ]]; then
            echo "  $path: $current -> $new"
        else
            echo "  $path: already correct ($new)"
        fi
    else
        echo "  $path: not found, skipping"
    fi
done

# =====================================================================
# Part 2: World-writable files
# =====================================================================
echo ""
echo "=== Scanning for world-writable files ==="
echo "(limited to: ${SCAN_PATHS[*]})"

WW_FILES=$(find "${SCAN_PATHS[@]}" -xdev -type f -perm -0002 2>/dev/null)

if [[ -z "$WW_FILES" ]]; then
    echo "  None found."
else
    COUNT=$(echo "$WW_FILES" | wc -l)
    echo "  Found $COUNT world-writable file(s):"
    echo "$WW_FILES" | sed 's/^/    /'

    if [[ "$FIX_WORLD_WRITABLE" -eq 1 ]]; then
        echo "  Removing world-write bit from all of the above..."
        echo "$WW_FILES" | while read -r f; do
            chmod o-w "$f"
        done
        echo "  Done."
    else
        echo "  FIX_WORLD_WRITABLE=0, so these were reported only, not changed."
    fi
fi

# =====================================================================
# Part 3: SUID / SGID binaries (report only -- do not auto-strip)
# =====================================================================
echo ""
echo "=== SUID/SGID binaries (for manual review -- NOT changed automatically) ==="
echo "Standard binaries (sudo, passwd, su, mount, etc.) are expected to have"
echo "these bits. Look for anything unfamiliar, especially outside normal"
echo "system directories like /usr/bin, /usr/sbin, /bin, /sbin."
echo ""

find "${SCAN_PATHS[@]}" -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
    | while read -r f; do
        printf "  %s %s\n" "$(stat -c '%a %U:%G' "$f")" "$f"
    done

echo ""
echo "To remove an unwanted SUID/SGID bit manually: chmod u-s,g-s <path>"
echo ""
echo "Before-state of critical files was saved to: $LOGFILE"
echo "Done."
