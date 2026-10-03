#!/bin/bash
#
# list_scheduled_jobs.sh
# Walks every cron/anacron location (system crontab, cron.d, the
# periodic cron.{hourly,daily,weekly,monthly} script dirs, every user's
# personal crontab, anacrontab) plus at-jobs and systemd timers as a
# bonus, and prints only the active (non-comment, non-blank) lines.
#
# Useful for spotting unauthorized persistence -- run this BEFORE and
# AFTER making changes to compare, or just read through it once for
# anything you don't recognize.
#
# Run as root for full visibility into every user's crontab and
# /var/spool/cron.

print_active_lines() {
    local file="$1"
    if [[ -f "$file" && -r "$file" ]]; then
        local content
        content=$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$file" 2>/dev/null)
        if [[ -n "$content" ]]; then
            echo "  >> $file"
            echo "$content" | sed 's/^/     /'
        fi
    fi
}

echo "===================================================================="
echo " 1. /etc/crontab"
echo "===================================================================="
print_active_lines "/etc/crontab"
[[ -z "$(print_active_lines /etc/crontab)" ]] && echo "  (no active entries, or file not found)"

echo ""
echo "===================================================================="
echo " 2. /etc/cron.d/*"
echo "===================================================================="
FOUND=0
if [[ -d /etc/cron.d ]]; then
    for f in /etc/cron.d/*; do
        [[ -f "$f" ]] || continue
        out=$(print_active_lines "$f")
        if [[ -n "$out" ]]; then
            echo "$out"
            FOUND=1
        fi
    done
fi
[[ "$FOUND" -eq 0 ]] && echo "  (no active entries found)"

echo ""
echo "===================================================================="
echo " 3. Periodic script directories (cron.hourly/daily/weekly/monthly)"
echo "    -- listing scripts present, then their active (non-comment) lines"
echo "===================================================================="
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$dir" ]] || continue
    echo "  --- $dir ---"
    scripts=$(find "$dir" -maxdepth 1 -type f 2>/dev/null)
    if [[ -z "$scripts" ]]; then
        echo "      (empty)"
        continue
    fi
    for s in $scripts; do
        perms=$(stat -c '%a %U:%G' "$s" 2>/dev/null)
        echo "    $s  [$perms]"
        out=$(print_active_lines "$s")
        [[ -n "$out" ]] && echo "$out"
    done
done

echo ""
echo "===================================================================="
echo " 4. /etc/anacrontab"
echo "===================================================================="
out=$(print_active_lines /etc/anacrontab)
if [[ -n "$out" ]]; then
    echo "$out"
else
    echo "  (no active entries, or anacron not installed)"
fi

echo ""
echo "===================================================================="
echo " 5. Per-user crontabs"
echo "===================================================================="
FOUND=0

# Method 1: read the spool directly (Debian/Ubuntu/Mint path shown; RHEL
# sometimes uses /var/spool/cron/ with no 'crontabs' subdir -- check both)
for spool in /var/spool/cron/crontabs /var/spool/cron; do
    [[ -d "$spool" ]] || continue
    for f in "$spool"/*; do
        [[ -f "$f" ]] || continue
        user=$(basename "$f")
        out=$(print_active_lines "$f")
        if [[ -n "$out" ]]; then
            echo "  User: $user"
            echo "$out"
            FOUND=1
        fi
    done
done

# Method 2 (belt-and-suspenders): also ask crontab(1) directly for every
# real user, in case the spool format/location differs from what we assumed
mapfile -t ALL_USERS < <(cut -d: -f1 /etc/passwd)
for u in "${ALL_USERS[@]}"; do
    content=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*#|^[[:space:]]*$')
    if [[ -n "$content" ]]; then
        echo "  User: $u (via crontab -l)"
        echo "$content" | sed 's/^/     /'
        FOUND=1
    fi
done

[[ "$FOUND" -eq 0 ]] && echo "  (no user crontabs with active entries found)"

echo ""
echo "===================================================================="
echo " 6. cron.allow / cron.deny (who's permitted to use cron at all)"
echo "===================================================================="
for f in /etc/cron.allow /etc/cron.deny; do
    if [[ -f "$f" ]]; then
        echo "  $f:"
        print_active_lines "$f"
    fi
done

echo ""
echo "===================================================================="
echo " 7. Bonus: at-jobs (one-off scheduled jobs, not cron, but similar risk)"
echo "===================================================================="
if command -v atq >/dev/null 2>&1; then
    atq_out=$(atq 2>/dev/null)
    if [[ -n "$atq_out" ]]; then
        echo "$atq_out" | sed 's/^/  /'
    else
        echo "  (no pending at-jobs)"
    fi
else
    echo "  (at/atq not installed)"
fi
for f in /etc/at.allow /etc/at.deny; do
    [[ -f "$f" ]] && { echo "  $f:"; print_active_lines "$f"; }
done

echo ""
echo "===================================================================="
echo " 8. Bonus: systemd timers (modern cron replacement -- easy to miss)"
echo "===================================================================="
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/  /'
else
    echo "  (systemctl not available)"
fi

echo ""
echo "Done. Review everything above for jobs you don't recognize --"
echo "especially anything running as root, pointing at /tmp, curl/wget"
echo "piped to a shell, base64-decoded commands, or unfamiliar script paths."
