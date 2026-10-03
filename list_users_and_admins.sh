#!/bin/bash
#
# list_users_and_admins.sh
#
# Finds the first real user in /etc/passwd (the first entry with UID >= 1000)
# and lists every account that appears AFTER it in the file -- by file
# position, not by UID number. /etc/passwd entries are appended in creation
# order, so this catches anything added later even if it was given a low,
# service-looking UID (a classic way to disguise a backdoor account). It
# also reports who currently has admin-equivalent rights, checked directly
# against /etc/group (including primary-group membership, which doesn't
# show up in a group's member list but still grants that group's
# privileges).
#
# Run as root (or with sudo) for full group info.

set -uo pipefail   # no -e here: we want to keep going and report, not abort on a grep miss

# A user account can be "suspicious" two different ways, so this script
# flags the union of both:
#   (a) UID >= 1000, anywhere in the file -- the normal convention for real
#       user accounts. Catches an account created with a deliberately high
#       UID even if it was added before the real first user.
#   (b) positioned AFTER the first real user's line in /etc/passwd,
#       regardless of its own UID -- since useradd appends to the end of
#       the file, this catches an account added later even if it was given
#       a low, service-looking UID to blend in.
#
# Known placeholder accounts that technically have a high UID but are not
# real users (e.g. "nobody" is commonly UID 65534) are excluded by name so
# rule (a) doesn't flag them.
UID_ANCHOR=1000
EXCLUDE_NAMES=(nobody nogroup)

# Groups treated as granting admin-equivalent privileges. sudo/wheel/admin are
# the classic ones; root/adm/lpadmin/docker are included because membership in
# them also grants meaningful elevated access (docker group membership is
# effectively root-equivalent via the docker socket). Adjust this list to
# match your own policy.
ADMIN_GROUPS=(sudo wheel admin root adm lpadmin docker)

# Returns matching admin group name(s), or "" if none, for whether $1 has
# admin-equivalent rights, checked directly against /etc/group -- both
# secondary membership (the group's member list) AND primary group
# membership (the GID set in /etc/passwd, which does NOT show up in
# /etc/group's member list but still grants that group's privileges).
check_admin_status() {
    local user="$1"
    local matched=()

    local primary_gid
    primary_gid=$(awk -F: -v u="$user" '$1 == u {print $4}' /etc/passwd)
    if [[ -n "$primary_gid" ]]; then
        local primary_group
        primary_group=$(awk -F: -v gid="$primary_gid" '$3 == gid {print $1}' /etc/group)
        for ag in "${ADMIN_GROUPS[@]}"; do
            if [[ "$primary_group" == "$ag" ]]; then
                matched+=("$ag(primary)")
            fi
        done
    fi

    for ag in "${ADMIN_GROUPS[@]}"; do
        local members
        members=$(awk -F: -v g="$ag" '$1 == g {print $4}' /etc/group)
        if [[ -n "$members" ]] && echo ",${members}," | grep -q ",${user},"; then
            matched+=("$ag")
        fi
    done

    if [[ ${#matched[@]} -gt 0 ]]; then
        printf '%s\n' "${matched[@]}" | sort -u | paste -sd, -
    else
        echo ""
    fi
}

echo "=================================================================="
echo " STEP 0: Accounts with UID 0 (full root privileges)"
echo "=================================================================="
echo "Only 'root' should ever have UID 0. Any other account here is a"
echo "critical finding -- it has full root access regardless of its name."
echo ""

UID0_ACCOUNTS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
UID0_COUNT=$(echo "$UID0_ACCOUNTS" | grep -c .)

if [[ "$UID0_COUNT" -le 1 && "$UID0_ACCOUNTS" == "root" ]]; then
    echo "  OK: only 'root' has UID 0."
else
    echo "  Accounts with UID 0:"
    echo "$UID0_ACCOUNTS" | sed 's/^/    /'
    extra=$(echo "$UID0_ACCOUNTS" | grep -v '^root$')
    if [[ -n "$extra" ]]; then
        echo ""
        echo "  [!] CRITICAL: the following non-root account(s) have UID 0:"
        echo "$extra" | sed 's/^/      /'
    fi
fi

echo ""
echo "=================================================================="
echo " STEP 1: Real/flagged user accounts"
echo "=================================================================="

mapfile -t PASSWD_LINES < /etc/passwd

is_excluded() {
    local name="$1"
    for ex in "${EXCLUDE_NAMES[@]}"; do
        [[ "$name" == "$ex" ]] && return 0
    done
    return 1
}

# Find the anchor: the entry whose UID is EXACTLY 1000 (the conventional
# first real user on most distros). Exact match, not ">=", so we don't
# latch onto an unrelated high-UID account (e.g. nobody=65534) that
# happens to appear earlier in the file.
ANCHOR_IDX=-1
for i in "${!PASSWD_LINES[@]}"; do
    uid=$(echo "${PASSWD_LINES[$i]}" | cut -d: -f3)
    name=$(echo "${PASSWD_LINES[$i]}" | cut -d: -f1)
    if [[ "$uid" == "$UID_ANCHOR" ]] && ! is_excluded "$name"; then
        ANCHOR_IDX=$i
        break
    fi
done

# Fallback if no exact UID==1000 exists (some distros start regular users
# elsewhere): use the smallest UID >= 1000 instead, ignoring excluded names.
if [[ "$ANCHOR_IDX" -eq -1 ]]; then
    best_uid=""
    for i in "${!PASSWD_LINES[@]}"; do
        uid=$(echo "${PASSWD_LINES[$i]}" | cut -d: -f3)
        name=$(echo "${PASSWD_LINES[$i]}" | cut -d: -f1)
        if [[ "$uid" =~ ^[0-9]+$ ]] && (( uid >= UID_ANCHOR )) && ! is_excluded "$name"; then
            if [[ -z "$best_uid" ]] || (( uid < best_uid )); then
                best_uid="$uid"
                ANCHOR_IDX=$i
            fi
        fi
    done
    if [[ "$ANCHOR_IDX" -ne -1 ]]; then
        echo "No account with UID exactly $UID_ANCHOR found; using the smallest UID >= $UID_ANCHOR as the anchor instead."
    fi
fi

declare -A SEEN
SYS_USERS=()

add_user() {
    local name="$1"
    if [[ -z "${SEEN[$name]:-}" ]]; then
        SEEN["$name"]=1
        SYS_USERS+=("$name")
    fi
}

# Rule (a): UID >= 1000, anywhere in the file.
for line in "${PASSWD_LINES[@]}"; do
    uid=$(echo "$line" | cut -d: -f3)
    name=$(echo "$line" | cut -d: -f1)
    if [[ "$uid" =~ ^[0-9]+$ ]] && (( uid >= UID_ANCHOR )) && ! is_excluded "$name"; then
        add_user "$name"
    fi
done

# Rule (b): positioned at/after the anchor line, regardless of UID.
if [[ "$ANCHOR_IDX" -ne -1 ]]; then
    anchor_user=$(echo "${PASSWD_LINES[$ANCHOR_IDX]}" | cut -d: -f1)
    anchor_uid=$(echo "${PASSWD_LINES[$ANCHOR_IDX]}" | cut -d: -f3)
    echo "Anchor: '$anchor_user' (UID $anchor_uid, line $((ANCHOR_IDX + 1)) of /etc/passwd)."
    echo "Showing: every account with UID >= $UID_ANCHOR, PLUS everything from the"
    echo "anchor's line onward regardless of UID (catches low-UID accounts added later)."
    echo ""
    for ((i = ANCHOR_IDX; i < ${#PASSWD_LINES[@]}; i++)); do
        name=$(echo "${PASSWD_LINES[$i]}" | cut -d: -f1)
        is_excluded "$name" || add_user "$name"
    done
else
    echo "No account with UID >= $UID_ANCHOR found at all -- showing nothing from rule (b)."
fi

# Rule (c): any account with UID 0 (full root privileges), regardless of
# name, position, or the rules above -- these need to show up in every
# check below, not just the dedicated Step 0 callout.
for line in "${PASSWD_LINES[@]}"; do
    uid=$(echo "$line" | cut -d: -f3)
    name=$(echo "$line" | cut -d: -f1)
    if [[ "$uid" == "0" ]]; then
        add_user "$name"
    fi
done

if [[ ${#SYS_USERS[@]} -eq 0 ]]; then
    echo "No accounts found after the anchor."
else
    printf "%-20s %-8s %-30s %-20s %s\n" "USERNAME" "UID" "SHELL" "HOME" "GROUPS"
    printf "%-20s %-8s %-30s %-20s %s\n" "--------" "---" "-----" "----" "------"
    for u in "${SYS_USERS[@]}"; do
        uid=$(id -u "$u" 2>/dev/null)
        shell=$(getent passwd "$u" | cut -d: -f7)
        home=$(getent passwd "$u" | cut -d: -f6)
        groups=$(id -nG "$u" 2>/dev/null | tr ' ' ',')
        printf "%-20s %-8s %-30s %-20s %s\n" "$u" "$uid" "$shell" "$home" "$groups"
    done
fi

echo ""
echo "=================================================================="
echo " STEP 2: Who currently has admin rights, per /etc/group"
echo "         (checking: ${ADMIN_GROUPS[*]})"
echo "=================================================================="

for g in "${ADMIN_GROUPS[@]}"; do
    line=$(awk -F: -v g="$g" '$1 == g {print}' /etc/group)
    if [[ -n "$line" ]]; then
        gid=$(echo "$line" | cut -d: -f3)
        members=$(echo "$line" | cut -d: -f4)
        primary_members=$(awk -F: -v gid="$gid" '$4 == gid {print $1}' /etc/passwd | paste -sd, -)
        echo "  Group '$g' (GID $gid):"
        echo "      secondary members: ${members:-none}"
        echo "      primary-group members: ${primary_members:-none}"
    fi
done

if [[ -f /etc/sudoers ]]; then
    echo ""
    echo "  Explicit /etc/sudoers entries (non-comment, non-blank):"
    grep -vE '^\s*#|^\s*$' /etc/sudoers 2>/dev/null | sed 's/^/    /'
fi
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        echo "  $f:"
        grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | sed 's/^/    /'
    done
fi

echo ""
echo "=================================================================="
echo " STEP 3: Per-user admin summary"
echo "=================================================================="

printf "%-20s %s\n" "SYSTEM USER" "ADMIN GROUPS (from /etc/group)"
printf "%-20s %s\n" "-----------" "------------------------------"

for u in "${SYS_USERS[@]}"; do
    admin_groups_matched=$(check_admin_status "$u")
    if [[ -n "$admin_groups_matched" ]]; then
        printf "%-20s %s\n" "$u" "$admin_groups_matched"
    else
        printf "%-20s %s\n" "$u" "no"
    fi
done

echo ""
echo "Done. Review the admin list above against your own policy for anyone"
echo "who shouldn't have those rights."
