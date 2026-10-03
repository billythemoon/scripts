#!/bin/bash
#
# compare_users_to_readme.sh
#
# Finds a README on the Desktop (any user's, or root's), lists every user
# account with UID >= 1000 (i.e. everyone added after the first real user,
# since UIDs are assigned sequentially -- includes service-style accounts
# too, nothing is filtered out), shows their group memberships, and then
# tries to cross-reference that against usernames/roles mentioned in the
# README so you can spot unauthorized accounts or wrong admin rights.
#
# Because README formats vary (bullet lists, tables, "Admins:" sections,
# etc.), this script does NOT try to silently guess and hide anything --
# it prints the raw README, the raw system data, AND a best-effort
# auto-match, so you can visually confirm anything the parser gets wrong.
#
# Run as root (or with sudo) for full group/lastlog info.

set -uo pipefail   # no -e here: we want to keep going and report, not abort on a grep miss

UID_MIN=1000

# Groups treated as granting admin-equivalent privileges. sudo/wheel/admin are
# the classic ones; root/adm/lpadmin/docker are included because membership in
# them also grants meaningful elevated access (docker group membership is
# effectively root-equivalent via the docker socket). Adjust this list if your
# README defines privilege differently.
ADMIN_GROUPS=(sudo wheel admin root adm lpadmin docker)

# Returns "yes" (with matching group names) or "no" for whether $1 has
# admin-equivalent rights, checked directly against /etc/group -- both
# secondary membership (the group's member list) AND primary group
# membership (the GID set in /etc/passwd, which does NOT show up in
# /etc/group's member list but still grants that group's privileges).
check_admin_status() {
    local user="$1"
    local matched=()

    # Primary group: look up the user's GID in /etc/passwd, then resolve
    # that GID to a group name via /etc/group.
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

    # Secondary membership: check each admin-equivalent group's member list
    # in /etc/group directly (field 4, comma-separated).
    for ag in "${ADMIN_GROUPS[@]}"; do
        local members
        members=$(awk -F: -v g="$ag" '$1 == g {print $4}' /etc/group)
        if [[ -n "$members" ]] && echo ",${members}," | grep -q ",${user},"; then
            matched+=("$ag")
        fi
    done

    if [[ ${#matched[@]} -gt 0 ]]; then
        # de-duplicate and print
        printf '%s\n' "${matched[@]}" | sort -u | paste -sd, -
    else
        echo ""
    fi
}

echo "=================================================================="
echo " STEP 1: Locate the README"
echo "=================================================================="

README=""
CANDIDATES=$(find /root/Desktop /home/*/Desktop -maxdepth 1 -iname "*readme*" 2>/dev/null)

if [[ -z "$CANDIDATES" ]]; then
    echo "No README found on any Desktop (/root/Desktop or /home/*/Desktop)."
    echo "Searching more broadly under /root and /home..."
    CANDIDATES=$(find /root /home -maxdepth 3 -iname "*readme*" 2>/dev/null)
fi

if [[ -z "$CANDIDATES" ]]; then
    echo "Still couldn't find a README automatically."
    echo "Pass the path manually: $0 /path/to/README"
    if [[ $# -ge 1 && -f "$1" ]]; then
        README="$1"
    else
        echo "No path given either. Exiting."
        exit 1
    fi
else
    COUNT=$(echo "$CANDIDATES" | wc -l)
    if [[ "$COUNT" -gt 1 ]]; then
        echo "Found multiple candidates:"
        echo "$CANDIDATES" | nl
        echo "Using the first one. Re-run with the path as an argument to pick a different one."
    fi
    README=$(echo "$CANDIDATES" | head -1)
fi

echo "Using README: $README"
echo ""

echo "=================================================================="
echo " STEP 2: Current system accounts (UID >= $UID_MIN)"
echo "=================================================================="

mapfile -t SYS_USERS < <(awk -F: -v minuid="$UID_MIN" '($3 >= minuid) {print $1}' /etc/passwd)

if [[ ${#SYS_USERS[@]} -eq 0 ]]; then
    echo "No accounts with UID >= $UID_MIN found."
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
echo " STEP 3: Who currently has admin rights, per /etc/group"
echo "         (checking: ${ADMIN_GROUPS[*]})"
echo "=================================================================="

for g in "${ADMIN_GROUPS[@]}"; do
    line=$(awk -F: -v g="$g" '$1 == g {print}' /etc/group)
    if [[ -n "$line" ]]; then
        gid=$(echo "$line" | cut -d: -f3)
        members=$(echo "$line" | cut -d: -f4)
        # Also find anyone whose PRIMARY group is this one (won't appear in $4 above)
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
echo " STEP 4: Best-effort auto cross-reference against the README"
echo "=================================================================="
echo "(This is a heuristic text match -- always eyeball the raw README"
echo " above too, since formats vary a lot.)"
echo ""

readme_lower=$(tr '[:upper:]' '[:lower:]' < "$README")

printf "%-20s %-15s %-25s %s\n" "SYSTEM USER" "IN README?" "ADMIN GROUPS (from /etc/group)" "README SAYS ADMIN?"
printf "%-20s %-15s %-25s %s\n" "-----------" "----------" "------------------------------" "------------------"

for u in "${SYS_USERS[@]}"; do
    u_lower=$(echo "$u" | tr '[:upper:]' '[:lower:]')

    # Is this username mentioned anywhere in the README at all?
    if echo "$readme_lower" | grep -qw "$u_lower"; then
        in_readme="yes"
    else
        in_readme="NO <-- check"
    fi

    # Admin status straight from /etc/group (primary + secondary), not `id`
    admin_groups_matched=$(check_admin_status "$u")
    if [[ -n "$admin_groups_matched" ]]; then
        is_admin_now="$admin_groups_matched"
    else
        is_admin_now="no"
    fi

    # Does the README mention this username near the word "admin" (same line, loose heuristic)?
    if grep -i "$u" "$README" 2>/dev/null | grep -qi "admin"; then
        readme_says_admin="yes (nearby 'admin')"
    else
        readme_says_admin="not indicated"
    fi

    printf "%-20s %-15s %-25s %s\n" "$u" "$in_readme" "$is_admin_now" "$readme_says_admin"
done

echo ""
echo "=================================================================="
echo " Flags to check manually"
echo "=================================================================="
for u in "${SYS_USERS[@]}"; do
    u_lower=$(echo "$u" | tr '[:upper:]' '[:lower:]')
    if ! echo "$readme_lower" | grep -qw "$u_lower"; then
        echo "  [!] '$u' exists on the system (UID >= $UID_MIN) but its name doesn't appear anywhere in the README."
        echo "      Could be unauthorized, or a service account the README describes differently -- verify manually."
    fi

    admin_groups_matched=$(check_admin_status "$u")
    if [[ -n "$admin_groups_matched" ]]; then
        if ! (grep -i "$u" "$README" 2>/dev/null | grep -qi "admin"); then
            echo "  [!] '$u' currently HAS admin rights (via: $admin_groups_matched) but the README doesn't clearly say they should."
        fi
    fi
done

echo ""
echo "Done. Remember: the README section above and the auto cross-reference"
echo "are only a starting point -- always confirm manually against the"
echo "README's actual wording, especially for service accounts."
