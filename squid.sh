#!/usr/bin/env bash
# =============================================================================
# squid_harden.sh - Apply hardening fixes to a Squid proxy (Debian/Ubuntu/RHEL)
#
# Pairs with squid_audit.sh. Applies the config, permission, systemd and
# (optionally) firewall fixes, validates with "squid -k parse" before touching
# the live config, and rolls back automatically if Squid fails to restart.
#
# Usage:
#   sudo ./squid_harden.sh [-i BIND_IP] [-s TRUSTED_SUBNET] [-n] [-u] [-R]
#
#   -i IP      Bind Squid to this internal IP (e.g. 10.0.0.1). Skipped if omitted.
#   -s CIDR    Firewall: allow the proxy port only from this subnet (e.g. 10.0.0.0/24).
#              Skipped if omitted. Repeatable (-s A -s B).
#   -n         Dry run: show the config diff and planned actions, change nothing.
#   -u         Also upgrade the squid package from the distro repositories.
#   -R         Don't restart Squid (you'll need to restart it yourself).
#   -c FILE    Path to squid.conf (auto-detected if omitted).
#   -h         Help.
#
# Examples:
#   sudo ./squid_harden.sh -n -i 10.0.0.1 -s 10.0.0.0/24     # preview
#   sudo ./squid_harden.sh -i 10.0.0.1 -s 10.0.0.0/24        # apply
# =============================================================================

set -uo pipefail

# ---------- tunables ----------------------------------------------------------
MAXCONN=50
REPLY_BODY_MAX="500 MB"
REQUEST_BODY_MAX="50 MB"
CLIENT_LIFETIME="1 hour"
VISIBLE_HOSTNAME="proxy"

# ---------- output helpers ----------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; BLD=""; RST=""
fi
ok()      { printf '  %s[ OK ]%s %s\n' "$GRN" "$RST" "$1"; }
skip()    { printf '  %s[SKIP]%s %s\n' "$BLU" "$RST" "$1"; }
note()    { printf '  %s[NOTE]%s %s\n' "$YEL" "$RST" "$1"; }
err()     { printf '  %s[FAIL]%s %s\n' "$RED" "$RST" "$1"; }
plan()    { printf '  %s[PLAN]%s %s\n' "$BLU" "$RST" "$1"; }
section() { printf '\n%s== %s ==%s\n' "$BLD" "$1" "$RST"; }
die()     { printf '%sError:%s %s\n' "$RED" "$RST" "$1" >&2; exit 2; }

usage() { sed -n '2,/^# =====/p' "$0" | sed '1d;$d;s/^# \{0,1\}//'; }

# ---------- arguments ---------------------------------------------------------
BIND_IP=""; SUBNETS=(); DRY_RUN=0; UPGRADE=0; NO_RESTART=0; CONF=""
while getopts ":i:s:c:nuRh" opt; do
  case $opt in
    i) BIND_IP=$OPTARG ;;
    s) SUBNETS+=("$OPTARG") ;;
    c) CONF=$OPTARG ;;
    n) DRY_RUN=1 ;;
    u) UPGRADE=1 ;;
    R) NO_RESTART=1 ;;
    h) usage; exit 0 ;;
    :) die "-$OPTARG needs a value" ;;
    *) usage; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)."

if [[ -z $CONF ]]; then
  for f in /etc/squid/squid.conf /etc/squid3/squid.conf /usr/local/squid/etc/squid.conf; do
    [[ -f $f ]] && { CONF=$f; break; }
  done
fi
[[ -n $CONF && -f $CONF ]] || die "squid.conf not found. Use -c /path/to/squid.conf"
CONF_DIR=$(dirname "$CONF")

SQUID_BIN=$(command -v squid || command -v squid3 || true)
[[ -n $SQUID_BIN ]] || die "squid binary not found."

if [[ -n $BIND_IP ]]; then
  [[ $BIND_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "-i must be an IPv4 address."
  if command -v ip >/dev/null 2>&1; then
    ip -o addr show | grep -qw "inet $BIND_IP" || die "$BIND_IP is not assigned to any interface on this host."
  elif command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -qx "$BIND_IP" || die "$BIND_IP is not assigned to any interface on this host."
  fi
fi
for s in "${SUBNETS[@]}"; do
  [[ $s =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "-s must be CIDR like 10.0.0.0/24 (got '$s')."
done

SQUID_USER=$(awk '$1=="cache_effective_user"{print $2}' "$CONF" | tail -n1)
if [[ -z $SQUID_USER ]]; then
  for u in proxy squid; do id "$u" >/dev/null 2>&1 && { SQUID_USER=$u; break; }; done
fi
SQUID_GROUP=$(id -gn "${SQUID_USER:-root}" 2>/dev/null || echo root)

HAS_SYSTEMD=0
command -v systemctl >/dev/null 2>&1 && systemctl cat squid.service >/dev/null 2>&1 && HAS_SYSTEMD=1

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/squid-harden-backup-$STAMP"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
STAGED="$WORK/squid.conf"
cp -a "$CONF" "$STAGED"

printf '%sSquid hardening%s  %s\n' "$BLD" "$RST" "$( ((DRY_RUN)) && echo '(DRY RUN: nothing will be changed)')"
printf 'Config: %s   Squid: %s   Run-as user: %s\n' "$CONF" \
  "$("$SQUID_BIN" -v | head -n1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')" "${SQUID_USER:-unknown}"

# =============================================================================
section "Package version"
# =============================================================================
ver=$("$SQUID_BIN" -v | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1)
if (( UPGRADE )); then
  if (( DRY_RUN )); then plan "Upgrade squid package from distro repositories"
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq --only-upgrade squid && ok "squid package upgraded (if an update was available)"
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y -q upgrade squid && ok "squid package upgraded (if an update was available)"
  else
    note "No apt/dnf found; upgrade squid manually"
  fi
else
  skip "Package upgrade (use -u to enable)"
fi
(( ${ver%%.*} < 6 )) && note "Squid $ver is EOL upstream. Distro security backports help, but plan a move to 6.x+ (OS upgrade or backports)."

# =============================================================================
section "Squid configuration"
# =============================================================================
# 1. Remove any previous block from this script (makes re-runs idempotent).
sed -i '/^# BEGIN squid_harden/,/^# END squid_harden/d' "$STAGED"

# 2. Comment out existing settings this script manages, so they can't override ours.
MANAGED='httpd_suppress_version_string|via|forwarded_for|visible_hostname|reply_body_max_size|request_body_max_size|client_lifetime'
sed -i -E "s/^([[:space:]]*)($MANAGED)([[:space:]])/# [squid_harden $STAMP] \1\2\3/" "$STAGED"

# 3. Build the hardening block.
MAXCONN_RULE="http_access deny harden_maxconn"
grep -qE '^[[:space:]]*acl[[:space:]]+localnet[[:space:]]' "$STAGED" && MAXCONN_RULE+=" localnet"

cat > "$WORK/block" <<EOF
# BEGIN squid_harden (managed by squid_harden.sh - edit tunables in the script)
# Block proxying to the proxy host itself and to cloud metadata / link-local
acl harden_linklocal dst 169.254.0.0/16 fe80::/10
http_access deny to_localhost
http_access deny harden_linklocal

# Per-client connection limit
acl harden_maxconn maxconn $MAXCONN
$MAXCONN_RULE

# Hide proxy identity and client addresses
httpd_suppress_version_string on
via off
forwarded_for delete
visible_hostname $VISIBLE_HOSTNAME

# Resource limits
reply_body_max_size $REPLY_BODY_MAX
request_body_max_size $REQUEST_BODY_MAX
client_lifetime $CLIENT_LIFETIME
# END squid_harden
EOF

# 4. Insert it before the first "http_access allow" (so the denies take effect),
#    else before the final "deny all", else at the end of the file.
anchor=$(grep -nE '^[[:space:]]*http_access[[:space:]]+allow' "$STAGED" | head -n1 | cut -d: -f1)
[[ -z $anchor ]] && anchor=$(grep -nE '^[[:space:]]*http_access[[:space:]]+deny[[:space:]]+all' "$STAGED" | tail -n1 | cut -d: -f1)
if [[ -n $anchor ]]; then
  awk -v n="$anchor" -v blk="$WORK/block" 'NR==n { while ((getline l < blk) > 0) print l; print "" } { print }' \
    "$STAGED" > "$WORK/tmp" && mv "$WORK/tmp" "$STAGED"
else
  { echo; cat "$WORK/block"; } >> "$STAGED"
fi

# 5. Bind listeners to the internal IP.
if [[ -n $BIND_IP ]]; then
  sed -i -E "s/^([[:space:]]*http_port[[:space:]]+)(0\.0\.0\.0:)?([0-9]+)([[:space:]]|$)/\1$BIND_IP:\3\4/" "$STAGED"
  grep -qE '^[[:space:]]*http_port' "$STAGED" || echo "http_port $BIND_IP:3128" >> "$STAGED"
fi

# 6. Warn about included files that might still override our settings.
for inc in $(awk '$1=="include"{ $1=""; print }' "$STAGED"); do
  for f in $inc; do
    [[ -f $f ]] && grep -qE "^[[:space:]]*($MANAGED)[[:space:]]" "$f" \
      && note "$f also sets one of the managed directives; check it doesn't override the hardening block"
  done
done

# 7. Validate the staged config before installing it.
if ! parse_out=$("$SQUID_BIN" -k parse -f "$STAGED" 2>&1); then
  err "New config failed validation; nothing was changed:"
  grep -E 'ERROR|FATAL' <<<"$parse_out" | head -n10 | sed 's/^/         /'
  exit 1
fi
ok "New config validated (squid -k parse)"

echo
diff -u --label "$CONF (current)" --label "$CONF (hardened)" "$CONF" "$STAGED" | sed 's/^/    /'
echo
[[ -z $BIND_IP ]] && note "No -i given: Squid still listens on all interfaces"

# =============================================================================
# Planned system changes
# =============================================================================
PORTS=$(awk '$1=="http_port"||$1=="https_port"{ n=split($2,a,":"); print a[n] }' "$STAGED" | sort -u)
[[ -z $PORTS ]] && PORTS=3128
OVERRIDE_DIR=/etc/systemd/system/squid.service.d
OVERRIDE="$OVERRIDE_DIR/hardening.conf"
LOG_DIRS=$(awk '($1=="access_log"||$1=="cache_log") && $2!="none"{ sub(/^[a-z]+:/,"",$2); print $2 }' "$STAGED" \
           | xargs -r -n1 dirname | sort -u)
[[ -z $LOG_DIRS ]] && LOG_DIRS=/var/log/squid

if (( DRY_RUN )); then
  section "Planned system changes"
  plan "Back up $CONF_DIR to $BACKUP"
  plan "Install hardened $CONF"
  plan "chown root:$SQUID_GROUP and chmod 640 on $CONF and $CONF_DIR/conf.d/*.conf"
  for d in $LOG_DIRS; do plan "chmod -R o-rwx $d"; done
  (( HAS_SYSTEMD )) && plan "Write $OVERRIDE (NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp)"
  if (( ${#SUBNETS[@]} )); then
    plan "Firewall: allow port(s) $(echo $PORTS) only from ${SUBNETS[*]}"
  else
    skip "Firewall (use -s SUBNET to enable)"
  fi
  (( NO_RESTART )) || plan "Restart squid (auto-rollback if it fails)"
  printf '\n%sDry run complete.%s Re-run without -n to apply.\n' "$BLD" "$RST"
  exit 0
fi

# =============================================================================
section "Applying"
# =============================================================================
mkdir -p "$BACKUP"
cp -a "$CONF_DIR" "$BACKUP/"
OVERRIDE_EXISTED=0
[[ -f $OVERRIDE ]] && { OVERRIDE_EXISTED=1; cp -a "$OVERRIDE" "$BACKUP/"; }
ok "Backup saved to $BACKUP"

cat "$STAGED" > "$CONF"          # keep the original file's inode/ownership
ok "Hardened config installed"

# --- permissions --------------------------------------------------------------
conf_files=("$CONF")
for f in "$CONF_DIR"/conf.d/*.conf; do [[ -f $f ]] && conf_files+=("$f"); done
chown root:"$SQUID_GROUP" "${conf_files[@]}" && chmod 640 "${conf_files[@]}"
ok "Config files set to root:$SQUID_GROUP 640"

for d in $LOG_DIRS; do
  [[ -d $d ]] && chmod -R o-rwx "$d" && ok "Removed world access from $d"
done
if [[ -f /etc/logrotate.d/squid ]] && grep -qE '^\s*create\s+[0-7]*[1-7]\b' /etc/logrotate.d/squid; then
  note "/etc/logrotate.d/squid 'create' mode gives others access to new logs; consider 'create 640 $SQUID_USER $SQUID_GROUP'"
fi

# --- systemd sandboxing -------------------------------------------------------
if (( HAS_SYSTEMD )); then
  mkdir -p "$OVERRIDE_DIR"
  cat > "$OVERRIDE" <<'EOF'
# Added by squid_harden.sh
[Service]
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
EOF
  systemctl daemon-reload
  ok "systemd sandboxing override written ($OVERRIDE)"
else
  skip "systemd not managing squid; sandboxing skipped"
fi

# --- firewall -----------------------------------------------------------------
if (( ${#SUBNETS[@]} == 0 )); then
  skip "Firewall (use -s SUBNET to restrict the proxy port)"
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  for p in $PORTS; do
    for s in "${SUBNETS[@]}"; do ufw allow from "$s" to any port "$p" proto tcp >/dev/null; done
    ufw deny "$p"/tcp >/dev/null
  done
  ok "ufw: port(s) $(echo $PORTS) allowed only from ${SUBNETS[*]}"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  for p in $PORTS; do
    firewall-cmd --permanent -q --remove-port="$p"/tcp 2>/dev/null
    for s in "${SUBNETS[@]}"; do
      firewall-cmd --permanent -q --add-rich-rule="rule family=ipv4 source address=$s port port=$p protocol=tcp accept"
    done
  done
  firewall-cmd -q --reload
  ok "firewalld: port(s) $(echo $PORTS) allowed only from ${SUBNETS[*]}"
elif command -v iptables >/dev/null 2>&1; then
  for p in $PORTS; do
    iptables -C INPUT -p tcp --dport "$p" -j DROP 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$p" -j DROP
    for s in "${SUBNETS[@]}"; do
      iptables -C INPUT -p tcp -s "$s" --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp -s "$s" --dport "$p" -j ACCEPT
    done
    iptables -C INPUT -i lo -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -p tcp --dport "$p" -j ACCEPT
  done
  ok "iptables: port(s) $(echo $PORTS) allowed only from ${SUBNETS[*]}"
  note "iptables rules are not persistent; save them (e.g. apt install iptables-persistent && netfilter-persistent save)"
else
  note "No active ufw/firewalld and no iptables found; restrict port(s) $(echo $PORTS) manually"
fi
command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q inactive && (( ${#SUBNETS[@]} )) \
  && note "ufw is installed but inactive; used iptables instead (not enabling ufw to avoid locking you out)"

# --- restart with rollback ----------------------------------------------------
rollback() {
  err "Squid failed to start; rolling back"
  cp -a "$BACKUP/$(basename "$CONF_DIR")/." "$CONF_DIR/"
  if (( HAS_SYSTEMD )); then
    if (( OVERRIDE_EXISTED )); then cp -a "$BACKUP/$(basename "$OVERRIDE")" "$OVERRIDE"; else rm -f "$OVERRIDE"; fi
    systemctl daemon-reload; systemctl restart squid
  fi
  err "Previous config restored. Check: journalctl -u squid -n 50"
  exit 1
}

if (( NO_RESTART )); then
  skip "Restart (-R given). Run: systemctl restart squid"
elif (( HAS_SYSTEMD )); then
  systemctl restart squid; sleep 3
  systemctl is-active -q squid && ok "Squid restarted and running" || rollback
else
  "$SQUID_BIN" -k reconfigure 2>/dev/null && ok "Squid reconfigured" \
    || note "Couldn't signal squid; restart it manually"
fi

section "Done"
echo "  Backup:   $BACKUP"
echo "  Undo:     cp -a $BACKUP/$(basename "$CONF_DIR")/. $CONF_DIR/ && rm -f $OVERRIDE && systemctl daemon-reload && systemctl restart squid"
echo "  Verify:   ./squid.sh   (the audit script)"
echo "  Not automated: proxy authentication (site-specific) and moving to Squid 6.x+ if you're on 5.x."
