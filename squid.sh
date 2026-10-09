#!/usr/bin/env bash
# =============================================================================
# squid_harden.sh (v2) - Fix the problems squid.sh (the audit) reports.
#
# What it does, in order:
#   1. Copies the whole config folder (squid.conf + included files like
#      conf.d/*.conf) to a scratch area and makes every edit there first.
#   2. Fixes dangerous access rules in place: "allow all" (open proxy), cache
#      manager open to everyone, and adds any missing deny rules just above the
#      first rule that lets clients in, so the denies actually take effect.
#   3. Makes sure the very last http_access rule is "deny all".
#   4. Puts all hardening settings at the END of squid.conf. Squid uses the last
#      value it reads, so this beats copies hidden in included files.
#   5. Checks the result with "squid -k parse". If it fails, nothing changes.
#   6. Backs up, installs, fixes permissions/ownership, adds systemd sandboxing,
#      optionally firewalls the port, then restarts Squid and rolls everything
#      back automatically if it won't start.
#
# Usage:
#   sudo ./squid_harden.sh [-i BIND_IP] [-s TRUSTED_SUBNET] [-n] [-u] [-R] [-c FILE]
#
#   -i IP      Make Squid listen only on this IP (e.g. 10.0.0.1).
#   -s CIDR    Firewall: allow the proxy port only from this subnet. Repeatable.
#              Also used as the "localnet" if the config doesn't define one.
#   -n         Dry run: show exactly what would change, change nothing.
#   -u         Also upgrade the squid package from the distro repositories.
#   -R         Don't restart Squid.
#   -c FILE    Path to squid.conf (auto-detected if omitted).
#   -h         Help.
#
#   sudo ./squid_harden.sh -n          # preview
#   sudo ./squid_harden.sh             # apply
#   ./squid.sh                         # re-audit
# =============================================================================

set -uo pipefail

# ---------- tunables ----------------------------------------------------------
MAXCONN=50
REPLY_BODY_MAX="500 MB"
REQUEST_BODY_MAX="50 MB"
CLIENT_LIFETIME="1 hour"
VISIBLE_HOSTNAME="proxy"
DEFAULT_LOCALNET="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 fe80::/10"

# ---------- output helpers ----------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; BLD=""; RST=""
fi
ok()      { printf '  %s[ OK ]%s %s\n' "$GRN" "$RST" "$1"; }
fix()     { printf '  %s[FIX ]%s %s\n' "$GRN" "$RST" "$1"; FIXES=$((FIXES+1)); }
skip()    { printf '  %s[SKIP]%s %s\n' "$BLU" "$RST" "$1"; }
note()    { printf '  %s[NOTE]%s %s\n' "$YEL" "$RST" "$1"; }
err()     { printf '  %s[FAIL]%s %s\n' "$RED" "$RST" "$1"; }
plan()    { printf '  %s[PLAN]%s %s\n' "$BLU" "$RST" "$1"; }
section() { printf '\n%s== %s ==%s\n' "$BLD" "$1" "$RST"; }
die()     { printf '%sError:%s %s\n' "$RED" "$RST" "$1" >&2; exit 2; }
usage()   { sed -n '2,/^# =====/p' "$0" | sed '1d;$d;s/^# \{0,1\}//'; }
FIXES=0

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
CONF=$(readlink -f "$CONF"); CONF_DIR=$(dirname "$CONF")

SQUID_BIN=$(command -v squid || command -v squid3 || true)
[[ -n $SQUID_BIN ]] || die "squid binary not found."
SQUID_VER=$("$SQUID_BIN" -v | head -n1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
SQUID_MAJOR=${SQUID_VER%%.*}

if [[ -n $BIND_IP ]]; then
  [[ $BIND_IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "-i must be an IPv4 address."
  if command -v ip >/dev/null 2>&1; then
    grep -qw "inet $BIND_IP" <<<"$(ip -o addr show)" || die "$BIND_IP is not assigned to any interface on this host."
  else
    grep -qx "$BIND_IP" <<<"$(hostname -I 2>/dev/null | tr ' ' '\n')" || die "$BIND_IP is not assigned to any interface on this host."
  fi
fi
for s in "${SUBNETS[@]}"; do
  [[ $s =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "-s must be CIDR like 10.0.0.0/24 (got '$s')."
done

HAS_SYSTEMD=0
command -v systemctl >/dev/null 2>&1 && systemctl cat squid.service >/dev/null 2>&1 && HAS_SYSTEMD=1

# ---------- staging area ------------------------------------------------------
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/squid-harden-backup-$STAMP"
TAG="# [squid_harden $STAMP]"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/stage"; mkdir -p "$STAGE"
cp -a "$CONF_DIR/." "$STAGE/"
MAIN="$STAGE/$(basename "$CONF")"

# Map a live path inside the config folder to its staged copy.
stage_path() { if [[ $1 == "$CONF_DIR"/* ]]; then printf '%s' "$STAGE/${1#"$CONF_DIR"/}"; else printf '%s' "$1"; fi; }

# Print a staged config with includes expanded, comments stripped, spaces squeezed.
expand_words() {   # $1 = the word list after "include"
  local -a ws; local w pat m
  read -ra ws <<<"$1"
  for w in "${ws[@]}"; do
    pat=$(stage_path "$w")
    for m in $pat; do [[ -f $m ]] && expand "$m" "${2:-1}"; done
  done
}
expand() {
  local f=$1 depth=${2:-0} line
  (( depth > 10 )) && return
  [[ -r $f ]] || return
  while IFS= read -r line; do
    if [[ $line =~ ^include[[:space:]]+(.+)$ ]]; then expand_words "${BASH_REMATCH[1]}" $((depth+1))
    else printf '%s\n' "$line"; fi
  done < <(awk '{ sub(/#.*/, ""); $1=$1; if (NF) print }' "$f")
}

# Every staged config file that Squid actually reads (main + included, inside the folder).
staged_files() {
  local f=$1 depth=${2:-0} inc w pat m; local -a ws
  (( depth > 10 )) && return
  [[ -f $f ]] || return
  printf '%s\n' "$f"
  while read -r inc; do
    read -ra ws <<<"$inc"
    for w in "${ws[@]}"; do
      pat=$(stage_path "$w")
      for m in $pat; do [[ $m == "$STAGE"/* ]] && staged_files "$m" $((depth+1)); done
    done
  done < <(awk '$1=="include" { $1=""; print }' "$f")
}
mapfile -t FILES < <(staged_files "$MAIN" | awk '!seen[$0]++')

CLIENT_ALLOW_RE='^http_access allow '
LOCAL_ALLOW_RE='^http_access allow localhost( manager)?$'

printf '%sSquid hardening v2%s  %s\n' "$BLD" "$RST" "$( ((DRY_RUN)) && echo '(DRY RUN: nothing will be changed)')"
printf 'Config: %s (+%d included)   Squid: %s\n' "$CONF" $(( ${#FILES[@]} - 1 )) "$SQUID_VER"

# ---------- which user should Squid run as? -----------------------------------
CUR_USER=$(expand "$MAIN" | awk '$1=="cache_effective_user"{u=$2} END{print u}')
SQUID_USER=""
if [[ -n $CUR_USER && $CUR_USER != root ]] && id "$CUR_USER" >/dev/null 2>&1; then
  SQUID_USER=$CUR_USER
else
  for u in proxy squid; do id "$u" >/dev/null 2>&1 && { SQUID_USER=$u; break; }; done
fi
SQUID_GROUP=$(id -gn "${SQUID_USER:-root}" 2>/dev/null || echo root)

# =============================================================================
section "Package version"
# =============================================================================
if (( UPGRADE )); then
  if (( DRY_RUN )); then plan "Upgrade squid package from distro repositories"
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq --only-upgrade squid && ok "squid package upgraded (if an update was available)"
  elif command -v dnf >/dev/null 2>&1; then
    dnf -y -q upgrade squid && ok "squid package upgraded (if an update was available)"
  else note "No apt/dnf found; upgrade squid manually"; fi
else
  skip "Package upgrade (use -u to enable)"
fi
(( SQUID_MAJOR < 6 )) && note "Squid $SQUID_VER is end-of-life upstream. -u installs distro security fixes; 6.x+ needs an OS upgrade or backports."

# =============================================================================
section "Access rules"
# =============================================================================
# Clean out anything a previous run added, so re-running never duplicates.
for f in "${FILES[@]}"; do sed -i '/^# BEGIN squid_harden/,/^# END squid_harden/d' "$f"; done

# Open proxy: "http_access allow all" -> "http_access allow localnet".
NEED_LOCALNET=0
for f in "${FILES[@]}"; do
  if grep -qE '^[[:space:]]*http_access[[:space:]]+allow[[:space:]]+all[[:space:]]*$' "$f"; then
    sed -i -E "s/^([[:space:]]*)(http_access[[:space:]]+allow[[:space:]]+all[[:space:]]*)$/$TAG open proxy: \2\n\1http_access allow localnet/" "$f"
    fix "Open proxy rule 'http_access allow all' replaced with 'allow localnet' (${f#"$STAGE"/})"
    NEED_LOCALNET=1
  fi
done

# Cache manager allowed to anyone other than localhost -> localhost only.
for f in "${FILES[@]}"; do
  bad=$(grep -E '^[[:space:]]*http_access[[:space:]]+allow[[:space:]]+(.*[[:space:]])?manager([[:space:]]|$)' "$f" | grep -vwE 'localhost' || true)
  if [[ -n $bad ]]; then
    sed -i -E "/localhost/!s/^([[:space:]]*)(http_access[[:space:]]+allow[[:space:]]+(.*[[:space:]])?manager([[:space:]].*)?)$/$TAG open cache manager: \2\n\1http_access allow localhost manager/" "$f"
    fix "Cache manager restricted to localhost (${f#"$STAGE"/})"
  fi
done

# SSL bump: never blanket-ignore upstream certificate errors.
for f in "${FILES[@]}"; do
  if grep -qE '^[[:space:]]*sslproxy_cert_error[[:space:]]+allow[[:space:]]+all' "$f"; then
    sed -i -E "s/^([[:space:]]*sslproxy_cert_error[[:space:]]+allow[[:space:]]+all.*)$/$TAG \1/" "$f"
    fix "Removed 'sslproxy_cert_error allow all' (${f#"$STAGE"/})"
  fi
  if grep -qE '^[[:space:]]*[^#].*DONT_VERIFY_PEER' "$f"; then
    sed -i -E "/^[[:space:]]*#/!{ /DONT_VERIFY_PEER/{ s/,DONT_VERIFY_PEER//g; s/DONT_VERIFY_PEER,?//g; s/[[:space:]]flags=([[:space:]]|$)/\1/; s/^([[:space:]]*(sslproxy_flags|tls_outgoing_options))[[:space:]]*$/$TAG \1/ } }" "$f"
    fix "Re-enabled upstream certificate checks (removed DONT_VERIFY_PEER) (${f#"$STAGE"/})"
  fi
done

# Find where client access starts: the first "allow" rule for network clients
# (not the localhost-only ones), or an include line that brings one in. Deny
# rules must sit above this point to protect anyone.
ANCHOR=""; WHY=""
while IFS=$'\t' read -r n l; do
  if [[ $l =~ $CLIENT_ALLOW_RE && ! $l =~ $LOCAL_ALLOW_RE ]]; then
    ANCHOR=$n; WHY="above the first client rule ($l)"; break
  fi
  if [[ $l =~ ^include[[:space:]]+(.+)$ ]] \
     && grep -E "$CLIENT_ALLOW_RE" <<<"$(expand_words "${BASH_REMATCH[1]}")" | grep -vE "$LOCAL_ALLOW_RE" >/dev/null; then
    ANCHOR=$n; WHY="above '$l', which adds client rules"; break
  fi
done < <(awk '{ sub(/#.*/, ""); $1=$1; if (NF) print NR "\t" $0 }' "$MAIN")
if [[ -z $ANCHOR ]]; then
  ANCHOR=$(grep -nE '^[[:space:]]*#[[:space:]]*INSERT YOUR OWN RULE' "$MAIN" | head -n1 | cut -d: -f1)
  [[ -n $ANCHOR ]] && WHY="at the 'INSERT YOUR OWN RULE(S)' marker"
fi
if [[ -z $ANCHOR ]]; then
  ANCHOR=$(grep -nE '^[[:space:]]*http_access[[:space:]]+deny[[:space:]]+all[[:space:]]*$' "$MAIN" | tail -n1 | cut -d: -f1)
  [[ -n $ANCHOR ]] && WHY="above the final 'deny all'"
fi

# Is an exact rule already active before the anchor (in squid.conf itself)?
before_anchor() {
  awk -v a="${ANCHOR:-999999999}" -v r="$1" '{ sub(/#.*/, ""); $1=$1 } NR < a && $0 == r { f=1 } END { exit !f }' "$MAIN"
}
trim_end() { awk '{ a[NR]=$0 } NF { last=NR } END { for (i=1; i<=last; i++) print a[i] }' "$1" > "$WORK/trim" && cat "$WORK/trim" > "$1"; }
acl_defined() { grep -qE "^acl $1 " <<<"$(expand "$MAIN")"; }

RULES=(); ACLS=()
if ! acl_defined Safe_ports; then
  ACLS+=("acl Safe_ports port 80 21 443 70 210 1025-65535 280 488 591 777")
fi
acl_defined SSL_ports || ACLS+=("acl SSL_ports port 443")
if (( SQUID_MAJOR < 6 )) && ! acl_defined CONNECT; then ACLS+=("acl CONNECT method CONNECT"); fi
if (( NEED_LOCALNET )) && ! acl_defined localnet; then
  ACLS+=("acl localnet src ${SUBNETS[*]:-$DEFAULT_LOCALNET}")
fi

if ! grep -qx 'http_access deny manager' <<<"$(expand "$MAIN")"; then
  RULES+=("http_access allow localhost manager" "http_access deny manager")
  fix "Added cache manager restriction (localhost only)"
fi
before_anchor 'http_access deny !Safe_ports' || { RULES+=('http_access deny !Safe_ports'); fix "Added 'deny !Safe_ports'"; }
before_anchor 'http_access deny CONNECT !SSL_ports' || { RULES+=('http_access deny CONNECT !SSL_ports'); fix "Added 'deny CONNECT !SSL_ports'"; }
before_anchor 'http_access deny to_localhost' || { RULES+=('http_access deny to_localhost'); fix "Added 'deny to_localhost' (no proxying to the server itself)"; }
if ! before_anchor 'http_access deny to_linklocal'; then
  ACLS+=("acl harden_linklocal dst 169.254.0.0/16 fe80::/10")
  RULES+=("http_access deny harden_linklocal")
  fix "Added link-local / cloud metadata block (169.254.0.0/16)"
fi
ACLS+=("acl harden_maxconn maxconn $MAXCONN")
RULES+=("http_access deny harden_maxconn")
fix "Per-client connection limit ($MAXCONN)"

{
  echo "# BEGIN squid_harden rules (managed by squid_harden.sh, re-run it instead of editing)"
  printf '%s\n' "${ACLS[@]}" "${RULES[@]}"
  echo "# END squid_harden rules"
} > "$WORK/rules"
if [[ -n $ANCHOR ]]; then
  awk -v n="$ANCHOR" -v blk="$WORK/rules" 'NR==n { while ((getline l < blk) > 0) print l } { print }' "$MAIN" > "$WORK/tmp" && cat "$WORK/tmp" > "$MAIN"
  ok "Rules inserted $WHY"
else
  { echo; cat "$WORK/rules"; } >> "$MAIN"
  ok "Rules appended (no http_access rules found)"
fi

# The last rule must be "deny all" (otherwise unmatched requests may be allowed).
if [[ $(expand "$MAIN" | grep -E '^http_access ' | tail -n1) != "http_access deny all" ]]; then
  trim_end "$MAIN"
  printf '\n# BEGIN squid_harden final rule\nhttp_access deny all\n# END squid_harden final rule\n' >> "$MAIN"
  fix "Added 'http_access deny all' as the final rule"
fi

# =============================================================================
section "Settings"
# =============================================================================
MANAGED='httpd_suppress_version_string|via|forwarded_for|visible_hostname|strip_query_terms|icp_port|htcp_port|snmp_port|pinger_enable|client_lifetime|request_body_max_size|reply_body_max_size|cache_effective_user'
for f in "${FILES[@]}"; do
  n=$(grep -cE "^[[:space:]]*($MANAGED)[[:space:]]" "$f")
  if (( n > 0 )); then
    sed -i -E "s/^([[:space:]]*)($MANAGED)([[:space:]])/$TAG \1\2\3/" "$f"
    ok "Commented out $n old setting line(s) in ${f#"$STAGE"/} (replaced below)"
  fi
done

if [[ -n $BIND_IP ]]; then
  for f in "${FILES[@]}"; do
    sed -i -E "s/^([[:space:]]*https?_port[[:space:]]+)(0\.0\.0\.0:|\[::\]:)?([0-9]+)([[:space:]]|$)/\1$BIND_IP:\3\4/" "$f"
  done
  fix "Listener bound to $BIND_IP"
fi

trim_end "$MAIN"
[[ $CUR_USER == root ]] && fix "cache_effective_user was root; Squid will run as '$SQUID_USER'"
{
  echo
  echo "# BEGIN squid_harden settings (at the end on purpose: the last value wins)"
  echo "httpd_suppress_version_string on"
  echo "via off"
  echo "forwarded_for delete"
  echo "visible_hostname $VISIBLE_HOSTNAME"
  echo "strip_query_terms on"
  echo "icp_port 0"
  echo "htcp_port 0"
  echo "snmp_port 0"
  echo "pinger_enable off"
  echo "client_lifetime $CLIENT_LIFETIME"
  echo "request_body_max_size $REQUEST_BODY_MAX"
  echo "reply_body_max_size $REPLY_BODY_MAX"
  [[ -n $SQUID_USER ]] && echo "cache_effective_user $SQUID_USER"
  if [[ -n $BIND_IP ]] && ! grep -qE '^https?_port ' <<<"$(expand "$MAIN")"; then echo "http_port $BIND_IP:3128"; fi
  echo "# END squid_harden settings"
} >> "$MAIN"
fix "Hardening settings added at the end of $(basename "$CONF")"

# =============================================================================
section "Validation"
# =============================================================================
# Validate a copy whose include lines point at the staged files, not the live ones.
PARSE="$WORK/parse"; cp -a "$STAGE" "$PARSE"
for f in "${FILES[@]}"; do
  sed -i -E "/^[[:space:]]*include[[:space:]]/ s#$CONF_DIR/#$PARSE/#g" "$PARSE/${f#"$STAGE"/}"
done
validate() { "$SQUID_BIN" -k parse -f "$PARSE/$(basename "$CONF")" 2>&1; }
if ! parse_out=$(validate); then
  # Some builds lack SNMP or ICMP support; drop those optional lines and retry once.
  dropped=0
  for d in snmp_port pinger_enable; do
    if grep -q "$d" <<<"$parse_out"; then
      sed -i "/^$d /d" "$MAIN" "$PARSE/$(basename "$CONF")"; dropped=1
      note "This Squid build doesn't support '$d'; left it out"
    fi
  done
  if (( ! dropped )) || ! parse_out=$(validate); then
    err "New config failed validation; nothing was changed:"
    grep -E 'ERROR|FATAL' <<<"$parse_out" | head -n10 | sed 's/^/         /'
    exit 1
  fi
fi
ok "New config validated (squid -k parse)"
grep 'WARNING' <<<"$parse_out" | sed -E 's/^.*\| //' | sort -u | while read -r w; do note "Squid says: $w"; done

echo
for f in "${FILES[@]}"; do
  live="$CONF_DIR/${f#"$STAGE"/}"
  diff -u --label "$live (current)" --label "$live (hardened)" "$live" "$f" | sed 's/^/    /'
done
echo

# ---------- facts needed for the system changes -------------------------------
PORTS=$(expand "$MAIN" | awk '$1=="http_port"||$1=="https_port"{ n=split($2,a,":"); print a[n] }' | sort -u)
[[ -z $PORTS ]] && PORTS=3128
LOG_DIRS=$(expand "$MAIN" | awk '($1=="access_log"||$1=="cache_log") && $2!="none"{ sub(/^[a-z]+:/,"",$2); print $2 }' \
           | xargs -r -n1 dirname | sort -u)
[[ -z $LOG_DIRS ]] && LOG_DIRS=/var/log/squid
CACHE_DIRS=$(expand "$MAIN" | awk '$1=="cache_dir"{print $3}' | sort -u)
OVERRIDE_DIR=/etc/systemd/system/squid.service.d
OVERRIDE="$OVERRIDE_DIR/hardening.conf"
LIVE_FILES=(); for f in "${FILES[@]}"; do LIVE_FILES+=("$CONF_DIR/${f#"$STAGE"/}"); done
[[ -z $BIND_IP ]] && note "No -i given: Squid still listens on all interfaces"

if (( DRY_RUN )); then
  section "Planned system changes"
  plan "Back up $CONF_DIR to $BACKUP"
  plan "Install the hardened config shown above"
  plan "chown root:$SQUID_GROUP + chmod 640 on ${#LIVE_FILES[@]} config file(s)"
  for d in $LOG_DIRS $CACHE_DIRS; do plan "chown -R ${SQUID_USER:-?}:$SQUID_GROUP + remove world access on $d"; done
  (( HAS_SYSTEMD )) && plan "Write $OVERRIDE (NoNewPrivileges, ProtectSystem, ProtectHome, PrivateTmp)"
  if (( ${#SUBNETS[@]} )); then plan "Firewall: port(s) $(echo $PORTS) allowed only from ${SUBNETS[*]}"
  else skip "Firewall (use -s SUBNET to enable)"; fi
  (( NO_RESTART )) || plan "Restart squid if it's running (auto-rollback if it fails)"
  printf '\n%sDry run complete:%s %d fix(es) planned. Re-run without -n to apply.\n' "$BLD" "$RST" "$FIXES"
  exit 0
fi

# =============================================================================
section "Applying"
# =============================================================================
mkdir -p "$BACKUP"; cp -a "$CONF_DIR" "$BACKUP/"
OVERRIDE_EXISTED=0
[[ -f $OVERRIDE ]] && { OVERRIDE_EXISTED=1; cp -a "$OVERRIDE" "$BACKUP/"; }
ok "Backup saved to $BACKUP"

for f in "${FILES[@]}"; do
  live="$CONF_DIR/${f#"$STAGE"/}"
  cmp -s "$f" "$live" || cat "$f" > "$live"     # keep each file's inode
done
ok "Hardened config installed"

chown root:"$SQUID_GROUP" "${LIVE_FILES[@]}" && chmod 640 "${LIVE_FILES[@]}"
ok "Config files set to root:$SQUID_GROUP 640"

for d in $LOG_DIRS $CACHE_DIRS; do
  [[ -d $d ]] || continue
  [[ -n $SQUID_USER ]] && chown -R "$SQUID_USER:$SQUID_GROUP" "$d"
  chmod -R o-rwx "$d"
  ok "$d owned by ${SQUID_USER:-unchanged}, no world access"
done

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
elif command -v ufw >/dev/null 2>&1 && grep -q 'Status: active' <<<"$(ufw status 2>/dev/null)"; then
  for p in $PORTS; do
    ufw --force delete allow "$p"/tcp >/dev/null 2>&1; ufw --force delete allow "$p" >/dev/null 2>&1
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
  note "iptables rules don't survive a reboot; save them (apt install iptables-persistent && netfilter-persistent save)"
else
  note "No active ufw/firewalld and no iptables; restrict port(s) $(echo $PORTS) manually"
fi

# --- restart with rollback ----------------------------------------------------
rollback() {
  err "Squid failed to start with the new config; rolling back"
  cp -a "$BACKUP/$(basename "$CONF_DIR")/." "$CONF_DIR/"
  if (( HAS_SYSTEMD )); then
    if (( OVERRIDE_EXISTED )); then cp -a "$BACKUP/$(basename "$OVERRIDE")" "$OVERRIDE"; else rm -f "$OVERRIDE"; fi
    systemctl daemon-reload; systemctl restart squid
  fi
  err "Previous config restored. See why: journalctl -u squid -n 50"
  exit 1
}

if (( NO_RESTART )); then
  skip "Restart (-R given). Run: systemctl restart squid"
elif (( HAS_SYSTEMD )); then
  if systemctl is-active -q squid; then
    systemctl restart squid
    for _ in $(seq 1 15); do
      state=$(systemctl is-active squid); [[ $state == active || $state == failed ]] && break; sleep 1
    done
    [[ $(systemctl is-active squid) == active ]] && ok "Squid restarted and running" || rollback
  else
    note "Squid wasn't running, so it wasn't started. Start it with: systemctl start squid"
  fi
elif pgrep -x squid >/dev/null 2>&1; then
  "$SQUID_BIN" -k reconfigure 2>/dev/null && sleep 2 && pgrep -x squid >/dev/null \
    && ok "Squid reconfigured (a full restart is needed for the run-as user change)" || rollback
else
  note "Squid isn't running; the new config applies when it starts"
fi

section "Done ($FIXES fixes)"
echo "  Backup:   $BACKUP"
echo "  Undo:     cp -a $BACKUP/$(basename "$CONF_DIR")/. $CONF_DIR/ && rm -f $OVERRIDE && systemctl daemon-reload && systemctl restart squid"
echo "  Verify:   ./squid.sh"
echo "  Not automated: proxy authentication (depends on your setup)."
