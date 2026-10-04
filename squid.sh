#!/usr/bin/env bash
# =============================================================================
# squid_audit.sh - Read-only security audit of a Squid proxy server
#
# Checks Squid's configuration and runtime state against a hardening checklist
# and reports PASS / WARN / FAIL for each item. Nothing is changed.
#
# Usage:   sudo ./squid_audit.sh [-c /path/to/squid.conf]
# Exit:    0 = no failures, 1 = one or more FAIL results, 2 = setup error
# =============================================================================

set -uo pipefail

# ---------- output helpers ----------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; BLD=""; RST=""
fi

PASS_N=0; WARN_N=0; FAIL_N=0

pass()    { printf '  %s[PASS]%s %s\n' "$GRN" "$RST" "$1"; PASS_N=$((PASS_N+1)); }
warn()    { printf '  %s[WARN]%s %s\n' "$YEL" "$RST" "$1"; [[ -n ${2:-} ]] && printf '         fix: %s\n' "$2"; WARN_N=$((WARN_N+1)); }
fail()    { printf '  %s[FAIL]%s %s\n' "$RED" "$RST" "$1"; [[ -n ${2:-} ]] && printf '         fix: %s\n' "$2"; FAIL_N=$((FAIL_N+1)); }
info()    { printf '  %s[INFO]%s %s\n' "$BLU" "$RST" "$1"; }
section() { printf '\n%s== %s ==%s\n' "$BLD" "$1" "$RST"; }

usage() {
  cat <<EOF
Usage: $0 [-c /path/to/squid.conf]

Audits a Squid proxy against a hardening checklist (read-only).
Run as root for complete results (file permissions, process and socket checks).

  -c FILE   Path to squid.conf (auto-detected if omitted)
  -h        Show this help
EOF
}

# ---------- arguments ---------------------------------------------------------
CONF_FILE=""
while getopts ":c:h" opt; do
  case $opt in
    c) CONF_FILE=$OPTARG ;;
    h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if [[ -z $CONF_FILE ]]; then
  for f in /etc/squid/squid.conf /etc/squid3/squid.conf \
           /usr/local/squid/etc/squid.conf /usr/local/etc/squid/squid.conf; do
    [[ -f $f ]] && { CONF_FILE=$f; break; }
  done
fi

if [[ -z $CONF_FILE || ! -r $CONF_FILE ]]; then
  echo "${RED}Error:${RST} squid.conf not found or not readable. Use -c /path/to/squid.conf" >&2
  exit 2
fi

SQUID_BIN=""
for b in squid squid3 /usr/sbin/squid /usr/local/squid/sbin/squid; do
  if command -v "$b" >/dev/null 2>&1; then SQUID_BIN=$(command -v "$b"); break; fi
done

[[ $EUID -ne 0 ]] && echo "${YEL}Note:${RST} not running as root; some checks may be incomplete."

# ---------- config loading (follows include directives) -----------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CONF_FILES=()

collect_conf() {
  local f=$1 depth=${2:-0} line inc
  (( depth > 10 )) && return
  [[ -r $f ]] || return
  CONF_FILES+=("$f")
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%%#*}
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    [[ -z $line ]] && continue
    if [[ $line =~ ^include[[:space:]]+(.+)$ ]]; then
      for inc in ${BASH_REMATCH[1]}; do collect_conf "$inc" $((depth+1)); done
    else
      printf '%s\n' "$line"
    fi
  done < "$f"
}

collect_conf "$CONF_FILE" > "$WORK/raw"
CONF=$(awk '{$1=$1; print}' "$WORK/raw")          # normalise whitespace
HTTP_ACCESS=$(grep -E '^http_access ' <<<"$CONF" || true)

values()     { awk -v d="$1" '$1==d { $1=""; sub(/^ +/, ""); print }' <<<"$CONF"; }
last_value() { values "$1" | tail -n1; }

# Position of the first "allow" rule for network clients (ignores rules that
# only match the proxy host itself, like 'allow localhost [manager]').
FIRST_ALLOW=$(grep -nE '^http_access allow' <<<"$HTTP_ACCESS" | grep -vE 'allow localhost( manager)?$' | head -n1 | cut -d: -f1)

# A deny rule must exist AND come before the first allow rule to be effective.
check_deny_rule() {
  local desc=$1 regex=$2 fix=$3 idx
  idx=$(grep -nE "$regex" <<<"$HTTP_ACCESS" | head -n1 | cut -d: -f1)
  if [[ -z $idx ]]; then
    fail "$desc: rule missing" "$fix"
  elif [[ -n $FIRST_ALLOW && $idx -gt $FIRST_ALLOW ]]; then
    warn "$desc: rule exists but comes after an allow rule, so clients matched by that rule bypass it" \
         "Move it above the first 'http_access allow' line"
  else
    pass "$desc"
  fi
}

perm_other() { stat -c '%a' "$1" 2>/dev/null | awk '{print substr($0, length($0), 1)}'; }
perm_group() { stat -c '%a' "$1" 2>/dev/null | awk '{print substr($0, length($0)-1, 1)}'; }

printf '%sSquid hardening audit%s  (%s)\n' "$BLD" "$RST" "$(date '+%Y-%m-%d %H:%M')"
printf 'Config: %s' "$CONF_FILE"
(( ${#CONF_FILES[@]} > 1 )) && printf '  (+%d included file(s))' $(( ${#CONF_FILES[@]} - 1 ))
printf '\n'

# =============================================================================
section "Version and configuration validity"
# =============================================================================
if [[ -z $SQUID_BIN ]]; then
  warn "Squid binary not found in PATH; version and parse checks skipped"
else
  ver_line=$("$SQUID_BIN" -v 2>/dev/null | head -n1)
  ver=$(grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$ver_line" | head -n1)
  major=${ver%%.*}
  if [[ -z $ver ]]; then
    warn "Could not determine Squid version"
  elif (( major < 6 )); then
    fail "Squid $ver is end-of-life and has unpatched vulnerabilities" "Upgrade to a supported release (6.x or newer)"
  else
    pass "Squid version $ver"
  fi
  info "Compare your version against https://github.com/squid-cache/squid/security/advisories"

  if command -v apt >/dev/null 2>&1; then
    apt list --upgradable 2>/dev/null | grep -q '^squid' && warn "A newer squid package is available" "apt upgrade squid"
  elif command -v dnf >/dev/null 2>&1; then
    dnf -q check-update squid >/dev/null 2>&1; [[ $? -eq 100 ]] && warn "A newer squid package is available" "dnf upgrade squid"
  fi

  parse_out=$("$SQUID_BIN" -k parse -f "$CONF_FILE" 2>&1)
  if [[ $? -eq 0 ]]; then
    nwarn=$(grep -c 'WARNING' <<<"$parse_out")
    if (( nwarn > 0 )); then
      warn "Config parses, but with $nwarn warning(s)" "Review: $SQUID_BIN -k parse"
    else
      pass "Config parses cleanly (squid -k parse)"
    fi
  else
    fail "Config has errors (squid -k parse failed)"
    grep -E 'ERROR|FATAL' <<<"$parse_out" | head -n5 | sed 's/^/         /'
  fi
fi

# =============================================================================
section "Access control"
# =============================================================================
if [[ -z $HTTP_ACCESS ]]; then
  fail "No http_access rules found" "Define explicit allow rules for your networks, ending with 'http_access deny all'"
else
  if [[ $(tail -n1 <<<"$HTTP_ACCESS") == "http_access deny all" ]]; then
    pass "Final http_access rule is 'deny all'"
  else
    fail "Final http_access rule is not 'deny all'" "Add 'http_access deny all' as the last http_access line"
  fi

  if grep -qx 'http_access allow all' <<<"$HTTP_ACCESS"; then
    fail "'http_access allow all' present: this is an open proxy" "Replace with 'http_access allow localnet' (or your own ACL)"
  else
    pass "No 'http_access allow all' (not an open proxy)"
  fi

  check_deny_rule "Unsafe ports denied" '^http_access deny (.* )?!Safe_ports( |$)' \
    "Add 'http_access deny !Safe_ports'"
  check_deny_rule "CONNECT limited to SSL ports" '^http_access deny (.* )?CONNECT (.* )?!SSL_ports( |$)' \
    "Add 'http_access deny CONNECT !SSL_ports'"
  check_deny_rule "Requests to the proxy host itself denied" '^http_access deny (.* )?to_localhost( |$)' \
    "Add 'http_access deny to_localhost'"

  meta_names=$(awk '$1=="acl" && /169\.254\./ {print $2}' <<<"$CONF" | sort -u | paste -sd'|')
  meta_regex="to_linklocal${meta_names:+|$meta_names}"
  check_deny_rule "Cloud metadata / link-local (169.254.0.0/16) denied" \
    "^http_access deny (.* )?($meta_regex)( |$)" \
    "Add 'http_access deny to_linklocal' (Squid 6+) or an ACL for 169.254.0.0/16"

  bad_mgr=$(grep -E '^http_access allow (.* )?manager( |$)' <<<"$HTTP_ACCESS" | grep -Ev '(^| )localhost( |$)' || true)
  if [[ -n $bad_mgr ]]; then
    fail "Cache manager allowed from non-localhost sources: $bad_mgr" "Use 'http_access allow localhost manager' then 'http_access deny manager'"
  elif grep -Eq '^http_access deny (.* )?manager( |$)' <<<"$HTTP_ACCESS"; then
    pass "Cache manager restricted to localhost"
  else
    warn "No explicit 'http_access deny manager' rule" "Add 'http_access allow localhost manager' and 'http_access deny manager'"
  fi
fi

# =============================================================================
section "Authentication"
# =============================================================================
auth_schemes=$(values auth_param | awk '{print $1}' | sort -u | paste -sd',')
auth_acls=$(awk '$1=="acl" && ($3=="proxy_auth" || $3=="proxy_auth_regex" || $3=="ext_user") {print $2}' <<<"$CONF")
if [[ -z $auth_schemes ]]; then
  warn "No proxy authentication configured; any host allowed by ACLs can use the proxy" \
       "Consider auth_param (negotiate/Kerberos or digest preferred) if users should be identified"
elif [[ -z $auth_acls ]]; then
  warn "auth_param ($auth_schemes) defined but no proxy_auth ACL enforces it" "Add 'acl authed proxy_auth REQUIRED' and use it in http_access"
else
  pass "Proxy authentication enforced (schemes: $auth_schemes)"
  [[ $auth_schemes == basic ]] && info "Basic auth sends passwords in cleartext to the proxy; prefer negotiate or digest, or an https_port"
fi

# =============================================================================
section "Network exposure"
# =============================================================================
PORTS=()
port_lines=$( { values http_port; values https_port; } )
if [[ -z $port_lines ]]; then
  warn "No http_port set; Squid defaults to 3128 on ALL interfaces" "Set e.g. 'http_port 10.0.0.1:3128'"
  PORTS+=(3128)
else
  while read -r line; do
    addr=${line%% *}
    PORTS+=("${addr##*:}")
    if [[ $addr =~ ^[0-9]+$ || $addr == 0.0.0.0:* || $addr == "[::]:"* ]]; then
      warn "Listener '$addr' binds to all interfaces" "Bind to an internal IP, e.g. 'http_port 10.0.0.1:${addr##*:}'"
    else
      pass "Listener bound to specific address: $addr"
    fi
  done <<<"$port_lines"
fi

if command -v ss >/dev/null 2>&1; then
  live=$(ss -Hltnp 2>/dev/null | awk '/"squid"/ {print $4}' | sort -u)
  if [[ -z $live ]]; then
    info "No live squid listening sockets found (not running, or need root to see process names)"
  else
    wide=$(grep -E '^(0\.0\.0\.0|\*|\[::\]):' <<<"$live" | paste -sd' ' || true)
    if [[ -n $wide ]]; then
      warn "Squid is currently listening on all interfaces: $wide"
    else
      pass "Live sockets bound to specific addresses: $(paste -sd' ' <<<"$live")"
    fi
  fi
fi

check_port_off() {
  local d=$1 v
  v=$(last_value "$d")
  if [[ -z $v || $v == 0 ]]; then pass "$d disabled"
  else fail "$d is enabled ($v)" "Set '$d 0' unless you use it"; fi
}
check_port_off icp_port
check_port_off htcp_port
check_port_off snmp_port

fw_rules=$( { iptables-save 2>/dev/null; ip6tables-save 2>/dev/null; nft list ruleset 2>/dev/null;
              ufw status 2>/dev/null; firewall-cmd --list-all 2>/dev/null; } || true)
for p in $(printf '%s\n' "${PORTS[@]}" | sort -u); do
  if grep -Eq "(dport|port|^)[ =:]*$p([^0-9]|$)|$p/tcp" <<<"$fw_rules"; then
    pass "Firewall rules reference port $p (verify they restrict source networks)"
  else
    warn "No firewall rule found referencing port $p (heuristic check)" "Allow port $p only from trusted subnets"
  fi
done

# =============================================================================
section "Information leakage"
# =============================================================================
[[ $(last_value httpd_suppress_version_string) == on ]] \
  && pass "Version string suppressed" \
  || fail "Squid version shown in error pages and headers" "Set 'httpd_suppress_version_string on'"

[[ $(last_value via) == off ]] \
  && pass "Via header disabled" \
  || fail "Via header enabled (reveals proxy name and version)" "Set 'via off'"

ff=$(last_value forwarded_for)
case ${ff:-on} in
  delete) pass "X-Forwarded-For removed (forwarded_for delete)" ;;
  off)    warn "forwarded_for off still sends 'X-Forwarded-For: unknown'" "Use 'forwarded_for delete'" ;;
  *)      fail "Client IPs leaked via X-Forwarded-For (forwarded_for ${ff:-on})" "Set 'forwarded_for delete'" ;;
esac

vh=$(last_value visible_hostname)
[[ -n $vh ]] \
  && pass "visible_hostname set ($vh)" \
  || warn "visible_hostname not set; real hostname appears in error pages" "Set a generic name, e.g. 'visible_hostname proxy'"

[[ $(last_value strip_query_terms) == off ]] \
  && fail "Full query strings are logged (may contain tokens/passwords)" "Set 'strip_query_terms on'" \
  || pass "Query strings stripped from logs"

# =============================================================================
section "Resource limits"
# =============================================================================
rh=$(last_value request_header_max_size)
pass "request_header_max_size: ${rh:-64 KB (default)}"

[[ -n $(values reply_body_max_size) ]] \
  && pass "reply_body_max_size set" \
  || warn "reply_body_max_size not set (unlimited downloads)" "e.g. 'reply_body_max_size 500 MB'"

[[ -n $(values request_body_max_size) ]] \
  && pass "request_body_max_size set" \
  || warn "request_body_max_size not set (unlimited uploads)" "e.g. 'request_body_max_size 50 MB'"

mc_acls=$(awk '$1=="acl" && $3=="maxconn" {print $2}' <<<"$CONF" | paste -sd'|')
if [[ -n $mc_acls ]] && grep -Eq "^http_access deny (.* )?($mc_acls)( |$)" <<<"$HTTP_ACCESS"; then
  pass "Per-client connection limit enforced (maxconn ACL)"
else
  warn "No per-client connection limit" "Add 'acl maxconn_limit maxconn 50' and 'http_access deny maxconn_limit localnet'"
fi

cl=$(last_value client_lifetime)
[[ -n $cl ]] && pass "client_lifetime: $cl" || warn "client_lifetime not set (default 1 day)" "e.g. 'client_lifetime 1 hour'"

# =============================================================================
section "System, users and permissions"
# =============================================================================
ceu=$(last_value cache_effective_user)
if [[ $ceu == root ]]; then
  fail "cache_effective_user is root" "Set 'cache_effective_user squid' (or 'proxy' on Debian/Ubuntu)"
elif [[ -n $ceu ]]; then
  pass "cache_effective_user: $ceu"
else
  info "cache_effective_user not set; using compile-time default"
fi

run_users=$(ps -eo user=,comm= 2>/dev/null | awk '$2 ~ /^squid/ {print $1}' | sort -u | paste -sd' ')
if [[ -z $run_users ]]; then
  info "No running squid processes found"
elif [[ $run_users == root ]]; then
  fail "All squid processes run as root"
else
  pass "Squid worker processes run as: $run_users"
fi

for f in "${CONF_FILES[@]}"; do
  owner=$(stat -c '%U' "$f" 2>/dev/null); o=$(perm_other "$f"); g=$(perm_group "$f")
  if [[ $owner != root ]]; then
    fail "$f owned by '$owner'" "chown root: $f"
  elif (( (o & 2) || (g & 2) )); then
    fail "$f is group/world-writable ($(stat -c '%a' "$f"))" "chmod 640 $f"
  elif (( o & 4 )); then
    warn "$f is world-readable ($(stat -c '%a' "$f"))" "chmod 640 $f"
  else
    pass "$f ownership and mode OK ($(stat -c '%U:%G %a' "$f"))"
  fi
done

log_dirs=$( { values access_log; values cache_log; } | awk '{print $1}' | grep -v '^none$' \
            | sed -E 's#^[a-z]+:##' | xargs -r -n1 dirname 2>/dev/null | sort -u)
[[ -z $log_dirs ]] && log_dirs=/var/log/squid
for d in $log_dirs; do
  [[ -d $d ]] || continue
  o=$(perm_other "$d")
  if (( o & 2 )); then
    fail "Log directory $d is world-writable" "chmod o-rwx $d"
  elif (( o & 4 )) || [[ -n $(find "$d" -maxdepth 1 -type f -perm -o+r 2>/dev/null | head -n1) ]]; then
    warn "Logs in $d are world-readable (they contain browsing history)" "chmod -R o-rwx $d"
  else
    pass "Log directory $d not world-accessible"
  fi
done

if [[ -n $(values logfile_rotate) || -f /etc/logrotate.d/squid ]]; then
  pass "Log rotation configured"
else
  warn "No log rotation found" "Add /etc/logrotate.d/squid or set logfile_rotate"
fi

while read -r line; do
  [[ -z $line ]] && continue
  cdir=$(awk '{print $2}' <<<"$line")
  [[ -d $cdir ]] || continue
  owner=$(stat -c '%U' "$cdir"); o=$(perm_other "$cdir")
  if [[ $owner == root ]]; then
    warn "Cache dir $cdir owned by root" "chown -R ${ceu:-squid}: $cdir"
  elif (( o & 2 )); then
    fail "Cache dir $cdir is world-writable" "chmod o-rwx $cdir"
  else
    pass "Cache dir $cdir ownership and mode OK"
  fi
done <<<"$(values cache_dir)"

# =============================================================================
section "SSL bumping"
# =============================================================================
if [[ -z $(values ssl_bump) ]]; then
  info "ssl_bump not configured; skipping"
else
  grep -Eq '^sslproxy_cert_error allow all' <<<"$CONF" \
    && fail "Upstream certificate errors are ignored (sslproxy_cert_error allow all)" "Remove it; allow only specific known exceptions" \
    || pass "Upstream certificate errors not blanket-ignored"

  grep -Eq '^(tls_outgoing_options|sslproxy_flags) .*DONT_VERIFY_PEER' <<<"$CONF" \
    && fail "Upstream certificate verification disabled (DONT_VERIFY_PEER)" "Remove DONT_VERIFY_PEER" \
    || pass "Upstream certificate verification enabled"

  grep -Eq '^ssl_bump splice' <<<"$CONF" \
    && pass "Some traffic is spliced (not decrypted)" \
    || warn "No 'ssl_bump splice' rules: all TLS traffic is decrypted" "Splice sensitive categories (banking, health) instead of bumping"

  keys=$( { values http_port; values https_port; } | grep -oE '(tls-)?(key|cert)=[^ ]+' | sed -E 's/^[^=]+=//' | sort -u)
  for k in $keys; do
    [[ -f $k ]] || continue
    if grep -q 'PRIVATE KEY' "$k" 2>/dev/null; then
      o=$(perm_other "$k")
      (( o != 0 )) \
        && fail "CA private key $k is accessible to other users ($(stat -c '%a' "$k"))" "chmod 600 $k" \
        || pass "CA private key $k not world-accessible"
    fi
  done
fi

# =============================================================================
section "Service sandboxing (systemd)"
# =============================================================================
if command -v systemctl >/dev/null 2>&1 && systemctl cat squid.service >/dev/null 2>&1; then
  missing=()
  [[ $(systemctl show -p NoNewPrivileges --value squid) == yes ]] || missing+=("NoNewPrivileges=yes")
  [[ $(systemctl show -p ProtectSystem   --value squid) =~ ^(yes|full|strict)$ ]] || missing+=("ProtectSystem=full")
  [[ $(systemctl show -p ProtectHome     --value squid) =~ ^(yes|read-only|tmpfs)$ ]] || missing+=("ProtectHome=yes")
  [[ $(systemctl show -p PrivateTmp      --value squid) == yes ]] || missing+=("PrivateTmp=yes")
  if (( ${#missing[@]} == 0 )); then
    pass "systemd sandboxing options enabled"
  else
    warn "systemd sandboxing not fully enabled; missing: ${missing[*]}" \
         "systemctl edit squid  ->  add them under [Service], then restart"
  fi
else
  info "squid.service not found; skipping systemd checks"
fi

# =============================================================================
printf '\n%sSummary:%s %s%d passed%s, %s%d warnings%s, %s%d failed%s\n' \
  "$BLD" "$RST" "$GRN" "$PASS_N" "$RST" "$YEL" "$WARN_N" "$RST" "$RED" "$FAIL_N" "$RST"
(( FAIL_N > 0 )) && exit 1
exit 0
