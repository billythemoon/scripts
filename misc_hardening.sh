#!/bin/bash
#
# misc_hardening.sh
# Enables the ufw firewall and applies kernel (sysctl) network hardening,
# including TCP SYN cookies.
#
# SAFETY NOTE: enabling a firewall over SSH can lock you out. This script
# detects your SSH port and allows it BEFORE enabling ufw. Keep your current
# session open until you've confirmed a new connection works.
#
# Must be run as root.

set -uo pipefail

# ----- Configurable values -----
ENABLE_UFW=1                    # 1 = configure and enable ufw
UFW_DEFAULT_INCOMING="deny"
UFW_DEFAULT_OUTGOING="allow"
UFW_LOGGING="low"               # off | low | medium | high
EXTRA_ALLOW_PORTS=()            # e.g. ("80/tcp" "443/tcp") -- SSH is added automatically

ENABLE_SYSCTL=1                 # 1 = write and apply sysctl hardening
IP_FORWARD=0                    # 0 = disable forwarding. Set to 1 if this box is a router/VPN/Docker host
# --------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

# =====================================================================
# Part 1: UFW
# =====================================================================
if [[ "$ENABLE_UFW" -eq 1 ]]; then
    echo "=== UFW firewall ==="

    if ! command -v ufw >/dev/null 2>&1; then
        echo "ufw not installed. Installing..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq && apt-get install -y ufw
        else
            echo "Couldn't auto-install ufw on this distro. Install it manually and re-run." >&2
        fi
    fi

    if command -v ufw >/dev/null 2>&1; then
        # Detect SSH port(s) so we never lock ourselves out
        SSH_PORTS=$(grep -iE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
        [[ -z "$SSH_PORTS" ]] && SSH_PORTS="22"

        ufw default "$UFW_DEFAULT_INCOMING" incoming
        ufw default "$UFW_DEFAULT_OUTGOING" outgoing

        for p in $SSH_PORTS; do
            echo "  Allowing SSH on $p/tcp"
            ufw allow "${p}/tcp" >/dev/null
        done

        for rule in "${EXTRA_ALLOW_PORTS[@]}"; do
            echo "  Allowing $rule"
            ufw allow "$rule" >/dev/null
        done

        ufw logging "$UFW_LOGGING"
        ufw --force enable
        systemctl enable ufw >/dev/null 2>&1 || true

        echo ""
        ufw status verbose
    fi
    echo ""
fi

# =====================================================================
# Part 2: sysctl hardening
# =====================================================================
if [[ "$ENABLE_SYSCTL" -eq 1 ]]; then
    echo "=== sysctl network/kernel hardening ==="

    SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
    if [[ -f "$SYSCTL_FILE" ]]; then
        cp "$SYSCTL_FILE" "${SYSCTL_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    fi

    cat > "$SYSCTL_FILE" << EOF
# Written by misc_hardening.sh

# --- SYN flood protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# --- Anti-spoofing (reverse path filtering) ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- Ignore ICMP redirects (prevents route hijacking) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Don't send redirects (we're not a router) ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# --- Disable source routing ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Log spoofed/impossible packets ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- ICMP hardening ---
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- TIME_WAIT assassination protection ---
net.ipv4.tcp_rfc1337 = 1

# --- IP forwarding ---
net.ipv4.ip_forward = ${IP_FORWARD}
net.ipv6.conf.all.forwarding = ${IP_FORWARD}

# --- Kernel protections ---
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

    echo "Wrote $SYSCTL_FILE"
    echo "Applying..."
    sysctl --system >/dev/null 2>/tmp/sysctl_err
    if [[ -s /tmp/sysctl_err ]]; then
        echo "Some keys couldn't be applied (usually harmless, e.g. IPv6 disabled or kernel lacks the key):"
        sed 's/^/  /' /tmp/sysctl_err
    fi
    rm -f /tmp/sysctl_err

    echo ""
    echo "Verification:"
    for key in net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter net.ipv4.ip_forward kernel.randomize_va_space; do
        printf "  %-35s = %s\n" "$key" "$(sysctl -n "$key" 2>/dev/null || echo 'n/a')"
    done
fi

echo ""
echo "Done. Confirm you can open a NEW SSH connection before closing this session."
