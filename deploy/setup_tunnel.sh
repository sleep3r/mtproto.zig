#!/usr/bin/env bash
#
# MTProto Proxy — AmneziaWG tunnel setup for blocked regions
#
# Runs the proxy inside an isolated network namespace with AmneziaWG,
# so Telegram DCs become reachable while the host keeps normal connectivity.
#
# Usage (on server):
#   bash setup_tunnel.sh /path/to/awg-client.conf [direct|preserve|middleproxy]
#
# Usage (via Makefile from workstation):
#   make deploy-tunnel SERVER=<ip> AWG_CONF=awg.conf [TUNNEL_MODE=direct|preserve|middleproxy]
#
# Prerequisites:
#   - mtproto-proxy already installed via install.sh or make deploy
#   - AmneziaWG client config file (.conf) from your VPN provider / AmneziaVPN app
#
# What it does:
#   1. Installs amneziawg-tools (DKMS kernel module + userspace tools)
#   2. Creates a network namespace "tg_proxy_ns"
#   3. Brings up AmneziaWG ONLY inside the namespace (host network untouched)
#   4. Sets up DNAT so incoming :443 traffic is forwarded into the namespace
#   5. Adds policy routing so response packets go back to clients (not into tunnel)
#   6. Patches the systemd service to run the proxy inside the namespace
#   7. Applies selected tunnel mode for use_middle_proxy (direct/preserve/middleproxy)
#   8. Restarts the proxy
#
# Architecture:
#
#   Client ──→ 195.x.x.x:443 ──→ [iptables DNAT] ──→ 10.200.200.2:443
#                 (host)              (host)              (tg_proxy_ns)
#                                                             │
#                                                        mtproto-proxy
#                                                             │
#                                                       awg0 (tunnel)
#                                                             │
#                                                     Telegram DC servers
#

set -euo pipefail

INSTALL_DIR="/opt/mtproto-proxy"
NS_NAME="tg_proxy_ns"
AWG_CONF_DIR="/etc/amnezia/amneziawg"
NETNS_SCRIPT="/usr/local/bin/setup_netns.sh"
SERVICE_FILE="/etc/systemd/system/mtproto-proxy.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()  { echo -e "${CYAN}▸${RESET} $*"; }
ok()    { echo -e "${GREEN}✓${RESET} $*"; }
warn()  { echo -e "${RED}⚠${RESET} $*"; }
fail()  { echo -e "${RED}✗${RESET} $*" >&2; exit 1; }

# ── Argument parsing ────────────────────────────────────────
AWG_CONF="${1:-}"
TUNNEL_MODE="${2:-direct}"

[[ -n "$AWG_CONF" ]] || fail "Usage: bash setup_tunnel.sh /path/to/awg-client.conf [direct|preserve|middleproxy]"
[[ -f "$AWG_CONF" ]] || fail "Config file not found: $AWG_CONF"
[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash setup_tunnel.sh ..."

case "$TUNNEL_MODE" in
    direct|preserve|middleproxy) ;;
    *) fail "Invalid tunnel mode '$TUNNEL_MODE'. Allowed: direct, preserve, middleproxy" ;;
esac

set_use_middle_proxy() {
    local value="$1"
    local cfg="$INSTALL_DIR/config.toml"

    if grep -Eq '^[[:space:]]*use_middle_proxy[[:space:]]*=' "$cfg"; then
        sed -i "0,/^[[:space:]]*use_middle_proxy[[:space:]]*=/{s/^[[:space:]]*use_middle_proxy[[:space:]]*=.*/use_middle_proxy = ${value}/}" "$cfg"
        return
    fi

    if grep -Eq '^[[:space:]]*\[general\][[:space:]]*$' "$cfg"; then
        sed -i "0,/^[[:space:]]*\[general\][[:space:]]*$/s//[general]\nuse_middle_proxy = ${value}/" "$cfg"
        return
    fi

    local tmp_cfg
    tmp_cfg="$(mktemp)"
    {
        echo "[general]"
        echo "use_middle_proxy = ${value}"
        echo ""
        cat "$cfg"
    } > "$tmp_cfg"
    mv "$tmp_cfg" "$cfg"
}

# ── Validate proxy is installed ─────────────────────────────
[[ -f "$INSTALL_DIR/mtproto-proxy" ]] || fail "mtproto-proxy not found at $INSTALL_DIR. Run install.sh first."
[[ -f "$INSTALL_DIR/config.toml" ]] || fail "config.toml not found at $INSTALL_DIR."

# ── Step 1: Install AmneziaWG ───────────────────────────────
info "Installing AmneziaWG..."
if command -v awg &>/dev/null; then
    ok "AmneziaWG already installed"
else
    apt-get update -qq
    apt-get install -y software-properties-common >/dev/null 2>&1
    add-apt-repository -y ppa:amnezia/ppa
    apt-get update -qq
    apt-get install -y amneziawg-tools >/dev/null 2>&1
    ok "AmneziaWG installed"
fi

# ── Step 2: Copy AWG config ─────────────────────────────────
info "Installing AmneziaWG config..."
mkdir -p "$AWG_CONF_DIR"
if [[ "$(realpath "$AWG_CONF")" != "$(realpath "$AWG_CONF_DIR/awg0.conf" 2>/dev/null)" ]]; then
    cp "$AWG_CONF" "$AWG_CONF_DIR/awg0.conf"
fi
chmod 600 "$AWG_CONF_DIR/awg0.conf"
ok "Config installed to $AWG_CONF_DIR/awg0.conf"

# ── Step 3: Create netns setup script ───────────────────────
info "Creating network namespace setup script..."
cat > "$NETNS_SCRIPT" << 'NETNS_EOF'
#!/bin/bash
set -e
NS_NAME="tg_proxy_ns"
MAIN_IF=$(ip route get 8.8.8.8 | awk '{printf $5}')

# Cleanup previous run
ip netns del $NS_NAME 2>/dev/null || true
ip link del veth_main 2>/dev/null || true

# Enable forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Create namespace
ip netns add $NS_NAME

# Setup DNS for namespace
mkdir -p /etc/netns/$NS_NAME
cat > /etc/netns/$NS_NAME/resolv.conf << EOF2
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF2

# Create veth pair: host <-> namespace
ip link add veth_main type veth peer name veth_ns
ip link set veth_ns netns $NS_NAME

# Configure host side
ip addr add 10.200.200.1/24 dev veth_main
ip link set veth_main up

# Configure namespace side
ip netns exec $NS_NAME ip addr add 10.200.200.2/24 dev veth_ns
ip netns exec $NS_NAME ip link set veth_ns up
ip netns exec $NS_NAME ip link set lo up
ip netns exec $NS_NAME ip route add default via 10.200.200.1

# Bring up AmneziaWG INSIDE the namespace (host network stays untouched)
ip netns exec $NS_NAME awg-quick up /etc/amnezia/amneziawg/awg0.conf

# Policy routing: response packets to external clients go back through veth,
# not through the AWG tunnel (which would blackhole them)
ip netns exec $NS_NAME ip rule add from 10.200.200.2 table 100 priority 100
ip netns exec $NS_NAME ip route add default via 10.200.200.1 table 100

# NAT on host: forward incoming :443 to proxy inside namespace
iptables -t nat -D PREROUTING -i $MAIN_IF -p tcp --dport 443 -j DNAT --to-destination 10.200.200.2:443 2>/dev/null || true
iptables -t nat -A PREROUTING -i $MAIN_IF -p tcp --dport 443 -j DNAT --to-destination 10.200.200.2:443
iptables -t nat -D POSTROUTING -s 10.200.200.0/24 -o $MAIN_IF -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.200.200.0/24 -o $MAIN_IF -j MASQUERADE

# Allow forwarding between host and namespace
iptables -D FORWARD -i $MAIN_IF -o veth_main -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i $MAIN_IF -o veth_main -j ACCEPT
iptables -D FORWARD -i veth_main -o $MAIN_IF -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i veth_main -o $MAIN_IF -j ACCEPT

echo "Network namespace $NS_NAME ready, awg0 tunnel active inside namespace"
NETNS_EOF
chmod +x "$NETNS_SCRIPT"
ok "Created $NETNS_SCRIPT"

# ── Step 4: Patch systemd service ───────────────────────────
info "Patching systemd service for tunnel mode..."
cat > "$SERVICE_FILE" << 'SVC_EOF'
[Unit]
Description=MTProto Proxy (Zig) via AmneziaWG Tunnel
Documentation=https://github.com/sleep3r/mtproto.zig
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/usr/local/bin/setup_netns.sh
ExecStart=/sbin/ip netns exec tg_proxy_ns /opt/mtproto-proxy/mtproto-proxy /opt/mtproto-proxy/config.toml
Restart=on-failure
RestartSec=5

# Capabilities needed for netns + privileged port binding
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_ADMIN

# Limits
LimitNOFILE=131582
TasksMax=65535

[Install]
WantedBy=multi-user.target
SVC_EOF
systemctl daemon-reload
ok "Systemd service patched for tunnel mode"

# ── Step 5: Apply selected tunnel mode ──────────────────────
info "Applying tunnel mode: $TUNNEL_MODE..."
MODE_STATUS=""
case "$TUNNEL_MODE" in
    direct)
        set_use_middle_proxy false
        MODE_STATUS="Direct mode for regular DC traffic (media keeps MiddleProxy path when available)"
        ;;
    preserve)
        MODE_STATUS="Preserved existing use_middle_proxy setting from config"
        ;;
    middleproxy)
        set_use_middle_proxy true
        MODE_STATUS="MiddleProxy mode enabled for regular and media traffic"
        ;;
esac
ok "$MODE_STATUS"

if grep -Eq '^[[:space:]]*tag[[:space:]]*=' "$INSTALL_DIR/config.toml"; then
    ok "Promotion tag preserved"
fi

if ! grep -Eq '^[[:space:]]*tag[[:space:]]*=' "$INSTALL_DIR/config.toml"; then
    if [[ -f "$INSTALL_DIR/env.sh" ]]; then
        TAG_FROM_ENV="$(awk -F= '/^[[:space:]]*export[[:space:]]+TAG[[:space:]]*=/{gsub(/"/,"",$2); gsub(/[[:space:]]/,"",$2); print tolower($2)}' "$INSTALL_DIR/env.sh" | head -1)"
        if [[ "$TAG_FROM_ENV" =~ ^[0-9a-f]{32}$ ]]; then
            if grep -Eq '^[[:space:]]*\[server\][[:space:]]*$' "$INSTALL_DIR/config.toml"; then
                sed -i "0,/^[[:space:]]*\[server\][[:space:]]*$/s//[server]\ntag = \"${TAG_FROM_ENV}\"/" "$INSTALL_DIR/config.toml"
                ok "Promotion tag restored from env.sh"
            fi
        fi
    fi
fi

PUBLIC_IP=$(curl -s4 --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
if [[ -n "$PUBLIC_IP" ]]; then
    if grep -Eq '^[[:space:]]*public_ip[[:space:]]*=' "$INSTALL_DIR/config.toml"; then
        sed -i "s/^[[:space:]]*public_ip[[:space:]]*=.*/public_ip = \"$PUBLIC_IP\"/" "$INSTALL_DIR/config.toml"
    else
        sed -i "/^\[server\]/a public_ip = \"$PUBLIC_IP\"" "$INSTALL_DIR/config.toml"
    fi
    ok "Injected public IP ($PUBLIC_IP) into config"
fi

# ── Step 6: Restart proxy ───────────────────────────────────
info "Restarting proxy..."
systemctl restart mtproto-proxy
sleep 2

if systemctl is-active --quiet mtproto-proxy; then
    ok "Proxy is running inside AmneziaWG tunnel"
else
    fail "Proxy failed to start. Check: journalctl -u mtproto-proxy -n 30"
fi

# ── Step 7: Validate tunnel connectivity ────────────────────
info "Validating Telegram DC connectivity through tunnel..."
FAIL=0
for dc_ip in 149.154.175.50 149.154.167.50 149.154.175.100 149.154.167.91 91.108.56.100; do
    if ip netns exec $NS_NAME nc -zw3 "$dc_ip" 443 2>/dev/null; then
        ok "DC $dc_ip reachable"
    else
        warn "DC $dc_ip NOT reachable"
        FAIL=1
    fi
done

if [[ $FAIL -eq 1 ]]; then
    warn "Some DCs are not reachable. Check your AWG config / VPN server."
fi

# ── Print result ────────────────────────────────────────────
PORT=$(awk '
    BEGIN { in_server = 0 }
    /^\[server\]/ { in_server = 1; next }
    /^\[/ { in_server = 0; next }
    in_server && /^port/ { split($0, a, "="); gsub(/[^0-9]/, "", a[2]); print a[2] }
' "$INSTALL_DIR/config.toml" | head -1)
PORT="${PORT:-443}"

# Extract first user secret
SECRET=$(grep -oP '=\s*"\K[0-9a-f]{32}' "$INSTALL_DIR/config.toml" | head -1)
TLS_DOMAIN=$(grep -oP 'tls_domain\s*=\s*"\K[^"]+' "$INSTALL_DIR/config.toml" || echo "wb.ru")
DOMAIN_HEX=$(echo -n "$TLS_DOMAIN" | xxd -p | tr -d '\n')
EE_SECRET="ee${SECRET}${DOMAIN_HEX}"

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  AmneziaWG Tunnel configured successfully!${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${DIM}Status:${RESET}  systemctl status mtproto-proxy"
echo -e "  ${DIM}Logs:${RESET}    journalctl -u mtproto-proxy -f"
echo -e "  ${DIM}Tunnel:${RESET}  ip netns exec $NS_NAME awg show"
echo ""
echo -e "  ${BOLD}Connection link:${RESET}"
echo -e "  ${CYAN}tg://proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${GREEN}${EE_SECRET}${RESET}"
echo ""
echo -e "  ${DIM}t.me/proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${EE_SECRET}${RESET}"
echo ""
echo -e "  ${BOLD}Architecture:${RESET}"
echo -e "  ${GREEN}✓${RESET} Proxy runs inside isolated network namespace"
echo -e "  ${GREEN}✓${RESET} AmneziaWG tunnel active (host network untouched)"
echo -e "  ${GREEN}✓${RESET} ${MODE_STATUS}"
echo -e "  ${GREEN}✓${RESET} SSH and host services unaffected by tunnel"
echo ""
