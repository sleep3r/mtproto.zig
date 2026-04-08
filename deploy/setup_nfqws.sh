#!/usr/bin/env bash
#
# setup_nfqws.sh — Install zapret's nfqws for OS-level TCP desync.
#
# This complements the proxy's built-in Split-TLS desync (1-byte split in proxy.zig)
# with OS-level packet manipulation that works on ALL outbound traffic from the proxy port.
#
# nfqws uses NFQUEUE to intercept outbound TCP packets and applies:
#   - Fake packets with low TTL (expires before reaching DPI but after the ISP router)
#   - TCP window size manipulation
#   - SYN/ACK desynchronization
#   - TLS record splitting at the OS level
#
# This is the same technique that zapret uses client-side, but applied server-side
# so clients don't need to configure anything.
#
# Usage:
#   sudo bash deploy/setup_nfqws.sh
#   sudo bash deploy/setup_nfqws.sh --ttl 6    # custom TTL for fake packets
#   sudo bash deploy/setup_nfqws.sh --remove    # uninstall
#
# Requirements:
#   - Linux with iptables/nftables and NFQUEUE support
#   - Root access
#

set -euo pipefail

ZAPRET_DIR="/opt/zapret"
SERVICE_NAME="nfqws-mtproto"
TTL="${TTL:-6}"
NFQUEUE_NUM=200

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

get_server_port() {
    local cfg="$1"
    awk '
        BEGIN { in_server = 0 }
        /^[[:space:]]*\[server\][[:space:]]*$/ { in_server = 1; next }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { in_server = 0; next }
        in_server {
            line = $0
            sub(/#.*/, "", line)
            if (line ~ /^[[:space:]]*port[[:space:]]*=/) {
                split(line, parts, "=")
                value = parts[2]
                gsub(/[^0-9]/, "", value)
                if (value != "") {
                    print value
                    exit
                }
            }
        }
    ' "$cfg" 2>/dev/null
}

remove_nfqws_rules() {
    local ipt="$1"
    command -v "$ipt" &>/dev/null || return 0

    while IFS= read -r rule; do
        rule="${rule/-A /-D }"
        # shellcheck disable=SC2086
        $ipt -t mangle $rule 2>/dev/null || true
    done < <(
        "$ipt" -t mangle -S OUTPUT 2>/dev/null | awk -v q="${NFQUEUE_NUM}" '
            $1 == "-A" && $2 == "OUTPUT" && $0 ~ ("-j NFQUEUE --queue-num " q "($| )") {
                print
            }
        '
    )
}

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash setup_nfqws.sh"

# ── Parse args ──────────────────────────────────────────────
REMOVE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ttl)
            TTL="$2"
            shift 2
            ;;
        --remove|--uninstall)
            REMOVE=true
            shift
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

# ── Parse config port ───────────────────────────────────────
PORT="$(get_server_port "/opt/mtproto-proxy/config.toml")"
PORT="${PORT:-443}"

# ── Uninstall ───────────────────────────────────────────────
if $REMOVE; then
    info "Removing nfqws-mtproto..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload

    # Remove iptables rules
    remove_nfqws_rules iptables
    remove_nfqws_rules ip6tables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

    ok "nfqws-mtproto removed"
    exit 0
fi

# ── Install dependencies ────────────────────────────────────
info "Installing build dependencies..."
apt-get update -qq || true
apt-get install -y build-essential git libnetfilter-queue-dev \
    libcap-dev iptables libmnl-dev zlib1g-dev >/dev/null 2>&1
ok "Dependencies installed"

# ── Clone and build zapret ──────────────────────────────────
if [[ -x "${ZAPRET_DIR}/nfq/nfqws" ]]; then
    ok "nfqws already built at ${ZAPRET_DIR}/nfq/nfqws"
else
    info "Cloning zapret..."
    rm -rf "$ZAPRET_DIR"
    git clone --depth 1 https://github.com/bol-van/zapret.git "$ZAPRET_DIR"

    info "Building nfqws..."
    cd "${ZAPRET_DIR}/nfq"
    make clean >/dev/null 2>&1 || true
    make >/dev/null 2>&1
    [[ -x nfqws ]] || fail "nfqws build failed"
    ok "nfqws built successfully"
fi

# ── Configure iptables NFQUEUE ──────────────────────────────
info "Setting up NFQUEUE rules..."

# Remove old rules (idempotent)
remove_nfqws_rules iptables
remove_nfqws_rules ip6tables

# Add NFQUEUE rules — intercept outbound TCP from port
iptables -t mangle -A OUTPUT -p tcp --sport "$PORT" -j NFQUEUE --queue-num "$NFQUEUE_NUM"
ip6tables -t mangle -A OUTPUT -p tcp --sport "$PORT" -j NFQUEUE --queue-num "$NFQUEUE_NUM"

# Persist rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
ok "NFQUEUE rules applied (queue ${NFQUEUE_NUM})"

# ── Create systemd service ──────────────────────────────────
info "Creating systemd service..."

cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=nfqws TCP desync for MTProto proxy
After=network.target
Before=mtproto-proxy.service

[Service]
Type=simple
# nfqws desync strategy for server-side DPI evasion:
#
# --dpi-desync=fake,split2
#   1. fake: Send a fake TLS ClientHello with TTL=${TTL} (expires before reaching
#      the real DPI box, but after the first ISP router). DPI sees "valid TLS"
#      and whitelists the connection.
#   2. split2: Split the real ServerHello into two TCP segments at byte 1.
#      Reinforces the proxy's built-in Split-TLS (proxy.zig sends 1 byte + rest).
#
# --dpi-desync-ttl=${TTL}
#   TTL for fake packets. Must be > hops to ISP router but < hops to DPI.
#   Typical values: 4-8. Use traceroute to find the right value.
#   Too low = fake doesn't reach ISP router (no effect).
#   Too high = fake reaches client (breaks connection).
#
# --dpi-desync-fooling=md5sig
#   Set invalid MD5 signature TCP option on fake packets.
#   Linux kernel drops packets with bad MD5sig, so the fake never reaches
#   the real client — only the DPI sees it.
#
ExecStart=${ZAPRET_DIR}/nfq/nfqws \\
    --qnum=${NFQUEUE_NUM} \\
    --dpi-desync=fake,split2 \\
    --dpi-desync-ttl=${TTL} \\
    --dpi-desync-split-pos=1 \\
    --dpi-desync-fooling=md5sig

Restart=always
RestartSec=5

# Security hardening
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# Verify it started
sleep 1
if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "nfqws service started"
else
    warn "nfqws may have failed to start — check: journalctl -u ${SERVICE_NAME}"
fi

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  nfqws TCP Desync Configured${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${DIM}Binary:${RESET}    ${ZAPRET_DIR}/nfq/nfqws"
echo -e "  ${DIM}Service:${RESET}   ${SERVICE_NAME}"
echo -e "  ${DIM}Queue:${RESET}     NFQUEUE #${NFQUEUE_NUM}"
echo -e "  ${DIM}TTL:${RESET}       ${TTL} (adjust with --ttl N)"
echo ""
echo -e "  ${BOLD}Strategy:${RESET}  fake + split2"
echo -e "  ${DIM}1. Fake TLS with TTL=${TTL} → DPI sees valid handshake${RESET}"
echo -e "  ${DIM}2. Split at byte 1 → DPI can't reassemble ServerHello${RESET}"
echo -e "  ${DIM}3. MD5sig fooling → fake never reaches real client${RESET}"
echo ""
echo -e "  ${BOLD}Tuning TTL:${RESET}"
echo -e "  Run: ${DIM}traceroute -n <client_ip>${RESET}"
echo -e "  Set TTL to 1-2 hops past your ISP's first router."
echo -e "  Default ${TTL} works for most Russian ISPs."
echo ""
echo -e "  ${BOLD}Commands:${RESET}"
echo -e "  Status:  ${DIM}systemctl status ${SERVICE_NAME}${RESET}"
echo -e "  Logs:    ${DIM}journalctl -u ${SERVICE_NAME} -f${RESET}"
echo -e "  Remove:  ${DIM}bash deploy/setup_nfqws.sh --remove${RESET}"
echo ""
