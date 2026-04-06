#!/usr/bin/env bash
#
# MTProto Proxy — one-line installer for Linux (Ubuntu/Debian)
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/install.sh | sudo bash
#
# What it does:
#   1. Installs Zig 0.15.2 (if not present)
#   2. Clones and builds the proxy
#   3. Generates a random user secret
#   4. Creates a systemd service
#   5. Opens port 443 in ufw (if active)
#   6. Applies TCPMSS clamping (DPI bypass: splits ClientHello into tiny packets)
#   7. Installs IPv6 address hopping script + cron job (optional, requires CF_TOKEN + CF_ZONE)
#   8. Prints the ready-to-use tg:// link

set -euo pipefail

ZIG_VERSION="0.15.2"
INSTALL_DIR="/opt/mtproto-proxy"
REPO_URL="https://github.com/sleep3r/mtproto.zig.git"
SERVICE_NAME="mtproto-proxy"

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

# ── Check root ──────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash install.sh"

# ── Packages & Dependencies ──────────────────────────────────
apt-get update -qq || true
apt-get install -y iptables xxd git curl openssl tar xz-utils >/dev/null 2>&1 || true

# ── Install Zig ─────────────────────────────────────────────
if command -v zig &>/dev/null && zig version 2>/dev/null | grep -q "$ZIG_VERSION"; then
    ok "Zig $ZIG_VERSION already installed"
else
    info "Installing Zig $ZIG_VERSION..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ZIG_ARCH="x86_64" ;;
        aarch64) ZIG_ARCH="aarch64" ;;
        *)       fail "Unsupported architecture: $ARCH" ;;
    esac

    ZIG_TAR="zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz"
    ZIG_URL="https://ziglang.org/download/${ZIG_VERSION}/${ZIG_TAR}"

    cd /tmp
    curl -sSfL -o "$ZIG_TAR" "$ZIG_URL"
    tar xf "$ZIG_TAR"
    rm -rf /usr/local/zig
    mv "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /usr/local/zig
    ln -sf /usr/local/zig/zig /usr/local/bin/zig
    rm -f "$ZIG_TAR"
    ok "Zig $ZIG_VERSION installed to /usr/local/zig"
fi

# ── Clone & build ───────────────────────────────────────────
info "Building mtproto-proxy..."
TMPBUILD=$(mktemp -d)
git clone --depth 1 "$REPO_URL" "$TMPBUILD"
cd "$TMPBUILD"
zig build -Doptimize=ReleaseFast
ok "Build complete"

# ── Install binary ──────────────────────────────────────────
info "Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl stop "$SERVICE_NAME"
fi
cp zig-out/bin/mtproto-proxy "$INSTALL_DIR/mtproto-proxy"
chmod +x "$INSTALL_DIR/mtproto-proxy"

# Keep helper scripts locally for future maintenance/update operations
cp "$TMPBUILD/deploy"/*.sh "$INSTALL_DIR/"
cp "$TMPBUILD/deploy/capture_template.py" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR"/*.sh

# ── Generate config (if not exists) ─────────────────────────
if [[ ! -f "$INSTALL_DIR/config.toml" ]]; then
    SECRET=$(openssl rand -hex 16)
    # wb.ru is the default masking domain — must match the hex suffix in the ee-secret.
    # ee-secret format: ee + hex(user_secret) + hex(tls_domain)
    TLS_DOMAIN="wb.ru"

    cat > "$INSTALL_DIR/config.toml" << EOF
[server]
port = 443
max_connections = 512
idle_timeout_sec = 120
handshake_timeout_sec = 15

[censorship]
tls_domain = "$TLS_DOMAIN"
mask = true
fast_mode = true

[access.users]
user = "$SECRET"
EOF
    ok "Generated config with new secret"
else
    ok "Config already exists, keeping it"
    SECRET=$(grep -oP '= "\K[0-9a-f]{32}' "$INSTALL_DIR/config.toml" | head -1 || echo "")
    TLS_DOMAIN=$(grep -oP 'tls_domain\s*=\s*"\K[^"]+' "$INSTALL_DIR/config.toml" || echo "wb.ru")
fi

# ── Create service user ─────────────────────────────────────
if ! id -u mtproto &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin mtproto
    ok "Created system user 'mtproto'"
fi
chown -R mtproto:mtproto "$INSTALL_DIR"

# ── Install systemd service ─────────────────────────────────
cp "$TMPBUILD/deploy/mtproto-proxy.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
ok "Systemd service installed and started"

# ── Firewall & DPI bypass ───────────────────────────────────
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw allow 443/tcp >/dev/null 2>&1
    ok "Opened port 443 in ufw"
fi

# TCPMSS clamping: force ClientHello fragmentation to bypass passive DPI
if command -v iptables &>/dev/null; then
    iptables -t mangle -D OUTPUT -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88 2>/dev/null || true
    iptables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    ok "TCPMSS=88 clamping applied to IPv4 (passive DPI bypass)"
else
    echo -e "${RED}⚠${RESET} iptables not found — IPv4 TCPMSS bypass NOT applied"
fi

if command -v ip6tables &>/dev/null; then
    ip6tables -t mangle -D OUTPUT -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88 2>/dev/null || true
    if ip6tables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j TCPMSS --set-mss 88 2>/dev/null; then
        mkdir -p /etc/iptables
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        ok "TCPMSS=88 clamping applied to IPv6 (passive DPI bypass)"
    else
        info "IPv6 TCPMSS skipped (IPv6 may be disabled)"
    fi
fi

# ── IPv6 Hopping (Cloudflare API) ───────────────────────────
if [[ -n "${CF_TOKEN:-}" && -n "${CF_ZONE:-}" ]]; then
    info "Setting up IPv6 auto-hopping..."
    cp "$TMPBUILD/deploy/ipv6-hop.sh" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/ipv6-hop.sh"
    
    # Save credentials securely
    cat > "$INSTALL_DIR/env.sh" << EOF
export CF_TOKEN="${CF_TOKEN}"
export CF_ZONE="${CF_ZONE}"
EOF
    chmod 600 "$INSTALL_DIR/env.sh"
    
    # Set up cron job (every 5 minutes)
    cat > /etc/cron.d/mtproto-ipv6 << EOF
*/5 * * * * root $INSTALL_DIR/ipv6-hop.sh >> /var/log/mtproto-ipv6-hop.log 2>&1
EOF
    chmod 644 /etc/cron.d/mtproto-ipv6
    # Run the first hop immediately to ensure it works
    $INSTALL_DIR/ipv6-hop.sh >/dev/null 2>&1 || true
    ok "IPv6 auto-hopping configured (via Cloudflare)"
else
    info "Skipping IPv6 hopping setup (CF_TOKEN and CF_ZONE not set)"
fi

# ── OS-Level DPI Evasion (Zero-RTT Masking & Zapret) ────────
info "Setting up Local Nginx Masking (zero-RTT)..."
bash "$TMPBUILD/deploy/setup_masking.sh" "$TLS_DOMAIN" || warn "Masking setup failed"

info "Setting up zapret nfqws TCP desync..."
bash "$TMPBUILD/deploy/setup_nfqws.sh" || warn "nfqws setup failed"

# Restart proxy to apply Mask Port and NFQUEUE capabilities
chown -R mtproto:mtproto "$INSTALL_DIR"
systemctl restart "$SERVICE_NAME"
ok "Advanced OS-Level DPI Evasion and Masking successfully configured!"

# Validate masking configuration after restart
MASK_PORT="$(awk '
    BEGIN { in_censorship = 0 }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
        in_censorship = ($0 ~ /^[[:space:]]*\[censorship\][[:space:]]*$/)
        next
    }
    in_censorship && /^[[:space:]]*mask_port[[:space:]]*=/ {
        line = $0
        sub(/#.*/, "", line)
        split(line, parts, "=")
        value = parts[2]
        gsub(/[[:space:]]/, "", value)
        print value
    }
' "$INSTALL_DIR/config.toml" | tail -1)"

if [[ -z "$MASK_PORT" ]]; then
    warn "mask_port is not set in [censorship] — masking may fall back to remote tls_domain:443"
elif curl -sk --max-time 5 "https://127.0.0.1:${MASK_PORT}/" >/dev/null 2>&1; then
    ok "Masking validation passed (127.0.0.1:${MASK_PORT} responds over TLS)"
else
    warn "Masking validation failed: https://127.0.0.1:${MASK_PORT}/ is not responding"
fi

# ── Cleanup ─────────────────────────────────────────────────
rm -rf "$TMPBUILD"

# ── Print connection info ───────────────────────────────────
PUBLIC_IP=$(curl -s --max-time 5 https://ifconfig.me || echo "<SERVER_IP>")
PORT=$(grep -oP 'port\s*=\s*\K[0-9]+' "$INSTALL_DIR/config.toml" || echo "443")

# Build ee-secret: ee + hex(secret) + hex(tls_domain)
DOMAIN_HEX=$(echo -n "$TLS_DOMAIN" | xxd -p | tr -d '\n')
EE_SECRET="ee${SECRET}${DOMAIN_HEX}"

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  MTProto Proxy installed successfully!${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${DIM}Status:${RESET}  systemctl status $SERVICE_NAME"
echo -e "  ${DIM}Logs:${RESET}    journalctl -u $SERVICE_NAME -f"
echo -e "  ${DIM}Config:${RESET}  $INSTALL_DIR/config.toml"
echo ""
echo -e "  ${BOLD}Connection link:${RESET}"
echo -e "  ${CYAN}tg://proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${GREEN}${EE_SECRET}${RESET}"
echo ""
echo -e "  ${DIM}t.me/proxy?server=${PUBLIC_IP}&port=${PORT}&secret=${EE_SECRET}${RESET}"
echo ""
echo -e "  ${BOLD}DPI Bypass active:${RESET}"
echo -e "  ${GREEN}✓${RESET} Anti-Replay Cache (ТСПУ Revisor protection)"
echo -e "  ${GREEN}✓${RESET} TCPMSS=88 (ClientHello fragmentation)"
echo -e "  ${GREEN}✓${RESET} Local Nginx Dummy (Zero-RTT Active Probe defense)"
echo -e "  ${GREEN}✓${RESET} Split-TLS (1-byte TLS Record chunking)"
echo -e "  ${GREEN}✓${RESET} TCP Desync nfqws (Zapret OS fragmentation)"
if [[ -f /etc/cron.d/mtproto-ipv6 ]]; then
echo -e "  ${GREEN}✓${RESET} IPv6 auto-hopping every 5 min"
else
echo -e "  ${DIM}○ IPv6 auto-hopping (set CF_TOKEN + CF_ZONE to enable)${RESET}"
fi
echo ""
