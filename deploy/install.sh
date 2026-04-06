#!/usr/bin/env bash
#
# MTProto Proxy — one-line installer & updater for Linux (Ubuntu/Debian)
#
# Usage (fresh install or update):
#   curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | sudo bash
#
# The script is idempotent:
#   - On first run: installs Zig, builds proxy, generates config, sets up systemd + DPI bypass.
#   - On subsequent runs: rebuilds from latest source, replaces binary, preserves config.toml.
#
# What it does:
#   1. Installs Zig 0.15.2 (if not present)
#   2. Clones and builds the proxy from latest source
#   3. Generates a random user secret (only on first install)
#   4. Creates a systemd service
#   5. Opens port 443 in ufw (if active)
#   6. Applies TCPMSS clamping (DPI bypass: splits ClientHello into tiny packets)
#   7. Installs IPv6 address hopping script + cron job (optional, requires CF_TOKEN + CF_ZONE)
#   8. Prints the ready-to-use tg:// link

set -euo pipefail

ZIG_VERSION="0.15.2"
INSTALL_DIR="/opt/mtproto-proxy"
REPO_URL="https://github.com/XXcipherX/mtproto.zig.git"
SERVICE_NAME="mtproto-proxy"
IS_UPDATE=false
[[ -f "$INSTALL_DIR/mtproto-proxy" ]] && IS_UPDATE=true

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
# NOTE: All apt-get calls use < /dev/null to prevent dpkg hooks from
# consuming stdin when this script is run via 'curl | bash'.
apt-get update -qq < /dev/null || true
apt-get install -y iptables xxd git curl openssl tar xz-utils < /dev/null >/dev/null 2>&1 || true

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
    # ee-secret format: ee + hex(user_secret) + hex(tls_domain)
    # Read domain from terminal (stdin is busy with curl pipe, so use /dev/tty)
    echo ""
    echo -e "${BOLD}${CYAN}  Enter TLS masking domain${RESET} ${DIM}(e.g. google.com, wb.ru)${RESET}"
    echo -ne "  ${CYAN}▸${RESET} Domain [wb.ru]: "
    read -r USER_DOMAIN < /dev/tty || true
    TLS_DOMAIN="${USER_DOMAIN:-wb.ru}"

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
# NOTE: Do NOT start the proxy here. Config will be modified by
# setup_masking.sh below. The proxy is started once at the end.
ok "Systemd service installed"

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
# These are optional hardening steps — failures must NOT prevent
# the final banner from being displayed.

MASKING_OK=false
NFQWS_OK=false

info "Setting up Local Nginx Masking (zero-RTT)..."
if bash "$TMPBUILD/deploy/setup_masking.sh" "$TLS_DOMAIN" < /dev/null 2>&1; then
    MASKING_OK=true
else
    warn "Masking setup failed (non-critical, proxy still works)"
fi

info "Setting up zapret nfqws TCP desync..."
if bash "$TMPBUILD/deploy/setup_nfqws.sh" < /dev/null 2>&1; then
    NFQWS_OK=true
else
    warn "nfqws setup failed (non-critical, proxy still works)"
fi

# Fix ownership: setup_masking.sh rewrites config.toml via awk+mv as root
chown -R mtproto:mtproto "$INSTALL_DIR"

# Restart proxy to apply Mask Port and NFQUEUE capabilities
systemctl restart "$SERVICE_NAME" 2>/dev/null || true
ok "Proxy restarted"

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
' "$INSTALL_DIR/config.toml" | tail -1)" || true

if [[ -n "${MASK_PORT:-}" ]]; then
    if curl -sk --max-time 5 "https://127.0.0.1:${MASK_PORT}/" >/dev/null 2>&1; then
        ok "Masking validation passed (127.0.0.1:${MASK_PORT} responds over TLS)"
    else
        warn "Masking validation failed: https://127.0.0.1:${MASK_PORT}/ is not responding"
    fi
fi

# ── Cleanup ─────────────────────────────────────────────────
rm -rf "$TMPBUILD"

# ── Print connection info ───────────────────────────────────
# This section MUST always run, so disable errexit for safety
set +e

PUBLIC_IP=$(curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null || echo "<SERVER_IP>")
# Match only 'port' in [server] section, not 'mask_port' in [censorship]
PORT=$(awk '
    /^[[:space:]]*\[server\]/ { in_server=1; next }
    /^[[:space:]]*\[/ { in_server=0 }
    in_server && /^[[:space:]]*port[[:space:]]*=/ {
        sub(/.*=[[:space:]]*/, ""); sub(/[[:space:]]*#.*/, ""); print; exit
    }
' "$INSTALL_DIR/config.toml" 2>/dev/null)
PORT="${PORT:-443}"

# Build ee-secret: ee + hex(secret) + hex(tls_domain)
DOMAIN_HEX=$(echo -n "$TLS_DOMAIN" | xxd -p | tr -d '\n')
EE_SECRET="ee${SECRET}${DOMAIN_HEX}"

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
if $IS_UPDATE; then
echo -e "${BOLD}  MTProto Proxy updated successfully!${RESET}"
else
echo -e "${BOLD}  MTProto Proxy installed successfully!${RESET}"
fi
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
echo -e "  ${BOLD}DPI Bypass:${RESET}"
echo -e "  ${GREEN}✓${RESET} Anti-Replay Cache (ТСПУ Revisor protection)"
echo -e "  ${GREEN}✓${RESET} TCPMSS=88 (ClientHello fragmentation)"
if $MASKING_OK; then
echo -e "  ${GREEN}✓${RESET} Local Nginx Dummy (Zero-RTT Active Probe defense)"
else
echo -e "  ${RED}✗${RESET} Local Nginx Masking (setup failed)"
fi
echo -e "  ${GREEN}✓${RESET} Split-TLS (1-byte TLS Record chunking)"
if $NFQWS_OK; then
echo -e "  ${GREEN}✓${RESET} TCP Desync nfqws (Zapret OS fragmentation)"
else
echo -e "  ${RED}✗${RESET} TCP Desync nfqws (setup failed)"
fi
if [[ -f /etc/cron.d/mtproto-ipv6 ]]; then
echo -e "  ${GREEN}✓${RESET} IPv6 auto-hopping every 5 min"
else
echo -e "  ${DIM}○ IPv6 auto-hopping (set CF_TOKEN + CF_ZONE to enable)${RESET}"
fi
echo ""
