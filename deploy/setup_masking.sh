#!/usr/bin/env bash
#
# setup_masking.sh — Install local Nginx for zero-RTT DPI masking.
#
# Problem: When the proxy masks bad clients by forwarding to a remote tls_domain
# (e.g. wb.ru:443), the additional RTT (30-60ms to wb.ru vs <1ms locally) creates
# a timing side-channel that ТСПУ can detect. A connection that takes 80ms to get
# a ServerHello from "wb.ru" when real wb.ru responds in 20ms is suspicious.
#
# Solution: Run Nginx locally with a self-signed cert. Update config.toml to use
# mask_port=8443 (or keep 443 with upstream). The proxy connects to 127.0.0.1
# instead of the remote domain, eliminating the RTT fingerprint.
#
# Usage:
#   sudo bash deploy/setup_masking.sh [tls_domain]
#   sudo bash deploy/setup_masking.sh wb.ru
#   sudo bash deploy/setup_masking.sh              # defaults to wb.ru
#
# What it does:
#   1. Installs Nginx (if not present)
#   2. Obtains a real Let's Encrypt certificate for tls_domain (via certbot)
#      OR generates a self-signed cert if certbot fails
#   3. Configures Nginx to listen on 127.0.0.1:8443
#   4. Serves a minimal page that mimics the real domain
#   5. Updates mtproto config to use local masking
#

set -euo pipefail

TLS_DOMAIN="${1:-wb.ru}"
NGINX_PORT=8443
INSTALL_DIR="/opt/mtproto-proxy"
CERT_DIR="/etc/nginx/ssl"

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

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash setup_masking.sh"

# ── Install Nginx ───────────────────────────────────────────
if command -v nginx &>/dev/null; then
    ok "Nginx already installed"
else
    info "Installing Nginx..."
    apt-get update -qq || true
    apt-get install -y nginx >/dev/null 2>&1
    ok "Nginx installed"
fi

# ── Generate certificates ──────────────────────────────────
mkdir -p "$CERT_DIR"

# Try certbot first for a real cert (better for DPI — matches real domain)
CERT_OK=false
if command -v certbot &>/dev/null; then
    info "Attempting Let's Encrypt certificate for ${TLS_DOMAIN}..."
    # This only works if the VPS actually resolves to this domain
    if certbot certonly --nginx -d "$TLS_DOMAIN" --non-interactive --agree-tos \
        --register-unsafely-without-email 2>/dev/null; then
        ln -sf "/etc/letsencrypt/live/${TLS_DOMAIN}/fullchain.pem" "${CERT_DIR}/cert.pem"
        ln -sf "/etc/letsencrypt/live/${TLS_DOMAIN}/privkey.pem" "${CERT_DIR}/key.pem"
        ok "Let's Encrypt certificate obtained for ${TLS_DOMAIN}"
        CERT_OK=true
    else
        warn "Certbot failed (domain may not point to this server)"
    fi
fi

if ! $CERT_OK; then
    info "Generating self-signed certificate for ${TLS_DOMAIN}..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${CERT_DIR}/key.pem" \
        -out "${CERT_DIR}/cert.pem" \
        -days 3650 -nodes \
        -subj "/CN=${TLS_DOMAIN}" \
        2>/dev/null
    ok "Self-signed certificate generated"
fi

# ── Configure Nginx ─────────────────────────────────────────
info "Configuring Nginx on 127.0.0.1:${NGINX_PORT}..."

# Create a minimal web root
mkdir -p /var/www/masking
cat > /var/www/masking/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1></body></html>
HTMLEOF

# Nginx config for local masking — binds ONLY on loopback
cat > /etc/nginx/sites-available/mtproto-masking << NGINXEOF
# MTProto proxy masking server — local only
# Serves TLS responses that mimic ${TLS_DOMAIN} for DPI evasion
server {
    listen 127.0.0.1:${NGINX_PORT} ssl;

    server_name ${TLS_DOMAIN};

    ssl_certificate     ${CERT_DIR}/cert.pem;
    ssl_certificate_key ${CERT_DIR}/key.pem;

    # Match Nginx defaults for realistic TLS fingerprint
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Minimal response
    root /var/www/masking;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Access log off — this is a DPI masking endpoint, not a real website
    access_log off;
    error_log /var/log/nginx/masking-error.log warn;
}
NGINXEOF

# Enable the site
ln -sf /etc/nginx/sites-available/mtproto-masking /etc/nginx/sites-enabled/

# Remove default site if it conflicts
if [[ -L /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
    info "Removed default Nginx site"
fi

# Test config and reload
nginx -t 2>/dev/null || fail "Nginx config test failed"
systemctl reload nginx
ok "Nginx configured on 127.0.0.1:${NGINX_PORT}"

# ── Verify Nginx is responding ──────────────────────────────
sleep 1
if curl -sk "https://127.0.0.1:${NGINX_PORT}/" >/dev/null 2>&1; then
    ok "Nginx responding on https://127.0.0.1:${NGINX_PORT}"
else
    warn "Nginx may not be responding yet — check: curl -sk https://127.0.0.1:${NGINX_PORT}/"
fi

# ── Update mtproto config ──────────────────────────────────
CONFIG_FILE="${INSTALL_DIR}/config.toml"
if [[ -f "$CONFIG_FILE" ]]; then
    TMP_CONFIG="$(mktemp)"
    if awk -v mask_port="${NGINX_PORT}" '
        BEGIN {
            in_censorship = 0;
            saw_censorship = 0;
            wrote_mask_port = 0;
        }

        function emit_mask_port() {
            if (!wrote_mask_port) {
                print "mask_port = " mask_port;
                wrote_mask_port = 1;
            }
        }

        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            if (in_censorship) {
                emit_mask_port();
            }
            in_censorship = ($0 ~ /^[[:space:]]*\[censorship\][[:space:]]*$/);
            if (in_censorship) {
                saw_censorship = 1;
                wrote_mask_port = 0;
            }
            print;
            next;
        }

        {
            if (in_censorship && $0 ~ /^[[:space:]]*mask_port[[:space:]]*=/) {
                emit_mask_port();
                next;
            }
            print;
        }

        END {
            if (in_censorship) {
                emit_mask_port();
            }
            if (!saw_censorship) {
                print "";
                print "[censorship]";
                print "mask_port = " mask_port;
            }
        }
    ' "$CONFIG_FILE" > "$TMP_CONFIG"; then
        mv "$TMP_CONFIG" "$CONFIG_FILE"
    else
        rm -f "$TMP_CONFIG"
        fail "Failed to update ${CONFIG_FILE} with mask_port=${NGINX_PORT}"
    fi

    ok "Updated ${CONFIG_FILE} with mask_port = ${NGINX_PORT}"
    info "Restart the proxy to apply: systemctl restart mtproto-proxy"
else
    warn "Config file not found at ${CONFIG_FILE}"
    info "Add 'mask_port = ${NGINX_PORT}' to your [censorship] section manually"
fi

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Local Nginx Masking Configured${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${DIM}Nginx:${RESET}     127.0.0.1:${NGINX_PORT} (TLS)"
echo -e "  ${DIM}Domain:${RESET}    ${TLS_DOMAIN}"
echo -e "  ${DIM}Cert:${RESET}      ${CERT_DIR}/cert.pem"
echo ""
echo -e "  ${BOLD}Effect:${RESET}"
echo -e "  Bad clients are now forwarded to local Nginx (<1ms RTT)"
echo -e "  instead of remote ${TLS_DOMAIN} (30-60ms RTT)."
echo -e "  This eliminates the timing side-channel that ТСПУ uses"
echo -e "  to detect proxy masking connections."
echo ""
