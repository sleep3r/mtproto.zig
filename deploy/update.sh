#!/usr/bin/env bash
#
# update.sh — update mtproto-proxy from GitHub Release artifacts.
#
# Usage:
#   sudo bash update.sh
#   sudo bash update.sh v0.1.0

set -euo pipefail

REPO_OWNER="${REPO_OWNER:-sleep3r}"
REPO_NAME="${REPO_NAME:-mtproto.zig}"
INSTALL_DIR="/opt/mtproto-proxy"
SERVICE_NAME="mtproto-proxy"
VERSION="${1:-}"

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

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash update.sh"

for cmd in curl tar systemctl uname mktemp; do
    command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"
done

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        ASSET_ARCH="x86_64"
        ;;
    aarch64|arm64)
        ASSET_ARCH="aarch64"
        ;;
    *)
        fail "Unsupported architecture: $ARCH"
        ;;
esac

if [[ -z "$VERSION" ]]; then
    info "Resolving latest release tag..."
    TAG="$(curl -fsSL "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | cut -d '"' -f4 || true)"
    [[ -n "$TAG" ]] || fail "Could not determine latest release tag"
else
    TAG="$VERSION"
fi

if [[ "$TAG" != v* ]]; then
    TAG="v${TAG}"
fi

ASSET_BASENAME="mtproto-proxy-linux-${ASSET_ARCH}"
ASSET_FILE="${ASSET_BASENAME}.tar.gz"
ASSET_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${TAG}/${ASSET_FILE}"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${TAG}/deploy"

TMP_DIR="$(mktemp -d)"
BACKUP_BINARY=""

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

info "Downloading ${TAG} artifact for ${ASSET_ARCH}..."
curl -fsSL "$ASSET_URL" -o "${TMP_DIR}/${ASSET_FILE}" || fail "Release artifact not found: ${ASSET_URL}"

tar -xzf "${TMP_DIR}/${ASSET_FILE}" -C "$TMP_DIR"
NEW_BINARY="${TMP_DIR}/${ASSET_BASENAME}"
[[ -f "$NEW_BINARY" ]] || fail "Extracted binary not found in artifact"
chmod +x "$NEW_BINARY"

info "Downloading deploy scripts and service from ${TAG}..."
for file in install.sh update.sh update_dns.sh ipv6-hop.sh setup_masking.sh setup_nfqws.sh capture_template.py mtproto-proxy.service; do
    curl -fsSL "${RAW_BASE}/${file}" -o "${TMP_DIR}/${file}" || fail "Failed to download ${file}"
done

[[ -d "$INSTALL_DIR" ]] || fail "Install directory not found: $INSTALL_DIR"

if [[ -f "${INSTALL_DIR}/mtproto-proxy" ]]; then
    BACKUP_BINARY="${INSTALL_DIR}/mtproto-proxy.backup.$(date +%Y%m%d%H%M%S)"
    cp "${INSTALL_DIR}/mtproto-proxy" "$BACKUP_BINARY"
    ok "Current binary backed up to ${BACKUP_BINARY}"
else
    warn "Existing binary not found, proceeding with fresh install"
fi

info "Stopping ${SERVICE_NAME}..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

install -m 0755 "$NEW_BINARY" "${INSTALL_DIR}/mtproto-proxy"

install -m 0755 "${TMP_DIR}/install.sh" "${INSTALL_DIR}/install.sh"
install -m 0755 "${TMP_DIR}/update.sh" "${INSTALL_DIR}/update.sh"
install -m 0755 "${TMP_DIR}/update_dns.sh" "${INSTALL_DIR}/update_dns.sh"
install -m 0755 "${TMP_DIR}/ipv6-hop.sh" "${INSTALL_DIR}/ipv6-hop.sh"
install -m 0755 "${TMP_DIR}/setup_masking.sh" "${INSTALL_DIR}/setup_masking.sh"
install -m 0755 "${TMP_DIR}/setup_nfqws.sh" "${INSTALL_DIR}/setup_nfqws.sh"
install -m 0644 "${TMP_DIR}/capture_template.py" "${INSTALL_DIR}/capture_template.py"

install -m 0644 "${TMP_DIR}/mtproto-proxy.service" "/etc/systemd/system/mtproto-proxy.service"
systemctl daemon-reload

info "Starting ${SERVICE_NAME}..."
if ! systemctl restart "$SERVICE_NAME"; then
    warn "Service failed to start after update"
    if [[ -n "$BACKUP_BINARY" && -f "$BACKUP_BINARY" ]]; then
        warn "Rolling back to previous binary..."
        cp "$BACKUP_BINARY" "${INSTALL_DIR}/mtproto-proxy"
        systemctl restart "$SERVICE_NAME" || fail "Rollback failed. Check: journalctl -u ${SERVICE_NAME} --no-pager"
        fail "Update rolled back because new binary failed to start"
    fi
    fail "Service failed and no backup binary was available"
fi

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Update complete: ${SERVICE_NAME} is active"
else
    fail "Service is not active after restart"
fi

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Update completed${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${DIM}Version:${RESET}   ${TAG}"
echo -e "  ${DIM}Arch:${RESET}      ${ASSET_ARCH}"
echo -e "  ${DIM}Status:${RESET}    systemctl status ${SERVICE_NAME} --no-pager"
echo -e "  ${DIM}Logs:${RESET}      journalctl -u ${SERVICE_NAME} -f"
if [[ -n "$BACKUP_BINARY" ]]; then
    echo -e "  ${DIM}Backup:${RESET}    ${BACKUP_BINARY}"
fi
echo ""
