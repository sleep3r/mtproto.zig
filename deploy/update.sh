#!/usr/bin/env bash
#
# update.sh — update mtproto-proxy from GitHub Release artifacts.
#
# Usage:
#   sudo bash update.sh
#   sudo bash update.sh v0.1.0
#   sudo FORCE_SERVICE_UPDATE=1 bash update.sh    # overwrite custom systemd unit

set -euo pipefail

REPO_OWNER="${REPO_OWNER:-sleep3r}"
REPO_NAME="${REPO_NAME:-mtproto.zig}"
INSTALL_DIR="/opt/mtproto-proxy"
SERVICE_NAME="mtproto-proxy"
SERVICE_FILE="/etc/systemd/system/mtproto-proxy.service"
VERSION="${1:-}"
FORCE_SERVICE_UPDATE="${FORCE_SERVICE_UPDATE:-0}"

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

is_tunnel_service_unit() {
    local unit_path="$1"
    [[ -f "$unit_path" ]] || return 1
    grep -Eq 'setup_netns\.sh|ip[[:space:]]+netns[[:space:]]+exec|AmneziaWG[[:space:]]+Tunnel' "$unit_path"
}

cpu_supports_x86_64_v3() {
    local flags=""
    local required

    if command -v lscpu >/dev/null 2>&1; then
        flags="$(LC_ALL=C lscpu 2>/dev/null | awk -F: '/^Flags:/ {print tolower($2)}')"
    fi

    if [[ -z "$flags" && -r /proc/cpuinfo ]]; then
        flags="$(LC_ALL=C grep -m1 -i '^flags[[:space:]]*:' /proc/cpuinfo | cut -d: -f2 | tr '[:upper:]' '[:lower:]')"
    fi

    [[ -n "$flags" ]] || return 1

    for required in avx2 bmi1 bmi2 fma f16c movbe sse4_1 sse4_2 ssse3 popcnt aes xsave; do
        [[ " $flags " == *" $required "* ]] || return 1
    done

    if [[ " $flags " != *" lzcnt "* && " $flags " != *" abm "* ]]; then
        return 1
    fi

    return 0
}

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

ASSET_CANDIDATES=()
if [[ "$ASSET_ARCH" == "x86_64" ]]; then
    if cpu_supports_x86_64_v3; then
        info "CPU supports x86_64_v3; preferring optimized artifact"
        ASSET_CANDIDATES=(
            "mtproto-proxy-linux-x86_64_v3"
            "mtproto-proxy-linux-x86_64"
        )
    else
        warn "CPU lacks x86_64_v3 features; using generic x86_64 artifact"
        ASSET_CANDIDATES=(
            "mtproto-proxy-linux-x86_64"
        )
    fi
else
    ASSET_CANDIDATES=(
        "mtproto-proxy-linux-${ASSET_ARCH}"
    )
fi

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

RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${TAG}/deploy"

TMP_DIR="$(mktemp -d)"
BACKUP_BINARY=""

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

SELECTED_ASSET_BASENAME=""
SELECTED_ASSET_FILE=""

info "Downloading ${TAG} artifact for ${ASSET_ARCH}..."
for candidate in "${ASSET_CANDIDATES[@]}"; do
    candidate_file="${candidate}.tar.gz"
    candidate_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${TAG}/${candidate_file}"
    info "Trying ${candidate_file}..."
    if curl -fsSL "$candidate_url" -o "${TMP_DIR}/${candidate_file}" 2>/dev/null; then
        ok "Selected artifact ${candidate_file}"
        SELECTED_ASSET_BASENAME="$candidate"
        SELECTED_ASSET_FILE="$candidate_file"
        break
    else
        warn "Artifact ${candidate_file} is unavailable for ${TAG}, trying fallback"
    fi
done

[[ -n "$SELECTED_ASSET_BASENAME" ]] || fail "No compatible release artifact found for ${ASSET_ARCH} in ${TAG} (tried: ${ASSET_CANDIDATES[*]})"

tar -xzf "${TMP_DIR}/${SELECTED_ASSET_FILE}" -C "$TMP_DIR"
NEW_BINARY="${TMP_DIR}/${SELECTED_ASSET_BASENAME}"
[[ -f "$NEW_BINARY" ]] || fail "Extracted binary not found in artifact"
chmod +x "$NEW_BINARY"

info "Validating binary compatibility with this CPU..."
set +e
"$NEW_BINARY" "/tmp/mtproto-proxy-update-check-does-not-exist.toml" >/dev/null 2>&1
BINARY_CHECK_RC=$?
set -e

if [[ "$BINARY_CHECK_RC" -eq 132 ]]; then
    fail "Downloaded artifact (${SELECTED_ASSET_FILE}) is incompatible with this CPU (illegal instruction)."
fi

info "Downloading deploy scripts and service from ${TAG}..."
for file in install.sh update.sh update_dns.sh ipv6-hop.sh setup_masking.sh setup_nfqws.sh capture_template.py mtproto-proxy.service; do
    curl -fsSL "${RAW_BASE}/${file}" -o "${TMP_DIR}/${file}" || fail "Failed to download ${file}"
done

if curl -fsSL "${RAW_BASE}/setup_mask_monitor.sh" -o "${TMP_DIR}/setup_mask_monitor.sh"; then
    ok "Downloaded setup_mask_monitor.sh"
else
    warn "setup_mask_monitor.sh is missing in ${TAG}, keeping existing local copy if present"
fi

if curl -fsSL "${RAW_BASE}/setup_tunnel.sh" -o "${TMP_DIR}/setup_tunnel.sh"; then
    ok "Downloaded setup_tunnel.sh"
else
    warn "setup_tunnel.sh is missing in ${TAG}, keeping existing local copy if present"
fi

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
if [[ -f "${TMP_DIR}/setup_mask_monitor.sh" ]]; then
    install -m 0755 "${TMP_DIR}/setup_mask_monitor.sh" "${INSTALL_DIR}/setup_mask_monitor.sh"
fi
install -m 0755 "${TMP_DIR}/setup_nfqws.sh" "${INSTALL_DIR}/setup_nfqws.sh"
if [[ -f "${TMP_DIR}/setup_tunnel.sh" ]]; then
    install -m 0755 "${TMP_DIR}/setup_tunnel.sh" "${INSTALL_DIR}/setup_tunnel.sh"
fi
install -m 0644 "${TMP_DIR}/capture_template.py" "${INSTALL_DIR}/capture_template.py"

if [[ "$FORCE_SERVICE_UPDATE" == "1" ]]; then
    warn "FORCE_SERVICE_UPDATE=1: replacing ${SERVICE_FILE} from release"
    install -m 0644 "${TMP_DIR}/mtproto-proxy.service" "$SERVICE_FILE"
elif is_tunnel_service_unit "$SERVICE_FILE"; then
    warn "Detected tunnel-aware service unit; preserving existing ${SERVICE_FILE}"
    warn "Run with FORCE_SERVICE_UPDATE=1 if you intentionally want to overwrite it"
else
    install -m 0644 "${TMP_DIR}/mtproto-proxy.service" "$SERVICE_FILE"
fi
systemctl daemon-reload

# Fix permissions up in case config or dir was modified as root
chown -R mtproto:mtproto "$INSTALL_DIR" 2>/dev/null || true

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

if [[ -x "${INSTALL_DIR}/setup_mask_monitor.sh" ]]; then
    info "Applying masking monitor setup..."
    if bash "${INSTALL_DIR}/setup_mask_monitor.sh" --quiet; then
        ok "Masking monitor setup applied"
    else
        warn "Masking monitor setup failed"
    fi
fi

echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Update completed${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${DIM}Version:${RESET}   ${TAG}"
echo -e "  ${DIM}Arch:${RESET}      ${ASSET_ARCH}"
echo -e "  ${DIM}Artifact:${RESET}  ${SELECTED_ASSET_FILE}"
echo -e "  ${DIM}Status:${RESET}    systemctl status ${SERVICE_NAME} --no-pager"
echo -e "  ${DIM}Logs:${RESET}      journalctl -u ${SERVICE_NAME} -f"
if [[ -n "$BACKUP_BINARY" ]]; then
    echo -e "  ${DIM}Backup:${RESET}    ${BACKUP_BINARY}"
fi
echo ""
