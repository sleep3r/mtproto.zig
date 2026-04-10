#!/usr/bin/env bash
# bootstrap.sh — download and run mtbuddy, the mtproto.zig installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash
#   curl -fsSL .../bootstrap.sh | sudo bash -s -- install --port 443 --domain wb.ru --yes
#   curl -fsSL .../bootstrap.sh | sudo bash -s -- --interactive
#
# After bootstrap, mtbuddy lives at /usr/local/bin/mtbuddy and can be called directly.

set -euo pipefail

REPO="sleep3r/mtproto.zig"
INSTALL_TO="/usr/local/bin/mtbuddy"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── colour helpers ────────────────────────────────────────────────
Y='\033[0;33m'; G='\033[0;32m'; R='\033[0;31m'; N='\033[0m'
ok()   { printf "  ${G}✔${N} %s\n" "$*" >&2; }
fail() { printf "  ${R}✖${N} %s\n" "$*" >&2; exit 1; }
step() { printf "  ${Y}●${N} %s...\n" "$*" >&2; }

[ "$(id -u)" = "0" ] || fail "Run as root: sudo bash bootstrap.sh"

# ── detect arch ───────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)
    # try v3 first (requires AVX2/BMI2); fall back at runtime if unsupported
    if grep -q 'avx2' /proc/cpuinfo 2>/dev/null; then
      ARTIFACT="mtbuddy-linux-x86_64_v3"
      ARTIFACT_FALLBACK="mtbuddy-linux-x86_64"
    else
      ARTIFACT="mtbuddy-linux-x86_64"
      ARTIFACT_FALLBACK=""
    fi
    ;;
  aarch64)
    ARTIFACT="mtbuddy-linux-aarch64"
    ARTIFACT_FALLBACK=""
    ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

# ── resolve latest tag ────────────────────────────────────────────
step "Fetching latest release"
TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')"
[ -n "$TAG" ] || fail "Could not resolve latest release tag"
ok "Latest release: $TAG"

# ── download helper ───────────────────────────────────────────────
download_artifact() {
  local artifact="$1"
  local url="https://github.com/${REPO}/releases/download/${TAG}/${artifact}.tar.gz"
  step "Downloading $artifact"
  curl -fsSL "$url" -o "$TMP/mtbuddy.tar.gz" || fail "Download failed: $url"
  tar xzf "$TMP/mtbuddy.tar.gz" -C "$TMP"
  echo "$TMP/$artifact"
}

# ── download ──────────────────────────────────────────────────────
BUDDY_BIN="$(download_artifact "$ARTIFACT")"
[ -f "$BUDDY_BIN" ] || fail "Binary not found in archive: $ARTIFACT"

# ── validate; fall back to base build if v3 illegal-instructions ─
if ! "$BUDDY_BIN" --version > /dev/null 2>&1; then
  if [ -n "$ARTIFACT_FALLBACK" ]; then
    step "CPU does not support v3 build, falling back to $ARTIFACT_FALLBACK"
    ARTIFACT="$ARTIFACT_FALLBACK"
    BUDDY_BIN="$(download_artifact "$ARTIFACT")"
    [ -f "$BUDDY_BIN" ] || fail "Binary not found in archive: $ARTIFACT"
    "$BUDDY_BIN" --version > /dev/null 2>&1 || fail "Binary validation failed"
  else
    fail "Binary validation failed"
  fi
fi

# ── install ───────────────────────────────────────────────────────
install -m 0755 "$BUDDY_BIN" "$INSTALL_TO"
ok "mtbuddy installed → $INSTALL_TO"

# ── run with forwarded args ───────────────────────────────────────
if [ $# -gt 0 ]; then
  exec mtbuddy "$@"
else
  mtbuddy --help
fi
