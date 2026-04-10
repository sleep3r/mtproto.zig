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
Y='\033[0;33m'; G='\033[0;32m'; R='\033[0;31m'; D='\033[2m'; N='\033[0m'
ok()   { printf "  ${G}✔${N} %s\n" "$*"; }
fail() { printf "  ${R}✖${N} %s\n" "$*" >&2; exit 1; }
step() { printf "  ${Y}●${N} %s...\n" "$*"; }

[ "$(id -u)" = "0" ] || fail "Run as root: sudo bash bootstrap.sh"

# ── detect arch ───────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)
    # try v3 first (AVX2/BMI2 etc); runtime validation will fall back if unsupported
    if grep -q 'avx2' /proc/cpuinfo 2>/dev/null; then
      ARTIFACT="mtproto-proxy-linux-x86_64_v3"
      ARTIFACT_FALLBACK="mtproto-proxy-linux-x86_64"
    else
      ARTIFACT="mtproto-proxy-linux-x86_64"
      ARTIFACT_FALLBACK=""
    fi
    ;;
  aarch64)
    ARTIFACT="mtproto-proxy-linux-aarch64"
    ARTIFACT_FALLBACK=""
    ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

# ── resolve latest tag ────────────────────────────────────────────
step "Fetching latest mtbuddy release"
TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')"
[ -n "$TAG" ] || fail "Could not resolve latest release tag"
ok "Latest release: $TAG"

# ── download ──────────────────────────────────────────────────────
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARTIFACT}.tar.gz"
step "Downloading $ARTIFACT"
curl -fsSL "$DOWNLOAD_URL" -o "$TMP/mtbuddy.tar.gz" \
  || fail "Download failed: $DOWNLOAD_URL"

tar xzf "$TMP/mtbuddy.tar.gz" -C "$TMP"
BUDDY_BIN="$TMP/$ARTIFACT"
[ -f "$BUDDY_BIN" ] || fail "binary not found in archive: $ARTIFACT"

# ── validate (fallback to base if v3 causes illegal instruction) ──
if ! "$BUDDY_BIN" --version > /dev/null 2>&1; then
  if [ -n "$ARTIFACT_FALLBACK" ]; then
    step "v3 binary unsupported by CPU, retrying with $ARTIFACT_FALLBACK"
    ARTIFACT="$ARTIFACT_FALLBACK"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARTIFACT}.tar.gz"
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP/mtbuddy.tar.gz" \
      || fail "Download failed: $DOWNLOAD_URL"
    tar xzf "$TMP/mtbuddy.tar.gz" -C "$TMP"
    BUDDY_BIN="$TMP/$ARTIFACT"
    [ -f "$BUDDY_BIN" ] || fail "binary not found in archive: $ARTIFACT"
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
