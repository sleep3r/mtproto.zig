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
PINNED_MINISIGN_PUBKEY="RWT8YwmUuq/3WpUnYJjD6rAfQugYdZKWr61U3O+2kdNvriLSyrvVU/NO"
MINISIGN_PUBKEY="${MTPROTO_MINISIGN_PUBKEY:-$PINNED_MINISIGN_PUBKEY}"
INSECURE_MODE="${MTPROTO_INSECURE:-0}"

FORWARD_ARGS=()
for arg in "$@"; do
  if [ "$arg" = "--insecure" ]; then
    INSECURE_MODE=1
  fi
  FORWARD_ARGS+=("$arg")
done

case "${INSECURE_MODE,,}" in
  1|true|yes|on) INSECURE_MODE=1 ;;
  *) INSECURE_MODE=0 ;;
esac

# ── colour helpers ────────────────────────────────────────────────
Y='\033[0;33m'; G='\033[0;32m'; R='\033[0;31m'; N='\033[0m'
ok()   { printf "  ${G}✔${N} %s\n" "$*" >&2; }
fail() { printf "  ${R}✖${N} %s\n" "$*" >&2; exit 1; }
step() { printf "  ${Y}●${N} %s...\n" "$*" >&2; }

[ "$(id -u)" = "0" ] || fail "Run as root: sudo bash bootstrap.sh"

# ── detect arch ───────────────────────────────────────────────────
cpu_supports_x86_64_v3() {
  local flags
  flags="$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null || true)"
  [ -n "$flags" ] || return 1

  local required=(avx2 bmi1 bmi2 fma f16c movbe sse4_1 sse4_2 ssse3 popcnt aes)
  local feat
  for feat in "${required[@]}"; do
    if ! grep -Eq "(^|[[:space:]:])${feat}([[:space:]]|$)" <<< "$flags"; then
      return 1
    fi
  done

  if ! grep -Eq "(^|[[:space:]:])(lzcnt|abm)([[:space:]]|$)" <<< "$flags"; then
    return 1
  fi

  return 0
}

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)
    # try v3+aes first; fall back at runtime if unsupported
    if cpu_supports_x86_64_v3; then
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
  local tar_name="${artifact}.tar.gz"
  local sha_name="${tar_name}.sha256"
  local url="https://github.com/${REPO}/releases/download/${TAG}/${tar_name}"
  local sha_url="https://github.com/${REPO}/releases/download/${TAG}/${sha_name}"
  step "Downloading $artifact"
  curl -fsSL "$url" -o "$TMP/${tar_name}" || fail "Download failed: $url"
  curl -fsSL "$sha_url" -o "$TMP/${sha_name}" || fail "Checksum download failed: $sha_url"
  if [ "$INSECURE_MODE" != "1" ]; then
    local sig_name="${sha_name}.minisig"
    local sig_url="https://github.com/${REPO}/releases/download/${TAG}/${sig_name}"
    curl -fsSL "$sig_url" -o "$TMP/${sig_name}" || fail "Signature download failed: $sig_url"
    if ! command -v minisign >/dev/null 2>&1; then
      fail "minisign is required for signature verification (use --insecure or MTPROTO_INSECURE=1 to bypass)"
    fi
    step "Verifying signature for $artifact"
    minisign -V -q -m "$TMP/${sha_name}" -x "$TMP/${sig_name}" -P "$MINISIGN_PUBKEY" \
      || fail "Signature verification failed: $sha_name"
  else
    step "INSECURE mode: skipping minisign signature verification"
  fi

  step "Verifying checksum for $artifact"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMP" && sha256sum -c "${sha_name}" >/dev/null) || fail "Checksum verification failed: $artifact"
  elif command -v shasum >/dev/null 2>&1; then
    local expected actual
    expected="$(awk '{print $1}' "$TMP/${sha_name}" | head -n1)"
    [ -n "$expected" ] || fail "Malformed checksum file: ${sha_name}"
    actual="$(shasum -a 256 "$TMP/${tar_name}" | awk '{print $1}')"
    [ "$expected" = "$actual" ] || fail "Checksum verification failed: $artifact"
  else
    fail "Neither sha256sum nor shasum is available for checksum verification"
  fi

  tar xzf "$TMP/${tar_name}" -C "$TMP"
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
if [ "${#FORWARD_ARGS[@]}" -gt 0 ]; then
  exec mtbuddy "${FORWARD_ARGS[@]}"
else
  mtbuddy --help
fi
