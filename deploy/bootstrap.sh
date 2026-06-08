#!/usr/bin/env bash
# bootstrap.sh — download and run mtbuddy, the mtproto.zig installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sleep3r/mtproto.zig/main/deploy/bootstrap.sh | sudo bash
#   curl -fsSL .../bootstrap.sh | sudo bash -s -- install --port 443 --domain rutube.ru --yes
#   curl -fsSL .../bootstrap.sh | sudo bash -s -- --interactive
#
# After bootstrap, mtbuddy lives at /usr/local/bin/mtbuddy and can be called directly.

set -euo pipefail
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export PATH

REPO="sleep3r/mtproto.zig"
INSTALL_TO="/usr/local/bin/mtbuddy"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PINNED_MINISIGN_PUBKEY="RWT8YwmUuq/3WpUnYJjD6rAfQugYdZKWr61U3O+2kdNvriLSyrvVU/NO"
MINISIGN_PUBKEY="${MTPROTO_MINISIGN_PUBKEY:-$PINNED_MINISIGN_PUBKEY}"
MINISIGN_BOOTSTRAP_VERSION="0.12"
MINISIGN_BOOTSTRAP_SHA256="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
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

install_minisign_if_needed() {
  command -v minisign >/dev/null 2>&1 && return 0
  [ "$INSECURE_MODE" = "1" ] && return 0

  step "Installing minisign for signature verification"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
    if apt-get -o DPkg::Lock::Timeout=600 update -qq \
      && apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends minisign; then
      :
    else
      step "apt could not install minisign, using pinned upstream binary"
      install_minisign_from_upstream
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y minisign || fail "dnf could not install minisign"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y minisign || fail "yum could not install minisign"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache minisign || fail "apk could not install minisign"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm minisign || fail "pacman could not install minisign"
  else
    fail "minisign is required for signature verification, but no supported package manager was found (use --insecure or MTPROTO_INSECURE=1 to bypass)"
  fi

  command -v minisign >/dev/null 2>&1 \
    || fail "minisign is required for signature verification (use --insecure or MTPROTO_INSECURE=1 to bypass)"
  ok "minisign installed"
}

curl_try_download() {
  local out="$1"
  shift
  rm -f "$out"
  if curl "$@" -o "$out" && [ -s "$out" ]; then
    return 0
  fi
  rm -f "$out"
  return 1
}

curl_download() {
  local url="$1"
  local out="$2"
  local common=(-fsSL --connect-timeout 8 --max-time 120 --retry 1 --retry-delay 1 --speed-time 30 --speed-limit 1)

  curl_try_download "$out" "${common[@]}" "$url" && return 0
  curl_try_download "$out" -4 "${common[@]}" "$url" && return 0
  curl_try_download "$out" --http1.1 "${common[@]}" "$url" && return 0
  curl_try_download "$out" -4 --http1.1 "${common[@]}" "$url" && return 0

  return 1
}

verify_sha256_literal() {
  local file="$1"
  local expected="$2"
  local actual

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    fail "Neither sha256sum nor shasum is available for checksum verification"
  fi

  [ "$actual" = "$expected" ] || fail "Checksum verification failed: $(basename "$file")"
}

install_minisign_from_upstream() {
  local minisign_arch
  case "$(uname -m)" in
    x86_64) minisign_arch="x86_64" ;;
    aarch64) minisign_arch="aarch64" ;;
    *) fail "No pinned minisign bootstrap binary for architecture: $(uname -m)" ;;
  esac

  local archive="minisign-${MINISIGN_BOOTSTRAP_VERSION}-linux.tar.gz"
  local url="https://github.com/jedisct1/minisign/releases/download/${MINISIGN_BOOTSTRAP_VERSION}/${archive}"
  curl_download "$url" "$TMP/$archive" || fail "Download failed: $url"
  verify_sha256_literal "$TMP/$archive" "$MINISIGN_BOOTSTRAP_SHA256"
  tar xzf "$TMP/$archive" -C "$TMP" "minisign-linux/${minisign_arch}/minisign"
  install -m 0755 "$TMP/minisign-linux/${minisign_arch}/minisign" /usr/local/bin/minisign
}

install_minisign_if_needed

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
LATEST_JSON="$TMP/latest-release.json"
curl_download "https://api.github.com/repos/${REPO}/releases/latest" "$LATEST_JSON" \
  || fail "Could not fetch latest release metadata"
TAG="$(grep '"tag_name"' "$LATEST_JSON" | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')"
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
  curl_download "$url" "$TMP/${tar_name}" || fail "Download failed: $url"
  curl_download "$sha_url" "$TMP/${sha_name}" || fail "Checksum download failed: $sha_url"
  if [ "$INSECURE_MODE" != "1" ]; then
    local sig_name="${sha_name}.minisig"
    local sig_url="https://github.com/${REPO}/releases/download/${TAG}/${sig_name}"
    curl_download "$sig_url" "$TMP/${sig_name}" || fail "Signature download failed: $sig_url"
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

if ! command -v mtbuddy >/dev/null 2>&1 && [ -d /usr/bin ]; then
  if [ ! -e /usr/bin/mtbuddy ] || [ -L /usr/bin/mtbuddy ]; then
    ln -sf "$INSTALL_TO" /usr/bin/mtbuddy \
      && ok "mtbuddy linked → /usr/bin/mtbuddy"
  fi
fi

# ── run with forwarded args, or point to the one next step ────────
if [ "${#FORWARD_ARGS[@]}" -gt 0 ]; then
  exec "$INSTALL_TO" "${FORWARD_ARGS[@]}"
else
  printf '\n'
  ok "mtbuddy is installed."
  printf '\n  \033[1mOne more step — create your proxy and get a Telegram link:\033[0m\n\n'
  printf '      \033[1msudo mtbuddy install --yes\033[0m\n\n'
  printf '  Prefer a guided setup?   sudo mtbuddy --interactive\n'
  printf '  See all options:         sudo mtbuddy --help\n\n'
fi
