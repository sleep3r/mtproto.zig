#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$ROOT/test/installer-e2e/Dockerfile"
LOG_DIR="${MTPROTO_INSTALLER_E2E_LOG_DIR:-$ROOT/test/installer-e2e/logs}"
IMAGES="${MTPROTO_INSTALLER_E2E_IMAGES:-debian:11 debian:12 ubuntu:20.04 ubuntu:22.04 ubuntu:24.04}"
VERSION="${MTPROTO_INSTALLER_E2E_VERSION:-latest}"
PORT="${MTPROTO_INSTALLER_E2E_PORT:-443}"
# Default to the shipped installer default (rutube.ru), not the domain the installer
# now warns against (wb.ru). The verify curl is domain-agnostic (-k + --resolve forces
# the local nginx on 127.0.0.1:8443 regardless of SNI/Host), so this stays green.
DOMAIN="${MTPROTO_INSTALLER_E2E_DOMAIN:-rutube.ru}"
SECRET="${MTPROTO_INSTALLER_E2E_SECRET:-00112233445566778899aabbccddeeff}"

mkdir -p "$LOG_DIR"

ACTIVE_CONTAINERS=()

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

docker_arch() {
  local arch
  arch="$(docker info --format '{{.Architecture}}')"
  case "$arch" in
    x86_64|amd64) echo "x86_64-linux-musl" ;;
    aarch64|arm64) echo "aarch64-linux-musl" ;;
    *)
      echo "unsupported docker architecture: $arch" >&2
      exit 2
      ;;
  esac
}

safe_name() {
  printf '%s' "$1" | tr '/:.' '---' | tr -cd 'A-Za-z0-9_-'
}

wait_for_systemd() {
  local container="$1"
  local state=""
  for _ in $(seq 1 90); do
    state="$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)"
    case "$state" in
      running|degraded)
        return 0
        ;;
    esac
    sleep 1
  done

  echo "systemd did not become ready in $container (last state: ${state:-unknown})" >&2
  docker exec "$container" journalctl -xb --no-pager -n 200 >&2 || true
  return 1
}

dump_container_debug() {
  local container="$1"
  local prefix="$2"

  docker logs "$container" >"$LOG_DIR/$prefix.docker.log" 2>&1 || true
  docker exec "$container" journalctl --no-pager -n 300 >"$LOG_DIR/$prefix.journal.log" 2>&1 || true
  docker exec "$container" bash -lc 'systemctl --failed --no-pager || true' >"$LOG_DIR/$prefix.systemd-failed.log" 2>&1 || true
  docker exec "$container" bash -lc 'iptables -t mangle -S || true; ip6tables -t mangle -S || true' >"$LOG_DIR/$prefix.iptables.log" 2>&1 || true
  docker exec "$container" bash -lc 'ip -4 rule show || true; ip -4 route show table 200 || true; cat /run/mtproto-proxy/tunnel-pool.state 2>/dev/null || true; systemctl status mtproto-proxy mtproto-tunnel-pool.service mtproto-tunnel-pool.timer --no-pager || true' >"$LOG_DIR/$prefix.tunnel.log" 2>&1 || true
  docker exec "$container" bash -lc 'ss -lntp || true' >"$LOG_DIR/$prefix.ss.log" 2>&1 || true
}

register_container() {
  ACTIVE_CONTAINERS+=("$1:$2")
}

unregister_container() {
  local container="$1"
  local entry
  local next=()
  for entry in "${ACTIVE_CONTAINERS[@]}"; do
    if [[ "${entry%%:*}" != "$container" ]]; then
      next+=("$entry")
    fi
  done
  ACTIVE_CONTAINERS=("${next[@]}")
}

cleanup_containers() {
  local entry
  local container
  local prefix
  for entry in "${ACTIVE_CONTAINERS[@]}"; do
    container="${entry%%:*}"
    prefix="${entry#*:}"
    if docker inspect "$container" >/dev/null 2>&1; then
      dump_container_debug "$container" "$prefix"
      docker rm -f "$container" >/dev/null 2>&1 || true
    fi
  done
}

trap cleanup_containers EXIT

run_in_container() {
  local container="$1"
  shift
  docker exec \
    -e DEBIAN_FRONTEND=noninteractive \
    -e LANG=C.UTF-8 \
    -e LC_ALL=C.UTF-8 \
    -e PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$container" "$@"
}

run_script_in_container() {
  local container="$1"
  docker exec -i \
    -e DEBIAN_FRONTEND=noninteractive \
    -e LANG=C.UTF-8 \
    -e LC_ALL=C.UTF-8 \
    -e PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$container" bash -s
}

verify_install_once() {
  local container="$1"

  run_in_container "$container" bash -lc '
    set -Eeuo pipefail

    test -x /usr/local/bin/mtbuddy
    test "$(readlink -f /usr/bin/mtbuddy)" = /usr/local/bin/mtbuddy
    command -v mtbuddy >/dev/null

    # The release is downloaded with signature verification, so minisign MUST have been
    # acquired (apt package, or the pinned upstream fallback on hosts like Ubuntu 20.04
    # whose apt has no minisign). A missing minisign here would mean the install fell
    # through to an unsigned / fail-open path.
    command -v minisign >/dev/null

    test -x /opt/mtproto-proxy/mtproto-proxy
    test -f /opt/mtproto-proxy/config.toml
    test -x /opt/zapret/nfq/nfqws
    test -L /etc/nginx/sites-enabled/mtproto-masking

    for unit in mtproto-proxy nginx nfqws-mtproto mtproto-mask-health.timer; do
      systemctl is-active --quiet "$unit"
      systemctl is-enabled --quiet "$unit"
    done

    nfq_count="$(iptables -t mangle -S OUTPUT | grep -c -- "--queue-num 200" || true)"
    test "$nfq_count" = "1"
    iptables -t mangle -S OUTPUT | grep -- "--sport 443" | grep -- "--queue-num 200" >/dev/null

    ss -lnt "( sport = :443 or sport = :8443 )" | grep ":443" >/dev/null
    ss -lnt "( sport = :443 or sport = :8443 )" | grep "127.0.0.1:8443" >/dev/null
    curl -kfsS --resolve "wb.ru:8443:127.0.0.1" https://wb.ru:8443/ >/dev/null
  '
}

install_fake_tunnel_tools() {
  local container="$1"

  run_script_in_container "$container" <<'CONTAINER_SCRIPT'
set -Eeuo pipefail

real_curl="$(command -v curl)"
if [[ "$real_curl" == "/usr/local/bin/curl" ]]; then
  real_curl="/usr/bin/curl"
fi
test -x "$real_curl"

cat >/usr/local/bin/awg-quick <<'AWG_QUICK'
#!/usr/bin/env bash
set -Eeuo pipefail

cmd="${1:-}"
case "$cmd" in
  strip)
    cat "${2:?missing config}"
    ;;
  up)
    conf="${2:?missing config}"
    iface="$(basename "$conf" .conf)"
    ip link show dev "$iface" >/dev/null 2>&1 || ip link add "$iface" type dummy 2>/dev/null || ip link add "$iface" type veth peer name "${iface}-peer"
    ip link set dev "$iface" up
    ip link set dev "${iface}-peer" up 2>/dev/null || true
    ;;
  down)
    conf="${2:?missing config}"
    iface="$(basename "$conf" .conf)"
    ip link del dev "$iface" 2>/dev/null || true
    ;;
  *)
    exit 0
    ;;
esac
AWG_QUICK
chmod 0755 /usr/local/bin/awg-quick

cat >/usr/local/bin/awg <<'AWG'
#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${1:-}" == "show" ]]; then
  iface="${2:-awg0}"
  ip link show dev "$iface" >/dev/null 2>&1 || exit 1
  cat <<EOF
interface: $iface
  public key: fake-public-key
  private key: (hidden)
  listening port: 51820

peer: fake-peer-key
  endpoint: 203.0.113.1:51820
  allowed ips: 0.0.0.0/0
  latest handshake: 1 second ago
  transfer: 1 KiB received, 1 KiB sent
EOF
  exit 0
fi

exit 0
AWG
chmod 0755 /usr/local/bin/awg

cat >/usr/local/bin/curl <<CURL
#!/usr/bin/env bash
set -Eeuo pipefail

next_is_iface=0
for arg in "\$@"; do
  if [[ "\$next_is_iface" == "1" ]]; then
    if [[ "\$arg" == "awg0" ]]; then
      echo "blocked fake tunnel probe: \$*" >>/run/mtproto-fake-curl.log
      exit 7
    fi
    if [[ "\$arg" == "awg1" ]]; then
      echo "healthy fake tunnel probe: \$*" >>/run/mtproto-fake-curl.log
      exit 0
    fi
    next_is_iface=0
    continue
  fi

  if [[ "\$arg" == "--interface" ]]; then
    next_is_iface=1
  fi
done

exec "$real_curl" "\$@"
CURL
chmod 0755 /usr/local/bin/curl
CONTAINER_SCRIPT
}

verify_tunnel_probe_failure_is_nonfatal() {
  local container="$1"

  run_script_in_container "$container" <<'CONTAINER_SCRIPT'
set -Eeuo pipefail

cat >/tmp/awg0.conf <<'AWG_CONF'
[Interface]
PrivateKey = fake-private-key
Address = 10.123.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = fake-peer-key
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
AWG_CONF

mtbuddy setup tunnel --iface awg0 /tmp/awg0.conf

systemctl is-active --quiet mtproto-proxy
systemctl is-active --quiet mtproto-tunnel-pool.timer
systemctl is-enabled --quiet mtproto-tunnel-pool.timer

# The tunnel unit runs the routing setup privileged (ExecStartPre=+...) while the
# proxy itself drops to User=mtproto, so the prefix is part of the expected line.
grep -F "ExecStartPre=+/usr/local/bin/setup_tunnel.sh" /etc/systemd/system/mtproto-proxy.service >/dev/null
grep -F "User=mtproto" /etc/systemd/system/mtproto-proxy.service >/dev/null
test -x /usr/local/bin/setup_tunnel.sh

/usr/local/bin/setup_tunnel.sh
# Single tunnel whose Telegram probe fails: still selected (don't go dark), but marked
# degraded so the operator knows the probe couldn't confirm reachability.
grep -F "active=awg0" /run/mtproto-proxy/tunnel-pool.state >/dev/null
grep -F "status=degraded" /run/mtproto-proxy/tunnel-pool.state >/dev/null
grep -F "reason=up; Telegram probe failed (fallback)" /run/mtproto-proxy/tunnel-pool.state >/dev/null
grep -F "blocked fake tunnel probe:" /run/mtproto-fake-curl.log >/dev/null

ip -4 rule show | grep -E "fwmark (0xc8|200).*(lookup|table) 200" >/dev/null
ip -4 route get 149.154.175.50 mark 200 | grep -F " dev awg0" >/dev/null
CONTAINER_SCRIPT
}

# Pool failover: with awg0 (Telegram probe BLOCKED) already active and degraded, adding a
# second tunnel awg1 whose probe SUCCEEDS must fail the pool over to awg1. Before the fix
# the controller kept the first up interface (awg0) and never switched.
verify_tunnel_pool_failover() {
  local container="$1"

  run_script_in_container "$container" <<'CONTAINER_SCRIPT'
set -Eeuo pipefail

cat >/tmp/awg1.conf <<'AWG_CONF'
[Interface]
PrivateKey = fake-private-key-1
Address = 10.123.1.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = fake-peer-key-1
Endpoint = 203.0.113.2:51820
AllowedIPs = 0.0.0.0/0
AWG_CONF

mtbuddy setup tunnel --iface awg1 /tmp/awg1.conf

# Pool is now [awg0 (probe blocked), awg1 (probe ok)] with priority-auto. The controller
# must skip the dead-but-up awg0 and select awg1.
/usr/local/bin/setup_tunnel.sh
grep -F "active=awg1" /run/mtproto-proxy/tunnel-pool.state >/dev/null
grep -F "status=healthy" /run/mtproto-proxy/tunnel-pool.state >/dev/null
grep -F "healthy fake tunnel probe:" /run/mtproto-fake-curl.log >/dev/null
ip -4 route get 149.154.175.50 mark 200 | grep -F " dev awg1" >/dev/null

# And when awg1 also goes unreachable, fall back (no healthy tunnel) rather than error out.
# (awg1 stays up; only its probe would need to fail — covered by the single-tunnel case.)
CONTAINER_SCRIPT
}

# Uninstall must remove every artifact AND do it without spewing expected-failure noise
# (stop/disable of absent units, flushing an absent table 200, deleting an absent netns).
verify_uninstall() {
  local container="$1"

  run_script_in_container "$container" <<'CONTAINER_SCRIPT'
set -Eeuo pipefail

out="$(mtbuddy uninstall --yes 2>&1)"
printf '%s\n' "$out"

fail=0
# No leftover artifacts (proxy, egress, tunnel pool, the binary itself).
for f in \
  /opt/mtproto-proxy \
  /etc/systemd/system/mtproto-proxy.service \
  /etc/systemd/system/mtproto-singbox-egress.service \
  /etc/systemd/system/mtproto-tunnel-pool.timer \
  /etc/systemd/system/mtproto-tunnel-pool.service \
  /etc/systemd/system/mtproto-proxy.service.d \
  /usr/local/bin/setup_tunnel.sh \
  /usr/local/bin/sing-box \
  /usr/local/bin/mtproto-singbox-route.sh \
  /usr/local/bin/mtbuddy ; do
  if [ -e "$f" ]; then echo "FAIL: leftover $f"; fail=1; fi
done

# No mtproto unit files registered with systemd anymore.
leftover_units="$(systemctl list-unit-files 2>/dev/null | grep -E "mtproto-(proxy|singbox|tunnel-pool|mask)" || true)"
if [ -n "$leftover_units" ]; then
  echo "FAIL: mtproto unit files still registered:"; printf '%s\n' "$leftover_units"; fail=1
fi

# The output must be clean — no expected-failure noise from a normal uninstall.
if printf '%s\n' "$out" | grep -qE "Failed to (stop|disable)|Unit .* not loaded|RTNETLINK|FIB table does not exist|Cannot remove namespace"; then
  echo "FAIL: noisy uninstall output (expected-failure messages leaked)"; fail=1
fi

[ "$fail" -eq 0 ] || exit 1
echo "uninstall: clean, no leftovers"
CONTAINER_SCRIPT
}

verify_install() {
  local container="$1"
  local attempt

  for attempt in $(seq 1 30); do
    if verify_install_once "$container"; then
      return 0
    fi
    echo "verification attempt $attempt failed; retrying..."
    sleep 1
  done

  run_in_container "$container" bash -lc '
    set +e
    for unit in mtproto-proxy nginx nfqws-mtproto mtproto-mask-health.timer; do
      echo "unit:$unit active=$(systemctl is-active "$unit" 2>/dev/null) enabled=$(systemctl is-enabled "$unit" 2>/dev/null)"
    done
    iptables -t mangle -S OUTPUT || true
    ss -lntp "( sport = :443 or sport = :8443 )" || true
    ls -l /usr/local/bin/mtbuddy /usr/bin/mtbuddy /opt/mtproto-proxy/mtproto-proxy /opt/zapret/nfq/nfqws /etc/nginx/sites-enabled/mtproto-masking 2>/dev/null || true
  ' >&2 || true
  return 1
}

run_case() {
  local base_image="$1"
  local safe
  local image_tag
  local container

  safe="$(safe_name "$base_image")"
  image_tag="mtproto-installer-e2e:$safe"
  container="mtproto-installer-e2e-$safe-$$"

  echo "::group::Build systemd image ($base_image)"
  docker build \
    --build-arg "BASE_IMAGE=$base_image" \
    -f "$DOCKERFILE" \
    -t "$image_tag" \
    "$ROOT/test/installer-e2e"
  echo "::endgroup::"

  echo "::group::Start systemd container ($base_image)"
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker run -d \
    --name "$container" \
    --privileged \
    --cgroupns=host \
    --tmpfs /run \
    --tmpfs /run/lock \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    "$image_tag" >/dev/null
  register_container "$container" "$safe"
  wait_for_systemd "$container"
  echo "::endgroup::"

  echo "::group::Install local mtbuddy ($base_image)"
  docker cp "$ROOT/zig-out/bin/mtbuddy" "$container:/tmp/mtbuddy"
  run_in_container "$container" bash -lc '
    set -Eeuo pipefail
    install -m 0755 /tmp/mtbuddy /usr/local/bin/mtbuddy
    ln -sf /usr/local/bin/mtbuddy /usr/bin/mtbuddy
    mtbuddy --version
    sha256sum /usr/local/bin/mtbuddy
  ' | tee "$LOG_DIR/$safe.mtbuddy.log"
  echo "::endgroup::"

  echo "::group::Run mtbuddy install ($base_image)"
  run_in_container "$container" \
    mtbuddy install \
      --port "$PORT" \
      --domain "$DOMAIN" \
      --secret "$SECRET" \
      --version "$VERSION" \
      --yes \
    2>&1 | tee "$LOG_DIR/$safe.install.log"
  echo "::endgroup::"

  echo "::group::Verify install ($base_image)"
  verify_install "$container" 2>&1 | tee "$LOG_DIR/$safe.verify.log"
  echo "::endgroup::"

  echo "::group::Re-run nfqws setup ($base_image)"
  run_in_container "$container" mtbuddy setup nfqws 2>&1 | tee "$LOG_DIR/$safe.nfqws-rerun.log"
  verify_install "$container" 2>&1 | tee "$LOG_DIR/$safe.verify-after-nfqws-rerun.log"
  echo "::endgroup::"

  echo "::group::Setup tunnel with failing Telegram probe ($base_image)"
  install_fake_tunnel_tools "$container"
  verify_tunnel_probe_failure_is_nonfatal "$container" 2>&1 | tee "$LOG_DIR/$safe.tunnel-probe-failure.log"
  echo "::endgroup::"

  echo "::group::Tunnel pool failover to a healthy tunnel ($base_image)"
  verify_tunnel_pool_failover "$container" 2>&1 | tee "$LOG_DIR/$safe.tunnel-pool-failover.log"
  echo "::endgroup::"

  echo "::group::Uninstall removes everything cleanly ($base_image)"
  verify_uninstall "$container" 2>&1 | tee "$LOG_DIR/$safe.uninstall.log"
  echo "::endgroup::"

  dump_container_debug "$container" "$safe"
  docker rm -f "$container" >/dev/null 2>&1 || true
  unregister_container "$container"
}

main() {
  require_cmd docker
  require_cmd zig

  local target
  target="$(docker_arch)"
  echo "Docker architecture target: $target"
  echo "Installer release version under test: $VERSION"

  zig build -Dtarget="$target" -Doptimize=ReleaseFast

  local image
  for image in $IMAGES; do
    run_case "$image"
  done
}

main "$@"
