#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$ROOT/test/installer-e2e/Dockerfile"
LOG_DIR="${MTPROTO_INSTALLER_E2E_LOG_DIR:-$ROOT/test/installer-e2e/logs}"
IMAGES="${MTPROTO_INSTALLER_E2E_IMAGES:-debian:12 ubuntu:24.04}"
VERSION="${MTPROTO_INSTALLER_E2E_VERSION:-latest}"
PORT="${MTPROTO_INSTALLER_E2E_PORT:-443}"
DOMAIN="${MTPROTO_INSTALLER_E2E_DOMAIN:-wb.ru}"
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

verify_install_once() {
  local container="$1"

  run_in_container "$container" bash -lc '
    set -Eeuo pipefail

    test -x /usr/local/bin/mtbuddy
    test "$(readlink -f /usr/bin/mtbuddy)" = /usr/local/bin/mtbuddy
    command -v mtbuddy >/dev/null

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
