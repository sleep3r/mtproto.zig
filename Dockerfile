# mtproto.zig — multi-stage image (Zig from ziglang.org, glibc on Debian).
#
# Build (see README "Docker image" for --platform and build-args):
#   docker build -t mtproto-zig .
#   docker build --platform linux/amd64 --build-arg ZIG_VERSION=0.16.0 -t mtproto-zig .
#
# Run (default config from image listens on 443; override with a volume for production):
#   docker run --rm -p 443:443 mtproto-zig
#   docker run --rm -p 443:443 -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" mtproto-zig
# To use 8443, set server.port = 8443 in config.toml and run with -p 8443:8443 or manipulate the port mapping like
# -p 48443:8443

ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256=

# CPU profiles, one per published architecture. Every relayed byte goes through AES-CTR
# twice, so a build that misses std's hardware-AES backend relays with the bitsliced
# software one and becomes CPU-bound under load. `zig build-obj -mcpu <profile>` with a
# comptime assert on std.crypto.core.aes.has_hardware_support is what qualifies these two
# strings; ci.yml re-runs that assert on exactly these lines so neither can regress.
#
#   amd64: `+aes` alone is NOT enough — std/crypto/aes.zig selects the AES-NI backend only
#          when the target has aes AND avx, and the x86_64 baseline model carries neither
#          (`aes` depends on sse2 only). x86_64+aes+avx is the most conservative pair that
#          turns it on: AES-NI is Westmere (2010), AVX is Sandy Bridge (2011), so it stays
#          below the x86_64_v3 (Haswell/AVX2) bar the release artifacts use.
#   arm64: aarch64's `generic` model carries `fuse_aes` — a scheduling hint, not the `aes`
#          feature — so the default build has no hardware AES either. `generic+aes` requires
#          the ARMv8 crypto extensions, which every ARM server part has (Graviton, Ampere,
#          Neoverse, Apple) but Cortex-A72 (Raspberry Pi 4) does not; build with
#          `--build-arg ZIG_CPU_ARM64=generic` there.
ARG ZIG_CPU_AMD64=x86_64+aes+avx
ARG ZIG_CPU_ARM64=generic+aes

FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS builder
ARG ZIG_VERSION
ARG ZIG_SHA256
ARG TARGETARCH
ARG BUILDARCH
ARG ZIG_CPU_AMD64
ARG ZIG_CPU_ARM64

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && if [ -z "$BUILDARCH" ]; then \
        BUILDARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"; \
       fi \
    # Per-arch known-good SHA256 for the default ZIG_VERSION (0.16.0). The Zig
    # toolchain tarball is ALWAYS checksum-verified — a compromised mirror/CDN
    # can't slip in a backdoored compiler. Override ZIG_SHA256 if you bump
    # ZIG_VERSION via --build-arg.
    && case "$BUILDARCH" in \
        amd64|x86_64)  ZIG_ARCH=x86_64;  ZIG_SHA256_DEFAULT=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00 ;; \
        arm64|aarch64) ZIG_ARCH=aarch64; ZIG_SHA256_DEFAULT=ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17 ;; \
        *)      echo "unsupported BUILDARCH=$BUILDARCH" >&2; exit 1 ;; \
       esac \
    && ZIG_SHA256="${ZIG_SHA256:-$ZIG_SHA256_DEFAULT}" \
    && curl -fsSL --retry 5 --retry-delay 2 --retry-connrefused \
        "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz \
    && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/zig.tar.xz -C /usr/local \
    && mv "/usr/local/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /usr/local/zig \
    && ln -sf /usr/local/zig/zig /usr/local/bin/zig \
    && rm -f /tmp/zig.tar.xz

WORKDIR /build

COPY build.zig build.zig.zon ./
COPY src ./src
COPY deploy ./deploy

RUN set -eu \
    && arch="${TARGETARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}" \
    && case "$arch" in \
        amd64|x86_64) \
            target="x86_64-linux"; \
            cpu="$ZIG_CPU_AMD64"; \
            ;; \
        arm64|aarch64) \
            target="aarch64-linux"; \
            cpu="$ZIG_CPU_ARM64"; \
            ;; \
        *) \
            echo "unsupported TARGETARCH=$arch" >&2; \
            exit 1; \
            ;; \
       esac \
    && if [ -n "$cpu" ]; then \
         zig build -Doptimize=ReleaseFast -Dtarget="$target" -Dcpu="$cpu"; \
       else \
         zig build -Doptimize=ReleaseFast -Dtarget="$target"; \
       fi

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/mtproto-proxy /usr/local/bin/mtproto-proxy
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
RUN groupadd --gid 10001 mtproto \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mtproto \
    && mkdir -p /etc/mtproto-proxy \
    && chown mtproto:mtproto /etc/mtproto-proxy \
    && setcap cap_net_bind_service=+ep /usr/local/bin/mtproto-proxy

WORKDIR /etc/mtproto-proxy

# Ship the example as documentation only. The entrypoint generates a config with
# a RANDOM secret on first start when none is mounted — never bake the example's
# publicly-known access secrets as the live config (that would defeat active-probe
# resistance for everyone running the image unchanged).
COPY config.toml.example /usr/share/doc/mtproto-proxy/config.toml.example

VOLUME ["/etc/mtproto-proxy"]
USER 10001:10001
# Process liveness only; enable/scrape the configured metrics /healthz endpoint for
# event-loop health. Metrics is optional, so the image must not require port 9400.
HEALTHCHECK --interval=30s --timeout=3s CMD kill -0 1 || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/etc/mtproto-proxy/config.toml"]
