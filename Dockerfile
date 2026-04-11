# mtproto.zig — multi-stage image (Zig from ziglang.org, glibc on Debian).
#
# Build (see README "Docker image" for --platform and build-args):
#   docker build -t mtproto-zig .
#   docker build --platform linux/amd64 --build-arg ZIG_VERSION=0.15.2 -t mtproto-zig .
#
# Run (default config from image listens on 443; override with a volume for production):
#   docker run --rm -p 443:443 mtproto-zig
#   docker run --rm -p 443:443 -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" mtproto-zig
# To use 8443, set server.port = 8443 in config.toml and run with -p 8443:8443 or manipulate the port mapping like
# -p 48443:8443

ARG ZIG_VERSION=0.15.2
ARG ZIG_SHA256=

FROM debian:bookworm-slim AS builder
ARG ZIG_VERSION
ARG ZIG_SHA256
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && if [ -z "$TARGETARCH" ]; then \
        TARGETARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"; \
       fi \
    && case "$TARGETARCH" in \
        amd64|x86_64)  ZIG_ARCH=x86_64 ;; \
        arm64|aarch64) ZIG_ARCH=aarch64 ;; \
        *)      echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
       esac \
    && curl -fsSL --retry 5 --retry-delay 2 --retry-connrefused \
        "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz \
    && if [ -n "$ZIG_SHA256" ]; then \
        echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c -; \
       fi \
    && tar -xJf /tmp/zig.tar.xz -C /usr/local \
    && mv "/usr/local/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /usr/local/zig \
    && ln -sf /usr/local/zig/zig /usr/local/bin/zig \
    && rm -f /tmp/zig.tar.xz

WORKDIR /build

COPY build.zig ./
COPY src ./src

RUN set -eu \
    && arch="${TARGETARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}" \
    && case "$arch" in \
        amd64|x86_64) \
            target="x86_64-linux"; \
            cpu="x86_64"; \
            ;; \
        arm64|aarch64) \
            target="aarch64-linux"; \
            cpu=""; \
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

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/mtproto-proxy /usr/local/bin/mtproto-proxy

WORKDIR /etc/mtproto-proxy

COPY config.toml.example /usr/share/doc/mtproto-proxy/config.toml.example
COPY config.toml.example /etc/mtproto-proxy/config.toml

ENTRYPOINT ["/usr/local/bin/mtproto-proxy"]
CMD ["/etc/mtproto-proxy/config.toml"]
