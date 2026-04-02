# mtproto.zig — multi-stage image (Zig from ziglang.org, glibc on Debian).
#
# Build (see README "Docker image" for --platform and build-args):
#   docker build -t mtproto-zig .
#   docker build --platform linux/amd64 --build-arg ZIG_VERSION=0.15.2 -t mtproto-zig .
#
# Run:
#   docker run --rm -p 8443:8443 -v "$PWD/config.toml:/etc/mtproto-proxy/config.toml:ro" mtproto-zig

ARG ZIG_VERSION=0.15.2

FROM debian:bookworm-slim AS builder
ARG ZIG_VERSION
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && case "$TARGETARCH" in \
        amd64)  ZIG_ARCH=x86_64 ;; \
        arm64)  ZIG_ARCH=aarch64 ;; \
        *)      echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
       esac \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz \
    && tar -xJf /tmp/zig.tar.xz -C /usr/local \
    && mv "/usr/local/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /usr/local/zig \
    && ln -sf /usr/local/zig/zig /usr/local/bin/zig \
    && rm -f /tmp/zig.tar.xz

WORKDIR /build

COPY build.zig ./
COPY src ./src

RUN zig build -Doptimize=ReleaseFast

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/mtproto-proxy /usr/local/bin/mtproto-proxy

WORKDIR /etc/mtproto-proxy

COPY config.toml.example /usr/share/doc/mtproto-proxy/config.toml.example

EXPOSE 443/tcp

ENTRYPOINT ["/usr/local/bin/mtproto-proxy"]
CMD ["/etc/mtproto-proxy/config.toml"]
