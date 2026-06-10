#!/bin/sh
# Docker entrypoint for mtproto-proxy.
#
# The image deliberately does NOT bake config.toml.example (which ships public,
# well-known access secrets) as the live config — that would let any DPI active
# prober complete the handshake with a published secret and fingerprint the host.
# Instead, on first start with no config present, generate one with a RANDOM
# per-container user secret. Mount your own /etc/mtproto-proxy/config.toml to
# override.
set -e

CONFIG="${1:-/etc/mtproto-proxy/config.toml}"

if [ ! -f "$CONFIG" ]; then
    SECRET="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    mkdir -p "$(dirname "$CONFIG")"
    cat > "$CONFIG" <<EOF
# Auto-generated on first container start. Mount your own config.toml to override.
[server]
port = 443

[censorship]
tls_domain = "google.com"
mask = true

[access.users]
user1 = "$SECRET"
EOF
    chmod 0640 "$CONFIG" 2>/dev/null || true
    # Don't echo the secret into the container log stream by default (json-file/journald/
    # CloudWatch persist it, exposing the access secret to anyone with log-read access).
    # Print where to find it; opt in to echoing it with MTPROTO_PRINT_SECRET=1.
    if [ "${MTPROTO_PRINT_SECRET:-0}" = "1" ]; then
        echo "mtproto-proxy: generated $CONFIG with a random user1 secret: $SECRET" >&2
    else
        echo "mtproto-proxy: generated $CONFIG with a random user1 secret. View it with: grep user1 $CONFIG (or set MTPROTO_PRINT_SECRET=1 to print it here)." >&2
    fi
fi

exec /usr/local/bin/mtproto-proxy "$CONFIG"
