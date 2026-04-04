#!/bin/bash
# IPv6 Address Hopping for MTProto Proxy
#
# Rotates the IPv6 address used by the proxy when called.
# ТСПУ can't ban /64 subnets (breaks too much legitimate traffic).
# With TTL=30s on DNS, clients pick up the new address within 30 seconds.
#
# Usage:
#   ./ipv6-hop.sh                  # rotate to a new random IPv6
#   ./ipv6-hop.sh --check          # print current status
#   ./ipv6-hop.sh --auto           # loop forever, rotate on ban detection
#
# Setup:
#   1. Set CLOUDFLARE_TOKEN and CF_ZONE_ID below (or export them as env vars)
#   2. Set DNS_NAME to your proxy domain
#   3. crontab -e → add: */5 * * * * /opt/mtproto-proxy/ipv6-hop.sh --auto
#
# Requirements: curl, ip, jq

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────
IPV6_PREFIX="2a01:48a0:4301:bf"   # Your /64 prefix (no trailing ::)
INTERFACE="eth0"
DNS_NAME="proxy.xxcipherx.ru"
CLOUDFLARE_TOKEN="${CF_TOKEN:-}"   # export CF_TOKEN=your_token
CF_ZONE_ID="${CF_ZONE:-}"          # export CF_ZONE=your_zone_id
STATE_FILE="/tmp/mtproto-ipv6-current"
LOG_FILE="/var/log/mtproto-ipv6-hop.log"
PROXY_SERVICE="mtproto-proxy"
BAN_THRESHOLD=10   # Rotate if >N "Handshake timeout" in last 60 seconds
# ─────────────────────────────────────────────────────────────────

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

# Generate a random IPv6 in our /64
random_ipv6() {
    local a b c d
    a=$(printf '%04x' $((RANDOM * RANDOM % 65536)))
    b=$(printf '%04x' $((RANDOM * RANDOM % 65536)))
    c=$(printf '%04x' $((RANDOM * RANDOM % 65536)))
    d=$(printf '%04x' $((RANDOM * RANDOM % 65536)))
    echo "${IPV6_PREFIX}:${a}:${b}:${c}:${d}"
}

# Remove old virtual IPv6 address (if any)
remove_old_ipv6() {
    if [[ -f "$STATE_FILE" ]]; then
        local old_ip
        old_ip=$(cat "$STATE_FILE")
        if ip -6 addr show dev "$INTERFACE" | grep -q "$old_ip"; then
            ip -6 addr del "${old_ip}/64" dev "$INTERFACE" 2>/dev/null || true
            log "Removed old IPv6: $old_ip"
        fi
    fi
}

# Add a new random IPv6 to the interface
add_new_ipv6() {
    local new_ip
    new_ip=$(random_ipv6)
    ip -6 addr add "${new_ip}/64" dev "$INTERFACE"
    echo "$new_ip" > "$STATE_FILE"
    log "Added new IPv6: $new_ip"
    echo "$new_ip"
}

# Update Cloudflare DNS AAAA record
update_dns() {
    local new_ip="$1"

    if [[ -z "$CLOUDFLARE_TOKEN" || -z "$CF_ZONE_ID" ]]; then
        log "WARNING: CF_TOKEN or CF_ZONE not set — skipping DNS update"
        log "  Set:  export CF_TOKEN=<your_cloudflare_api_token>"
        log "  Set:  export CF_ZONE=<your_zone_id>"
        return 0
    fi

    # Get existing AAAA record ID
    local record_id
    record_id=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?type=AAAA&name=${DNS_NAME}" \
        -H "Authorization: Bearer ${CLOUDFLARE_TOKEN}" \
        -H "Content-Type: application/json" \
        | jq -r '.result[0].id // empty')

    if [[ -z "$record_id" ]]; then
        # Create new record
        curl -s -X POST \
            "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
            -H "Authorization: Bearer ${CLOUDFLARE_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"AAAA\",\"name\":\"${DNS_NAME}\",\"content\":\"${new_ip}\",\"ttl\":30,\"proxied\":false}" \
            > /dev/null
        log "DNS AAAA record created: ${DNS_NAME} → ${new_ip}"
    else
        # Update existing record
        curl -s -X PUT \
            "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${record_id}" \
            -H "Authorization: Bearer ${CLOUDFLARE_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "{\"type\":\"AAAA\",\"name\":\"${DNS_NAME}\",\"content\":\"${new_ip}\",\"ttl\":30,\"proxied\":false}" \
            > /dev/null
        log "DNS AAAA record updated: ${DNS_NAME} → ${new_ip}"
    fi
}

# Reload proxy to also bind on new IPv6
reload_proxy() {
    # Our proxy binds on [::]:443 which covers all IPv6 addresses automatically
    # No restart needed — the OS will route new IPv6 connections to our socket
    log "Proxy is listening on [::]:443 — no restart needed"
}

# Check if we're likely banned (many Handshake timeouts in recent logs)
is_likely_banned() {
    local recent_timeouts
    recent_timeouts=$(journalctl -u "$PROXY_SERVICE" --since "60 seconds ago" --no-pager -q 2>/dev/null \
        | grep -c "Handshake timeout" || true)
    [[ "$recent_timeouts" -ge "$BAN_THRESHOLD" ]]
}

# ── Main ──────────────────────────────────────────────────────────

case "${1:-}" in
    --check)
        echo "Current IPv6: $(cat "$STATE_FILE" 2>/dev/null || echo 'none')"
        echo "Recent Handshake timeouts: $(journalctl -u "$PROXY_SERVICE" --since "60 seconds ago" --no-pager -q 2>/dev/null | grep -c "Handshake timeout" || echo 0)"
        exit 0
        ;;

    --auto)
        log "Auto-hop mode started (ban threshold: ${BAN_THRESHOLD} timeouts/60s)"
        while true; do
            if is_likely_banned; then
                log "Ban detected — rotating IPv6..."
                remove_old_ipv6
                new_ip=$(add_new_ipv6)
                update_dns "$new_ip"
                reload_proxy
                log "Hop complete. Sleeping 60s before next check."
                sleep 60
            else
                sleep 15
            fi
        done
        ;;

    *)
        # Manual rotation
        log "Manual IPv6 rotation triggered"
        remove_old_ipv6
        new_ip=$(add_new_ipv6)
        update_dns "$new_ip"
        reload_proxy
        log "Done. New IPv6: $new_ip"
        ;;
esac
