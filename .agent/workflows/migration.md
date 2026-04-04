---
description: Guide on how to migrate the MTProto proxy server
---

# Server Migration Guide

If the current VPS is permanently blocked or blacklisted by the ISP, migrating to a new VPS requires these steps to maintain seamless connectivity for clients without changing their proxy links.

## Step 1: Deploy to New VPS

Use the `install.sh` script to set up Zig, clone the proxy, compile it, and enable DPI bypass metrics (TCPMSS).
*The `--auto` mode for IPv6 hopping requires Cloudflare API credentials.*

```bash
curl -sSf https://raw.githubusercontent.com/XXcipherX/mtproto.zig/main/deploy/install.sh | ssh root@<NEW_VPS_IP> "export CF_TOKEN='...'; export CF_ZONE='...'; bash"
```

## Step 2: Migrate Configuration

It is crucial to keep the `[access.users]` secrets identical so the client connection strings (`tg://proxy?server=...&secret=...`) remain valid.

1. Copy `/opt/mtproto-proxy/config.toml` from the old server to the new one.
2. Restart the proxy on the new server.

```bash
# On the new server
systemctl restart mtproto-proxy
```

## Step 3: Update DNS Records

To ensure transparent failover without changing the immutable client link:

- Update the **A record** (`proxy.xxcipherx.ru`) to point to the new `<NEW_VPS_IP>` using the Cloudflare Dashboard or API.
- Run `/opt/mtproto-proxy/ipv6-hop.sh` on the new server to force an immediate **AAAA record** overwrite to the new server's IPv6 pool.

## Step 4: Verify Connectivity

1. Check `systemctl status mtproto-proxy`.
2. Verify that the Cloudflare DNS now resolves to the new IP addresses using `dig +short proxy.xxcipherx.ru`.
3. Telegram clients will automatically pick up the new IPs from the existing proxy link.
