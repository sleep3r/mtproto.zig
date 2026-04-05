.PHONY: build release run test bench soak clean fmt deploy migrate update-dns stability-check stability-check-load capacity-probe-idle capacity-probe-active deploy-tunnel deploy-tunnel-only

SERVER ?= 185.125.46.60
CONFIG ?= config.toml
AWG_CONF ?=
HOST ?= 127.0.0.1
PORT ?= 443
PID ?=

build:
	zig build

release:
	zig build -Doptimize=ReleaseFast

run:
	zig build run -- $(CONFIG)

test:
	zig build test

bench:
	zig build -Doptimize=ReleaseFast bench

soak:
	zig build -Doptimize=ReleaseFast soak -- --seconds=30

fmt:
	zig fmt src/

clean:
	rm -rf .zig-cache zig-out

deploy:
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
	ssh root@$(SERVER) 'systemctl stop mtproto-proxy || true'
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	scp deploy/*.sh root@$(SERVER):/opt/mtproto-proxy/
	-if [ -f $(CONFIG) ]; then \
		scp $(CONFIG) root@$(SERVER):/opt/mtproto-proxy/config.toml; \
	fi
	ssh root@$(SERVER) 'chmod +x /opt/mtproto-proxy/*.sh'
	-if [ -f .env ]; then \
		awk '{print "export " $$0}' .env > .env.tmp_deploy; \
		scp .env.tmp_deploy root@$(SERVER):/opt/mtproto-proxy/env.sh; \
		ssh root@$(SERVER) 'chmod 600 /opt/mtproto-proxy/env.sh'; \
		rm .env.tmp_deploy; \
	fi
	ssh root@$(SERVER) 'systemctl start mtproto-proxy && systemctl status mtproto-proxy --no-pager'

migrate:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make migrate SERVER=<ip> [PASSWORD=<pass>]"; exit 1; fi
	@echo "--- 1. Setting up SSH key ---"
	@if [ -n "$(PASSWORD)" ]; then \
		PUBKEY=$$(cat ~/.ssh/id_rsa.pub 2>/dev/null || cat ~/.ssh/id_ed25519.pub 2>/dev/null); \
		if [ -n "$$PUBKEY" ]; then \
			sshpass -p '$(PASSWORD)' ssh -o StrictHostKeyChecking=no root@$(SERVER) "mkdir -p ~/.ssh && echo \"$$PUBKEY\" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh" || true; \
		fi; \
	fi
	@echo "--- 2. Running bootstrap install script ---"
	ssh -o StrictHostKeyChecking=no root@$(SERVER) 'bash -s' < deploy/install.sh
	@echo "--- 3. Pushing local configuration ---"
	scp config.toml root@$(SERVER):/opt/mtproto-proxy/
	@echo "--- 4. Deploying binary & restarting ---"
	$(MAKE) deploy SERVER=$(SERVER)
	@if [ "$(UPDATE_DNS)" = "1" ] || [ "$(UPDATE_DNS)" = "true" ]; then \
		echo "--- 5. Updating Cloudflare DNS ---"; \
		$(MAKE) update-dns SERVER=$(SERVER); \
	fi
	@echo "--- MIGRATION COMPLETE ---"

# Full migration + AmneziaWG tunnel (for servers where Telegram is blocked)
deploy-tunnel:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make deploy-tunnel SERVER=<ip> AWG_CONF=<path> [PASSWORD=<pass>]"; exit 1; fi
	@if [ -z "$(AWG_CONF)" ]; then echo "AWG_CONF is required (path to AmneziaWG client config)"; exit 1; fi
	@if [ ! -f "$(AWG_CONF)" ]; then echo "AWG_CONF file not found: $(AWG_CONF)"; exit 1; fi
	$(MAKE) migrate SERVER=$(SERVER) PASSWORD=$(PASSWORD)
	@echo "--- Setting up AmneziaWG tunnel ---"
	scp $(AWG_CONF) root@$(SERVER):/tmp/awg_client.conf
	scp deploy/setup_tunnel.sh root@$(SERVER):/tmp/setup_tunnel.sh
	ssh root@$(SERVER) 'bash /tmp/setup_tunnel.sh /tmp/awg_client.conf && rm -f /tmp/awg_client.conf /tmp/setup_tunnel.sh'

# Add tunnel to existing installation
deploy-tunnel-only:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make deploy-tunnel-only SERVER=<ip> AWG_CONF=<path>"; exit 1; fi
	@if [ -z "$(AWG_CONF)" ]; then echo "AWG_CONF is required (path to AmneziaWG client config)"; exit 1; fi
	scp $(AWG_CONF) root@$(SERVER):/tmp/awg_client.conf
	scp deploy/setup_tunnel.sh root@$(SERVER):/tmp/setup_tunnel.sh
	ssh root@$(SERVER) 'bash /tmp/setup_tunnel.sh /tmp/awg_client.conf && rm -f /tmp/awg_client.conf /tmp/setup_tunnel.sh'

update-dns:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make update-dns SERVER=<ip>"; exit 1; fi
	bash deploy/update_dns.sh $(SERVER)

# Linux/VPS regression harness (memory/socket churn)
stability-check:
	@if [ -z "$(PID)" ]; then echo "Usage: make stability-check PID=<mtproto_pid> [HOST=127.0.0.1 PORT=443]"; exit 1; fi
	python3 test/connection_stability_check.py --host $(HOST) --port $(PORT) --pid $(PID) --idle-cycles 5

# Load-only mode (no /proc assertions, useful for quick local smoke)
stability-check-load:
	python3 test/connection_stability_check.py --host $(HOST) --port $(PORT)

# Capacity probe (idle sockets; FD/socket ceiling)
capacity-probe-idle:
	python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode idle

# Capacity probe (authenticated traffic; memory-efficiency comparison)
capacity-probe-active:
	python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth
