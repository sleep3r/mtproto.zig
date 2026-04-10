.PHONY: help build fmt test deploy

SERVER ?= mtproto.sleep3r.ru
CONFIG ?= config.toml

.DEFAULT_GOAL := help

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── local dev ─────────────────────────────────────────────────────────────────

build: ## Cross-compile proxy + mtbuddy for Linux x86_64
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3

fmt: ## Format all Zig source files
	zig fmt src/

test: ## Run unit tests
	zig build test

# ── server ops ────────────────────────────────────────────────────────────────

deploy: build ## Build and push proxy + mtbuddy to server
	ssh root@$(SERVER) 'pkill -9 -x mtproto-proxy || true; systemctl reset-failed mtproto-proxy 2>/dev/null; true'
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	scp zig-out/bin/mtbuddy root@$(SERVER):/usr/local/bin/mtbuddy
	-@if [ -f $(CONFIG) ]; then scp $(CONFIG) root@$(SERVER):/opt/mtproto-proxy/config.toml; fi
	-@if [ -f .env ]; then \
		awk '{print "export " $$0}' .env > .env.tmp && \
		scp .env.tmp root@$(SERVER):/opt/mtproto-proxy/env.sh && \
		ssh root@$(SERVER) 'chmod 600 /opt/mtproto-proxy/env.sh' && \
		rm .env.tmp; \
	fi
	ssh root@$(SERVER) 'chown -R mtproto:mtproto /opt/mtproto-proxy/ && systemctl start mtproto-proxy'
	ssh root@$(SERVER) 'if [ -f /etc/systemd/system/proxy-monitor.service ]; then mtbuddy setup dashboard --quiet; fi'

# ── dashboard ─────────────────────────────────────────────────────────────────

dashboard:
	ssh -L 61208:localhost:61208 root@$(SERVER)