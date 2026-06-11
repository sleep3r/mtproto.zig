.PHONY: help build fmt test e2e deploy

SERVER ?= mtproto.sleep3r.ru
CONFIG ?= config.toml

.DEFAULT_GOAL := help

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── local dev ─────────────────────────────────────────────────────────────────

build: ## Cross-compile proxy + mtbuddy for Linux x86_64 (AES-enabled)
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3+aes

fmt: ## Format all Zig source files
	zig fmt src/

test: ## Run unit tests
	zig build test

e2e: ## Run E2E/integration harness
	zig build e2e

# ── server ops ────────────────────────────────────────────────────────────────

deploy: build ## Build and push proxy + mtbuddy to server (binary-only; PUSH_CONFIG=1 also pushes config/env)
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/mtproto-proxy.new
	scp zig-out/bin/mtbuddy root@$(SERVER):/usr/local/bin/mtbuddy.new
	@# Config/env push is OPT-IN: by default `make deploy` ships ONLY the binary and never
	@# touches the live config/secrets. Pushing a stale or drifted local config.toml over a
	@# live deploy can break every share link (secrets/tls_domain) and the egress mode. Run
	@# `make deploy PUSH_CONFIG=1` deliberately when you intend to overwrite the remote config.
	@if [ "$(PUSH_CONFIG)" = "1" ]; then \
		if [ -f $(CONFIG) ]; then echo "PUSH_CONFIG=1: pushing $(CONFIG) -> remote config.toml"; scp $(CONFIG) root@$(SERVER):/opt/mtproto-proxy/config.toml; fi; \
		if [ -f .env ]; then \
			tmp=$$(mktemp) && awk '{print "export " $$0}' .env > "$$tmp" && \
			scp "$$tmp" root@$(SERVER):/opt/mtproto-proxy/env.sh && \
			ssh root@$(SERVER) 'chmod 600 /opt/mtproto-proxy/env.sh'; rm -f "$$tmp"; \
		fi; \
	else echo "binary-only deploy (config/env left untouched; use PUSH_CONFIG=1 to push them)"; fi
	ssh root@$(SERVER) 'install -m 0755 /opt/mtproto-proxy/mtproto-proxy.new /opt/mtproto-proxy/mtproto-proxy'
	ssh root@$(SERVER) 'install -m 0755 /usr/local/bin/mtbuddy.new /usr/local/bin/mtbuddy'
	ssh root@$(SERVER) 'chown -R mtproto:mtproto /opt/mtproto-proxy/ && systemctl restart mtproto-proxy && systemctl is-active --quiet mtproto-proxy'
	ssh root@$(SERVER) 'if [ -f /etc/systemd/system/proxy-monitor.service ]; then mtbuddy setup dashboard --quiet; fi'

# ── dashboard ─────────────────────────────────────────────────────────────────

dashboard:
	ssh -L 61208:localhost:61208 root@$(SERVER)
