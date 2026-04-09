.PHONY: help deploy update-server deploy-monitor monitor test-stability test-capacity release

SERVER ?= 185.125.46.60
CONFIG ?= config.toml
PORT   ?= 443

.DEFAULT_GOAL := help

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── server ops ────────────────────────────────────────────────────────────────

deploy: ## Build and push binary directly to server (dev iteration)
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3
	ssh root@$(SERVER) 'systemctl stop mtproto-proxy || true'
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	-@if [ -f $(CONFIG) ]; then scp $(CONFIG) root@$(SERVER):/opt/mtproto-proxy/config.toml; fi
	-@if [ -f .env ]; then \
		awk '{print "export " $$0}' .env > .env.tmp && \
		scp .env.tmp root@$(SERVER):/opt/mtproto-proxy/env.sh && \
		ssh root@$(SERVER) 'chmod 600 /opt/mtproto-proxy/env.sh' && \
		rm .env.tmp; \
	fi
	ssh root@$(SERVER) 'chown -R mtproto:mtproto /opt/mtproto-proxy/ && systemctl start mtproto-proxy'

update: ## Trigger mtbuddy update on the server (Usage: make update SERVER=<ip> [VERSION=vX.Y.Z])
	@if [ -z "$(SERVER)" ]; echo "Usage: make update SERVER=<ip> [VERSION=...]" && exit 1; fi
	ssh root@$(SERVER) 'mtbuddy update $(if $(VERSION),--version $(VERSION),)'

deploy-monitor: ## Upload and install the monitoring dashboard
	@if [ -z "$(SERVER)" ]; echo "Usage: make deploy-monitor SERVER=<ip>" && exit 1; fi
	ssh root@$(SERVER) 'mkdir -p /opt/mtproto-proxy/monitor/static'
	scp deploy/monitor/server.py deploy/monitor/install.sh root@$(SERVER):/opt/mtproto-proxy/monitor/
	scp deploy/monitor/static/index.html deploy/monitor/static/style.css deploy/monitor/static/app.js root@$(SERVER):/opt/mtproto-proxy/monitor/static/
	ssh root@$(SERVER) 'cd /opt/mtproto-proxy/monitor && bash install.sh'

monitor: ## Open SSH tunnel to the monitoring dashboard
	@if [ -z "$(SERVER)" ]; echo "Usage: make monitor SERVER=<ip>" && exit 1; fi
	@echo "Opening tunnel → http://localhost:61208"
	ssh -L 61208:localhost:61208 root@$(SERVER)

# ── testing ───────────────────────────────────────────────────────────────────

test-stability: ## Run stability tests (Usage: make test-stability [PID=<pid>])
	@if [ -z "$(PID)" ]; then \
		echo "Running active stability check..."; \
		python3 test/connection_stability_check.py --host 127.0.0.1 --port $(PORT); \
	else \
		echo "Running idle stability check on PID $(PID)..."; \
		python3 test/connection_stability_check.py --host 127.0.0.1 --port $(PORT) --pid $(PID) --idle-cycles 5; \
	fi

test-capacity: ## Run capacity probes (Usage: make test-capacity [MODE=idle|tls-auth])
	@MODE="$(if $(MODE),$(MODE),idle)"; \
	echo "Running capacity probe in $$MODE mode..."; \
	python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode $$MODE

# ── release ───────────────────────────────────────────────────────────────────

release: ## Create and push a new GitHub release (Usage: make release VERSION=vX.Y.Z)
	@if [ -z "$(VERSION)" ]; echo "Usage: make release VERSION=v1.2.3" && exit 1; fi
	@if git rev-parse "$(VERSION)" >/dev/null 2>&1; then echo "Tag $(VERSION) already exists"; exit 1; fi
	git tag "$(VERSION)"
	git push origin "$(VERSION)"
	gh release create "$(VERSION)" --title "$(VERSION)" --generate-notes
