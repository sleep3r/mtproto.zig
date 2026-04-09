.PHONY: build release run test bench soak clean fmt deploy update-server deploy-monitor monitor capacity-probe-idle capacity-probe-active stability-check stability-check-load release-manual

SERVER ?= 185.125.46.60
CONFIG ?= config.toml
HOST   ?= 127.0.0.1
PORT   ?= 443
PID    ?=

# ── local dev ─────────────────────────────────────────────────────────────────

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

# ── server ops ────────────────────────────────────────────────────────────────

# Push a freshly-built binary to the server (dev iteration).
# Production servers use: buddy update
deploy:
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux -Dcpu=x86_64_v3
	ssh root@$(SERVER) 'systemctl stop mtproto-proxy || true'
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	-if [ -f $(CONFIG) ]; then scp $(CONFIG) root@$(SERVER):/opt/mtproto-proxy/config.toml; fi
	-if [ -f .env ]; then \
		awk '{print "export " $$0}' .env > .env.tmp; \
		scp .env.tmp root@$(SERVER):/opt/mtproto-proxy/env.sh; \
		ssh root@$(SERVER) 'chmod 600 /opt/mtproto-proxy/env.sh'; \
		rm .env.tmp; \
	fi
	ssh root@$(SERVER) 'chown -R mtproto:mtproto /opt/mtproto-proxy/'
	ssh root@$(SERVER) 'systemctl start mtproto-proxy && systemctl status mtproto-proxy --no-pager'

# Update server via buddy (preferred)
update-server:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make update-server SERVER=<ip> [VERSION=vX.Y.Z]"; exit 1; fi
	@if [ -n "$(VERSION)" ]; then \
		ssh root@$(SERVER) 'buddy update --version $(VERSION)'; \
	else \
		ssh root@$(SERVER) 'buddy update'; \
	fi

# Deploy monitoring dashboard
deploy-monitor:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make deploy-monitor SERVER=<ip>"; exit 1; fi
	ssh root@$(SERVER) 'mkdir -p /opt/mtproto-proxy/monitor/static'
	scp deploy/monitor/server.py root@$(SERVER):/opt/mtproto-proxy/monitor/static/../server.py
	scp deploy/monitor/static/index.html deploy/monitor/static/style.css deploy/monitor/static/app.js root@$(SERVER):/opt/mtproto-proxy/monitor/static/
	ssh root@$(SERVER) 'bash -s' < deploy/monitor/install.sh

# Open SSH tunnel to monitoring dashboard
monitor:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make monitor SERVER=<ip>"; exit 1; fi
	@echo "Opening tunnel → http://localhost:61208"
	ssh -L 61208:localhost:61208 root@$(SERVER)

# ── testing ───────────────────────────────────────────────────────────────────

stability-check:
	@if [ -z "$(PID)" ]; then echo "Usage: make stability-check PID=<pid> [HOST=127.0.0.1 PORT=443]"; exit 1; fi
	python3 test/connection_stability_check.py --host $(HOST) --port $(PORT) --pid $(PID) --idle-cycles 5

stability-check-load:
	python3 test/connection_stability_check.py --host $(HOST) --port $(PORT)

capacity-probe-idle:
	python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode idle

capacity-probe-active:
	python3 test/capacity_connections_probe.py --profile mtproto.zig --traffic-mode tls-auth

# ── release ───────────────────────────────────────────────────────────────────

release-manual:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release-manual VERSION=v1.2.3"; exit 1; fi
	@if git rev-parse "$(VERSION)" >/dev/null 2>&1; then echo "Tag $(VERSION) already exists"; exit 1; fi
	git tag "$(VERSION)"
	git push origin "$(VERSION)"
	gh release create "$(VERSION)" --title "$(VERSION)" --generate-notes
