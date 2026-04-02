.PHONY: build release run test bench soak clean fmt deploy update-server migrate update-dns release-manual

SERVER ?= 185.125.46.60
CONFIG ?= config.toml

build:
	zig build

release:
	zig build -Doptimize=ReleaseFast

release-manual:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make release-manual VERSION=v1.2.3"; \
		exit 1; \
	fi
	@if git rev-parse "$(VERSION)" >/dev/null 2>&1; then \
		echo "Tag $(VERSION) already exists"; \
		exit 1; \
	fi
	git tag "$(VERSION)"
	git push origin "$(VERSION)"
	gh release create "$(VERSION)" --title "$(VERSION)" --generate-notes

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

update-server:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make update-server SERVER=<ip> [VERSION=vX.Y.Z]"; exit 1; fi
	@if [ -n "$(VERSION)" ]; then \
		ssh root@$(SERVER) 'bash -s -- $(VERSION)' < deploy/update.sh; \
	else \
		ssh root@$(SERVER) 'bash -s' < deploy/update.sh; \
	fi

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

update-dns:
	@if [ -z "$(SERVER)" ]; then echo "Usage: make update-dns SERVER=<ip>"; exit 1; fi
	bash deploy/update_dns.sh $(SERVER)
