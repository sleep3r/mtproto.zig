.PHONY: build release run test clean fmt deploy

SERVER ?= 185.125.46.60
CONFIG ?= config.toml

build:
	zig build

release:
	zig build -Doptimize=ReleaseFast

run:
	zig build run -- $(CONFIG)

test:
	zig build test

fmt:
	zig fmt src/

clean:
	rm -rf .zig-cache zig-out

deploy:
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
	ssh root@$(SERVER) 'systemctl stop mtproto-proxy || true'
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	scp deploy/ipv6-hop.sh root@$(SERVER):/opt/mtproto-proxy/
	ssh root@$(SERVER) 'chmod +x /opt/mtproto-proxy/ipv6-hop.sh'
	-if [ -f .env ]; then \
		awk '{print "export " $$0}' .env > .env.tmp_deploy; \
		scp .env.tmp_deploy root@$(SERVER):/opt/mtproto-proxy/env.sh; \
		ssh root@$(SERVER) 'chmod 600 /opt/mtproto-proxy/env.sh'; \
		rm .env.tmp_deploy; \
	fi
	ssh root@$(SERVER) 'systemctl start mtproto-proxy && systemctl status mtproto-proxy --no-pager'
