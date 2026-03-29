.PHONY: build run test clean fmt

# Build the proxy binary
build:
	zig build

# Build with release optimizations
release:
	zig build -Doptimize=ReleaseFast

# Run the proxy (pass CONFIG via: make run CONFIG=path/to/config.toml)
CONFIG ?= config.toml
run:
	zig build run -- $(CONFIG)

# Run unit tests
test:
	zig build test

# Remove build artifacts
clean:
	rm -rf .zig-cache zig-out

# Format all Zig source files
fmt:
	zig fmt src/

# Deploy to VPS (cross-compiles for Linux, uploads, and restarts service)
SERVER ?= 45.77.223.232
deploy: release_linux
	@echo "Deploying to $(SERVER)..."
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	ssh root@$(SERVER) 'systemctl restart mtproto-proxy && systemctl status mtproto-proxy --no-pager'

# Cross-compile for Linux (x86_64)
release_linux:
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
