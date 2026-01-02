.PHONY: help build test lint clean doc

# Convenience Makefile that delegates to cargo xtask
# For users who prefer `make` over `cargo xtask`

help:
	@echo "KernelLens Build System"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build-cli    Build the CLI tool"
	@echo "  build-ffi    Build the FFI library"
	@echo "  run-app      Build and run Flutter app"
	@echo "  test         Run all tests"
	@echo "  lint         Run clippy"
	@echo "  fmt          Format code"
	@echo "  doc          Generate documentation"
	@echo "  clean        Clean build artifacts"
	@echo ""
	@echo "Or use: cargo xtask <command>"

build-cli:
	cargo xtask build-cli --release

build-ffi:
	cargo xtask build-ffi --release

run-app:
	cargo xtask run-app

test:
	cargo xtask test

lint:
	cargo xtask lint

fmt:
	cargo xtask fmt

doc:
	cargo xtask doc --open

clean:
	cargo xtask clean
