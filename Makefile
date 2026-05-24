GO ?= go
BIN_DIR ?= bin

.PHONY: fmt install-git-hooks test test-acme-e2e build build-sandboxd build-toolboxd docs-install docs-dev docs-build clean

fmt:
	$(GO) fmt ./...

install-git-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit
	@printf '%s\n' 'Installed git hooks from .githooks/'

test:
	$(GO) test ./...

# Operator-runnable ACME end-to-end test. Requires a local Docker daemon;
# pulls Pebble + localstack images and builds Caddy via xcaddy on first run.
# Not wired into CI — gated by the e2e build tag.
test-acme-e2e:
	$(GO) test -tags=e2e -count=1 -timeout=10m ./internal/service -run TestACME

build: build-sandboxd build-toolboxd

build-sandboxd:
	mkdir -p $(BIN_DIR)
	$(GO) build -ldflags "-X github.com/aerol-ai/microvm/internal/version.Version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o $(BIN_DIR)/sandboxd ./cmd/sandboxd

build-toolboxd:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -ldflags "-X github.com/aerol-ai/microvm/internal/version.Version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o $(BIN_DIR)/toolboxd ./cmd/toolboxd

docs-install:
	cd docs && npm install

docs-dev:
	cd docs && npm run dev

docs-build:
	cd docs && npm run build

clean:
	rm -rf $(BIN_DIR)