GO ?= go
BIN_DIR ?= bin

.PHONY: fmt install-git-hooks test test-acme-e2e build build-sandboxd build-toolboxd docs-install docs-dev docs-build clean \
	integration-local integration-single integration-cluster-mixed integration-cluster-hetero integration-all integration-reap

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

# Integration test harness (see integration-tests/README.md). These provision
# REAL AWS via the prod TF module against isolated state — they cost money and
# need creds + integration-tests/scenarios/domains.yml. The suite itself is
# behind the `integration` build tag, so `make test` above never touches AWS.
integration-local:
	integration-tests/run.sh local-mode

integration-single:
	integration-tests/run.sh single-node

integration-cluster-mixed:
	integration-tests/run.sh cluster-3-mixed

integration-cluster-hetero:
	# Every hetero node runs On-Demand (spot = false in cluster-hetero.tfvars):
	# the bare-metal Firecracker box alone exceeds the account Spot vCPU quota,
	# so --metal-on-demand is unnecessary here.
	integration-tests/run.sh cluster-hetero

integration-all:
	integration-tests/run.sh all

# Cost safety net: terminate leaked itest instances past their ttl.
integration-reap:
	scripts/integration-reap.sh