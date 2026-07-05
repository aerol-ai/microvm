GO ?= go
BIN_DIR ?= bin

.PHONY: fmt install-git-hooks test test-acme-e2e build build-sandboxd build-toolboxd docs-install docs-dev docs-build clean \
	integration-local integration-single integration-single-wasm integration-cluster-mixed integration-cluster-mixed-wasm \
	integration-cluster-mixed-fc integration-cluster-hetero integration-cluster-hetero-safe \
	integration-benchmark integration-benchmark-only integration-benchmark-fc integration-benchmark-fc-only \
	integration-benchmark-wasm integration-benchmark-wasm-only \
	integration-single-fc integration-arm64 integration-arm64-single integration-arm64-cluster integration-all integration-collect-logs integration-destroy integration-reap \
	integration-cert-store-init

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
#
# Two ways to pass run.sh flags. `make` eats anything starting with `--` as its
# OWN option (so `make ... --keep` errors before the recipe runs), so we accept
# bare words instead and add the dashes for you:
#   make integration-cluster-hetero keep                # -> run.sh ... --keep
#   make integration-cluster-hetero keep prod-tls       # -> ... --keep --prod-tls
# The explicit form still works if you prefer it:
#   make integration-cluster-hetero FLAGS=--keep
# Supported words: keep (leave infra up), prod-tls (real Let's Encrypt),
# metal-on-demand (force firecracker bare-metal off spot),
# no-disruptive (skip node-kill UCs on cluster-hetero).
FLAGS ?=
INTEGRATION_FLAG_WORDS := keep prod-tls metal-on-demand no-disruptive
RUN_EXTRA := $(filter $(INTEGRATION_FLAG_WORDS),$(MAKECMDGOALS))
RUN_FLAGS := $(strip $(FLAGS) $(patsubst %,--%,$(RUN_EXTRA)))
# Swallow the bare flag-words as no-op goals so `make` doesn't try to build them
# ("No rule to make target 'keep'").
ifneq ($(RUN_EXTRA),)
.PHONY: $(RUN_EXTRA)
$(foreach w,$(RUN_EXTRA),$(eval $(w): ; @:))
endif
# One-time (per operator/account) bootstrap of the PERSISTENT cross-run Caddy
# cert bucket + a stable encryption key in config/secrets.yml. After this, every
# domain-bearing scenario REUSES a leased-domain's wildcard cert across runs
# instead of re-issuing it against Let's Encrypt. Idempotent; safe to re-run.
integration-cert-store-init:
	integration-tests/lib/provision.sh cert-store-init

integration-local:
	integration-tests/run.sh local-mode $(RUN_FLAGS)

integration-single:
	integration-tests/run.sh single-node $(RUN_FLAGS)

# Single-node with the WASM runtime enabled (wasm.enabled + staged standard
# modules, driven entirely by the `wasm` capability in single-node-wasm.caps.yml).
# Smallest scenario that exercises the wasm-runtime use cases.
integration-single-wasm:
	integration-tests/run.sh single-node-wasm $(RUN_FLAGS)

integration-cluster-mixed:
	integration-tests/run.sh cluster-3-mixed $(RUN_FLAGS)

# 3× mixed cluster with the WASM runtime enabled — pairs the wasm-runtime use
# cases with cluster placement/forwarding (see cluster-3-mixed-wasm.caps.yml).
integration-cluster-mixed-wasm:
	integration-tests/run.sh cluster-3-mixed-wasm $(RUN_FLAGS)

# 3× mixed cluster with Firecracker on the seed c5.metal node — same domain/TLS,
# Raft, forwarding, and shared Caddy cert shape as integration-cluster-mixed, but
# exercises firecracker placement through a multi-node cluster (cheaper than hetero).
integration-cluster-mixed-fc:
	integration-tests/run.sh cluster-3-mixed-fc $(RUN_FLAGS)

integration-cluster-hetero:
	# Every hetero node runs On-Demand (spot = false in cluster-hetero.tfvars):
	# the bare-metal Firecracker box alone exceeds the account Spot vCPU quota,
	# so --metal-on-demand is unnecessary here. Disruptive failover tests
	# (UC-58b) run by default; use integration-cluster-hetero-safe to skip them.
	integration-tests/run.sh cluster-hetero $(RUN_FLAGS)

# Same as integration-cluster-hetero but skips node-kill / failover fault injection.
integration-cluster-hetero-safe:
	integration-tests/run.sh cluster-hetero --no-disruptive $(RUN_FLAGS)

# Create benchmark (UC-94 create latency + UC-95 fleet density). Provisions
# cluster-hetero, runs the suite WITH the benchmark turned on (AEROL_BENCH=1 is
# the master switch — the bench is dormant otherwise), writes the JSON artifact,
# and tears down. Benchmark runs skip disruptive failover tests by default so
# `keep` leaves a usable cluster for repeat bench-only runs. Override the artifact
# path with BENCH_OUT=. See integration-tests/README.md.
#   make integration-benchmark
#   make integration-benchmark keep
#   make integration-benchmark BENCH_OUT=/tmp/bench.json
BENCH_OUT ?= integration-tests/reports/cluster-hetero-bench.json
integration-benchmark:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(BENCH_OUT) \
		integration-tests/run.sh cluster-hetero --no-disruptive $(RUN_FLAGS)

# Re-run UC-94/UC-95 only against a cluster left up with `keep` (no reprovision).
#   make integration-benchmark-only
#   make integration-benchmark-only BENCH_OUT=/tmp/bench.json
integration-benchmark-only:
	AEROL_BENCH_OUT=$(BENCH_OUT) \
		integration-tests/run.sh cluster-hetero --bench-only

# Firecracker-focused benchmark on the 3× mixed-fc cluster: provisions
# cluster-3-mixed-fc with domain/TLS, runs the full suite with UC-94 (docker +
# firecracker latency) and UC-95 (docker density). Narrow UC-94 to firecracker
# only with AEROL_BENCH_RUNTIMES=firecracker (UC-95 will skip in that case).
#   make integration-benchmark-fc
#   make integration-benchmark-fc keep
#   make integration-benchmark-fc FC_BENCH_OUT=/tmp/fc-bench.json
FC_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-fc-bench.json
integration-benchmark-fc:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(FC_BENCH_OUT) \
		integration-tests/run.sh cluster-3-mixed-fc --no-disruptive $(RUN_FLAGS)

# Re-run UC-94/UC-95 only against a cluster-3-mixed-fc left up with `keep`.
integration-benchmark-fc-only:
	AEROL_BENCH_OUT=$(FC_BENCH_OUT) \
		integration-tests/run.sh cluster-3-mixed-fc --bench-only

# WASM-focused benchmark on the 3× mixed-wasm cluster: provisions
# cluster-3-mixed-wasm with domain/TLS, runs the full suite with UC-94 (docker +
# wasm latency) and UC-95 (docker density). Pool depth defaults to 2 at provision
# time so UC-94 measures warm wasm hits without overloading small nodes (override
# with AEROL_WASM_POOL_DEPTH). Narrow UC-94 to wasm only with
# AEROL_BENCH_RUNTIMES=wasm (UC-95 will skip in that case).
#   make integration-benchmark-wasm
#   make integration-benchmark-wasm keep
#   make integration-benchmark-wasm WASM_BENCH_OUT=/tmp/wasm-bench.json
WASM_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-wasm-bench.json
WASM_BENCH_SAMPLES ?= 10
integration-benchmark-wasm:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(WASM_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(WASM_BENCH_SAMPLES) \
	AEROL_WASM_POOL_DEPTH=$(if $(AEROL_WASM_POOL_DEPTH),$(AEROL_WASM_POOL_DEPTH),2) \
		integration-tests/run.sh cluster-3-mixed-wasm --no-disruptive $(RUN_FLAGS)

# Re-run UC-94/UC-95 only against a cluster-3-mixed-wasm left up with `keep`.
integration-benchmark-wasm-only:
	AEROL_BENCH_OUT=$(WASM_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(WASM_BENCH_SAMPLES) \
		integration-tests/run.sh cluster-3-mixed-wasm --bench-only

# Single-node x86 Firecracker on bare metal (c5.metal). Smallest scenario that
# exercises the firecracker use cases (UC-24/47-50) without the full hetero
# cluster. On-Demand only (the metal box exceeds the Spot vCPU quota).
integration-single-fc:
	integration-tests/run.sh single-node-fc $(RUN_FLAGS)

integration-arm64-single:
	integration-tests/run.sh single-node-fc-arm64 $(RUN_FLAGS)

integration-arm64-cluster:
	integration-tests/run.sh cluster-arm64 $(RUN_FLAGS)

integration-arm64: integration-arm64-single integration-arm64-cluster

integration-all:
	integration-tests/run.sh all $(RUN_FLAGS)

# Collect full per-node forensics (bootstrap + cluster-init/join logs, rendered
# cluster.env, listening ports, seed reachability probe, cluster membership view,
# sandboxd + caddy journals) from an ALREADY-RUNNING scenario brought up with
# `run.sh <scenario> --keep`. No apply, no teardown. Defaults to cluster-hetero.
#   make integration-collect-logs                       # cluster-hetero
#   make integration-collect-logs SCENARIO=cluster-3-mixed
integration-collect-logs:
	integration-tests/run.sh --collect-logs-only '$(or $(SCENARIO),cluster-hetero)'

# Full teardown of a scenario brought up with `keep` — runs terraform destroy
# (VPC, S3, IAM, instances) and clears the isolated state. This is the REAL
# cleanup; integration-reap only terminates EC2 instances. Defaults to
# cluster-hetero; override with SCENARIO=.
#   make integration-destroy
#   make integration-destroy SCENARIO=cluster-3-mixed
integration-destroy:
	integration-tests/run.sh --destroy-only '$(or $(SCENARIO),cluster-hetero)'

# Cost safety net: terminate leaked itest instances past their ttl. Faster than
# integration-destroy but instance-only — leaves VPC/S3/IAM + TF state behind.
integration-reap:
	scripts/integration-reap.sh
