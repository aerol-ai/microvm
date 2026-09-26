GO ?= go
BIN_DIR ?= bin

.PHONY: fmt install-git-hooks test test-acme-e2e build build-sandboxd build-toolboxd docs-install docs-dev docs-build clean \
	integration-local integration-single integration-single-containerd integration-single-wasm integration-single-isolate integration-cluster-mixed integration-cluster-mixed-docker integration-cluster-mixed-containerd integration-cluster-mixed-wasm \
	integration-cluster-mixed-fc integration-cluster-mixed-gvisor integration-cluster-hetero integration-cluster-hetero-safe \
	integration-cluster-mixed-obs integration-cluster-mixed-obs-only \
	integration-cluster-hetero-obs integration-cluster-hetero-obs-only integration-obs-snapshot \
	integration-benchmark integration-benchmark-only integration-benchmark-docker integration-benchmark-docker-only \
	integration-benchmark-docker-sparse \
	integration-benchmark-containerd integration-benchmark-containerd-only \
	integration-benchmark-fc integration-benchmark-fc-only \
	integration-benchmark-wasm integration-benchmark-wasm-only \
	integration-benchmark-isolate integration-benchmark-isolate-only \
	integration-benchmark-gvisor integration-benchmark-gvisor-only \
	integration-benchmark-gvisor-docker integration-benchmark-gvisor-docker-only \
	integration-single-fc integration-benchmark-fc-single integration-arm64 integration-arm64-single integration-arm64-cluster integration-all integration-collect-logs integration-destroy integration-reap \
	integration-cert-store-init integration-clear-lease \
	itest-build itest-publish itest-artifacts-init \
	integration-secrets-single integration-secrets-cluster integration-secrets-kms \
	integration-secrets-enterprise integration-secrets-hetero integration-secrets-hetero-kms \
	integration-secrets-gate integration-bench-cluster

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

# -s -w: toolboxd is bind-mounted into every sandbox and exec'd as the
# container entrypoint; a stripped binary means fewer pages to fault in on
# the first boot per host and a smaller deploy artifact. Debug symbols for
# the in-guest agent add no value — it's never debugged in place.
build-toolboxd:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -ldflags "-s -w -X github.com/aerol-ai/microvm/internal/version.Version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o $(BIN_DIR)/toolboxd ./cmd/toolboxd

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
# no-disruptive (skip node-kill UCs on cluster-hetero),
# released (provision from releases/latest instead of a local build),
# no-build (reuse the last published local build).
# A pinned tag needs a value, so it goes through the explicit form:
#   make integration-single FLAGS=--version=v0.7.21
FLAGS ?=
INTEGRATION_FLAG_WORDS := keep prod-tls metal-on-demand no-disruptive released no-build
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

# Local artifact pipeline (plans/integration-test-security.md §4). Scenarios
# build + publish on their own, so these are for iterating on the build itself
# or for pre-warming the cache before a matrix run.
#
# BUILD_FLAGS passes through to build.sh:
#   make itest-build BUILD_FLAGS="--ref main"            # UC-165 baseline arm
#   make itest-build BUILD_FLAGS="--arch amd64,arm64"
#   make itest-build BUILD_FLAGS=--with-caddy
BUILD_FLAGS ?=

# One-time (per operator/account) bootstrap of the PERSISTENT artifacts bucket
# the harness publishes locally-built binaries to. Like the cert bucket, it
# lives OUTSIDE every scenario's Terraform state so a per-scenario destroy can
# never wipe artifacts another scenario is still installing from. Idempotent.
itest-artifacts-init:
	integration-tests/lib/build.sh artifacts-init

itest-build:
	integration-tests/lib/build.sh build $(BUILD_FLAGS)

# Uploads the current build and prints the presigned tfvars on stdout, so
# `make itest-publish > /tmp/artifacts.tfvars` composes into a manual
# terraform apply. Scenarios do this for themselves.
itest-publish:
	@integration-tests/lib/build.sh publish $(BUILD_FLAGS)

# Security matrix (plans/integration-test-security.md §6.2). Cadence: the gate
# (S1→S4, ~$0.75, ~1.5h) every push; the flagship (S5+S6, ~$28, ~2h) once
# pre-merge and after any internal/cluster, fan-out or reseal change.
integration-secrets-single:
	integration-tests/run.sh single-node-secrets $(RUN_FLAGS)

integration-secrets-cluster:
	integration-tests/run.sh cluster-3-mixed-secrets $(RUN_FLAGS)

integration-secrets-kms:
	integration-tests/run.sh cluster-3-mixed-secrets-kms $(RUN_FLAGS)

integration-secrets-enterprise:
	integration-tests/run.sh cluster-3-mixed-secrets-enterprise $(RUN_FLAGS)

# S1→S4 in order, cheapest first: a red S1 means the cluster scenarios are not
# worth paying for. Sequential on purpose — they share the domain pool.
integration-secrets-gate: integration-secrets-single integration-secrets-cluster integration-secrets-kms integration-secrets-enterprise

# Flagship. 8 nodes including a c5.metal, on-demand (spot reclaim makes
# multi-node convergence flaky and metal exceeds the spot quota).
integration-secrets-hetero:
	integration-tests/run.sh cluster-hetero-secrets $(RUN_FLAGS)

integration-secrets-hetero-kms:
	integration-tests/run.sh cluster-hetero-secrets-kms $(RUN_FLAGS)

# The latency arm UC-165's band is measured against (D5: baseline is
# main-built binaries via `make itest-build BUILD_FLAGS="--ref main"`).
integration-bench-cluster:
	AEROL_BENCH=1 integration-tests/run.sh cluster-3-mixed-bench $(RUN_FLAGS)

integration-local:
	integration-tests/run.sh local-mode $(RUN_FLAGS)

integration-single:
	integration-tests/run.sh single-node $(RUN_FLAGS)

# Single-node with SB_CONTAINER_ENGINE=containerd (containerd-engine cap).
# Exercises UC-99..102 soak gates + docker UCs against the native driver.
integration-single-containerd:
	integration-tests/run.sh single-node-containerd $(RUN_FLAGS)

# Single-node with the WASM runtime enabled (wasm.enabled + staged standard
# modules, driven entirely by the `wasm` capability in single-node-wasm.caps.yml).
# Smallest scenario that exercises the wasm-runtime use cases.
integration-single-wasm:
	integration-tests/run.sh single-node-wasm $(RUN_FLAGS)

# Single-node with the V8-isolate (workerd) runtime enabled. Driven entirely by
# default_with_isolate=true in single-node-isolate.tfvars (install.sh
# --with-isolate downloads workerd + writes SB_ENABLE_ISOLATE=true) — no config
# overlay, no node-side staging. Exercises the isolate-runtime use cases
# (UC-103..105), including the per-sandbox egress-attribution proof.
integration-single-isolate:
	integration-tests/run.sh single-node-isolate $(RUN_FLAGS)

# Same box with the workerd jail ON (the daemon default): chroot + cgroup +
# privilege drop + enforcing seccomp. Runs UC-103..105 against jailed groups
# and UC-109, which inspects the workerd process over SSH. This is the gate for
# trusting the jail with untrusted tenant code (setup/runbooks/isolate-jail.md).
integration-single-isolate-jail:
	integration-tests/run.sh single-node-isolate-jail $(RUN_FLAGS)

integration-cluster-mixed:
	integration-tests/run.sh cluster-3-mixed $(RUN_FLAGS)

# 3× mixed cluster for docker-only benchmarks — same topology as
# integration-cluster-mixed but advertises `benchmark` and names artifacts
# cluster-3-mixed-docker-* (parallel to cluster-3-mixed-wasm).
integration-cluster-mixed-docker:
	integration-tests/run.sh cluster-3-mixed-docker $(RUN_FLAGS)

# 3× mixed cluster running SB_CONTAINER_ENGINE=containerd — exercises the
# containerd engine through the full cluster path (Raft placement + forwarding +
# failover) plus the Phase-5 soak gates UC-99..102, which single-node-containerd
# cannot cover (see cluster-3-mixed-containerd.caps.yml).
integration-cluster-mixed-containerd:
	integration-tests/run.sh cluster-3-mixed-containerd $(RUN_FLAGS)

# 3× mixed cluster with the WASM runtime enabled — pairs the wasm-runtime use
# cases with cluster placement/forwarding (see cluster-3-mixed-wasm.caps.yml).
integration-cluster-mixed-wasm:
	integration-tests/run.sh cluster-3-mixed-wasm $(RUN_FLAGS)

# 3× mixed cluster with Firecracker on the seed c5.metal node — same domain/TLS,
# Raft, forwarding, and shared Caddy cert shape as integration-cluster-mixed, but
# exercises firecracker placement through a multi-node cluster (cheaper than hetero).
integration-cluster-mixed-fc:
	integration-tests/run.sh cluster-3-mixed-fc $(RUN_FLAGS)

# 3× mixed cluster with gVisor on every node — same cheap t3 topology as
# integration-cluster-mixed, but runsc is installed at bootstrap so gvisor-runtime
# UCs and the gvisor benchmark row exercise placement + forwarding.
integration-cluster-mixed-gvisor:
	integration-tests/run.sh cluster-3-mixed-gvisor $(RUN_FLAGS)

# Investor-grade mixed benchmark + live Grafana (Phase 0).
# Provisions 3× t3.large on-demand + obs1; runs UC suite + AEROL_BENCH + AEROL_SIMS.
# Headline p50/p90/p99 must NOT be sourced from this t3 topology (CM-4) — mixed
# validates connectivity and screenshots only. See plans/investor-benchmark-observability.md.
MIXED_OBS_BENCH_OUT ?= integration-tests/reports/cluster-mixed-benchmark-with-obs-bench.json
MIXED_OBS_BENCH_SAMPLES ?= 10
# containerd is the fleet engine (SB_CONTAINER_ENGINE=containerd; dockerd is
# backward-compat only and NOT on the create path). Sweep containerd warm +
# containerd-cold (forced past the pool) so both hot and cold paths are reported
# under the containerd label — no docker-labeled rows.
MIXED_OBS_BENCH_RUNTIMES ?= containerd,containerd-cold,gvisor,gvisor-cold,wasm,isolate
integration-cluster-mixed-obs:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(MIXED_OBS_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(MIXED_OBS_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(MIXED_OBS_BENCH_RUNTIMES) \
	AEROL_SIMS=1 \
		integration-tests/run.sh cluster-mixed-benchmark-with-obs --no-disruptive $(RUN_FLAGS)

integration-cluster-mixed-obs-only:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(MIXED_OBS_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(MIXED_OBS_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(MIXED_OBS_BENCH_RUNTIMES) \
	AEROL_SIMS=1 \
		integration-tests/run.sh cluster-mixed-benchmark-with-obs --bench-only

# Flagship hetero soak — T7 resolved: 5×c5.metal workers (~$21/hr, ~$63–84/3–4h).
# AEROL_HETERO_OBS_T7_OK=1 acknowledges the cost; override to 0 to force refuse.
HETERO_OBS_BENCH_OUT ?= integration-tests/reports/cluster-hetero-benchmark-with-obs-bench.json
HETERO_OBS_BENCH_RUNTIMES ?= containerd,containerd-cold,gvisor,gvisor-cold,wasm,isolate,firecracker
integration-cluster-hetero-obs:
	AEROL_HETERO_OBS_T7_OK=$${AEROL_HETERO_OBS_T7_OK:-1} \
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(HETERO_OBS_BENCH_OUT) \
	AEROL_BENCH_RUNTIMES=$(HETERO_OBS_BENCH_RUNTIMES) \
	AEROL_SIMS=1 AEROL_SOAK_HOURS=$${AEROL_SOAK_HOURS:-3} \
		integration-tests/run.sh cluster-hetero-benchmark-with-obs --no-disruptive $(RUN_FLAGS)

integration-cluster-hetero-obs-only:
	AEROL_HETERO_OBS_T7_OK=$${AEROL_HETERO_OBS_T7_OK:-1} \
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(HETERO_OBS_BENCH_OUT) \
	AEROL_BENCH_RUNTIMES=$(HETERO_OBS_BENCH_RUNTIMES) \
	AEROL_SIMS=1 \
		integration-tests/run.sh cluster-hetero-benchmark-with-obs --bench-only

# Render+pull Grafana snapshots from a keep-provisioned obs stack.
integration-obs-snapshot:
	AEROL_OBS_SNAPSHOT=1 \
		integration-tests/run.sh '$(or $(SCENARIO),cluster-mixed-benchmark-with-obs)' --obs-snapshot-only

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

# Docker-focused benchmark on the 3× mixed-docker cluster: provisions
# cluster-3-mixed-docker with domain/TLS, runs the full integration suite
# (UC matrix → cluster-3-mixed-docker.json/.md) with UC-94 docker latency +
# UC-95 docker density (AEROL_BENCH_RUNTIMES=docker). Cheap t3 spot boxes.
#   make integration-benchmark-docker
#   make integration-benchmark-docker keep
#   make integration-benchmark-docker DOCKER_BENCH_OUT=/tmp/docker-bench.json
DOCKER_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-docker-bench.json
DOCKER_BENCH_SAMPLES ?= 10
# docker-cold is the pool-ineligible variant of the same runtime: with the
# warm pool on, the docker row measures warm hits and docker-cold keeps the
# cold floor visible next to it (and shows the pause-netns pool's effect).
DOCKER_BENCH_RUNTIMES ?= docker,docker-cold
# SB_NETRULES_BACKEND is node-side provisioning config the bench cannot flip
# from here. Set AEROL_BENCH_EXPECT_NETRULES=netlink (or exec) to make the
# bench FAIL unless /v1/metrics confirms the cluster actually runs that
# backend — otherwise a netlink run can silently bench exec. Empty = no check.
AEROL_BENCH_EXPECT_NETRULES ?=
integration-benchmark-docker:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(DOCKER_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(DOCKER_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(DOCKER_BENCH_RUNTIMES) \
	AEROL_BENCH_EXPECT_NETRULES=$(AEROL_BENCH_EXPECT_NETRULES) \
		integration-tests/run.sh cluster-3-mixed-docker --no-disruptive $(RUN_FLAGS)

# Re-run UC-94/UC-95 against a cluster-3-mixed-docker left up with `keep`.
integration-benchmark-docker-only:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(DOCKER_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(DOCKER_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(DOCKER_BENCH_RUNTIMES) \
	AEROL_BENCH_EXPECT_NETRULES=$(AEROL_BENCH_EXPECT_NETRULES) \
		integration-tests/run.sh cluster-3-mixed-docker --bench-only

# Sparse docker warm-create bench (plans/warm-create-latency-tier1.md Phase 2
# gate): one create per ≥15s so the image-ID TTL would expire without the
# Client-owned warm loop. Run with SB_NETRULES_BACKEND=netlink on the cluster
# to also exercise Phase 1, and AEROL_BENCH_EXPECT_NETRULES=netlink so the run
# fails instead of silently benching exec. Against a kept cluster:
#   make integration-benchmark-docker-sparse AEROL_BENCH_EXPECT_NETRULES=netlink
DOCKER_SPARSE_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-docker-sparse-bench.json
DOCKER_SPARSE_BENCH_SAMPLES ?= 8
integration-benchmark-docker-sparse:
	AEROL_BENCH=1 AEROL_BENCH_SPARSE=1 \
	AEROL_BENCH_OUT=$(DOCKER_SPARSE_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(DOCKER_SPARSE_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=docker \
	AEROL_BENCH_EXPECT_NETRULES=$(AEROL_BENCH_EXPECT_NETRULES) \
		integration-tests/run.sh cluster-3-mixed-docker --bench-only

# Containerd-engine benchmark on the 3× mixed-containerd cluster — the point of
# the docker→containerd migration: does the native containerd driver create
# faster than docker? Provisions cluster-3-mixed-containerd (domain/TLS,
# SB_CONTAINER_ENGINE=containerd) and runs UC-94 containerd latency + UC-95
# density (AEROL_BENCH_RUNTIMES=containerd; the density probe is engine-aware and
# labels its row containerd). Compare the `containerd` row's server p50 against
# the `docker-cold` row in cluster-3-mixed-docker-bench.json — both are cold
# engine creates on the same netlink egress backend + t3.medium boxes.
#   make integration-benchmark-containerd
#   make integration-benchmark-containerd keep
#   make integration-benchmark-containerd CONTAINERD_BENCH_OUT=/tmp/ctd-bench.json
CONTAINERD_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-containerd-bench.json
CONTAINERD_BENCH_SAMPLES ?= 10
CONTAINERD_BENCH_RUNTIMES ?= containerd
integration-benchmark-containerd:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(CONTAINERD_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(CONTAINERD_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(CONTAINERD_BENCH_RUNTIMES) \
	AEROL_BENCH_EXPECT_NETRULES=$(AEROL_BENCH_EXPECT_NETRULES) \
		integration-tests/run.sh cluster-3-mixed-containerd --no-disruptive $(RUN_FLAGS)

# Re-run UC-94/UC-95 against a cluster-3-mixed-containerd left up with `keep`.
integration-benchmark-containerd-only:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(CONTAINERD_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(CONTAINERD_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(CONTAINERD_BENCH_RUNTIMES) \
	AEROL_BENCH_EXPECT_NETRULES=$(AEROL_BENCH_EXPECT_NETRULES) \
		integration-tests/run.sh cluster-3-mixed-containerd --bench-only

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
# cluster-3-mixed-wasm with domain/TLS, then runs UC-94 wasm latency only
# (no full suite, no Docker sandbox creates). Pool depth defaults to 2 at
# provision time so UC-94 measures warm wasm hits (override with
# AEROL_WASM_POOL_DEPTH). UC-95 (docker density) is skipped because
# AEROL_BENCH_RUNTIMES=wasm. Add docker back with AEROL_BENCH_RUNTIMES=docker,wasm.
#   make integration-benchmark-wasm
#   make integration-benchmark-wasm keep
#   make integration-benchmark-wasm WASM_BENCH_OUT=/tmp/wasm-bench.json
WASM_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-wasm-bench.json
WASM_BENCH_SAMPLES ?= 10
WASM_BENCH_RUNTIMES ?= wasm
integration-benchmark-wasm:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(WASM_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(WASM_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(WASM_BENCH_RUNTIMES) \
	AEROL_WASM_POOL_DEPTH=$(if $(AEROL_WASM_POOL_DEPTH),$(AEROL_WASM_POOL_DEPTH),2) \
		integration-tests/run.sh cluster-3-mixed-wasm --bench-only $(RUN_FLAGS)

# Re-run UC-94/UC-95 against a cluster-3-mixed-wasm left up with `keep`.
integration-benchmark-wasm-only:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(WASM_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(WASM_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(WASM_BENCH_RUNTIMES) \
		integration-tests/run.sh cluster-3-mixed-wasm --bench-only

# V8-isolate (workerd) create-latency benchmark on the single-node-isolate box.
# Provisions single-node-isolate (t3.medium, jail off) and runs UC-94 isolate
# latency only (AEROL_BENCH_RUNTIMES=isolate). warmBenchmarkRuntimes spawns the
# tenant's workerd group once, so the samples measure the warm create path
# (isolate loaded into an already-running group). UC-95 (density) is skipped: it
# needs CapCluster, which a single node lacks. UC-94 is meaningful single-node
# (no Raft/placement/forward in the number). Add docker with
# AEROL_BENCH_RUNTIMES=docker,isolate.
#   make integration-benchmark-isolate
#   make integration-benchmark-isolate keep
#   make integration-benchmark-isolate ISOLATE_BENCH_OUT=/tmp/isolate-bench.json
ISOLATE_BENCH_OUT ?= integration-tests/reports/single-node-isolate-bench.json
ISOLATE_BENCH_SAMPLES ?= 10
ISOLATE_BENCH_RUNTIMES ?= isolate
integration-benchmark-isolate:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(ISOLATE_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(ISOLATE_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(ISOLATE_BENCH_RUNTIMES) \
		integration-tests/run.sh single-node-isolate --bench-only $(RUN_FLAGS)

# Re-run UC-94 against a single-node-isolate left up with `keep`.
integration-benchmark-isolate-only:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(ISOLATE_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(ISOLATE_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(ISOLATE_BENCH_RUNTIMES) \
		integration-tests/run.sh single-node-isolate --bench-only

# gVisor create-latency benchmark on the 3× mixed-gvisor cluster (containerd
# engine — the harness default; the scenario has no docker-engine cap, so
# runtime "gvisor" is served by the native containerd driver via the
# io.containerd.runsc.v1 shim). Provisions cluster-3-mixed-gvisor with
# domain/TLS, runs UC-94 gvisor latency only (AEROL_BENCH_RUNTIMES=gvisor →
# UC-95 density skips; it's engine-capacity-bound, not runtime-bound), writes
# the artifact, and tears down. Engine A/B twin: integration-benchmark-gvisor-docker.
# Compare against the runc rows in cluster-3-mixed-{docker,containerd}-bench.json
# (same t3.medium boxes) for the sandboxing overhead.
#   make integration-benchmark-gvisor
#   make integration-benchmark-gvisor keep
#   make integration-benchmark-gvisor GVISOR_BENCH_OUT=/tmp/gvisor-bench.json
GVISOR_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-gvisor-bench.json
GVISOR_BENCH_SAMPLES ?= 10
GVISOR_BENCH_RUNTIMES ?= gvisor
integration-benchmark-gvisor:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(GVISOR_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(GVISOR_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(GVISOR_BENCH_RUNTIMES) \
		integration-tests/run.sh cluster-3-mixed-gvisor --bench-only $(RUN_FLAGS)

# Re-run UC-94 against a cluster-3-mixed-gvisor left up with `keep`.
integration-benchmark-gvisor-only:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(GVISOR_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(GVISOR_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(GVISOR_BENCH_RUNTIMES) \
		integration-tests/run.sh cluster-3-mixed-gvisor --bench-only

# Same gvisor benchmark on the DOCKER engine (cluster-3-mixed-gvisor-docker
# carries the docker-engine cap): runsc launched through dockerd's daemon.json
# runtime registration instead of the containerd shim. Together with
# integration-benchmark-gvisor this gives the per-engine gvisor A/B on
# identical t3.medium topology.
#   make integration-benchmark-gvisor-docker
#   make integration-benchmark-gvisor-docker keep
GVISOR_DOCKER_BENCH_OUT ?= integration-tests/reports/cluster-3-mixed-gvisor-docker-bench.json
integration-benchmark-gvisor-docker:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(GVISOR_DOCKER_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(GVISOR_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(GVISOR_BENCH_RUNTIMES) \
		integration-tests/run.sh cluster-3-mixed-gvisor-docker --bench-only $(RUN_FLAGS)

# Re-run UC-94 against a cluster-3-mixed-gvisor-docker left up with `keep`.
integration-benchmark-gvisor-docker-only:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(GVISOR_DOCKER_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(GVISOR_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=$(GVISOR_BENCH_RUNTIMES) \
		integration-tests/run.sh cluster-3-mixed-gvisor-docker --bench-only

# Single-node x86 Firecracker on bare metal (c5.metal). Smallest scenario that
# exercises the firecracker use cases (UC-24/47-50) without the full hetero
# cluster. On-Demand only (the metal box exceeds the Spot vCPU quota).
integration-single-fc:
	integration-tests/run.sh single-node-fc $(RUN_FLAGS)

# Firecracker create-latency benchmark on ONE c5.metal box (single-node-fc).
# The cheap diagnostic: cluster-hetero costs 8 nodes, this costs one, and being
# single-node it isolates the FC DRIVER cost — no Raft placement or cross-node
# forward hop in the number, so the per-stage Server-Timing breakdown
# (fc_verify / fc_spawn / fc_load / fc_resume / fc_handshake / fc_post_resume)
# attributes cleanly to the driver. UC-94 firecracker only (UC-95 density skips
# because AEROL_BENCH_RUNTIMES=firecracker). Measures the COLD path (warm-VMM
# pool stays default-off); enable SB_FIRECRACKER_VMM_POOL_ENABLED on the box to
# also measure warm. Provisions On-Demand (metal exceeds Spot quota) and tears
# down on exit unless you pass `keep`.
#   make integration-benchmark-fc-single
#   make integration-benchmark-fc-single keep
#   make integration-benchmark-fc-single FC_SINGLE_BENCH_OUT=/tmp/fc-single.json
FC_SINGLE_BENCH_OUT ?= integration-tests/reports/single-node-fc-bench.json
FC_SINGLE_BENCH_SAMPLES ?= 10
integration-benchmark-fc-single:
	AEROL_BENCH=1 AEROL_BENCH_OUT=$(FC_SINGLE_BENCH_OUT) \
	AEROL_BENCH_SAMPLES=$(FC_SINGLE_BENCH_SAMPLES) \
	AEROL_BENCH_RUNTIMES=firecracker \
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
#   make integration-collect-logs SCENARIO=cluster-3-mixed-docker
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

# Reset the domain-lease STATE so the next run re-leases from the CURRENT
# domains.yml pool. Use this when a run is stuck re-picking a stale domain after
# you edit the pool. A domain is remembered in THREE places, and this clears all
# three (a --keep run reads them in this order, run.sh lease_domain_for_scenario):
#   1. .tf/.domain-lease            — last pool index (fresh runs avoid repeats)
#   2. .tf/<scenario>/.leased-domain — the pin a --keep run returns first
#   3. .tf/<scenario>/config/cluster.yml .ingress.domain_name — the --keep
#      fallback read after the pin + TF state; survives `destroy` and a
#      pin-only clear, so it's the usual reason a stale domain "won't die".
# Clears every scenario by default; scope to one with SCENARIO=. Infra-safe:
# removes only local generated files (never touches AWS/TF state); the overlay
# cluster.yml is regenerated from config/cluster.yml on the next run. For a
# still-running --keep cluster the domain is re-derived from live TF state, so
# this won't rotate a live deployment.
#   make integration-clear-lease
#   make integration-clear-lease SCENARIO=cluster-3-mixed-wasm
integration-clear-lease:
	@if [ -n "$(strip $(SCENARIO))" ]; then \
		rm -f "integration-tests/.tf/$(SCENARIO)/.leased-domain" \
		      "integration-tests/.tf/$(SCENARIO)/config/cluster.yml"; \
		echo "cleared leased domain + stale overlay for '$(SCENARIO)'; next run re-leases from domains.yml"; \
	else \
		rm -f integration-tests/.tf/.domain-lease \
		      integration-tests/.tf/*/.leased-domain \
		      integration-tests/.tf/*/config/cluster.yml; \
		echo "cleared ALL domain-lease state + stale overlays; next run re-leases from domains.yml"; \
	fi
