# Integration Test Harness

Stands up **real** AerolVM deployments from the released install artifacts and
drives the live `/v1` API + Go SDK against them, producing a use-case coverage
matrix. Full design + decisions: [`../plans/integration-tests.md`](../plans/integration-tests.md).

> ⚠️ **These tests provision real AWS EC2 and cost money.** They use the
> production Terraform module but against **isolated state** (`integration/<scenario>`
> key + separate `TF_DATA_DIR`) so production state is never touched. Spot
> instances + auto-teardown + `make integration-reap` keep cost down.

## Status: Phase 0 (walking skeleton)

Implemented end-to-end on the `single-node` scenario: UC-10 (auth), UC-11
(create), UC-16 (delete), UC-29 (expose), UC-30 (reachable). Everything else is
in the registry as **pending** and shows up that way in the report. Cluster
scenarios land in Phase 2.

## Prerequisites

- `terraform`, `go`, `awscli`, `jq`, `yq`, `curl`, `openssl`, `ssh`
- AWS credentials with permission to create EC2/VPC/etc.
- `config/secrets.yml` populated (PAT, Cloudflare token) — see `config/secrets.example.yml`
- `integration-tests/scenarios/domains.yml` — copy from `domains.example.yml`, fill in
  **real test FQDNs you control** (distinct from your prod domain)

## Run

```bash
make integration-single                 # single-node scenario (Phase 0)
make integration-local                  # local-mode (--local install on a throwaway box)
integration-tests/run.sh single-node --keep        # leave infra up for debugging
integration-tests/run.sh single-node --prod-tls    # use real Let's Encrypt instead of staging
make integration-cluster-hetero           # 8-node heterogeneous cluster (x86 fc)
make integration-cluster-mixed-fc         # 3× mixed cluster, FC on seed c5.metal
make integration-cluster-mixed-gvisor       # 3× mixed cluster, gVisor on every node
make integration-single-fc                # single-node-fc (x86 firecracker, c5.metal)
make integration-arm64                    # arm64 firecracker single + cluster scenarios
make integration-arm64-single             # single-node-fc-arm64 (Graviton metal)
make integration-arm64-cluster            # cluster-arm64 (homogeneous arm64)
make integration-reap                   # terminate any leaked itest instances past ttl
```

Reports land in `integration-tests/reports/` (`<scenario>.md`, `<scenario>.json`,
`index.md` matrix). Legend: ✅ pass · ❌ fail · ⚪ skip(n/a) · 🟡 pending · 🟤 inconclusive.

## Persistent cert store (avoid Let's Encrypt re-issuance)

Every domain scenario provisions a fresh box whose Caddy issues a `*.<domain>`
wildcard via DNS-01. Because the box is thrown away each run, that cert used to
be re-issued **every run** — the managed cert bucket is created and destroyed
with each cluster, and single-node disabled sharing entirely. Against
`--prod-tls` (or if staging limits bite) that burns the issuance budget.

Run this **once per operator/account** to back the harness with a persistent,
cross-run cert store:

```bash
make integration-cert-store-init
```

It idempotently creates a long-lived S3 bucket (`aerol-itest-caddy-certs-<acct>`,
versioning + AES256 + public-access-block) that lives **outside** all scenario
Terraform state — so per-scenario `terraform destroy` never wipes it — and
writes a stable `caddy_cert_store` block (bucket coords + encryption key) into
`config/secrets.yml`. From then on `run.sh` points every domain scenario at
that bucket in BYO mode.

Behaviour after bootstrap: domains are still **randomly** leased from the pool
(`scenarios/domains.yml`), but `certmagic-s3` keys certs by
`<prefix>/certificates/<acme-issuer>/<domain>`, so **the first run to land on a
domain issues + stores its wildcard; every later run that draws the same domain
reads it back instead of re-issuing.** The pool is finite, so each domain issues
exactly once per cert lifetime. Staging and `--prod-tls` runs never collide
(different issuer directory). The encryption key is the only way to read the
stored certs — save it like any root credential; losing or rotating it orphans
every stored cert. See [`setup/multi-node-cert-sharing.md`](../setup/multi-node-cert-sharing.md).

## Create benchmark (UC-94 / UC-95)

`suite/benchmark_test.go` is an **opt-in** benchmark that reuses the live
deployment to measure sandbox creation. It only runs where the scenario
advertises the `benchmark` capability — **`cluster-hetero`** (every runtime),
**`cluster-3-mixed`** (docker only), **`cluster-3-mixed-fc`** (docker +
firecracker), **`cluster-3-mixed-gvisor`** (docker + gvisor), and
**`cluster-3-mixed-wasm`** (docker + wasm) in 3-node mixed clusters — because
it is slow and provisions many sandboxes. Everywhere else UC-94/UC-95 skip (not-applicable).

- **UC-94 — create latency:** for each runtime the scenario has (docker,
  firecracker, gvisor, wasm) it creates `AEROL_BENCH_SAMPLES` sandboxes
  serially, reporting p50/p90/p99 + mean for three timings: **api** (the
  `Create()` client round-trip), **server** (the API's own `Server-Timing`
  header for the create — client↔cluster network excluded), and **running**
  (create→`started`). `api − server` is that network overhead, so you can tell a
  slow create from a slow link.
- **UC-95 — fleet density:** creates docker sandboxes until the fleet rejects on
  capacity (HTTP 503 `capacity exceeded`), reports how many landed, then tears
  them all down. `AEROL_BENCH_MAX` bounds cost if admission never trips.

Every result is stamped with the **machine configuration** parsed from the
scenario's `*.tfvars` (per-node `instance_type`, role, `with_*` flags,
`default_instance_type`) so a latency number is read against the hardware it ran
on (e.g. firecracker on `c5.metal` vs docker on `t3.medium`).

Even on `cluster-hetero` the benchmark is **dormant by default** — it's a second
gate, `AEROL_BENCH=1`, on top of the capability, so a normal hetero run doesn't
pay the cost (UC-94/UC-95 show as ⚪ skip with that reason). Turn it on and it
runs inside the normal orchestrated suite, which provisions and tears down for
you (`run.sh` passes the parent environment through to `go test`):

```bash
# Full hetero run (docker + firecracker + gvisor + wasm):
make integration-benchmark

# Docker-focused 3× mixed cluster (docker latency + density only; cheapest):
make integration-benchmark-docker

# Firecracker-focused 3× mixed cluster (docker + firecracker only; cheaper):
make integration-benchmark-fc

# WASM-focused 3× mixed cluster (wasm latency benchmark only; no Docker
# sandbox creates). Provisions cluster-3-mixed-wasm, runs UC-94 with
# AEROL_BENCH_RUNTIMES=wasm (UC-95 skips). Full integration coverage
# (docker + wasm UCs) is `make integration-cluster-mixed-wasm`.
make integration-benchmark-wasm

# gVisor-focused 3× mixed cluster (docker + gvisor only; cheap t3 spot boxes):
make integration-benchmark-gvisor

# Manual env form (hetero):
AEROL_BENCH=1 \
AEROL_BENCH_OUT=integration-tests/reports/cluster-hetero-bench.json \
  make integration-cluster-hetero
```

To iterate without re-provisioning, bring the cluster up once with `keep`, then
re-run only UC-94/UC-95 with `make integration-benchmark-only` (hetero) or
`make integration-benchmark-fc-only` (mixed-fc) — they read the API URL + PAT
from TF state and force `AEROL_BENCH=1`, so nothing to export:

```bash
make integration-cluster-hetero keep         # provision, leave it up
make integration-benchmark-only              # re-run just the bench against it

make integration-cluster-mixed keep          # 3× mixed docker cluster
make integration-benchmark-docker-only       # re-run docker bench against it

make integration-cluster-mixed-fc keep       # 3× mixed FC cluster
make integration-benchmark-fc-only         # re-run UC-94/UC-95 against it

make integration-cluster-mixed-wasm keep   # 3× mixed WASM cluster (full suite)
make integration-benchmark-wasm-only       # re-run wasm bench against kept cluster

make integration-cluster-mixed-gvisor keep # 3× mixed gVisor cluster
make integration-benchmark-gvisor-only     # re-run UC-94/UC-95 against it

# Narrow the UC-94 sweep on hetero / mixed-fc / mixed-gvisor benches:
AEROL_BENCH_RUNTIMES=docker,gvisor,wasm make integration-benchmark-only
# …or isolate firecracker latency (UC-95 skips when docker is excluded):
AEROL_BENCH_RUNTIMES=firecracker make integration-benchmark-fc-only
# …or isolate gvisor latency (UC-95 skips when docker is excluded):
AEROL_BENCH_RUNTIMES=gvisor make integration-benchmark-gvisor-only
# …or add docker density/latency back on the wasm cluster:
AEROL_BENCH_RUNTIMES=docker,wasm make integration-benchmark-wasm-only

make integration-destroy                     # tear the kept cluster down
make integration-destroy SCENARIO=cluster-3-mixed
make integration-destroy SCENARIO=cluster-3-mixed-fc
make integration-destroy SCENARIO=cluster-3-mixed-gvisor
make integration-destroy SCENARIO=cluster-3-mixed-wasm
```

Percentiles + the density ceiling also print as `bench[...]` log lines (captured
by `go test -json`); the `AEROL_BENCH_OUT` JSON adds the machine block.

**Docker benchmark path.** `make integration-benchmark-docker` provisions
`cluster-3-mixed` and runs **docker-only** benchmarks (`--bench-only`,
`AEROL_BENCH_RUNTIMES=docker`): UC-94 times docker creates and UC-95 probes
fleet density. Use `make integration-cluster-mixed` for the full docker
integration suite (placement, forwarding, domain/TLS UCs).

**WASM warm pool.** wasm scenarios boot with the warm-worker pool on so creates
skip the cold module compile — CPython-on-wasm is ~10s cold on a t3.
`make integration-benchmark-wasm` provisions `cluster-3-mixed-wasm` and runs
**wasm-only** benchmarks (`--bench-only`, `AEROL_BENCH_RUNTIMES=wasm`): UC-94
times wasm creates, UC-95 skips, and no full-suite Docker sandboxes are created.
Use `make integration-cluster-mixed-wasm` for the full docker+wasm integration
suite. Pool depth defaults to
`2` by default at provision time so UC-94 measures warm hits without exhausting
small nodes; `make integration-cluster-mixed-wasm` (non-benchmark) also keeps
depth `2`.
Depth is baked into **node boot env**, so a cluster brought up before a pool
depth change shows cold numbers until re-provisioned.

**Firecracker benchmark path.** UC-94 creates one Firecracker template before
timing and measures sandbox clones with `template_id`, not plain OCI image cold
boots. Override the template source with `AEROL_BENCH_FC_TEMPLATE_IMAGE` when
you need a different base image.

| Env var | Default | Purpose |
|---------|---------|---------|
| `AEROL_BENCH` | *(unset)* | **master switch** — must be `1` or the bench skips |
| `AEROL_BENCH_RUNTIMES` | *(all advertised)* | comma list narrowing the UC-94 sweep, e.g. `docker,gvisor,wasm` (skip firecracker) or `firecracker` (isolate) |
| `AEROL_BENCH_SAMPLES` | `10` | sandboxes timed per runtime (UC-94) |
| `AEROL_BENCH_MAX` | `200` | safety cap on the density probe (UC-95) |
| `AEROL_BENCH_OUT` | *(unset)* | path to write the JSON artifact; logs only if unset |
| `AEROL_BENCH_TFVARS` | `../scenarios/<scenario>.tfvars` | override the machine-config source |
| `AEROL_BENCH_FC_TEMPLATE_IMAGE` | `docker://alpine:3.20` | Firecracker template image used for UC-94 clone latency |
| `AEROL_WASM_MODULE_REF` | *(unset)* | staged `.wasm` ref; wasm latency skips without it |
| `AEROL_WASM_POOL_DEPTH` | `2` | warm wasm workers per module digest (provision-time; `0` when wasm off) |

## What runs where

| Layer | Command | Needs AWS? |
|-------|---------|-----------|
| Harness self-tests (caps logic, report classifier, prod-safety tripwires) | `make test` (`go test ./...`) | No — offline, in CI |
| Live integration suite | `make integration-*` / `go test -tags=integration ./integration-tests/suite/...` | Yes |

The live suite is behind the `integration` build tag, so the everyday
`make test` never reaches AWS.

## Safety model

- **State:** `-backend-config=key=integration/<scenario>/...` + separate
  `TF_DATA_DIR`. The prod key (`prod/terraform.tfstate`) is never opened.
- **Tripwires** (`lib/provision.sh check-safety`, unit-tested in `safety/`):
  abort before any apply if the state key targets prod, the leased domain
  collides with the prod domain, or `cluster_name` lacks the `itest` marker.
- **Config overlay:** generated at runtime from `config/cluster.yml` with AOCR
  auto-import + fleet **disabled** and the leased domain substituted — never a
  committed copy, so it can't drift.
- **Teardown:** `run.sh` trap on EXIT/INT/TERM + the standalone reaper.
