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
make integration-single-fc                # single-node-fc (x86 firecracker, c5.metal)
make integration-arm64                    # arm64 firecracker single + cluster scenarios
make integration-arm64-single             # single-node-fc-arm64 (Graviton metal)
make integration-arm64-cluster            # cluster-arm64 (homogeneous arm64)
make integration-reap                   # terminate any leaked itest instances past ttl
```

Reports land in `integration-tests/reports/` (`<scenario>.md`, `<scenario>.json`,
`index.md` matrix). Legend: ✅ pass · ❌ fail · ⚪ skip(n/a) · 🟡 pending · 🟤 inconclusive.

## Create benchmark (UC-94 / UC-95)

`suite/benchmark_test.go` is an **opt-in** benchmark that reuses the live
deployment to measure sandbox creation. It only runs where the scenario
advertises the `benchmark` capability — currently **`cluster-hetero`**, the one
cluster carrying every runtime — because it is slow and provisions many
sandboxes. Everywhere else UC-94/UC-95 skip (not-applicable).

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
# Full run: provision cluster-hetero, run the suite WITH the benchmark, teardown.
AEROL_BENCH=1 \
AEROL_BENCH_OUT=integration-tests/reports/cluster-hetero-bench.json \
  make integration-cluster-hetero
```

To iterate without re-provisioning, bring the cluster up once with `keep`, then
re-run only UC-94/UC-95 with `make integration-benchmark-only` — it reads the API
URL + PAT from TF state and forces `AEROL_BENCH=1`, so nothing to export:

```bash
make integration-cluster-hetero keep         # provision, leave it up
make integration-benchmark-only              # re-run just the bench against it

# Narrow the UC-94 sweep — firecracker cold-boots are slow; skip them to finish:
AEROL_BENCH_RUNTIMES=docker,gvisor,wasm make integration-benchmark-only
# …or isolate one runtime:
AEROL_BENCH_RUNTIMES=firecracker make integration-benchmark-only

make integration-destroy                     # tear the kept cluster down
```

Percentiles + the density ceiling also print as `bench[...]` log lines (captured
by `go test -json`); the `AEROL_BENCH_OUT` JSON adds the machine block.

**WASM warm pool.** wasm scenarios boot with the warm-worker pool on
(`wasm.pool.enabled`, depth `AEROL_WASM_POOL_DEPTH`, default `2`) so creates skip
the cold module compile — CPython-on-wasm is ~10s cold on a t3. Depth is baked
into **node boot env**, so a cluster brought up before this change shows cold
numbers until re-provisioned. The bench's serial burst drains a shallow pool, so
for an all-warm wasm reading keep `AEROL_BENCH_SAMPLES` ≤ depth (e.g.
`AEROL_BENCH_RUNTIMES=wasm AEROL_BENCH_SAMPLES=2`). Raise the depth only on
`cluster-hetero` (worker-z is bare metal) — `depth × standard-modules` warm
workers won't fit on a t3.medium.

| Env var | Default | Purpose |
|---------|---------|---------|
| `AEROL_BENCH` | *(unset)* | **master switch** — must be `1` or the bench skips |
| `AEROL_BENCH_RUNTIMES` | *(all advertised)* | comma list narrowing the UC-94 sweep, e.g. `docker,gvisor,wasm` (skip firecracker) or `firecracker` (isolate) |
| `AEROL_BENCH_SAMPLES` | `10` | sandboxes timed per runtime (UC-94) |
| `AEROL_BENCH_MAX` | `200` | safety cap on the density probe (UC-95) |
| `AEROL_BENCH_OUT` | *(unset)* | path to write the JSON artifact; logs only if unset |
| `AEROL_BENCH_TFVARS` | `../scenarios/<scenario>.tfvars` | override the machine-config source |
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
