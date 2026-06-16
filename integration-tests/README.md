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
make integration-arm64                    # arm64 firecracker single + cluster scenarios
make integration-arm64-single             # single-node-fc-arm64 (Graviton metal)
make integration-arm64-cluster            # cluster-arm64 (homogeneous arm64)
make integration-reap                   # terminate any leaked itest instances past ttl
```

Reports land in `integration-tests/reports/` (`<scenario>.md`, `<scenario>.json`,
`index.md` matrix). Legend: ✅ pass · ❌ fail · ⚪ skip(n/a) · 🟡 pending · 🟤 inconclusive.

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
