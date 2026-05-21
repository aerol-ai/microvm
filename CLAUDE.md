# AerolVM — Claude Code Instructions

Self-hosted Docker-backed sandbox platform. Go daemon + 5 SDKs + Astro docs site.
For non-trivial changes, invoke the matching project skill before coding (they live in
[`.claude/skills/`](./.claude/skills/) — see the "Project skills" table below).
Read [`pr-review.md`](./pr-review.md) before opening any PR that touches the server.

## Hard rules

### Documentation

- **No raw HTTP / `curl` examples in any `.md` / `.mdx` file.** Code examples must
  use one of the five SDK languages (TypeScript, Python, Go, Rust, Java) inside
  `<Tabs syncKey="lang">` blocks. The only allowed curl is the install one-liner
  in `getting-started.md`.
- **New top-level feature → new `.mdx` file**, not a subsection on an existing
  page. Register it in the sidebar at `docs/src/content.config.ts` (note: file
  is `content.config.ts`, not `content/config.ts`).
- Every new docs page must cover all five SDK languages with matching
  `syncKey="lang"` tab order.

### API & server changes

Before touching `internal/service`, `internal/store`, `internal/cluster`,
`pkg/caddy`, `pkg/api`, or the SDKs, read [`pr-review.md`](./pr-review.md).
Non-negotiables (silence in the PR description is **not** acceptable on
these axes):

1. **Idempotency.** Every sandbox API must be safe under retry + concurrent
   duplicate calls. `expose_port` returns the existing URL; never walks the
   TCP host-port pool on PK conflict.
2. **Boot-path latency.** Any new work on `CreateSandbox` / its callees must be
   explicitly called out in the PR description, including the first-call case.
3. **Lazy bootstrap pattern.** Best-effort daemon-start work uses the
   `atomic.Bool` latch + `sync.Mutex` single-flight pattern. Canonical example:
   `Service.EnsureLayer4Ready` (`internal/service/service.go` →
   `layer4_bootstrap_test.go`).
4. **Failure-path consistency.** Multi-step writes touching both caddy and the
   store must have a documented rollback rule. Don't lean on reconcile as
   routine cleanup.
5. **TCP host-port pool & L4 bootstrap are fragile.** Any change to
   `TryReserveHostPort`, the `host_port` partial unique index, `allocateHostPort`,
   `EnsureLayer4`, `EnsureLayer4Ready`, or the `l4Ready` latch needs a
   regression test (see `store_test.go` / `layer4_bootstrap_test.go`) AND a PR
   call-out.
6. **Cluster mode is fragile.** `internal/cluster/` runs Raft (FSM placement
   state), SWIM gossip (membership + capacity heartbeats), and cross-node
   forwarding. Any change to the FSM, placement selection, recovery
   replication, owner watcher, or capacity-lease/heartbeat path needs a
   regression test next to the file it changes (cluster_test.go, fsm_*_test.go,
   placement_test.go, etc.) AND a PR call-out describing the cluster-correctness
   impact (split brain risk, replay safety, leader-change behavior, single-node
   regression). Cluster-mode code must remain a no-op when `cfg.EnableCluster`
   is false — `Noop` exists for that.

## Repository map

```
cmd/
  sandboxd/      Daemon entrypoint (main.go wires config → store → docker →
                 caddy → service → api server).
  toolboxd/      In-container agent (file/exec/sessions proxy target).
internal/
  cluster/       Cluster mode (Phase 1): SWIM gossip + Raft FSM placement +
                 owner-sharded execution. cluster.go is the package overview.
                 fsm.go owns the placement state machine; placement.go does
                 power-of-two-choices selection; recovery_replication.go and
                 recovery_store.go handle failover replicas; forward.go is
                 the cross-node HTTP reverse proxy. High-risk area — touching
                 anything in here needs the same care as the TCP pool.
  config/        Env-driven config loader.
  observability/ OTEL traces + expvar metrics exporter for sandboxd.
  runtime/       Runtime.Runtime interface (Docker today, gVisor/Kata later).
  scaleobs/      Scale-out observability metrics (admission / placement).
  service/       Business logic. Version-agnostic. Owns Service struct,
                 CreateSandbox / CreateSandboxWithID / RecreateSandbox entry
                 points, lifecycle, snapshots, l4 latch, mounts, cluster
                 secrets, image distribution. Daytona/E2B helpers live here
                 as named files (daytona.go, e2b.go), NOT version-aware
                 branching.
  store/         SQLite store. Single-writer (MaxOpenConns=1, WAL).
                 store.go has all schema + CRUD; store_test.go is the
                 regression-test target for host-port pool changes.
  version/       Build version string.
pkg/
  api/           HTTP server entrypoint (server.go) + middleware + auth.
    apihttp/     Shared helpers (WriteJSON, WriteError, WriteStoreAwareError).
    v1/          v1 routes. routes.go is the single grep target for
                 "what does v1 expose?". handlers.go is thin: decode →
                 service call → encode.
    v2/          Reserved for future breaking changes; not in active use.
    daytona/     Daytona-SDK compatibility facade (/daytona/...).
  caddy/         Caddy admin API client (L7 routes + L4 routes for TCP).
  capacity/      Host capacity detection + admission control (Admitter).
  docker/        Docker client, /events stream, image GC, netrules (egress fw).
  models/        Wire types + validation (CreateSandboxRequest, Sandbox,
                 ExposedPort, Lifecycle, Mount, Runtime constants, E2B/Daytona
                 metadata DTOs). Lives outside internal/ because SDKs and
                 facades depend on it.
  mounts/        External-storage mount manager (S3, NFS, SSHFS, rclone).
                 Mount inputs run on the host — see pr-review.md §5.
  secrets/       Credential AEAD cipher (env_json + sealed mount blobs).
  sshgateway/    SSH gateway for per-sandbox Ed25519 keys.
sdk/
  typescript/    @aerol-ai/aerolvm-sdk. src/MicroVM.ts + Sandbox.ts; transport
                 in src/internal/api/v1/.
  python/        microvm package. client.py + types.py; transport in
                 microvm/_internal/api/v1/.
  go/            pkg/microvm + pkg/types; transport in internal/apiclient/v1/.
  rust/          src/lib.rs + types.rs.
  java/          Maven; src/main/java/...
docs/
  src/content/docs/   Astro/Starlight .md / .mdx pages.
  src/content.config.ts   Sidebar nav config (register new pages here).
plans/
  sdk-compatibility/  Daytona + E2B compat planning & support matrices.
  *.md                Active design docs.
.github/
  pull_request_template.md   Auto-fills PR descriptions; sections are required.
  workflows/                 test.yml (path-filtered), release.yml, publish-sdks.yml.
Ansible/         Cluster deployment + role-change playbooks (sandboxd install,
                 inventory, drain/remove-member, recovery runbooks).
Terraform/       AWS provisioning for AerolVM clusters (network, nodes, IAM,
                 DNS via Cloudflare, S3 backend for state).
agentic_docs/    Reference docs for AI agents working in this repo
                 (E2B SDK method map, request flow, idempotency timeline).
packaging/       Systemd unit + Caddyfile template for sandboxd deployment.
scripts/         Operational scripts (install/uninstall, cluster init/join,
                 backup/restore, lost-quorum recovery, node-lifecycle, load).
setup/           Operator-facing setup assets (Prometheus alerts, Alertmanager
                 config, Grafana dashboards, deployment topology docs,
                 runbooks).
pr-review.md     The canonical PR review rules. Read before reviewing.
.claude/skills/  Project-local Claude Code skills — invocable via /<name>.
                 See "Project skills" below.
Makefile         fmt, test, build, build-sandboxd, build-toolboxd, docs-*.
```

## Build, test, format

```
make fmt                          # go fmt ./...
make test                         # go test ./...   (server + SDK Go)
go test ./internal/service/...    # narrow run
go test -run TestEnsureLayer4 ./internal/service/...
make build                        # sandboxd + toolboxd into bin/
make docs-dev                     # local Astro dev server
make docs-build                   # static docs build
```

Per-SDK tests:

```
(cd sdk/typescript && npm ci && npm run build && npm test)
(cd sdk/python && python -m unittest discover -s tests -v)
(cd sdk/go && go test ./...)
(cd sdk/java && mvn -B -ntp test)
(cd sdk/rust && cargo test)
```

CI is path-filtered (`.github/workflows/test.yml`): touching `docs/**`
short-circuits the Go and SDK jobs, and each SDK only runs when its own folder
changes.

## Project skills

These live in `.claude/skills/<name>/SKILL.md` and are invocable as `/<name>`.
Each one enforces the rules above for one common change shape and lists the
exact files to touch. Prefer invoking the skill over working from memory.

| Skill | Use when |
|---|---|
| `/add-v1-endpoint` | Adding a new route under `/v1/...` |
| `/add-sdk-method` | Adding a method across all 5 SDKs in lockstep |
| `/add-docs-page` | Adding a new `.mdx` page with five-tab examples |
| `/add-store-column` | Adding a column or table to `internal/store/store.go` |
| `/touch-create-sandbox` | Changing `CreateSandbox` or any boot-path callee |
| `/touch-tcp-pool` | Touching the TCP host-port pool or L4 bootstrap |
| `/add-daytona-route` | Adding to the Daytona compatibility facade |
| `/add-e2b-route` | Adding to the (planned) E2B compatibility facade |
| `/add-mount-adapter` | Adding an external-storage mount adapter |

For changes that don't match a skill, the file-level "where to look" map is:

| Task | Start here |
|---|---|
| Add server business logic | `internal/service/service.go` (or new file in same package) |
| Cluster placement / Raft FSM / gossip / failover | `internal/cluster/` — see `cluster.go` for the package overview, `fsm.go` + `placement.go` for owner assignment, `recovery_*.go` for failover replicas |
| OTEL traces / expvar metrics exporter | `internal/observability/` |
| Caddy route / TLS / L4 wiring | `pkg/caddy/client.go` |
| Capacity / admission rules | `pkg/capacity/` |
| Docker events / image GC | `pkg/docker/events.go`, `pkg/docker/image_gc_test.go` |
| SSH gateway behavior | `pkg/sshgateway/gateway.go` |
| In-sandbox toolbox agent | `cmd/toolboxd/` |
| Cluster ops playbooks / inventory | `Ansible/playbooks/`, `Ansible/inventory/` |
| Cluster infra (AWS) | `Terraform/` |
| Operator alerts / dashboards / runbooks | `setup/prometheus/`, `setup/alertmanager/`, `setup/grafana/`, `setup/runbooks/` |
| Operational scripts (backup, restore, cluster lifecycle) | `scripts/` |

## Conventions

- **Comments explain WHY, not WHAT.** This codebase has dense rationale comments
  on non-obvious decisions (latches, allocator caps, partial unique indexes,
  schema reasoning). Match that style. Don't narrate trivia.
- **Service layer is version-agnostic.** v1/v2/daytona/e2b handlers translate
  wire DTOs ↔ `pkg/models` and call `service.*`. No version checks in
  `internal/`.
- **Errors that the API surfaces use `apihttp.WriteStoreAwareError`** so
  `models.ErrNotFound`, capacity errors, etc. get the right HTTP status.
- **SQLite is single-writer in this process** (`MaxOpenConns=1`). Don't add a
  second `*sql.DB` — queue through the existing one.
- **`pkg/models` is shared between server, facades, and SDK-internal Go
  transport.** Adding a field there ripples; keep DTOs lean and stable.
