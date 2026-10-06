# TODOS

Deferred work items with enough context to pick up cold. Each entry says
what, why, the caveat that motivated capturing it, and where to start.

Open items come first, grouped by area. Finished items are kept at the end
under **Done** as a record of what was decided and where the code lives.
Code comments and plans cite entries by title, so keep titles stable.

Every entry was re-verified against `main` at `704c9e74` on 2026-10-06.
`file:line` references are as of that commit.

---

## A partitioned node keeps serving: /health ignores cluster membership (readiness gap)

- **What:** a node with no Raft leader, or that is not a Raft member, still
  answers `/health` with 200, so the ingress keeps routing traffic to it and
  every request that lands there fails.
- **Status (2026-10-06):** still open. `handleHealth`
  (`pkg/api/server.go:146`) answers 200 unless `Service.Health` errors.
  `Service.Health` (`internal/service/service.go:4434`) only marks the body
  `"degraded"` for runtime, Caddy, SSH or topology faults
  (`clusterTopologyErrorFor`, `:4543-4555`), never for "no raft leader" or
  "not a raft member". No `/ready` route exists anywhere in `pkg/`,
  `internal/` or `cmd/`.
- **Measured** (S3 `cluster-3-mixed-secrets-kms`, 2026-09-27). node1 was
  `active`, `NRestarts=0`, and `/health` = 200, while the cluster's member
  list held only node2 and node3, node1's own list held only node1, and node1
  was stuck `entering candidate state`. About one request in three failed
  across the run (4 of 5 calls to S4's `/v1/audit/verify` returned 502),
  mostly `cluster: reserve placement failed: cluster: not raft leader`.
  That partition's cause was the restarted-seed bug, now fixed (see Done).
  This gap is what turned it into user-visible errors, and it will do the
  same for any other way a node falls out of the cluster.
- **Why it matters most:** every one of those reds looks like a bug in
  whatever test happened to run. A cluster that is degraded but advertising
  itself as healthy costs the most debugging time per incident.
- **The fix needs design, not a one-liner.** Failing `/health` when there is
  no leader would take the whole cluster out of rotation during any routine
  election. It needs readiness distinct from liveness, a grace period so
  elections do not flap it, and a decision about whether a partitioned node
  should still serve reads.
- **Design exists, unmerged:** PR #522 (branch
  `origin/plans/kubernetes-ceo-review`) designs `/ready` (decision D8, §5.4:
  503 when not a Raft member, with an election grace window). The plan on
  `main` (`plans/kubernetes-deployment.md:146-148`) still says `/health`
  backs the readiness probe.
- **Start:** `pkg/api/server.go` health handler, `cfg.EnableCluster` gating,
  the Caddy upstream health config in `pkg/caddy` / `packaging/`, and the
  PR #522 design.

## Reconcile still reaps a healthy sandbox on a transient Inspect error (UC-20 residual, unconfirmed)

- **What:** decide whether `reconcileGoneContainerConfirmed`
  (`internal/service/service.go:4800`) should reap only on a definite
  not-found, rather than on any `Inspect` error.
- **Why:** UC-20 (reconcile deleted a freshly created owned sandbox ~200ms
  after create; a cross-node snapshot then 404'd) was fixed in PR #360
  (`dd06a979`). Reconcile now re-Inspects a container missing from the bulk
  `ListManaged` snapshot before reaping it. But the root cause in that commit
  is containerd's `ListManaged` skipping a container whose `Inspect` errors
  mid-adopt or mid-start. The re-check treats **any** `Inspect` error as
  "gone" (`:4808-4811`), so the same transient error on the targeted call
  still deletes the row and the cluster placement of a healthy sandbox.
- **Caveat (why it is a TODO, not a bug):** unreproduced. Whether the
  targeted `Inspect` can fail transiently in the same window is unknown.
  Narrowing to not-found also has a cost: a container whose `Inspect` keeps
  erroring would never be reaped. Get a reproduction first.
- **Start:** `reconcileGoneContainerConfirmed`;
  `TestReconcileReInspectsBeforeReap`
  (`internal/service/reconcile_destroy_test.go:692`); the containerd
  driver's `ListManaged` skip. UC-20 itself is implemented and not skipped
  (`integration-tests/suite/lifecycle_more_test.go:176`).

## Destroy events WARN about an already-deleted placement (cluster)

- **What:** stop `handle docker event failed … cluster: unknown sandbox
  placement` from warning when an API-driven destroy has already removed the
  placement.
- **Why:** `Driver.Destroy` ends with `container.Delete`, so the
  `/containers/delete` event arrives after `DestroySandbox` started removing
  the placement. `handleDestroyEvent` (`internal/service/events.go:234`) then
  calls `beginSelfOwnedClusterPlacementDeleteStrict` (`:287`) for work that
  is already done.
- **Narrower than first recorded:** if the placement is already gone when
  the lookup runs, that function returns nil (`service.go:3121-3125`, added
  in `8afaf50d`). The warning fires only in a race: the lookup still sees the
  placement, but `DestroySandbox`'s `opDelete` lands before this
  `opBeginDelete` applies (`internal/cluster/fsm.go:1029-1031` returns
  `ErrUnknownSandbox`). How often this happens in practice is unmeasured.
- **Caveat (why it is a TODO, not a bug):** cosmetic, since the destroy
  succeeds. The risk is noise that masks a real finalization failure.
- **Start:** `service.go:3133` wraps the error with `%v`, so
  `errors.Is(err, ErrUnknownSandbox)` cannot match. Wrap with `%w` (or check
  before wrapping) and treat it as benign in `handleDestroyEvent`, the same
  way its `store.Delete` already treats `ErrNotFound`.

## UC-145b (retention prune) cannot run on any scenario — needs a seam

- **What:** UC-145b forces a prune with `SB_SECRET_AUDIT_RETENTION_DAYS=0`
  and needs the audit witness. The witness exists only on enterprise
  scenarios, and enterprise refuses zero retention at config load
  (`internal/config/config.go:2477-2478`, "secret audit and tomb retention
  must be non-zero when SB_ENTERPRISE_MODE=true"). The use case also requires
  `CapEnterprise` (`integration-tests/suite/harness/usecases.go:519`), so it
  runs only where it must skip
  (`integration-tests/suite/audit_export_test.go:361-362`). The only path
  that legitimately destroys evidence has no live coverage at all.
- **Now:** the case skips on enterprise with that reason (it is not a pass).
- **Unblock:** a test-only way to make records prunable under enterprise,
  e.g. an `itestretention` build tag (same pattern as `itestwitness`,
  `cmd/sandboxd/provider_itest.go`) that lets retention be expressed in
  minutes. Do not relax the enterprise validator for it.

## A resealed secret whose replacement holder is dead never re-seals (cluster secrets)

- **What:** give `finalizeResealedSecret`
  (`internal/service/cluster_secrets.go:1832`) a fallback when no staged
  replacement recipient acknowledges the new generation.
- **Why:** after a holder probe and a re-push both fail, it returns
  `"resealed secret has no acknowledged replacement backup"` (`:1869-1871`).
  Its caller returns at `:1620`, before the live-set and dead-target reseal
  path that starts at `:1622`. So each reconcile pass hits the same error
  until a staged recipient comes back, and nothing triggers a fresh reseal to
  live recipients. The secret stays without a failover backup in the
  meantime.
- **Context:** PR #431 follow-up ("dead-replacement fallback"). The function
  was last changed in `eb854acf` (2026-09-17).
- **Start:** `finalizeResealedSecret` and its caller. Decide whether a dead
  staged set should fall through to the normal reseal path. That path then
  needs a regression test covering a staged recipient that never returns.

## Rejoin outbox sweep can stall behind rows for other members (cluster secrets)

- **What:** filter the outbox listing by recipient on a rejoin pass, instead
  of filtering an unfiltered page in Go.
- **Why:** PR #432's fix (`922e8fa2`) narrowed rejoin retries to the
  returning member (`secretOutboxPass.rejoinedNodes` /
  `targetsRejoinedNode`, `internal/service/cluster_secrets.go:464-486`). But
  the narrowing runs over an unfiltered page of up to 1024 rows
  (`ListSecretDeleteOutboxBatch`, ordered by `updated_at`,
  `internal/store/store.go:6251`). Rows owed to other members are skipped and
  never touched, so they stay at the head of the queue. Once a page holds no
  rows for the returning member, the sweep returns (`cluster_secrets.go:596`),
  and that member's rows further down wait for their normal backoff.
- **Caveat:** found by reading the code, not by test. The effect is extra
  delay on a large outbox, not data loss.
- **Start:** pass the rejoined node ids into the store query for both the
  delete outbox (`:526`) and the put outbox (`:1965`). Add a test with more
  than one page of other members' rows ahead of the returning member's.

## Indexed / central secret-audit store (scale) — partly done, residual parked

- **Done since this was written:** local queries read a per-sandbox index
  (#402, `internal/service/secret_audit_index.go`; `ListSecretAuditLocal`,
  `secret_audit_query.go:152`) and fall back to a file scan only when the
  index is not ready or is corrupt. Boot verification has an opt-in
  `SB_SECRET_AUDIT_BOOT_VERIFY=checkpoint` mode that checks only bytes written
  since the last sync, then re-verifies the whole chain in the background
  (#405). The all-member fan-out is parallel (`secretAuditFanoutParallel =
  16`, `secret_audit_query.go:33`), not sequential.
- **Earlier interim work:** sidecar flock; Close/Prune `sendMu`; verified
  startup chain; authenticated, idempotent HTTPS batch export with a durable
  watermark; gap markers (`kind=gap`, included in kind-filtered pages);
  compound cursor; malformed JSONL → gap event; WASM queue-full writes a
  durable gap marker; post-delete ACL via `sandbox_audit_acl` +
  `Placement.OwnerRef`.
- **Residual:** no central or indexed durable sink. The default boot verify
  (`full`, `internal/config/config.go:1801`) is still one full pass over the
  JSONL, now constant-memory. Enterprise mode requires the external
  exporter/receiver. Receiver indexing, WORM retention and operational
  verification remain deployment gates.
- **Start:** `internal/service/secret_audit_query.go` and
  `secret_audit_index.go`. An E2b witness sink may double as the central
  store.

## Ingress route changes reset in-flight TLS connections on :443 — IMPLEMENTED behind `SB_INGRESS_PROXY_ROUTING`; default flip pending

- **Shipped 2026-09-28 (#503–#512, released in v0.6.0; design in
  `plans/ingress-proxy-routing.md`):** a static Caddy config, with sandboxd
  answering *where* via a loopback DNS responder (Caddy `dynamic a` +
  caddy-l4 placeholder dial). Bytes stay in Caddy. Raw TCP host ports are
  **kernel-DNATed**, so sessions live in conntrack. The code lives in
  `internal/routedns/`, `internal/service/ingress_routing.go`,
  `internal/service/route_index_writer.go`, `internal/network/hostport/` and
  `pkg/caddy/static_routes.go`.
- **Proven live:**
  - `cluster-3-mixed-routing`: 77 pass / 0 fail.
  - `cluster-hetero-lite-routing`: 125 pass / 0 fail.
  - UC-171 churn gate: **0** failed fresh HTTP/raw-TCP connections under
    sandbox churn (was ~2.6%).
  - UC-172: established sessions survive sandboxd restarts on the ingress
    and the owner.
  - UC-173: no per-sandbox Caddy routes on any node.
- **Still off by default everywhere (2026-10-06):**
  `internal/config/config.go:1781`, `setup/config-defaults.md:177`,
  `Terraform/variables.tf:379-383`, `scripts/install.sh:29`. Only the two
  t3.medium `-routing` scenarios turn it on. The 2026-10-04 cluster-hetero
  run behind #595 ran with it off.
- **Remaining before the default flips on:** a run on the metal flagship
  with the flag on (no metal routing scenario or make target exists yet;
  `Makefile:179-183` has only `integration-routing` and
  `integration-routing-hetero-lite`), and a latency/throughput A/B
  (`plans/ingress-proxy-routing.md:300-301`, `:494-496`).
- **Background (why the flag exists):** seen in T19 S6 (UC-09). A TLS dial
  to the apex was reset 0.5s in, after another test's route DELETE made
  Caddy reload, and every route change reloads the whole config, including
  the layer-4 `tls-mux` server that fronts :443. A local repro on 2026-09-28
  (Caddy v2.11.4 + caddy-l4 master, `scripts/dev/caddy-reload-repro.py`,
  8 clients, one fresh TLS connection per request, ~18 reloads/s):

  | Path | No churn | Churn |
  |---|---|---|
  | via layer4 `tls-mux` (the ingress) | 0 / 39,841 | **2.6%** fail (~1,500 empty replies, ~220 resets/broken pipes/TLS EOF, a few refused) |
  | straight to the http server | 0 / 45,434 | **2.2%** fail (almost all empty replies, ~15 resets) |

  The dominant failure is a completed TLS handshake followed by a clean
  close with zero bytes: the old http server's graceful shutdown closing
  connections that have not sent a request yet. The T19 notes are in
  `plans/integration-test-security.md` §7.12.

## First boot Caddy config lacks S3 certificate storage

- **What:** make the first Caddy config an ingress loads already carry the
  S3 certificate storage, rather than adding it in a later reload.
- **Why:** T19 S6's first config (06:28:50) had no S3 storage. The cert jobs
  failed with "failed storage check: context canceled" and were not retried
  until Caddy reloaded with S3 storage at 06:33:35. At the same boundary
  sandboxd got a 500 installing the on-demand TLS policy ("on-demand TLS
  cannot be enabled without a permission module").
- **Correction (2026-10-06):** that policy is **not** retried on reconcile,
  despite the log line. `pkg/daemon/daemon.go:1006-1007` logs "will retry on
  next reconcile", but `EnsureOnDemandTLS` has only that one boot-time call.
  A failed install stays failed until the next daemon restart. Fix the
  message or add the retry.
- **Caveat:** two later "slow HTTPS" runs were not this. They were the
  harness Mac caching an NXDOMAIN for the freshly leased hostname, fixed in
  the harness (`direct_resolve_args`, `GODEBUG=netdns=go`). Some of S6's
  delay may be the same artifact, so re-check this on the next run before
  investing. The "failed storage check" errors are real; whether they
  delayed HTTPS is unproven. `integration-tests/lib/common.sh:356-362` raised
  the health-wait to 600s because of this entry.
- **Status:** unchanged since 2026-09-29. The storage block is still injected
  at `scripts/install.sh:1097`.
- **Start:** the ingress Caddyfile / bootstrap in `scripts/install.sh` and
  `packaging/`, and the on-demand policy install
  (`pkg/caddy/client.go:913` `ensureOnDemandTLSLocked`, called from
  `pkg/daemon/daemon.go:1006`).

## Owner-side protocol=tls port routes behind a static route

- **What:** replace the per-exposure owner layer-4 `…-port-{p}-tls` routes,
  where the owner terminates non-HTTP TLS, with a static SNI route whose
  target comes from the sandboxd route responder, like HTTP.
- **Why:** with `SB_INGRESS_PROXY_ROUTING` on, these are the last
  per-sandbox Caddy writes: one full reload per TLS-port expose or unexpose.
  They are called directly (`internal/service/service.go:4156`, `:4166`),
  bypassing the route-write choke point on purpose
  (`internal/service/public_routes.go:24-26`).
- **Pros:** truly zero lifecycle writes. **Cons:** it needs an L4
  TLS-terminate route with a placeholder dial, which the 2026-09-28 spike did
  not cover.
- **Context:** `plans/ingress-proxy-routing.md` §2 non-goals;
  `pkg/caddy/client.go` `UpsertTLSSNIRoute` (:1310) and
  `UpsertWakeTLSSNIRoute` (:1380). Both now write through
  `upsertTLSMuxRoute` (:1343), which takes the admin lock from #595.
- **Depends on:** the route responder (plan task T3), which has shipped.

## IP mode on the ingress router

- **What:** serve IP-mode path routing (`/{id}/*`, `/{id}/proxy/{p}/*`)
  through the static route plus the responder and router, instead of
  per-sandbox Caddy routes.
- **Why:** IP mode still reloads Caddy per sandbox. That matters for
  single-node and dev installs without a domain. The flag refuses to engage
  without a domain (`internal/service/ingress_routing.go:99`), and the index
  writer's peer route is a no-op outside domain mode
  (`route_index_writer.go:133-137`).
- **Pros:** one routing model everywhere. **Cons:** path dispatch plus
  prefix stripping, for low churn in practice.
- **Context:** the IP-mode branch of `UpsertSandboxRoute`
  (`pkg/caddy/client.go:188`, branch at `:207-208`) and
  `UpsertSandboxRouteToPeer` (`:284`).
- **Depends on:** the plan's tasks T3 and T6.

## Delete the old per-sandbox route code after the ingress-routing default flips

- **What:** remove the flag-off path, in which the Caddy client itself is the
  `publicRouteWriter` (`internal/service/public_routes.go:61`, returned at
  `:74` when no writer is installed). Also remove the per-sandbox
  `Upsert*`/`Delete*` route methods and their reconcile and GC paths.
- **Why:** two routing paths double the test and maintenance surface. The
  old one exists only for rollback.
- **Pros:** a large deletion and a single path. Every call site already goes
  through `publicRoutes()` (79 non-test call sites), so the cut is clean.
  **Cons:** it removes the rollback lever, so do it only after a soak at
  default-on.
- **Context:** `plans/ingress-proxy-routing.md` §3.6.
- **Depends on:** `SB_INGRESS_PROXY_ROUTING` defaulting to true (still
  false, see above), plus a soak of about one release cycle.

## Warm-adopted (`park-*`) destroys fall to reconcile (containerd)

- **What:** restore prompt row deletion for a warm-adopted container, or
  confirm the reconcile sweep is enough and close this out.
- **Why:** only `/containers/delete` maps to `destroy`
  (`internal/runtime/containerd/events.go:89-90`); `/tasks/delete` is left
  unmapped on purpose (`:92-101`) because mapping it made a manual stop
  delete the sandbox. By the time `/containers/delete` fires, the container
  is gone, so the label lookup (`LoadContainer` + `sandboxIDFromContainer`,
  `events.go:52-53`; defined at `lifecycle.go:461`) fails and the event
  carries the `park-*` id. That id matches no store row and is dropped
  silently (`internal/service/events.go:92-98`).
- **Caveat (why it is a TODO, not a bug):** the outcome is correct, just
  slower. The row is reclaimed by `Reconcile`'s missing-runtime branch
  (`internal/service/service.go:4896-4897`, then
  `reconcileGoneContainerConfirmed` at `:4957`), not by `removeOrphans`,
  which is a closure inside `Reconcile` (`:5182`) that skips `park-*` ids
  (`:5187`). The alternative, caching container id → sandbox id before
  deletion, adds state to the event path for a latency win that may not
  matter. Measure how long a warm-adopted row actually lingers first.
- **Depends on:** a scenario that exercises warm-pool adoption plus destroy.
- **Start:** `internal/runtime/containerd/events.go`, then `Reconcile`'s
  missing-runtime branch.

## Isolate orphan sweep survives a daemon restart (runtime) — part 2

- **What:** give `internal/runtime/isolate` a host-backed enumeration so
  `Reconcile`'s orphan sweep can find workerd groups leaked across a
  restart. `Driver.ListManaged` (`internal/runtime/isolate/driver.go:205-213`)
  returns the driver's in-memory `byID` map, and `HostSupervisor`
  (`internal/runtime/isolate/seams.go:48-50`) exposes only `SpawnGroup`, so
  there is no way to ask the host what is running.
- **Why:** part 1 (isolate in `mergeManagedRuntimes` + `removeOrphans`,
  `internal/service/service.go:4875` and `:5244`; live-checked by UC-167)
  covers a transient `Destroy` failure while the daemon stays up. It cannot
  cover a crash. A jailed group owns a cgroup under
  `SB_ISOLATE_JAIL_CGROUP_ROOT` and a uid-owned chroot tree under
  `SB_ISOLATE_JAIL_CHROOT_BASE`, so a leak across a restart strands host
  state permanently and invisibly.
- **Caveat (why it is its own change):** it needs a new seam (`ListGroups` on
  `HostSupervisor`) plus a real cgroup or chroot walk with its own failure
  modes: enumerate-while-spawning races, partial teardown, and a jail-off
  mode where neither directory exists.
- **Start:** `pkg/isolate/cgroup.go` + `chroot.go` already know the layout
  (`linkGroupJail` :121 / `removeGroupJail` :181 in `chroot.go`). Add
  `ListGroups` to `HostSupervisor`, implement it over the cgroup root, have
  `Driver.ListManaged` union it with `byID`, and extend
  `internal/service/reconcile_isolate_orphan_test.go`.

## Audit Firecracker outbound NAT path (networking)

- **What:** confirm on a live Firecracker host that a guest reaches the
  internet and that block-all, CIDR lists and a hostname allowlist hold:
  `iptables -t nat -S POSTROUTING | grep aerolvm-fc-masq`,
  `iptables -S AEROLVM-FC`, `nft list set inet aerolvm_egress fqdn_src`,
  `sysctl net.ipv4.conf.fctapN.rp_filter`.
- **Why:** the audit confirmed the gap. Nothing in the daemon, `Terraform/`,
  `Ansible/`, `scripts/`, `packaging/` or `install.sh` set up SNAT or
  FORWARD accepts for the TAP subnet (`internal/network/hostport` is
  ingress DNAT only), and dockerd's FORWARD DROP policy would drop guest
  traffic anyway. Egress Phase 4 fixes it in-repo:
  - `tap.EnsureNAT`: a `MASQUERADE` for `SB_FIRECRACKER_TAP_BASE_CIDR`,
    comment `aerolvm-fc-masq`;
  - the `AEROLVM-FC` netrules chain with FORWARD accepts for the subnet and
    per-guest-IP block-all, CIDR lists and holds;
  - strict `rp_filter` per TAP, wired at boot by
    `pkg/daemon/firecracker_egress_wiring.go`;
  - hostname filtering through the egress gateway, which serves the TAP pool
    on wildcard listeners behind its input guard
    (`setup/runbooks/egress-gateway.md` "Firecracker").
- **Caveat:** proven only on a real kernel with veth stand-ins
  (`internal/network/tap/fc_egress_kernel_test.go`,
  `internal/egress/gatewayd/tappool_kernel_test.go`), not on a Firecracker
  host. Integration UC-204 (`single-node-fc`) covers the hostname path.
- **Start:** any FC bench host, or `make integration-single-fc` with UC-204.
  Operator-run (metal).

## Shard the WASM resident net-host mutex (performance, P3)

- **What:** shard `multiNetHost`'s single mutex
  (`pkg/wasm/engine_multi_network.go:20`), or split it into per-map
  RWMutexes. It guards the `hooks` / `conns` lookups (`:21-22`) in the
  resident compile-once/instantiate-many WASM host
  (`plans/wasm-resident-module-host.md`).
- **Why:** at very high co-tenant IO rates on one shared host process, the
  single lock on every `tcp_dial`/`read`/`write`/`close` map lookup could
  show up as contention. The resident host is now **on by default**
  (`SB_WASM_RESIDENT_HOST_ENABLED`, `internal/config/config.go:1913`), so
  this is the production path.
- **Caveat (why it is not built):** the lock is released before the
  blocking `conn.Read`/`Write`, so contention is only on microsecond map
  lookups. There is still no evidence of contention: no benchmark in
  `pkg/wasm/`, and no profile or report.
- **Depends on / start:** a profile (`go test -bench` or a live
  cluster-3-mixed-wasm run) that shows lock contention. Eng review
  2026-07-17 (D9).

## SDK create retries can duplicate unnamed sandboxes (all SDKs)

- **What:** every SDK retries `POST /v1/sandboxes` after the request may
  already have reached the server. Without a name, a lost reply creates a
  second sandbox.
  - **Go:** create at `sdk/go/internal/apiclient/client.go:144-150` →
    `doJSON` (:967) → `doWithRetry` (:1055-1093).
    `isTransientTransportError` (:1018-1041) matches EOF, timeout,
    connection reset and DeadlineExceeded. Retryable statuses are 421, 429,
    502, 503 and 504 (:1047-1053).
  - **TypeScript:** `sdk/typescript/src/internal/client.ts:941` `request()`
    retries every method on ECONNRESET, ETIMEDOUT, UND_ERR_HEADERS_TIMEOUT
    and "socket hang up", plus 421/429/5xx. Create is at :425. The comment at
    :933-939 is wrong: it says these errors mean the request never reached
    the server, and that every mutating endpoint is built for idempotent
    retry.
  - **Python:** `sdk/python/microvm/client.py:990-1043` `_request_headers`
    retries 421/429/502/503/504 and **any** `Exception`. Create is at :462.
  - **Java:** `MicroVMClient.java:1038-1092` `sendRequest` retries on any
    `IOException`. Create is at :146. `MicroVMConfig.java` only holds the
    setting.
  - **Rust:** `sdk/rust/src/lib.rs:1527-1585` `do_json_headers` retries on
    `is_request()`, `is_connect()` and `is_timeout()`, plus 421/429/5xx.
    Create is at :545.
- **Why:** duplicate billed sandboxes the caller never sees. A **named**
  create is not idempotent either: the retry gets 409 `"sandbox name already
  in use"` (`pkg/api/apihttp/apihttp.go:163-164`), which plain SDKs return as
  an error. Only the CLI/MCP path turns that 409 into a GET by name
  (`internal/agenttools/create.go:84`), so only it is safe, because it also
  auto-generates names (`plans/mcp-server-and-agent-cli.md` §5.4, D5, D16).
- **Status:** no create idempotency key exists, server-side or in any SDK.
- **Start:** choose between (a) no retry for non-idempotent POSTs once the
  request may have been sent and (b) a create idempotency key (server + 5
  SDKs). Add a test per SDK: a fake server creates, then drops the
  connection, and exactly one sandbox must exist. Fix the TS comment either
  way.
- **Depends on:** nothing.

## Daytona facade cannot distinguish "no env" from "env withheld" (API)

- **What:** decide and implement a Daytona-side signal for D9's withheld env.
- **Why:** under D9, `internal/service` returns a nil `Env` unless
  `GetSandboxOptions.IncludeEnv` is set, so the facade's default response
  serializes `"env": {}` (`pkg/api/daytona/dto.go:102`). That asserts the
  sandbox has no environment rather than that none was returned.
  `?include_env=true` exists as the opt-in (`hydrateEnvIfRequested`,
  `pkg/api/daytona/handlers.go:802`), but the default is still ambiguous.
- **Caveat (why it is a TODO):** `json:"env,omitempty"` was tried and
  **reverted**. The Daytona SDK's deserializer rejects a sandbox payload with
  no `env` key, and `TestDaytonaSDKContracts` fails across the whole read
  surface. Any fix has to stay inside what the real SDK accepts, so it needs
  a Daytona-compatible convention, not a Go struct tag.
- **Start:** `pkg/api/daytona/contract_test.go:960` is the gate any change
  must pass; `pkg/api/daytona/include_env_test.go` covers the existing
  opt-in.

## Metrics-scoped read-only token (security, `pkg/api` auth)

- **What:** add a read-only / metrics-scoped bearer token so a scrape
  credential can `GET /v1/metrics` (and read-only observability endpoints)
  but cannot mutate the cluster.
- **Why:** the investor-benchmark obs stack scrapes `/v1/metrics` with the
  full-access cluster PAT (`setup/obs/prometheus.yml.tftpl:14-16`), which is
  baked into the Prometheus config on `obs1` and into Terraform state. Any
  real Prometheus deployment wants this too: a leaked scrape token should
  not be able to create or destroy sandboxes.
- **Status:** still open. `/v1/metrics` is registered with full auth in
  `pkg/api/dashboard.go:27`. `requireAuth` (`pkg/api/middleware.go:103`)
  accepts the PAT (full operator access) or a control-plane user token. The
  open-source `controlplane.Noop()` rejects the latter, so open-source builds
  are PAT-only.
- **Caveat (why deferred):** eng review 2026-07-19 (Arch-4) accepted the
  PAT-at-rest risk for the disposable itest cluster.
- **Start:** `pkg/api/middleware.go` + the token model. The obs scrape is the
  first consumer.

## Native per-runtime metric labels (observability, `internal/service` + `internal/pool`)

- **What:** add a `runtime=` label to the native create-latency metric so
  per-runtime slicing works from Prometheus directly.
- **Status (partly changed):** the §9 create-stage instrumentation this
  depended on has landed (`3e6fa2e6`):
  `aerolvm_create_stage_latency_seconds_bucket`
  (`pkg/createtiming/metrics.go:12`), keyed by stage only. But
  `aerolvm_create_latency_seconds_bucket` is still a plain
  `scaleobs.NewDurationBuckets` with no runtime key
  (`internal/service/metrics.go:24`, observed at :111). The pool hit/miss
  half is moot, because each runtime's pool already has its own metric name
  (`aerolvm_docker_pool_*`, `aerolvm_vmm_pool_*`, `aerolvm_wasm_pool_*`,
  `aerolvm_isolate_pool_*`). `internal/pool/containerdpool/` exports no pool
  metrics at all.
- **Why:** eng review 2026-07-19 (CM-2). The benchmark works around the gap
  by pushing runtime-labeled `benchReport` metrics to a Pushgateway. A real
  operator dashboard wants native per-runtime observability.
- **Caveat:** hot-path server work (extra expvar cardinality + a label on
  the create path); needs its own pr-review and regression test. Watch
  histogram cardinality (runtime × `le_*` buckets).
- **Start:** `internal/service/metrics.go`; consider containerd pool metrics
  alongside.

## A scenario destroy can need two passes (integration harness)

- **What:** retry the teardown inside `integration-tests/run.sh`, or make the
  failure say what it could not delete, and make the exit code reflect it.
- **Why:** observed 2026-09-23 tearing down `single-node` with
  `secret_kms_enabled = true`. The first destroy left 3 resources; an
  immediate identical re-run destroyed them, so it is a transient (most
  likely eventual consistency around the KMS key or an IAM detach), not a
  config error.
- **What the code does (2026-10-06):** `teardown` runs one
  `terraform destroy` (`run.sh:312-322`). On failure it prints "run 'make
  integration-reap'" to stderr and returns. `--destroy-only` then exits 0
  regardless (`run.sh:325-329`), so a failed teardown cannot be detected
  from the exit code.
- **Caveat (why it matters):** `make integration-reap`
  (`scripts/integration-reap.sh`) terminates **EC2 instances only**, not the
  VPC, IAM roles, S3 buckets or KMS aliases. That scope is documented
  (`Makefile:602-604,611-612`, `run.sh:118-120`), but the failure message
  (`run.sh:321`) and the `--keep` message (`run.sh:308`) still point at reap
  instead of `make integration-destroy` (`Makefile:608`). The audit bucket's
  3-day expiry (`Terraform/audit_export.tf:48-50`) exists as a backstop for
  this.
- **Start:** one bounded retry in `teardown`, surface terraform's own error,
  propagate a non-zero exit from `--destroy-only`, and point both messages at
  `make integration-destroy`. The root cause was never captured (the output
  went through a pipe), so keep the full log on the next KMS-enabled
  teardown.
- **Depends on:** nothing.

## NVMe instance-store data-dir option (infra)

- **What:** an optional bootstrap that mounts an instance-store NVMe
  (c5d/m5d/m6id) at the sandboxd data dir (`/var/lib/sandboxd`,
  `Terraform/templates/bootstrap.sh.tftpl:817`) when present.
- **Already possible:** the io2 half of the original idea. The data dir
  lives on the root volume, and Terraform already supports io2 there
  (`default_volume_type` / `default_volume_iops`,
  `Terraform/variables.tf:170-180`; per-node `volume_type`,
  `Terraform/nodes.tf:24-28,250-254`; since `427f923b`).
- **Why:** gp3 fsync (~1ms) is the floor under every remaining fsync on the
  warm-create path: both Raft stores and the single-writer SQLite WAL behind
  `svc_persist` and the secrets ref. NVMe drops fsync to ~0.1ms (Raft commit
  ~1–2ms, `svc_persist` sub-ms); io2 is the safer middle (~0.5ms).
- **Caveat (why it needs its own plan):** it is **not
  semantics-preserving.** Instance-store evaporates on stop, and the data
  dir holds the local SQLite sandbox store too, not just Raft logs. A
  single-node loss recovers via rejoin, but a **full-cluster stop loses
  everything.** Gate the topology on the lost-quorum recovery runbook and
  document the durability trade in `Terraform/` docs.
- **Note:** `plans/nvme-datadir.md` was never written, although
  `plans/warm-create-latency-tier1.md:29,435`, the tier-1.5 plan (`:250`)
  and the tier-2 plan (`:223`) point at it. Write it before building.
- **Depends on:** nothing (operator opt-in). Split out of
  `plans/warm-create-latency-tier1.md` at eng review 2026-07-11.
- **Start:** `Terraform/templates/obs-bootstrap.sh.tftpl:15-35` already
  mounts an extra data volume for Prometheus and is a usable template. Add
  one optional NVMe bench scenario for the stretch gate (≤25ms).

---

## Done

Kept for the record. Each entry names the fix and where it lives.

### L4 splice drops the response after a client half-close — FIXED (egress P1-0)

- **Was:** `spliceConns` (`internal/service/l4proxy.go`) closed both sides
  as soon as the first direction ended. A client that sent its request and
  then half-closed its write side never received the response
  (netcat-style, some database and RPC clients). Found while testing the 3A
  extraction (2026-09-28). It applied to the wake / WASM / isolate mediator
  path and, with the flag on, the REDIRECT listener (`l4redirect.go:65`);
  started containers' raw TCP goes by kernel DNAT and never touched it.
- **Fix:** the splice and the connection limiter moved to
  `internal/netsplice` (egress plan P1-0, D12/D17) as `netsplice.Splice`
  (`splice.go:75`) and `netsplice.Limiter`. `Splice` waits for both
  directions, forwards each EOF as a `CloseWrite`, and closes both conns
  only when both are done, on a copy error, or on an optional idle timeout
  (`WithIdleTimeout`). It still copies raw conn to raw conn, so splice(2)
  applies. Both paths reach it through `proxyL4WakeConn`
  (`internal/service/l4wake.go:239`).
- **Tests:** `TestSpliceHalfCloseDeliversTheRest` (both directions),
  `TestSpliceIdleTimeout`, `TestSpliceWithoutIdleTimeoutWaits` and
  `TestSpliceWritesBufferedPrefixFirst` (the old
  `TestSpliceConnsWritesBufferedPrefixFirst` contract) in
  `internal/netsplice/splice_test.go`.
- **Residual:** the L4 wake proxy passes no idle timeout, because
  wake-proxied database connections legitimately sit idle for hours. A peer
  that half-closes and whose other side never closes now holds its active
  slot until it does, where the old code dropped it at once. The egress
  proxy passes an idle timeout.

### Enterprise boot can fail its own witness check (audit) — FIXED

- **Was:** `ValidateSecretAuditWitness` looked the witnessed head up under
  the node id `"standalone"` while the shipping path published it under the
  real cluster node id. An enterprise node failed closed at boot, and only
  intermittently, so it read as flake:

      secret audit witness mismatch:
        local_head="7334bf03cb2b4ab7bc858bba55a44e3c3fda66031837eb079026503240e7ce7b"
        witnessed_head=""

- **Fix:** the ship path uses `witnessNodeID()`
  (`internal/service/secret_audit_witness.go:509`, called at `:201`), which
  prefers `cfg.NodeID` (the value `pkg/daemon` builds the cluster from) and
  falls back to the cluster handle. The four read sites (`:299`, `:416`,
  `:478`, `:604`) go through `lastWitnessedHeadAny` →
  `witnessNodeIDCandidates()` (`:537`). That helper also tries the
  cluster-handle id, so receipts shipped before the upgrade still match.
- **Regression tests:** `secret_audit_witness_nodeid_test.go`, including
  `TestNoWitnessCallSiteReadsTheClusterHandleDirectly` (`:76`). The guard
  allows those two helpers and only scans the witness file. The audit
  exporter (`secret_audit_export.go:279`) still reads `c.SelfNodeID()` for
  batch ids. It is a different sink and not covered by the guard; whether it
  matters is unverified.

### A restarted seed could never rejoin the cluster — FIXED, PROVEN LIVE (UC-170 green ×3)

- **Was recorded as "Losing the seed"** (a title still cited by
  `integration-tests/suite/harness/usecases.go:569`). That diagnosis was
  wrong: the survivors elected a new leader and correctly evicted the seed.
- **Actual bug:** the seed runs `SB_CLUSTER_BOOTSTRAP=true` with no
  `SB_CLUSTER_PEERS`, and memberlist keeps no state across a restart. The
  restarted seed came back as a gossip island and stayed a lone Raft
  candidate forever, while its `/health` still said 200.
- **Fix (#487, `b62437dc`):** `internal/cluster/gossip_peer_cache.go`. Each
  node persists the gossip addresses of live control-plane peers
  (`<raft dir>/gossip-peers.json`, ≤8, never overwritten with an empty set),
  and the background rejoin loop dials configured ∪ remembered peers. They
  are not dialled on the boot path.
- **Tests:** `TestRestartedSeedRejoinsAfterEviction`
  (`gossip_peer_cache_test.go:199`) replays the live failure on loopback.
  Mutation-checked.
- **Proven live:** UC-170 passed on three T18 runs (both profiles).
- The readiness gap this exposed is still open (see the first open entry).

### Draining a node records no visible storage-retirement obligation — FIXED, PROVEN LIVE (UC-160 green)

- **Design:** one job per leaving node, opened by `opSetNodeDrainState` when
  the node still holds a sealed copy or is owed a delete. Uncordon withdraws
  it; an attestation discharges it; a delete ACK never closes it. Owners
  report a current total on a timer (every 30s when changed, every 5 min
  regardless). The leader replaces each owner's report (per-owner Seq
  rejects retries and reordering) and folds all reports into one Raft entry
  per second.
- **View:** `GET /v1/cluster/storage-retirements` returns `obligations`
  from the local FSM (`pkg/api/v1/routes.go:186`, `cluster_handler.go:1032`).
  An expected reporter with no report in 15 min is listed stale and the job
  is `complete: false`, never shown as all-clear.
- **Code (#495, `d51b30c3`):** `internal/cluster/storage_obligations.go`,
  `internal/service/storage_obligations.go`, and `internal/store`
  `SecretDeleteOwedByRecipient` (`store.go:6208`).
- **Status:** passed live on hetero-lite (`e65c9cbc`) and on both T19 metal
  scenarios (2026-09-28).

### Caddy route upsert does not retry a transport EOF — ROOT CAUSE FIXED (#595)

- **Was:** a hypothesis, from one EOF seen under self-inflicted churn, that
  `upsertRoute` should retry a dropped admin connection.
- **Confirmed and fixed at the cause:** #595 (`e8203405`) saw the EOF on the
  live cluster-hetero run of 2026-10-04. Two concurrent admin writes were
  involved, and a request rode a keep-alive connection that the previous
  reload had closed. The fix:
  - one admin mutex serializes all config writes
    (`pkg/caddy/admin_lock.go:46`, `do()` in `batch.go:90`);
  - admin keep-alives are disabled (`admin_lock.go:83`);
  - the reconcile pool runs one worker (`ingress_metrics.go:26`);
  - the cluster ingress reconcile retries transient admin errors after
    500ms (`internal/service/ingress_delta.go:319`,
    `IsTransientAdminError`).
- **Not done, deliberately:** `upsertRoute` / `sendJSONDetail` still do not
  retry inline. With the cause gone, an inline retry of a PATCH that may
  have landed would be untested code on the boot path. Reopen only if an EOF
  recurs on the flag-off `start` / `expose_port` path.

### Promote-fail rollback can leave a ghost Placed row (cluster) — FIXED

- **Was:** promote-fail rollback in `cluster_handler.go` used
  Destroy+CancelReservation only. `CancelReservation` is a no-op on Placed,
  so an errored-but-committed Raft place left a ghost row until reconcile
  (~5 min).
- **Fix (Tier 1.5, then reworked in `8afaf50d`):** every promote-fail path
  calls `svc.DestroySandbox`, which deletes the placement only when owner
  and incarnation still match (`DestroySandbox` →
  `deleteSelfOwnedClusterPlacementStrict` → `c.DeletePlacementExact`,
  `internal/service/service.go:2935`, `:3138`, `:3173`). The overlapped path
  is `retractFailedPromote` (`pkg/api/clustercreate/overlap.go:306`). The
  sequential self-wins path is `RollbackLocalCreate`
  (`pkg/api/clustercreate/clustercreate.go:461`, called at
  `pkg/api/v1/cluster_handler.go:269`). The comment at
  `cluster_handler.go:192` still says "uses DeletePlacement" and is stale.
- See `plans/warm-create-latency-tier1.5-seal-promote-overlap.md`.

### cluster_promote is recovery-replication-bound, not fsync-bound (latency) — CLOSED

- **Was:** `cluster_promote` p50 was 23–25ms because every apply
  synchronously PUT the recovery blob to every other member. Warm
  `create;dur` failed the ≤30ms Tier 1 gate at 40–44ms.
- **Fix:** inline secret-free recovery payloads in the Raft command
  (`plans/warm-create-latency-tier2-recovery-replication.md`, PR #307). The
  blob emit path was later removed entirely (next entry), so the
  `inlineRecoveryEligible` gate and externalize metric no longer exist.
- **T4 bench (2026-07-12, v0.6.0, 3× t3.medium, all-WAL, netlink):**
  `cluster_promote` p50 **23–25ms → 10–11ms**. Warm `create;dur` p50
  **28ms sparse (gate PASS) / 32ms burst**. The remaining 10–11ms is the
  Raft round itself. Shaving below ~8ms is a Tier 3 shape and only matters
  if the 2ms burst overshoot does.

### Remove the legacy recovery-blob emit path (inline-only recovery) — DONE 2026-07-12

- **Deleted (`c9fabce4`):** the eligibility gate, blob emit + member PUT
  fan-out, `command.SealedSecrets` / `Name` / `RecoveryRef`,
  `PlacementSecrets.LegacySealed`, `Placement.SealedSecrets`,
  `SealedSecretsOf`, command-level `hydrateCommandRecovery`, the legacy
  `openPlacementSecrets` branch and the externalize metric. That was a net
  ~1,650 lines removed.
- **Kept:** blob GET + `fetchRecoveryBlob` + `resolveRecoveryRef`
  fetch-on-miss and the local recovery store, pinned by
  `TestFSMSnapshotJoinFetchOnMiss`
  (`internal/cluster/fsm_snapshot_join_test.go:21`).
- **Product rule:** in cluster mode, specs whose recovery record encodes
  >4KiB are rejected at create with a clean 400
  (`cluster.ErrRecoveryPayloadTooLarge`,
  `internal/cluster/recovery_replication.go:25,32`). Single-node has no cap.
  "No secrets in the Raft log" is structural.

### netrules Manager mutex head-of-line blocking — DONE (PR #306)

Shipped as per-IP refcounted locks in `pkg/docker/netrules/manager.go`
(`lockIP`, :145; `0fbe7a92`). Same-IP Exists+Insert mutual exclusion is
preserved; different IPs no longer serialize. See `ip_lock_test.go`. A stale
duplicate of this entry, still written as open, was removed on 2026-10-06.

### netrules backend switch on iptables-legacy hosts — DONE

Counter parity (`translator_linux.go`) makes exec↔netlink cleanup
interoperate on iptables-nft hosts. On iptables-legacy hosts, sandboxd logs
a boot warning when `SB_NETRULES_BACKEND=netlink` meets a legacy iptables
(`netrules.WarnIfLegacyIptables`, `pkg/docker/netrules/legacy_check.go:29`,
wired at `pkg/daemon/daemon.go:173`). The drain-before-switch procedure is
in `setup/single-node.md:199` and `packaging/.env.template`. That template's
lines 16 and 22 still describe `exec` as the default, which is stale (see
next entry).

### netlink live enforcement probe + bench backend gate — DONE; default flipped to netlink

- **UC-98** (`integration-tests/suite/netrules_test.go:42`): an egress deny
  rule must drop real traffic from inside the sandbox. PASS on netlink on the
  T4 bench cluster (2026-07-12).
- **Bench backend gate:** the `aerolvm_netrules_backend` expvar
  (`pkg/docker/netrules/metrics.go:12`) plus `AEROL_BENCH_EXPECT_NETRULES`
  confirmed netlink on the burst, sparse and suite-load runs.
- **Follow-up done:** the server default `SB_NETRULES_BACKEND` flipped
  exec → netlink in `0dd6589f` (`internal/config/config.go:1663`,
  `setup/config-defaults.md:27`).

### Flaky `internal/cluster` memberlist tests (testing) — mitigated 2026-08-08

- Construct/Close of real raft/memberlist harnesses is serialized by
  `testClusterMu` (`internal/cluster/cluster_test.go:231`), with a 50ms
  settle after Close (`:283`). It is used by `newTestClusterWithAPI`,
  `newTestClusterWithRole`, `newTestAgentWithRole`,
  `newTestClusterWithRoleAndGrace`, `newTestClusterWithTLSDir`,
  `newTestAgentWithTLS` and `gossip_peer_cache_test.go`. The lock is not
  held for a cluster's lifetime.
- **Verify:** `go test -count=1 ./internal/cluster/` (`-count=3` if
  chasing). If flakes return, widen the settle or serialize the whole
  short-lived gossip pair.

### Per-node identity for cluster-internal HTTP (security) — landed 2026-09-02

Every cluster role exposes a dedicated TLS 1.3 internal listener. Clients
pin the peer to a required `node:<SB_NODE_ID>` SAN, servers bind that
identity to live membership, and every delegated route is authorized before
dispatch; the fleet PAT remains defense in depth. Leaf/key files hot-reload,
and expiry metrics and alerts exist. Automated issuance, revocation
distribution and coordinated CA rotation remain operator work. Code:
`internal/cluster/{tls,internal_server,peer_dial}.go`. Docs:
`docs/src/content/docs/cluster-secrets.mdx:85-89`,
`setup/runbooks/secrets-and-audit.md:64`,
`docs/designs/secrets-hardening.md` (Deferred),
`plans/secrets-hardening.md` re-review row 6.

### Durable secret-delete outbox / ACK ledger (cluster secrets) — landed 2026-08-09

Generation-scoped tombstones plus a persistent cleanup outbox
(`cluster_secret_tombs`, `cluster_secret_delete_outbox`,
`internal/store/store.go:202,211`) mean peer DELETE fan-out survives a
daemon crash. It retries until every recipient ACKs, and stale PUTs are
rejected until a newer seal generation clears the tomb. It reconciles at
boot and every 30s (`pkg/daemon/daemon.go:705-732`). `failover_ready`
HEAD-probes remote holders for the current `seal_generation`, and a member
rejoin triggers a reconcile narrowed to that member (`922e8fa2`; see the
open "Rejoin outbox sweep" entry for its residual). Long partitions still
need operator action using the outbox age/backlog metrics. Code:
`internal/service/cluster_secrets.go`,
`internal/cluster/secret_replication.go`.

### WASM egress audit via bounded IPC (not shared JSONL) — landed 2026-09-02

Worker subprocesses send egress audit events to the daemon's authoritative
audit writer instead of opening `secrets.jsonl` themselves. The daemon side
is `internal/service/audit_ingest.go` (`StartAuditIngestServer` :61,
`handleEgress` :272). It listens on loopback TCP
`127.0.0.1:SB_AUDIT_INGEST_PORT`, not a Unix socket, and requires a
per-sandbox capability. A bounded worker pool acknowledges events durably
and counts gaps under overload. When the endpoint is unavailable, workers
append to a shared spill file (`auditlog.SpillFile`) that the daemon drains
(`pkg/wasm/worker/egress_audit.go:21-25`). The worker side is
`pkg/wasm/worker/egress_audit.go`, with the environment passed at
`pkg/wasm/worker/supervisor.go:54`.
