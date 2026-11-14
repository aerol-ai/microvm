# TODOS

Deferred work items with enough context to pick up cold. Each entry says
what, why, the caveat that motivated capturing it, and where to start.

Open items come first, grouped by area. Finished items are kept at the end
under **Done** as a record of what was decided and where the code lives.
Code comments and plans cite entries by title, so keep titles stable.

Every entry was re-verified against `main` at `704c9e74` on 2026-10-06.
`file:line` references are as of that commit.

---

## An orphaned recreate-policy sandbox answers 410 while it waits for room (API, cluster)

- **What:** a `failover.policy=recreate` sandbox orphaned because no node had
  room when its owner died is now retried until a node has room (R14,
  `internal/cluster/orphan_recovery.go`, `retryOrphanedRecoveries`). While it
  waits, `OwnerOf` still returns `ErrOrphaned`, which the API answers as
  410 Gone (`internal/cluster/client.go`, `OwnerOf`; `internal/cluster/agent.go`,
  `OwnerOf`). A client reading 410 as "gone for good" may delete it or make
  a new one.
- **Why:** R14 made the wait temporary; the answer still says permanent.
- **Fix sketch:** for an orphan whose hot row has `FailoverRecreate`, answer
  503 with Retry-After ("waiting for a node with room") instead of 410, in
  both lookups and in the error classifier. Keep 410 for every other orphan.
- **Effort:** human S / CC S. **Priority:** P2.

---

## A reused sandbox ID drops the old lifetime's WASM push rows (cleanup obligations)

- **What:** `finalizeStaleLocalSandbox` (`internal/service/service.go`)
  bulk-deletes the WASM checkpoint push rows of an old lifetime when the ID
  is reused. Those rows are the only record of manifests in the registry,
  the same obligation R8 kept when no pusher is configured.
- **Why:** seen while fixing R8 (#1273); left alone because the path is
  cluster-sensitive.
- **Fix sketch:** keep the rows that name a ref until the orphan-ref sweep
  deletes their manifests, as `wasm_cleanup.go` now does without a pusher.
- **Effort:** human S / CC S. **Priority:** P2.

---

## The chart does not set shard-aware ingress for more than 10 gateways (ingress)

- **What:** with `SB_CLUSTER_SHARD_AWARE_INGRESS=false` a daemon refuses or
  degrades above `MaxReplicatedIngressRouteNodes` (10) ingress nodes. The
  chart sets ingress proxy routing but not shard-aware ingress, and a plain
  load balancer in front of more than 10 gateways sends most connections to
  a gateway without the route (`plans/data-plane-load-balancer.md`).
- **Why:** from the 2026-11-13 review's scale table (100 ingress). The
  operator now honours `maxReplicas` (#1272), but nothing renders the
  shard-aware path.
- **Fix sketch:** a chart value that turns on shard-aware ingress together
  with a documented shard-aware load balancer contract, refused when
  gateways exceed 10 without it.
- **Effort:** human M / CC S. **Priority:** P2.

---

## Advisory cleanups from the 2026-11-13 Kubernetes review (maintainability)

- **What:** six refactors the review marked advisory. None changes behaviour:
  1. one artefact GC helper (list, reference check, delete) for templates,
     WASM modules, built and pending images and isolate bundles
     (`template.go`, `wasm_module_health.go`, `service.go`,
     `isolate_bundle_gc.go`);
  2. isolate bundle GC through `startPeriodic` (cancel race, per-tick
     timeout) instead of its own ticker;
  3. one artefact-GC settings profile, with overrides only where a TTL must
     differ, instead of a set of `SB_*_GC_{ENABLED,INTERVAL,TTL}` per runtime;
  4. the operator's decommission states as a thin driver of the cluster's
     cordon and evacuate answers (`operator/internal/controller/decommission.go`);
  5. one `EvacuateRequest`/`EvacuateResult` wire type shared by
     `operator/internal/aerolapi` and `internal/cluster/decommission.go`;
  6. drop the one-method `NodeEvacuator` interface if only `*Cluster`
     implements it.
- **Why:** the review asks for shared machinery, not merged tables: the
  separate tables (`firecracker_tap_pool`, `firecracker_vmm_pool`,
  `container_netns_slots`, `firecracker_templates`, `wasm_modules`,
  `wasm_state_kv`, `wasm_checkpoint_pushes`) are justified and stay.
- **Effort:** human M / CC M. **Priority:** P3.

---

## Security addenda from the 2026-11-13 Kubernetes review (Kubernetes, security)

- **What:**
  - the chart lets `containerdVolume` be a hostPath (`charts/aerolvm/values.yaml`),
    against the plan's "no hostPath";
  - signed-image enforcement is an example Kyverno policy, not a chart
    default;
  - the pod and Service ranges go to workers as a private default that an
    egress profile may open (`operator/internal/controller/egress.go`,
    `setEgressRanges`). The API server's own addresses are in the deny floor,
    which nothing opens, and since R4 (#1272) a failed discovery no longer
    leaves that floor empty; what is left is to check that the API server
    answers on no address found only in the private default;
  - the worker-pod guard allows a delete when it cannot read the pod's
    AerolNode (`operator/internal/webhook/podguard.go`). This is intended with
    `failurePolicy: Ignore`, but it widens what a guard outage allows.
- **Why:** listed by the review as gaps against plan promises, not new P0s.
- **Fix sketch:** refuse a hostPath `containerdVolume` unless a bank preset
  opts out; ship the image policy as an opt-in chart value; a test that every
  API server address the operator finds lands in the deny floor; record each fail-open in the
  "lost without decommission" alert's labels.
- **Effort:** human M / CC S. **Priority:** P2.

---

## A worker's lease renewed without a read covers a sandbox started later (cluster)

- **What:** a worker with no running `failover.policy=recreate` sandbox keeps
  its ownership lease without asking the leader
  (`internal/service/ownership_lease.go`, `confirmOwnership`: "nothing to
  confirm"). If it is cut off from the servers and one of its recreate
  sandboxes then starts there (a stopped one started again, or a create whose
  image pull finishes), that sandbox runs on a lease the leader never saw, past
  the grace, while the leader recreates it elsewhere: two copies.
- **Why:** found while proving C19 live on kind (2026-11-12). C19's early
  failover now refuses a node that was not reading until the leader last
  heard from it, which closes it there except for a node whose recreate
  sandboxes all stopped within one read interval (about 6 s) of being cut
  off. The dead-owner grace path reaches it with no such limit, as on main
  before Phase 2.
- **Fix sketch:** a renewal without a read must not extend the lease; a
  recreate sandbox that starts on a node whose lease is older than the lease
  needs one authoritative read first (one leader round trip, only the first
  start after the node was idle). That touches the boot path: use
  `/touch-create-sandbox`.
- **Effort:** human M / CC S. **Priority:** P1.

---

## The snapshot list is node-local on a cluster (API)

`GET /v1/snapshots` (`pkg/api/v1/snapshot.go` `listSnapshots`) reads only the
answering server's own store; unlike `GET`/`DELETE /v1/snapshots/{id}` it has no
`snapshotForwardWrap` and no owner fan-out. On a cluster the API usually lands
on a server or the ingress, which holds no sandboxes, so `aerolvm get snapshots`
(and the older `aerolvm snapshot` list) shows nothing for snapshots made on
workers, while get, describe and delete by name work.

Found 2026-11-09 by an unfiltered live run of the kubectl cases (UC-674) on
cluster-join-token and cluster-rollout-join. UC-674 now skips its list checks on
a cluster. Fix: page the list across owners the way the sandbox list does
(`internal/clusterlist`), or list from the Raft artifact catalogue, then drop
the skip.

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
  e.g. an `itestretention` build tag that lets retention be expressed in
  minutes (the `itestwitness` tag that set that precedent is gone: the
  enterprise scenarios now use the S3 witness and the shipped daemon). Do not
  relax the enterprise validator for it.

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

## Ingress route changes reset in-flight TLS connections on :443 — IMPLEMENTED behind `SB_INGRESS_PROXY_ROUTING`; default on (Go, install.sh, Terraform null)

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
- **The gate moved (`plans/cluster-phase-2.md` §4.2):** from the metal
  flagship to `cluster-hetero-lite-routing` (8 × t3.medium), with the test
  binary on one of its server nodes rather than a laptop, so neither the
  laptop's network nor its SSH and DNS blips are in the numbers
  (`integration-tests/scripts/run-on-node.sh`). Churn: UC-171 and UC-357
  with 0 failed connections. A/B: UC-171 records expose-to-first-200 and
  p50/p99 of fresh-connection requests; run it flag on, flip every node off
  (`integration-tests/scripts/routing-ab.sh <scenario> off`), run again, flip
  back, and repeat the pair once (t3 CPU credits add noise). Pass: flag-on
  p50/p99 no worse than flag-off beyond that noise. The commands are in
  `integration-tests/README.md`, "Routing gate from inside the VPC".
- **Default on where it applies:** `internal/config/config.go` defaults the
  flag on and clears it on a node without a Caddy domain (no ERROR, no
  probe). `scripts/install.sh` turns it on for a `--domain` install
  (`--no-ingress-proxy-routing` for off). Terraform's
  `default_ingress_proxy_routing` is nullable (the owner's answer to
  `plans/cluster-phase-2.md` §8, question 1): null, the default, passes no
  flag and renders the same user data as the old default false, so no
  running node is replaced and new nodes come up on; `true` or `false`
  passes an explicit flag. `cluster-chaos` pins false (its cases were proven
  against the page walk); the three routing scenarios set true; every other
  domain scenario now runs with routing on.
- **Why it matters (cluster-bank-flagship, 2026-11-01, flag off):** UC-230
  and UC-266 exec-stream dials failed with `unexpected EOF`, 1 run in 20.
  Every create or destroy anywhere in the cluster made both dedicated
  ingress nodes write a `-ingress-sni` route, and each write reloaded Caddy:
  330 reloads in one hour on ingress-2.
- **Mechanism, confirmed against the release build** (Caddy v2.11.7 +
  caddy-l4 v0.1.2, `make test-ingress-reload-e2e`, Linux): a reload restarts
  every Caddy app, and new connections die two ways. (1) Go's `http.Server`,
  once `Shutdown` has begun, reads the next request on a connection it
  already accepted and returns without answering (`net/http`
  `conn.serve`), so the client sees TLS succeed, then zero bytes:
  `unexpected EOF` on a WebSocket upgrade. (2) Caddy binds a fresh
  `SO_REUSEPORT` socket per config and closes the old one, and Linux resets
  what was still queued on it: `connection reset by peer` or EOF in the TLS
  handshake. caddy-l4 itself does not cut connections it already accepted.
  At ~18 reloads/s: 2,053 of 33,241 exec-stream dials failed (1,765
  `unexpected EOF`); with a 20 ms RTT the resets dominate. The static routes:
  0 of 20,410. Neither mechanism has a Caddy knob, so the only fix is not
  reloading.
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
- **Resolver stalls under the flag (fixed, 2026-11-01):** the first flagship run with the flag failed UC-171 with 6 fresh HTTPS dials ending in EOF. caddy-l4's dial of `{sni}.rt.internal` timed out in systemd-resolved: resolved pins its socket for the `aerolvm-rt` link's DNS server to that dummy link, so UDP to the loopback responder was dropped, and every time it re-probed UDP (about 7, 19 and 70 minutes apart on the flagship) lookups stalled for about 20 s. Zero Caddy loads happened on any node in the suite. Fix: the link's DNS server is the link's own address (`SB_ROUTE_DNS_LINK_ADDR`), and the responder echoes EDNS0.
- **Containerd sandboxes froze after ~128 KiB of output (fixed, 2026-11-01):** the next flagship run (with the resolver fix) still failed UC-171, 2 dials timing out. Not routing: the target's `python3 -m http.server` blocked on its access log. sandboxd closed a containerd task's log file when Create returned, the FIFO copy stopped, and the task froze after ~128 KiB more output. It was reproduced live, stopping at 127 KiB, and froze for good from 47 s to about 5 min into a run depending on request rate. Also after any sandboxd restart: nothing re-attached to running tasks. Fix in `internal/runtime/containerd/logio.go`; live gate UC-360. Docker sandboxes were never affected, which is why the docker routing cluster passed UC-171.
- **Established WebSockets too (#712):** each reload also closed every
  WebSocket a `reverse_proxy` carried (exec streams, `aerolvm shell`, session
  attach) with code 1001 (UC-68 on `cluster-hetero-lite-secrets`,
  2026-10-16). The #712 fix sets `stream_close_delay 10m` on every proxy. The
  flag still matters: each stream that outlives a reload pins the old config.

## First boot Caddy config lacks S3 certificate storage

- **What:** make the first Caddy config an ingress loads already carry the
  S3 certificate storage, rather than adding it in a later reload.
- **Why:** T19 S6's first config (06:28:50) had no S3 storage. The cert jobs
  failed with "failed storage check: context canceled" and were not retried
  until Caddy reloaded with S3 storage at 06:33:35. At the same boundary
  sandboxd got a 500 installing the on-demand TLS policy ("on-demand TLS
  cannot be enabled without a permission module").
- **Update (2026-11-10):** the 500 was not storage timing. Since Caddy
  2.10, the TLS app checks automation policies before it turns the
  deprecated `ask` into a permission, so an on-demand policy behind `ask`
  alone always failed, and no custom domain got a certificate. Fixed:
  `EnsureOnDemandTLS` sends the `http` permission module (Caddy 2.8+), POSTs
  `on_demand` (PUT answered 409 whenever sandboxd restarted under a running
  Caddy) with a PUT fallback when its parent keys are missing, and appends
  the policy as a list to `policies/...` so it also works with no list yet.
  The boot log no longer promises a retry. Proven by `make test-acme-e2e`
  on Caddy 2.11.9.
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
- **Depends on:** `SB_INGRESS_PROXY_ROUTING` defaulting to true (on in Go
  and install.sh, still off in Terraform, see above), plus a soak of about
  one release cycle.

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

## Isolate orphan sweep survives a daemon restart (runtime) — part 2 — DONE 2026-11-08

- **Done by the WASM/isolate restart work (`fix/kops-wasm-isolate-restart`):**
  a group host now outlives sandboxd and keeps a record on tmpfs
  (`pkg/isolate/adopt.go`). At boot `workerdSupervisor.AdoptGroups` takes
  over the hosts whose workerd still runs and then
  `pkg/isolate.SweepLeftovers` kills every group-host process (the
  `aerolvm-isolate-hosts` cgroup, and each `aerolvm-isolate-<key>` jail
  cgroup) and removes every chroot no adopted host owns. It runs once, at
  boot, before any spawn, so there is no enumerate-while-spawning race.
  `Driver.ListManaged` stays the in-memory map: after boot it is complete.
- **Was:** give `internal/runtime/isolate` a host-backed enumeration so
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
- **Status: RESOLVED by the identity-and-access stack**
  (`plans/identity-and-access.md`, CEO review D6), **with a caveat.**
  `/v1/metrics` now needs the `metrics.read` permission, which every role
  holds when it is bound to every team (`*`). The scrape credential is a
  `viewer` API token on `*`
  (`aerolvm token create --name prometheus --role viewer --team '*' --expires-in 90d`),
  set as the optional Terraform `cluster.metrics_token`; when it is empty
  the scrape keeps using the PAT (`setup/obs/prometheus.yml.tftpl`).
  `/debug/vars` stays admin-only. A stale token mirror still accepts
  `metrics.read`, so worker metrics keep flowing through a server-tier
  outage (D16).
- **Caveat (D6): the credential is read-only, not metrics-only.** A `viewer`
  on `*` can also read every team's sandbox metadata and audit records. It
  can never create, exec, delete or read env. A true metrics-only scope
  would need a fifth role or per-route scopes, which the plan rules out for
  v1 (four fixed roles). Reopen only if a buyer needs a scrape credential
  that cannot read audit records.
- **Docs:** `docs/src/content/docs/enterprise/sso.mdx`,
  `setup/obs/README.md`, `setup/runbooks/identity-and-access.md`.

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

## Per-node witness write scoping (v2 layout) (security, audit witness)

- **What:** let IAM confine each node's witness writes to its own path by
  putting the writer's AWS identity (`${aws:userid}`) in the witness key.
- **Why:** the open audit witness shares one node role across a cluster, so
  a compromised node can write into another node's witness history. The
  victim refuses its next restart, the offline verifier blames the victim,
  and attribution needs CloudTrail S3 data events. Accepted as a documented
  v1 limit at eng review 2026-10-11 (`plans/open-audit-witness.md`, R7/D8).
- **Pros:** closes the cross-node DoS structurally and gives attribution
  without CloudTrail.
- **Cons:** a v2 key layout with a dual-read migration, one more boot call
  (`sts:GetCallerIdentity`), a data volume moved to a new instance fails
  closed, and S3-compatible stores need a static writer segment.
- **Start:** the cluster-join rendezvous already scopes writes with
  `${aws:userid}` (`Terraform/iam.tf:97-112`). `witnessNodeIDCandidates`
  (`internal/service/secret_audit_witness.go:522-549`) is the precedent for
  reading an old and a new key during the migration.
- **Effort / priority:** M, P3.
- **Depends on:** open audit witness v1 (Phases 1–5 of
  `plans/open-audit-witness.md`) shipped.

---

## GCP Cloud KMS and Azure Key Vault key providers (security, key custody)

- **What:** add `gcpkms` and `azurekv` providers on the `DataKeyWrapper`
  seam (`pkg/secrets/kms.go:16-19`), next to `awskms`, `vault` and `pkcs11`.
- **Why:** customers on Google Cloud or Azure keep their keys in those
  clouds' key services. Deferred at CEO review 2026-10-20
  (`plans/customer-key-custody.md`, CEO-E5): no GCP or Azure customer has
  asked, and the live test harness only knows AWS.
- **Pros:** native key custody on every major cloud; Cloud KMS is what a GKE
  Marketplace listing would expect.
- **Cons:** each needs its own cloud account, credentials and harness
  support before the docs can say "tested".
- **Start:** copy `pkg/secrets/awskms.go` (narrow client interface plus
  error mapping) and run `testProviderContract`
  (`pkg/secrets/provider_contract_test.go:17`) over the new wrapper. Bind the
  encryption context as AAD (Cloud KMS `additionalAuthenticatedData`).
- **Trigger:** the GKE phase of `plans/kubernetes-deployment.md` for Cloud
  KMS; a named Azure customer for Key Vault.
- **Effort / priority:** M each (L with test accounts), P3.
- **Depends on:** `plans/customer-key-custody.md` Phase 1 (seam split and
  provider tags).

---

## HSM signing of audit chain heads (security, audit witness)

- **What:** sign each witnessed audit chain head with a PKCS#11 key the
  daemon cannot read, and have `aerolvm audit verify` (`cmd/aerolvm/audit.go`)
  check the signatures, with a dual-read for old unsigned heads.
- **Why:** a compromised node can still write a new head that matches a
  rewritten chain; a signature from a key it cannot read stops that. This is
  the second follow-up in `plans/secrets-hardening.md:1014` and a non-goal of
  `plans/open-audit-witness.md`. Deferred at CEO review 2026-10-20
  (`plans/customer-key-custody.md`, CEO-E6) so the key-custody stack does not
  change a just-shipped evidence format.
- **Pros:** forged heads fail the verifier even after a full node compromise.
- **Cons:** a new signed-head format and verifier dual-read; needs its own
  plan and eng review.
- **Start:** reuse the PKCS#11 session pool from `plans/customer-key-custody.md`
  Phase 3; the witness writer is `internal/service/secret_audit_witness.go`.
- **Effort / priority:** L, P3.
- **Depends on:** `plans/customer-key-custody.md` Phase 3 merged.

---

## A cancelled warm-pool park can leave its slot's container (containerd)

- **What:** the containerd warm pool's park path
  (`internal/runtime/containerd/warm_park.go`) undoes a failed park on the
  request context, the pattern "fix(containerd): undo a failed create even
  when its client hung up" removed from `Driver.Create`. A park cancelled
  mid-way can leave its slot's container until the orphan sweep.
- **Why it is only a TODO:** slot IDs are fresh (`park-*`), so no create or
  retry ever collides with one; it costs a container until the sweep, not a
  failed call.
- **Status (2026-11-06):** the create-side leftovers this came from are
  fixed in the parity stack: the undo runs on `undoContext`, and a keyed
  create that still meets a leftover (a hang-up inside Docker's
  `/containers/create` or containerd's `NewContainer`) removes it under the
  create lease and creates again (`internal/service/create_leftover.go`).
- **Fix:** run the park undo on a context like `undoContext`.
- **Effort / priority:** S, P3.

---


## Enforce the ownership lease when sandboxd is down on a VM (cluster correctness, P1)

- **What:** a small host-side lease watchdog (its own systemd unit, outside
  `sandboxd`'s cgroup) that stops this node's sandboxes when the ownership lease
  expires without renewal, plus a regression test that keeps `sandboxd` down past
  the lease and checks no sandbox runs twice.
- **Why:** the ownership lease (invariant I1, one executor) is enforced only
  inside `sandboxd` (`internal/service/ownership_lease.go:193-197`). containerd
  sandboxes are not in `sandboxd`'s unit cgroup, so they outlive it. After 10
  crashes in 5 minutes systemd stops restarting `sandboxd`
  (`scripts/install.sh:2826-2827`), and failover then recreates its `recreate`
  sandboxes elsewhere while the originals keep running. Found by the outside
  voice in the 2026-11-10 CEO review of `plans/kubernetes-v2-architecture.md`,
  whose C7 fixes the same hole for pods.
- **Pros:** closes a real break of a shipped correctness rule; shares its design
  with the plan's C7 (the `runtime` supervisor's lease check).
- **Cons:** one more unit on every node; touches the fragile cluster path.
- **Effort:** human M / CC S. **Priority:** P1.
- **Depends on:** nothing. Can share code with C7 when the Kubernetes work starts.
- **Start:** `internal/service/ownership_lease.go` (`StartOwnershipLease`) and
  the systemd unit in `scripts/install.sh` (around line 2809). C7's T3 built
  the pod version to reuse: sandboxd writes `SB_OWNERSHIP_LEASE_FILE`
  (`internal/ownerlease`), and `internal/supervisor/lease.go` (`LeaseGuard`)
  freezes `<cgroup parent>/<ref>` when it runs out and thaws only on proof.

---

## Design a pod mode for banks that refuse privileged pods (Kubernetes, P2)

- **What:** a worker mode where each sandbox is its own Kubernetes pod, made
  through the Kubernetes API or through agent-sandbox underneath, with
  AerolVM's API, SDKs, sessions and audit on top.
- **Why:** `plans/kubernetes-v2-architecture.md` §20 says a bank that refuses
  privileged pods gets "No worker at all". Spike S9 (§8.7, the worker pod in a
  Kubernetes user namespace) may remove the privileged pod. If it fails, pod
  mode is the only way such a bank can run AerolVM.
- **Pros:** no privileged pod; every Kubernetes tool sees each sandbox.
- **Cons:** loses the speed and density the plan exists for (option A in §5:
  seconds to start cold, etcd writes per sandbox, 110 pods per machine); rule
  K5 does not hold in that mode; egress control needs a new home, because
  there is no worker firewall.
- **Effort:** design first, human M / CC S. **Priority:** P2.
- **Depends on:** spike S9's result. Trigger: a bank refuses privileged pods
  and S9 fails on its machine image.

---

## Propose a controller-class field upstream in agent-sandbox (Kubernetes, P2)

- **What:** open an issue/KEP in `kubernetes-sigs/agent-sandbox` for a
  `spec.controllerName` class field (precedent: IngressClass, GatewayClass) so
  several backends can serve `agents.x-k8s.io` objects in one cluster.
- **Why:** D5 (`plans/kubernetes-deployment.md`, kept by
  `plans/kubernetes-v2-architecture.md` §16) makes AerolVM serve the
  agents.x-k8s.io API in place of the upstream controller, and the chart refuses
  to install next to it.
  A customer therefore cannot run upstream gVisor sandboxes and AerolVM
  sandboxes side by side. A class field removes that for every backend (Mitos
  included) and puts AerolVM in the upstream conversation.
- **Pros:** removes the main adoption caveat of the facade; SIG Apps visibility.
- **Cons:** the upstream timeline is out of our control; design discussion, not code.
- **Effort:** human S / CC S. **Priority:** P2.
- **Depends on:** the agent-sandbox API (`plans/kubernetes-v2-architecture.md`,
  C17, Phase 6, CEO review RQ10) existing, so the proposal can cite a real
  second backend.
- **Start:** the agent-sandbox issue tracker; cite GatewayClass
  `controllerName` semantics.

---

## `aerolvm apply -f` and a manifest shared with the Kubernetes operator (CLI)

- **What:** `aerolvm apply -f sandbox.yaml`, and an `-o yaml` object shape
  (`apiVersion`, `kind`, `metadata`, `spec`, `status`) that is the same as the
  `Sandbox` object AerolVM serves to `kubectl` (`agents.x-k8s.io/v1beta1`,
  `internal/kubeapi`), so one YAML file works with `aerolvm apply` and
  `kubectl apply`.
- **Why deferred:** CEO review of `plans/kubectl-style-cluster-ops.md`
  (D3, 2026-11-07). The format had to match the CRD shape the Kubernetes v2
  plan would pick (its Q1: implement `kubernetes-sigs/agent-sandbox` or own
  CRDs), which was still open on PR #522. Picking a format first risked a
  rename that breaks saved files.
- **Status (2026-11-14):** ready to start. The Kubernetes v2 plan picked the
  agent-sandbox API, and AerolVM serves it (C17 in
  `plans/kubernetes-v2-architecture.md`, built 2026-11-13). `aerolvm apply`
  does not exist yet.
- **Where to start:** `plans/kubectl-style-cluster-ops.md` D12 and §3.3;
  `cmd/aerolvm/verbs.go` (today's `get` and `create`); `internal/kubeapi`
  (the `Sandbox` object's shape).

---

## External-CA mode for cluster joins on VMs (security, cluster PKI)

- **What:** `sandboxd init --external-ca` keeps the cluster CA key out of
  the cluster. A join then waits as a pending CSR until
  `aerolvm certificate approve <id>` or an outside signer signs it.
  `aerolvm get csr` lists pending CSRs.
- **Why deferred:** CEO review of `plans/kubectl-style-cluster-ops.md`
  (D4, 2026-11-07). The default path (CA key on server nodes, like kubeadm)
  already makes joining one line, and this mode can be added later without
  changing it. It would add a pending-CSR record in Raft and a second
  signing path to the riskiest phase.
- **Status (2026-11-14):** built for Kubernetes installs only, as C23
  (`plans/kubernetes-v2-architecture.md` §15.2.1, #1252 to #1258): the
  bank's issuer signs each pod's certificate through cert-manager, the pod
  joins with that certificate (`JoinByCert` in
  `internal/cluster/join_cert.go`), and the CA key never enters the
  cluster. On VMs it is not built: `sandboxd init --external-ca` works only
  with `--files-only`, and there is no pending-CSR flow (`aerolvm
  certificate approve`, `aerolvm get csr`). A VM version can reuse C23's
  join by certificate instead of a pending CSR in Raft.
- **Start when:** a customer running on VMs needs the CA key outside the
  cluster.
- **Where to start:** `plans/kubectl-style-cluster-ops.md` D5, §4 and §8;
  `plans/kubernetes-v2-architecture.md` §15.2.1; `cmd/sandboxd/node.go`
  (`--external-ca`); `internal/cluster/join_cert.go`;
  `internal/cluster/tls.go` (cert checks and reload).

---

## Done

Kept for the record. Each entry names the fix and where it lives.

### A forwarded control-plane 4xx reaches the API caller as 500 (API) — FIXED

- **What:** when a gateway or worker forwards a control-plane call to a
  server and the server refuses it with a 4xx, the caller gets HTTP 500
  with the server's status in the message: "cluster control-plane request
  failed with status 412: …" (`internal/cluster/agent.go`, `statusError`;
  the API's error writer does not know that type, so it answers 500).
- **Why:** seen live in run `c23-extca-3` (2026-11-13): a join-token
  request in external-CA mode is refused with 412 by the server, and the
  caller saw 500. The message is right; only the status is wrong, so a
  client cannot tell a refusal from a fault.
- **Caveat:** not every forwarded 4xx is the caller's: a 403 "cluster peer
  not in membership" is between nodes and must stay a 5xx (retryable) to
  the caller. Pass through only refusals about the request itself (400,
  404, 409, 412), and keep the rest as they are.
- **Where to start:** `statusError` in `internal/cluster/agent.go`, and
  `apihttp.WriteStoreAwareError`, which maps error types to statuses.
- **Effort:** S. **Priority:** P3.
- **Fixed** (2026-11-14): `cluster.ForwardedStatus` gives a forwarded
  refusal about the request (400, 404, 409, 412, 422, 429) its own status,
  in `cluster.JoinErrorStatus` and `apihttp.Classify`; a 401 or 403 between
  nodes, "peer not in membership", and every 5xx keep their old answers.
  Tests: `TestForwardedStatus`, `TestClassifyForwardedRefusal`.

### Decide the agent-sandbox facade's storage and namespace rules (Kubernetes, P2) — DECIDED and BUILT

- **What:** before C17 (`plans/kubernetes-v2-architecture.md` §16, Phase 6) is
  built, decide (1) where upstream `SandboxTemplate` and `SandboxWarmPool`
  records live, and (2) which sandboxes `kubectl get sandboxes -n X` shows and
  what deleting namespace X deletes.
- **Why:** the 2026-11-10 CEO review (RQ10) moved the facade out of the
  current phases and added no storage for those records, in Kubernetes or in
  AerolVM. The founder rule "no facade-specific tables" rules out a
  Kubernetes-only store inside AerolVM. Upstream puts `SandboxClaim` (one per
  sandbox) in the same group-version as templates and pools, so the whole
  group must be served by the aggregated API.
- **Options seen so far:** internal CRDs in etcd written by the gateways; a new
  AerolVM FSM kind (breaks the rule); serve only `Sandbox`. On namespaces:
  show and delete only what was created through the Kubernetes API, or
  everything the mapped owner has.
- **Effort:** design only, human S / CC S. **Priority:** P2.
- **Depends on:** Phase 3 of the Kubernetes plan being done.
- **Decided** (the user, 2026-11-13): templates and warm pools are
  Kubernetes CRDs; a namespace shows, and deleting it deletes, all of its
  owner's sandboxes. Built as C17 (#1233 to #1246); see the plan's §16.1.

### A partitioned node keeps serving: /health ignores cluster membership (readiness gap) — FIXED

- **Was:** a node with no raft leader, or not a raft member, still
  answered `/health` with 200, so the ingress kept routing traffic to it
  and every request that landed there failed (about one request in three
  in S3 `cluster-3-mixed-secrets-kms`, 2026-09-27). Failing `/health`
  instead would have taken the whole cluster out of rotation during any
  election.
- **Fix:** a separate `GET /ready` (Kubernetes v2 plan C1, the first
  plan's decision D8): `Service.Ready` (`internal/service/ready.go`) is
  `Health` on a single node; in cluster mode it is 503 when this server is
  not in the raft configuration or the node has had no proof of a working
  control plane for longer than `SB_READY_LEADER_GRACE` (10 s, above an
  election). The proof is `cluster.ControlPlaneContact`
  (`internal/cluster/readiness.go`): the leader, a follower's last leader
  contact, or an agent's last successful control-plane call (one shared
  `Leader` probe when that is older than 6 s). `/health` is unchanged.
- **Tests:** `TestClusterControlPlaneContact`,
  `TestAgentControlPlaneContact`, `TestReadinessAgainstRealRaft` in
  `internal/cluster/readiness_test.go`; `TestServiceReady`;
  `TestReadyRoute`.
- **Residual:** nothing probes `/ready` yet: the Kubernetes chart (P3) and
  the VM installer's `--lb-health-port`, which still serves `/health`.

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
