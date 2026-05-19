# Data-Plane Load Balancer — Release Plan

**Status:** Proposal, awaiting approval.
**Scope:** Land the missing piece called out in
`plans/cluster-criticial-thinking-stage-2/04-data-plane-load-balancer.md`
(item **B** in the post-PR-58 release-blocker list).
**Bar:** A single advertised LB endpoint that routes HTTP/TLS/TCP sandbox
traffic to the correct owner node, scales toward 200 × 50, and is operable by
a self-hosted user without standing up Envoy or HAProxy.

## TL;DR

1. Adopt **`sandboxd --mode ingress`** as the supported ingress topology — same
   binary, same Caddy + caddy-l4 integration, no new component to operate.
2. Introduce **`SB_NODE_ROLE = server | worker | ingress | mixed`**. Carve
   ingress responsibility off the worker so a 200-worker cluster does *not* run
   a 200-route Caddy reconciler on every node.
3. Define an **advertised data-plane endpoint** (`SB_INGRESS_ADVERTISE_HOST` +
   wildcard DNS) that the SDK, the docs, and the install script can point at.
   It can sit behind any cloud LB (NLB, MetalLB-assigned VIP, BGP) — that's a
   deployment choice, not a build choice.
4. Keep the existing per-node ingress reconciler running for **`mixed`** mode
   (the dev/single-region default) so single-node and small clusters continue
   to work with zero topology changes.

This plan deliberately rejects: building MetalLB, building an xDS feeder,
building per-sandbox DNS, and rewriting Caddy with HAProxy. Stage-2's
`04-data-plane-load-balancer.md` argues for `sandboxd --mode ingress` and this
plan executes that choice.

## What we have today

| Piece | State |
|---|---|
| Per-node ingress reconciler | Implemented in `internal/service/service.go::ReconcileClusterIngress` (5s poll). Every node installs Caddy routes for every remote sandbox. |
| TLS/SNI passthrough | `caddy.UpsertSNIPassthroughRoute` + `caddy.IngressSandboxSNIRouteID` — used when `cfg.Domain != ""`. |
| HTTP path-mode reverse-proxy | `caddy.UpsertSandboxRouteToPeer` + `UpsertPortRouteToPeer` — used when no domain is configured. |
| Raw TCP cluster-wide ingress | `caddy.UpsertTCPProxyRoute` + FSM-level host-port uniqueness in `internal/cluster/fsm.go`. |
| Data-plane advertise host | `SB_DATA_PLANE_ADVERTISE_HOST` (`internal/config/config.go:130`). |
| Node role | **Missing.** Every node runs Raft + ingress reconciler + worker. |
| Advertised LB endpoint as a first-class config | **Missing.** Docs still show a per-node DNS RR / NLB fronting `:443`. |
| `sandboxd --mode ingress` | **Missing.** |

The functional gap is **not** that we can't route — Shape C (every node a
router) already routes correctly. The gap is operational: at 200 × 50 this
becomes the bottleneck called out in stage-1 §5 (10K SNI rules on every node,
200× write-amplification on every placement change). Stage-2 confirms it's
acceptable for a beta but blocks "production cluster" classification.

## Decision

Ship **Shape D via `sandboxd --mode ingress`** behind a small role split. Keep
the existing reconciler as the implementation; what changes is *where* it
runs.

| Mode | Runs Raft voter? | Runs worker (docker)? | Runs ingress reconciler? |
|---|---|---|---|
| `server` | yes | no | optional (off by default) |
| `worker` | no (non-voter only) | yes | **no** (this is the key fan-out cut) |
| `ingress` | no (non-voter only) | no | yes |
| `mixed` (default) | yes | yes | yes |

`mixed` preserves single-node and small-cluster behaviour bit-for-bit. The
split only kicks in when an operator opts into it.

### Why not Envoy / HAProxy / MetalLB

- **Envoy + xDS:** Best long-term answer for a managed offering. Wrong shape
  for a self-hosted beta release — we'd own the xDS feeder, the operator
  would own a second binary, and the surface area triples.
- **HAProxy with generated config:** Possible, but Caddy is already wired
  with the exact route shapes (caddy-l4 SNI, raw TCP listener, path-mode
  reverse-proxy). Re-doing it in HAProxy is pure rework.
- **MetalLB:** Allocates a VIP. Does **not** know `sandbox_id → owner`.
  Useful as a *deployment* in front of the ingress tier
  (`MetalLB VIP → ingress-1..N → owner`); not a substitute for the ingress
  reconciler. Treated as an operator concern, not a build concern.

These are the same conclusions stage-2 §04 reaches; this plan just commits to
them.

## Work breakdown

Numbered phases. Each is mergeable on its own; later phases assume earlier
ones landed.

### Phase 1 — `SB_NODE_ROLE` plumbing (no behaviour change for `mixed`)

**Files:** `internal/config/config.go`, `internal/config/config_test.go`,
`cmd/sandboxd/main.go`.

1. Add `NodeRole string` to `Config` with values `server | worker | ingress |
   mixed`. Default `mixed` (current behaviour). Invalid value → boot error.
2. Add helpers `(c Config) IsWorker() bool`, `IsIngress() bool`,
   `IsServer() bool`. `mixed` returns true for all three.
3. Validate in cluster-mode invariants block: any non-default role requires
   `EnableCluster=true`. `worker` and `ingress` cannot have
   `ClusterBootstrap=true`. `ingress` cannot have `worker`-only
   responsibilities (we'll let docker still init for now to keep this phase
   small; the gating happens in Phase 2).
4. Test: each role value parses, defaults to `mixed`, and rejects unknown.

**Acceptance:** `go test ./...` green. `mixed` is byte-identical to current
config behaviour.

### Phase 2 — Gate component startup on role

**Files:** `cmd/sandboxd/main.go`, `internal/service/service.go`,
`internal/cluster/voter_autojoin.go`, `pkg/api/v1/routes.go`.

1. In `main.go`, only call `StartClusterIngressReconcile` when
   `cfg.IsIngress()`. Workers stop installing peer routes — they keep only
   local owner routes via the existing per-sandbox install path.
2. In `voter_autojoin.go`, only request voter promotion when
   `cfg.IsServer()`. `worker` and `ingress` register and stay non-voter for
   life. This is independent of the existing `SB_CLUSTER_MAX_AUTO_VOTERS`
   cap; the cap remains the safety net for `mixed`.
3. In `main.go`, skip the bits a pure `ingress` node does not need:
   - `svc.StartLifecycleSweep`, `svc.StartEventMonitor`,
     `svc.StartBuiltImageGC` — worker-only, so gate on `cfg.IsWorker()`.
   - `svc.ReplayReservations` — keep on `IsWorker()`; ingress has no local
     sandboxes to replay.
   - `svc.Cluster().AssertOwnership` — same; gate on `IsWorker()`.
4. v1 routes that mutate local sandboxes (create, exec, expose, destroy,
   sessions, file IO) **stay registered on every role**. Owner-forwarding
   already handles "I'm not the owner" via `clusterForwardWrap`. A pure
   ingress node will forward 100% of mutating traffic; that's intended.
5. Test: bring up a synthetic three-role test cluster
   (`server+worker+ingress`) under `internal/cluster/` integration tests and
   assert (a) only the server is a voter, (b) only the ingress node
   reconciles peer routes, (c) creating a sandbox via the ingress node lands
   on the worker via the existing target-locked forward.

**Acceptance:** at 200 simulated workers (using the existing fake-membership
test harness), only the configured server count appears as Raft voters and
only the configured ingress count holds peer routes.

### Phase 3 — Advertised LB endpoint as a first-class config

**Files:** `internal/config/config.go`, `setup/install.sh`,
`scripts/cluster-init.sh`, docs (`setup/cluster.md`,
`docs/src/content/docs/cluster-setup.md`, new
`docs/src/content/docs/cluster-ingress.mdx`).

1. Add `IngressAdvertiseHost string` (env `SB_INGRESS_ADVERTISE_HOST`). This
   is the **public** endpoint the SDK and end users hit. Distinct from
   `DataPlaneAdvertiseHost` (which is the peer-internal LAN address used by
   the reconciler).
2. When `EnableCluster=true` and the role is `mixed`,
   `IngressAdvertiseHost` defaults to `PublicHost`/`Domain`-derived value
   (current behaviour). For `worker` or `ingress` it is required if
   `Domain` is set, because the URL the API returns to the SDK must point
   somewhere stable.
3. URL composition: `Service.publicURL` and the equivalent SDK-facing URL
   builders read `IngressAdvertiseHost` (not the local `PublicHost`) when
   cluster mode is on. Single-node mode keeps using `PublicHost`.
4. Install scripts: add a `--role ingress|worker|server|mixed` flag.
   `cluster-init.sh` accepts `--ingress-advertise-host <host>` and writes
   `SB_INGRESS_ADVERTISE_HOST` into the systemd env file.
5. Docs: new `cluster-ingress.mdx` covering the four roles, the recommended
   3-ingress topology, the optional MetalLB / cloud-NLB in front, and the
   wildcard-DNS requirement.

**Acceptance:** install-script smoke test produces a working three-node
cluster (1 server + 1 worker + 1 ingress) where `client.Create()` against the
ingress node lands on the worker, and the returned sandbox URL routes back
through the ingress node.

### Phase 4 — Ingress robustness: explicit failure modes and metrics

**Files:** `internal/service/service.go`, `pkg/caddy/client.go`, new
`internal/service/ingress_metrics.go`.

1. **"Placement in flux" response.** Today, when ingress sees a sandbox the
   FSM hasn't placed yet (or one that was just orphaned), the request falls
   through Caddy's fallback. Replace with an explicit 503 + `Retry-After: 2`
   handler installed at the catch-all layer. This is the release-gate ask
   in stage-2 §06 ("ingress serves a clear 502/409 during placement-in-flux,
   not a Caddy fallback").
2. **Wrong-owner detection.** Worker's local Caddy returns 404 for unknown
   `Host` headers. The ingress reconciler should treat that as a signal to
   refresh its placement view immediately rather than waiting out the 5s
   poll. This is the cheapest pre-watch fix.
3. **Metrics** (prom-style via expvar; matches the rest of the codebase):
   - `aerolvm_ingress_routes_total{type=http|tls|tcp}`
   - `aerolvm_ingress_reconcile_seconds{outcome}` histogram
   - `aerolvm_ingress_caddy_admin_seconds` histogram
   - `aerolvm_ingress_route_lag_seconds` (placement version – installed
     version) gauge
   - `aerolvm_ingress_wrong_owner_total` counter (seeded from the 404
     refresh path above)
4. **Caddy admin batching.** The reconciler currently calls Caddy admin once
   per route per tick. At 10K routes per ingress node × 5s polls this is
   ~2K req/s peak. Move to a batched `apply` (Caddy admin supports posting a
   whole config blob; we already do this in `EnsureLayer4`). Goal: one
   admin call per reconcile tick that changed anything, with an idle no-op
   when the view is unchanged (hash the placement view and skip).

**Acceptance:**
- 10K simulated placements on one ingress node: reconcile p95 < 2s, Caddy
  admin p95 < 500ms.
- 50-sandbox owner death → wrong-owner-counter spikes briefly, route lag
  returns to zero within 5s (current poll period).

### Phase 5 — Convergence proof and release-gate run

**Files:** new test under `internal/cluster/cluster_ingress_test.go`, new
load harness `scripts/load/ingress_churn.go`.

1. Integration test: 3 ingress + 5 workers + 3 servers, 500 sandboxes, kill
   one worker — assert (a) every placement converges to the next owner
   within `SB_DEAD_OWNER_GRACE + 5s`, (b) the ingress route map drops the
   dead node within one reconcile tick, (c) public URLs return 503 (not
   404) during the gap.
2. Churn harness: 1% creates/destroys per minute for 60 minutes, measure
   the stage-2 §06 SLOs (Raft apply p99, route lag p95, Caddy admin p95).
   Output a CSV. This becomes the artifact attached to the release PR.

**Acceptance:** SLOs hit at the simulated 3 × 5 × 3 scale. Push the same
harness against a real 50 × 10 × 3 cluster before flipping the docs from
"beta" to "GA".

## Out of scope for this plan

Each of these is a real piece of work; calling them out so they don't sneak
into the same PR train:

- **xDS / Envoy adapter.** Future managed-service work. The
  `sandboxd --mode ingress` route map is conceptually a subset of what an
  xDS feeder would expose, so this work doesn't lock us out.
- **Per-sandbox DNS** (Shape B). Operator escape hatch for users who don't
  want a wildcard. Not on the critical path; add as a follow-up if a user
  asks.
- **`<id>.<node>.sandbox.example.com` per-node URLs** (Shape E). Same — a
  fallback we can ship later if a deployment has no wildcard cert.
- **Watch-based route propagation** (replacing the 5s poll). Plan in
  `plans/cluster-criticial-thinking-stage-2/05-placement-correctness.md`,
  blocked on a durable Raft-index watch revision (B9). Acceptable to defer:
  Phase 4's wrong-owner-refresh covers the urgent case; the 5s steady-state
  poll is within SLO.
- **UDP exposure.** Explicitly unsupported until separately designed.
- **TLS termination at the ingress.** SNI passthrough only. Cert management
  stays on the workers (where ACME already lives). Revisit if we move to a
  managed offering where the operator never sees the workers.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Operators who don't read the doc keep deploying `mixed` at 50+ nodes. | `mixed` continues to work (Shape C). Log a warning at boot when `cluster_size > 10 && role == mixed && IsWorker()`. |
| Caddy admin reload latency at 10K routes is worse than the SLO. | Phase 4's batching + idle-skip is the first lever. If that's not enough, fall back to per-ingress-node sharding (each ingress holds 1/N of the SNI table — the cloud LB upstream picks via consistent hashing on SNI). Plumbing is small. |
| Wildcard cert renewal storms across many ingress nodes. | The DNS-01 wildcard pattern in `install.sh` is already shared; ingress nodes share the same cert via the existing distribution path. No new work required, but verify in Phase 5. |
| The ingress reconciler still runs on workers in `mixed` mode → existing CI tests pass but operators silently get the bad fan-out shape. | Phase 3's boot warning + the docs explicitly recommending `worker` role above 10 nodes. Not technically blocking; flagged for the release-readiness checklist. |

## Open questions

These belong in the PR description, not blocking this plan:

1. **Default role on a fresh install.** Proposal: keep `mixed` for the
   single-node install one-liner; recommend `--role` explicitly in the
   cluster-init script. Confirm before merge.
2. **Should ingress nodes register in gossip as non-voters or stay completely
   out of Raft?** Stage-2 §03 leans toward "out of Raft entirely." This plan
   keeps them as non-voters because they still need a placement view. Worth a
   second pass after Phase 2 lands.
3. **Do we want a `sandboxd ingress` *subcommand* instead of `SB_NODE_ROLE`?**
   Both work; an env-var is less surgery and matches the rest of the
   configuration surface. Going with the env var unless someone objects.

## Sequencing

| Order | Phase | Approximate diff size | Blocks |
|---|---|---|---|
| 1 | Phase 1 — `SB_NODE_ROLE` plumbing | ~200 lines | nothing |
| 2 | Phase 2 — Gate components on role | ~300 lines | Phase 1 |
| 3 | Phase 3 — Advertised LB endpoint | ~400 lines | Phase 1; docs + install script changes |
| 4 | Phase 4 — Robustness + metrics | ~600 lines | Phase 2 |
| 5 | Phase 5 — Convergence proof | ~400 lines test/load | all above |

Phases 1 and 3 are independently reviewable and could ship as the first two
PRs of the release train. Phase 2 is the structural change. Phases 4 and 5
are the release-gate artifacts.

## Linkage

- Stage-1: `plans/cluster-criticial-thinking/05-data-plane-and-load-balancer.md`
- Stage-2: `plans/cluster-criticial-thinking-stage-2/04-data-plane-load-balancer.md`
- Release gates: `plans/cluster-criticial-thinking-stage-2/06-release-gates.md`
- Related code paths: `internal/service/service.go::ReconcileClusterIngress`,
  `pkg/caddy/client.go::UpsertSNIPassthroughRoute`,
  `internal/cluster/voter_autojoin.go`, `internal/config/config.go:130`.
