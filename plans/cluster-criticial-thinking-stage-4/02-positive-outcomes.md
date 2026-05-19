# 02 - Positive Outcomes

This file states what the PR achieves **against the Stage 4 product bar**:

- 500 nodes total (3-5 servers + ~500 workers + a small ingress tier);
- 100,000 concurrent sandboxes;
- HA control plane, HA sandbox creation, HA node membership;
- non-HA individual sandboxes (410 Gone is fine);
- no impact on MicroVM SDKs, Daytona, E2B;
- TCP/TLS L4 routing preserved end-to-end.

## P1. The architecture is now k3s-shaped, not "every node runs Raft"

The most important architectural shift is that the leader no longer adds
worker/ingress peers as Raft non-voters, and worker/ingress processes no
longer construct a Raft transport at all.

- `cmd/sandboxd/main.go:130-159` branches construction on `cfg.IsServer()`:
  the server-role binary calls `cluster.New(...)`, every other role calls
  `cluster.NewAgent(...)`.
- `internal/cluster/agent.go:60-85` shows the Agent has only gossip,
  control-plane RPC client, mTLS internal listener, and a placement cache
  for read fallbacks. **There is no `raft` field, no FSM field, no
  `setupRaft` call.**
- `internal/cluster/voter_autojoin.go:108-148` guarantees that even on a
  rolling upgrade where an old binary lands as a worker, the leader's
  auto-promotion code refuses to AddVoter and the new path skips AddNonvoter
  entirely (the peer has no `RaftAddr` to add).

**Outcome for the 500-node target.** With 3 or 5 server nodes and 500
agents, the Raft configuration is bounded at 3-5 entries. Worker restarts,
drains, and dead-owner evictions do not churn Raft membership. This is the
same control-plane shape as k3s (`k3s server` vs `k3s agent`) and HashiCorp
Nomad (servers vs clients). Stage 3 P0 R1 / R7 are structurally fixed.

## P2. Sandbox creation is HA across all three product APIs

The reservation-first flow is no longer v1-only. Every public create
endpoint funnels through the same `pkg/api/clustercreate` package:

- `pkg/api/clustercreate/clustercreate.go:34-130` — `Prepare(...)` runs
  `SelectPlacement`, writes `opReserve` to the cluster, sets
  `X-Cluster-Create-Target` + `X-Cluster-Create-ID`, and forwards.
- `pkg/api/clustercreate/clustercreate.go:155-202` — `CreateOnSelectedNode`
  promotes via `RecordPlacement` on the target.
- v1 (`pkg/api/v1/cluster_handler.go:117-247`), Daytona
  (`pkg/api/daytona/handlers.go:42-119`), E2B
  (`pkg/api/e2b/handlers.go:44-138`) all call the shared package.

This means:

- if Node A receives the request but Node T is the chosen target, the
  reservation is durably committed in the Raft log **before** any local side
  effect runs on T;
- if Node T crashes mid-create, the 120-second TTL + 5-second leader GC
  releases the reservation;
- if leadership changes during create, the agent's `doControlPlaneBytes`
  fallback loop in `internal/cluster/agent.go:606-629` retries the apply
  against any server-role member (cycling through them on
  `ErrNotLeader`/503);
- E2B's deterministic create ID (sandboxIDFromFingerprint) flows into
  `clustercreate.PrepareOptions.PreferredSandboxID`, so retries behind a
  load balancer that random-spray E2B requests across the cluster still
  reach the same owner.

**Outcome.** A 100k-create burst arriving on a 500-node fleet routes through
the Raft leader once per create for `opReserve`, then forwards to the
chosen target. A leader failover during the burst loses at most the
in-flight RPCs — they retry against the new leader. Stage 3 P0 R6
(Daytona/E2B bypass cluster placement) is structurally fixed.

## P3. Sandboxes are deliberately non-HA, matching the product policy

The user explicitly asked for non-HA individual sandboxes, and this PR
matches that:

- `internal/cluster/dead_owner.go:12-27` — `clusterRecreateOnFailoverEnabled
  = false` is an explicit comment-anchored product policy gate.
- `internal/cluster/fsm.go:475-505` — `opOrphanOwner` marks every placement
  for a dead owner as `owner_state="orphaned"` in a single batch command and
  also cancels their pending reservations.
- `pkg/api/v1/cluster_handler.go:67-80` — `clusterForwardWrap` returns 410
  Gone for orphaned placements, with a stable message ("sandbox owner died;
  placement orphaned").
- `pkg/api/v1/cluster_handler.go` exposes operator recovery surfaces
  (`POST /v1/cluster/orphans/{id}/reclaim-local`,
  `DELETE /v1/cluster/orphans/{id}`,
  `GET /v1/cluster/placements/{id}`) so a false-positive eviction (network
  blip) on a node that still owns the local sandbox row can be reclaimed
  without database surgery. `ClaimOrphan` only succeeds when the previous
  owner is the calling node, so a returning third-party node cannot steal
  another worker's orphan.

**Outcome.** The blast radius of a node death is bounded: every placement on
that node moves to `orphaned` in one Raft command (verified by
`TestScaleGateBatchOrphanOwnerAt100KPlacements` at 100k placements), and
clients see 410 instead of mysterious 5xx. This is the correct shape for the
stated non-HA-sandbox policy.

## P4. Existing public APIs and SDKs are not impacted

The cluster routing layer lives **below** the facade and SDK surfaces.
Confirmed by diffing against `main`:

- `pkg/api/v1/routes.go` keeps the existing `/v1/...` URLs; the only
  additions are operator endpoints under `/v1/cluster/...` (sandbox-index,
  ingress-route, placements, orphans, internal apply/placement).
- `pkg/api/daytona/routes.go` is byte-identical at the URL layer — every
  existing Daytona route stays mounted; the only change is the
  `clusterForwardWrap` middleware wrapping handlers, which is transparent
  to clients (a forwarded request looks like a local 200).
- `pkg/api/e2b/routes.go` is the same shape; the underlying `clusterForward
  Wrap` middleware does not alter response bodies for owner-local
  requests.
- `sdk/typescript/src/MicroVM.ts` adds `list({tags})` as an additive option;
  no method signatures break.
- `sdk/python/microvm/client.py` mirrors the same change.
- `sdk/go/pkg/microvm/client.go`, `sdk/rust/src/lib.rs`,
  `sdk/java/.../MicroVMClient.java` see only the same additive `tags`
  filter for `list(...)`. There is no removed method, no required new
  argument, no changed response shape.
- The release workflow `.github/workflows/release.yml` is the only CI file
  touched and it adds the cluster scripts to release artifacts; SDK
  publish remains unchanged.

**Outcome.** Any existing user of the MicroVM SDKs, Daytona, or E2B who
upgrades the daemon **does not need to change client code**. Cluster mode
is opt-in via `SB_ENABLE_CLUSTER=true`.

## P5. TCP / TLS L4 routing is preserved across cluster boundaries

This was the user's specific concern. The TCP/TLS host-port pool stays
fragile-by-design — that's the existing trade-off — but it now works
**cluster-wide**:

- `internal/cluster/fsm.go:803-847` — the FSM `hostPortIndex` is the
  cluster-wide source of truth for raw TCP host port allocation. Two
  concurrent `opAddExposedPort` commands on different owners cannot land on
  the same host port; the second one returns `ErrHostPortReserved`.
- `internal/store/store.go:276-282` — the existing partial unique index on
  `exposed_ports.host_port` keeps per-node bind safety.
- `pkg/caddy/client.go:646-682` — `UpsertTCPProxyRoute` is the non-owner
  half of cluster-stable TCP: any ingress node can bind `:hostPort` and
  forward to the owner's same `hostPort`.
- `pkg/caddy/client.go:776-820` — `UpsertSNIPassthroughRoute` does
  ClientHello-preserving SNI forwarding to the owner's L4 TLS listener;
  TLS termination still happens on the owner so the cert manager stays
  centralized.
- `internal/service/service.go:1263-1277` — `EnsureLayer4Ready` still uses
  the canonical `atomic.Bool + Mutex` single-flight latch documented in
  `CLAUDE.md`. The L4 bootstrap is gated to worker / ingress / mixed roles
  in `cmd/sandboxd/main.go:181-185` so pure server nodes don't bind L4
  sockets they'll never use.
- `internal/service/ingress_delta.go:136-156` — the cluster ingress
  reconciler builds per-port TCP intents with the placement's replicated
  HostPort, so a TLS-exposed sandbox on owner T installs a passthrough
  route on every other ingress node automatically as soon as the placement
  commits.

**Outcome.** A client dialing `tcp://cluster-ingress:40123` lands on
*any* alive ingress node and is forwarded to the owner's :40123 listener.
A TLS connection to `sb-abc.example.com:443` is SNI-forwarded to the
owner's L4 TLS listener, which terminates the cert and proxies the
plaintext bytes into the container — exactly the existing single-node
behavior, just with one transparent extra hop.

## P6. The control plane is HA

- `internal/cluster/raft.go` and `raft_tls.go` — Raft transport over an
  mTLS-pinned channel. Operators run 3 or 5 server nodes; quorum survives
  single-node failure.
- `internal/cluster/voter_autojoin.go` — `ClusterMaxAutoVoters` caps the
  voter set; additional server-eligible nodes become non-voters but still
  store the FSM. Workers/ingress never enter the configuration.
- `internal/cluster/dead_owner.go:113-170` — the leader-side reconciler
  evicts dead voters from the Raft configuration after the configured
  grace period (default 30s) and clears the in-memory tracker.
- `internal/cluster/agent.go:606-646` — agents iterate every server-role
  control-plane member on `ErrNotLeader`/503 before failing. Leader change
  is invisible to the SDK / Daytona / E2B caller.

**Outcome.** A single server-node failure does not surface as cluster-wide
unavailability: the remaining quorum elects a new leader and agent RPCs
retry. Operators run 3 servers for tolerate-1 or 5 servers for tolerate-2,
exactly like every other Raft-backed control plane.

## P7. Worker churn does not affect Raft, the FSM, or quorum

- A worker death is observed via gossip's `NotifyLeave`. The dead-owner
  loop runs after the grace period and emits **one** Raft command
  (`opOrphanOwner`) per dead owner, not one per sandbox.
- The FSM's `ownerIndex` makes that command O(owned-sandboxes) inside the
  leader's lock; from the outside it is one log entry replicated to the
  3-5 servers.
- The FSM also cancels every pending reservation owned by the dead worker,
  so dead-mid-create requests don't hold capacity for 120 seconds.
- `internal/cluster/scale_gates_test.go:133-174` verifies that with 100k
  placements distributed across 10k owners, batch-orphaning one owner
  returns all of its sandboxes to the orphaned state in one apply.

**Outcome.** A churning fleet of 500 workers, even with simultaneous
death of dozens of workers, generates a bounded number of Raft writes —
one per dead owner — instead of the O(sandboxes) write storm that Stage 3
P0 flagged.

## P8. Cluster-wide name uniqueness and idempotency

- Sandbox names are now globally unique. Two `POST /daytona/sandbox` with
  the same `name` field, racing against different API nodes, will both
  hit the FSM's `validateNameUniqueLocked` at apply time and the second
  one returns `ErrNameConflict` → 409.
- E2B idempotency uses the fingerprint to mint a deterministic sandbox
  ID; that ID is fed to `clustercreate.Prepare(..., PreferredSandboxID:
  deterministicID)`. A second retry behind the load balancer will see
  `ErrReservationConflict` from the FSM and `routeExistingPlacement`
  forwards the retry to the original owner — the existing sandbox is
  returned by replay.

**Outcome.** "Any node accepts any request" is true at the wire level for
v1, Daytona, and E2B, including under retry.

## P9. Snapshotting is local — matches the stated scope

- `pkg/models/types.go` adds `ImageDistribution` modes:
  `external_registry`, `aocr`, `local_only`.
- `internal/service/image_distribution.go` classifies images; `local_only`
  refs (and snapshot rows with `imageDistribution.Mode == local_only`)
  flow through `ImageRequiresLocalPlacement` which pins placement to the
  receiving worker.
- `pkg/api/clustercreate/clustercreate.go:66-72` — when an image must be
  local, `Prepare` skips remote placement entirely and either runs locally
  or returns 503 if this node is drained.

This is enough to match the user's "local snapshots are fine" constraint
without claiming distributed snapshot HA. A snapshot created on Node T
stays addressable on Node T; trying to create-from-snapshot on a different
worker fails-fast instead of triggering a registry pull storm.

## P10. Observability is in place to debug 100k-scale problems

The `internal/cluster/metrics.go`, `internal/service/metrics.go`, and
`internal/scaleobs/metrics.go` files add expvar gauges/counters/histograms
across every Stage 3 critical path:

- raft apply latency + in-flight queue depth + snapshot duration/bytes;
- gossip member liveness + lease loss;
- scheduler decisions + per-rejection-reason counters;
- create queue depth + state transitions;
- per-node host pressure (CPU/Mem/Disk/GPU reserved);
- ingress desired/applied/failed revisions + route counts per protocol +
  Caddy admin latency histogram;
- owner forwarding latency + stale-owner 421 count;
- facade idempotency claim/replay/conflict;
- secret decrypt latency + recipient-deny + key mismatch.

**Outcome.** When something does go wrong at 500/100k scale, the operator
has a dashboard, not a printf.
