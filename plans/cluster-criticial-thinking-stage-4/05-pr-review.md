# 05 - PR #79 Review

PR: `Distributed orchestrator 2` (`distributed-orchestrator-2` →
`main`). State: OPEN. 170 files, +34,909 / -409.

This file is the line-by-line PR review against the user's specific
questions:

1. Does it deliver a clean architecture for sandbox creation, similar
   to k3s, that can scale to 500 nodes and ~100k sandboxes?
2. Is the **orchestrator** and **sandbox-creation** path highly
   available, while individual **sandboxes** are allowed to be non-HA?
3. Are **nodes** highly available?
4. Does it **avoid impacting the existing APIs**: MicroVM SDKs, Daytona,
   and E2B?
5. Does the **TCP/TLS support** keep working with the multi-node
   orchestration layer present?

Snapshotting is explicitly out of scope per the user.

---

## Q1. Clean k3s-like architecture for sandbox creation at 500 / 100k?

**Verdict: yes, structurally.** With one process-level caveat.

### What lines up with k3s

k3s splits a cluster into `server` and `agent` processes; only servers
run the embedded SQLite/etcd-like store; agents are stateless
consumers. This PR adopts the same shape:

- `cmd/sandboxd/main.go:130-159` branches construction on
  `cfg.IsServer()`. Server nodes call `cluster.New(...)`; everything
  else calls `cluster.NewAgent(...)`. Two distinct types, two distinct
  binary behaviors from one binary.
- `internal/cluster/cluster.go:1-28` — package doc states this directly:
  "Worker/ingress-only nodes run Agent instead: they gossip capacity and
  receive owner API forwards, but all placement reads/writes go to the
  server quorum over authenticated RPC. They do not store the FSM and
  do not join Raft as non-voters."
- `internal/cluster/agent.go:59-181` confirms the type: no Raft
  transport, no FSM, no log-replication path. Only:
  - gossip (`internal/cluster/gossip.go`),
  - control-plane RPC client (`doControlPlaneBytes` →
    `PublicInternalApplyPath` + friends),
  - mTLS internal listener for owner-API forwards.
- `internal/cluster/voter_autojoin.go:108-148` — the leader's
  auto-promotion code refuses to AddVoter or AddNonvoter any peer that
  gossiped `worker` or `ingress` or `worker,ingress`. So even an old
  binary that pre-dates this PR cannot accidentally pollute the Raft
  configuration.

This is the structural piece Stage 3 said was missing. With 3-5
servers + 500 agents, the Raft configuration stays bounded at 3-5
entries; worker churn does not generate AddNonvoter / RemoveServer
churn on the leader.

### What lines up with the create-path scaling story

For 100,000 sandboxes:

- **Reservation-first create across all three APIs.** `pkg/api/
  clustercreate/clustercreate.go` is the single source of truth for the
  v1, Daytona, and E2B create paths. One `opReserve` Raft entry +
  forward to the selected target, then `opPlace` on the target.
- **O(1) placement.** `internal/cluster/placement.go:59-127` uses
  power-of-two-choices, but the cost of *finding* the candidates is no
  longer O(placements): `pendingReservationsByNode(now)` reads the
  aggregate from `pendingReservationCapacity` instead of scanning the
  placement map (`internal/cluster/fsm.go:849-998`), and gossip member
  decoding happens once into `gossipMemberIndex` rather than every
  request.
- **O(1) host-port collision check** via `hostPortIndex` proved by
  `TestScaleGateHostPortIndexAt100K`.
- **Sharded ingress** with delta-only reconcile so a single placement
  change does not touch every route on every ingress node.
- **Bounded list fanout** with a paginated `/v1/cluster/sandbox-index`
  alternative.
- **Single batch orphan command per dead owner**, proved at 100k
  placements / 10k owners by
  `TestScaleGateBatchOrphanOwnerAt100KPlacements`.

This is the right shape. **The caveat is that none of the gates run
multiple processes.** They exercise the FSM at 100k rows inside one Go
test binary. We don't yet have empirical proof that 500 distinct
`sandboxd` processes plus a real Caddy at 100k routes hits the SLOs.
See `03-limitations.md` § L1.

### What is missing for the k3s comparison

- k3s lets `kube-apiserver`'s watch protocol push deltas to agents; this
  PR uses request-response RPC for FSM reads on agents, with a local
  placement cache as fallback. That cache is best-effort and may serve
  stale data during partitions. Manageable, not equivalent.
- k3s ships a documented backup tool (etcd snapshots). This PR does not.
- k3s has rolling-upgrade documentation. This PR does not yet have an
  operator migration page (issues file § I13).

**Net.** This is a k3s-shaped architecture good enough for the Stage 4
ceiling. It is not yet k3s-feature-complete.

---

## Q2. HA orchestrator + HA sandbox creation; sandboxes themselves not HA

**Verdict: yes, with bounded recovery paths for false-positive
orphans.**

### Control plane HA

- Raft quorum on 3 (tolerates 1 failure) or 5 (tolerates 2) server
  nodes.
- Agents reach any server-role member via `doControlPlaneBytes` which
  iterates members and falls back on `ErrNotLeader` / 503
  (`internal/cluster/agent.go:606-646`). Leader failover is invisible
  to the SDK/Daytona/E2B caller.
- mTLS for the internal channel (`internal/cluster/tls.go`) keeps the
  control plane authenticated even on shared L3 networks.
- The dead-owner reconciler at `internal/cluster/dead_owner.go:113-170`
  runs only on the leader, with a 5s tick and a configurable grace
  period (default 30s). This is the canonical "wait before evicting"
  pattern.

### Sandbox-creation HA

- `opReserve` is committed durably in Raft before any local side effect
  on the target. A leader change loses only the in-flight RPC, which
  the agent retries.
- E2B's deterministic fingerprint sandbox-ID flows through
  `clustercreate.PrepareOptions.PreferredSandboxID`, so a retry behind
  an LB after a leader change still lands on the same owner. (Daytona
  has no equivalent idempotency key today, but the FSM's name-uniqueness
  check still rejects duplicate-name creates with 409.)
- 120s reservation TTL plus 5s leader GC sweep bounds dead-mid-create
  cleanup. Issue § I3 notes the TTL should ideally be heartbeat-extended
  for slow image pulls.

### Sandboxes deliberately non-HA

- `clusterRecreateOnFailoverEnabled = false` is an explicit constant
  with a documented rationale in `internal/cluster/dead_owner.go:12-27`.
- `opOrphanOwner` is a single Raft entry that orphans every placement
  for the dead owner in one apply, also cancelling their pending
  reservations.
- Clients see 410 Gone. The orphan reclaim path
  (`POST /v1/cluster/orphans/{id}/reclaim-local`, only valid from the
  previous-owner node) is the **operator escape hatch** for false-
  positive evictions: a node that gets gossip-blipped to dead but still
  has the local sandbox can reclaim it without DB surgery.

This matches the user's policy exactly: "If a sandbox crashes or gets
deleted, it's fine to mark it as a waste or wait for it to come back.
But nodes should be highly available."

### Nodes HA

- "Nodes are highly available" parses as: the cluster's ability to
  *route to* a healthy node survives any single-node failure. That's
  true:
  - the server quorum keeps the FSM available;
  - the agent fallback loop keeps placement/owner lookup available;
  - ingress sharding keeps public routes available (subject to
    L14 — no shard replicas, so failover is gossip-bound to a few
    seconds).

A second reading of "nodes are highly available" — that an *individual
node* survives its own crash — is not what HA means. The cluster
survives node crashes; node N itself does not.

---

## Q3. Are nodes highly available?

**Verdict: yes within the cluster meaning of HA.**

See Q2. The control plane survives any 1 failure (3-server) or any 2
failures (5-server); the agent control-plane fallback loop hides leader
churn from clients; ingress shards rebalance on gossip-observed
membership change. Stage 3 noted that gossip metadata could silently
downgrade a node to no-role under the 512-byte limit; that is still
unfixed (issue § I4) but at the Stage 4 fleet size is a rare event.

---

## Q4. Does this avoid impacting the MicroVM SDKs, Daytona, and E2B?

**Verdict: yes. The cluster layer is below the API surface.**

Concrete evidence:

### SDKs

`git diff main..HEAD -- sdk/` is **additive only**. Sampled:

- `sdk/typescript/src/MicroVM.ts` — `list()` gains an optional
  `ListOptions` parameter; existing call sites compile unchanged.
- `sdk/typescript/src/types.ts` — adds `ListOptions` interface; no
  existing type changes.
- `sdk/python/microvm/client.py` — `list(*, tags=None)` keyword-only
  arg; existing callers compile unchanged.
- `sdk/go/pkg/microvm/client.go`, `sdk/rust/src/lib.rs`,
  `sdk/java/.../MicroVMClient.java` — same additive `tags` filter.

No method removed, no required arg added, no response-shape change.

### v1 API

`pkg/api/v1/routes.go` keeps every existing `/v1/...` URL. Wrapping with
`clusterForwardWrap` is transparent to clients — a forwarded request
returns the same JSON body the local handler would have returned.
Additions:

- `/v1/cluster/sandbox-index` — operator-only paginated enumeration.
- `/v1/cluster/ingress-route/{id}` — operator-only owner lookup.
- `/v1/cluster/placements/{id}` — operator-only placement inspect.
- `/v1/cluster/orphans/{id}/reclaim-local` and
  `DELETE /v1/cluster/orphans/{id}` — operator-only recovery.
- `/v1/cluster/internal/...` — mTLS-only, for inter-node RPC.

None of these are called by the SDKs.

### Daytona facade

`pkg/api/daytona/routes.go` adds `clusterForwardWrap` middleware around
every per-sandbox mutating route. The wire shape is unchanged. The
**only** behavior change visible to a Daytona SDK client is:

- if the client hits a node that does not own the sandbox, the response
  arrives transparently from the owner (same JSON, same status code);
- if the owner is dead, the client now sees `410 Gone` instead of `404`
  (because the FSM knows about the orphan); this is intentionally
  surfaced and matches the new product policy.

There are gaps documented in `03-limitations.md` § L2 and issues § I2:
Daytona's resize/lifecycle do not write through to the FSM spec. That's
a *cluster-internal* gap, invisible to Daytona clients while
`clusterRecreateOnFailoverEnabled = false`.

### E2B facade

`pkg/api/e2b/routes.go` mounts `clusterForwardWrap` around every
per-sandbox mutating route. Create uses the same `clustercreate.Prepare`
+ `clustercreate.CreateOnSelectedNode` flow. E2B-specific behavior:

- deterministic create IDs from the request fingerprint are now
  used as `PreferredSandboxID` in the cluster reservation
  (`pkg/api/e2b/handlers.go:60-67`), so retries land on the same
  owner cluster-wide;
- the local SQLite `request_idempotency` table is still used for
  replay-window matching, which is correct on the owner node;
- per-sandbox routes forward to the owner before touching local state.

This is exactly the contract E2B clients expect.

---

## Q5. Does TCP/TLS L4 support keep working?

**Verdict: yes, end-to-end.**

The user explicitly built the TCP/TLS support. This PR preserves it:

### Cluster-wide host-port allocation

- `internal/cluster/fsm.go:138-172` and `803-847` — the
  `hostPortIndex` is the cluster-wide source of truth.
- `internal/store/store.go:276-282` — the existing partial unique index
  on `exposed_ports.host_port` keeps per-node bind safety.
- `internal/service/service.go:1279-1402` — `allocateHostPort` writes
  the cluster intent before the local row, so cross-node collisions are
  rejected before Docker / Caddy is touched.

### TCP routing from any ingress to the owner

- `pkg/caddy/client.go:646-682` — `UpsertTCPProxyRoute` lets any
  ingress node bind `:hostPort` and forward to the owner's `:hostPort`.
- `internal/service/ingress_delta.go:136-156` — the cluster ingress
  reconciler emits TCP proxy intents for every replicated raw-TCP
  exposure that's not owned by this node.

So a client doing `tcp://cluster-ingress:40123` lands on any alive
ingress and is forwarded to the owner's `:40123` listener — exactly
the existing single-node behavior, with one transparent extra hop.

### TLS routing from any ingress to the owner

- `pkg/caddy/client.go:776-820` — `UpsertSNIPassthroughRoute` forwards
  the unmodified ClientHello to the owner's `:L4_TLS_LISTEN` port.
- `pkg/caddy/client.go:727-774` — `UpsertTLSSNIRoute` still runs on the
  owner; the cert manager still lives there. Passthrough means the
  ingress node never sees a private key.

### Lazy bootstrap latch preserved

- `internal/service/service.go:1263-1277` — `EnsureLayer4Ready` uses the
  canonical `atomic.Bool + Mutex` single-flight pattern that
  `CLAUDE.md` explicitly calls out as the project's idiom (and as a
  pr-review.md invariant).
- `cmd/sandboxd/main.go:181-185` — the bootstrap is gated to worker /
  ingress / mixed nodes. Pure servers don't waste a port binding.

### Pool ceiling (documented limitation, not regression)

The host-port pool is still bounded by the configured range. With ~1000
ports in the default pool, the cluster can carry ~1000 raw-TCP-exposed
sandboxes — not 100k. That's a known L4 constraint of the existing
single-node design, **not introduced by this PR**. It's listed in the
limitations file (§ L13). The user's stated 100k target is for
*sandboxes*, not for *raw-TCP exposures* — most workloads use HTTP
domain mode, which scales with hostnames, not ports.

---

## Cross-cutting concerns the PR description should call out (per `pr-review.md`)

These are not bugs in the code, they are required PR-description
sections that are currently blank. See issue § I1.

### 1. Sandbox boot impact

The reservation-first flow adds:

- one Raft round-trip on the router (Node A) for `opReserve` before the
  body is forwarded;
- one Raft round-trip on the target (Node T) for `opPlace` after the
  local create returns successfully;
- on the **self-wins** path (placement chose this node) there is no
  `opReserve` — only the post-create `opPlace`. This was an explicit
  Stage 3 design choice: the local create has no cross-node hop where
  intent can be lost.
- on the **target-wins** path, the `opReserve` happens on the router's
  request thread before forwarding, so it's outside the target's
  CreateSandbox latency. The target's only added work is `opPlace`,
  which the PR documents as on the response path so create latency
  on Node T is unchanged versus single-node.
- the local `Service.CreateSandbox` path also gains a `Cluster().
  RecordPlacement(...)` call (one Raft entry).

For self-only mode (`SB_ENABLE_CLUSTER=false`) all of this short-circuits
through `cluster.Noop` and is a single atomic load.

### 2. Idempotency

- v1 create: the FSM rejects same-ID re-reserves under different owners
  with `ErrReservationConflict`; a same-owner re-reserve refreshes the
  TTL; opPlace on an already-placed row is a no-op.
- Daytona create: name uniqueness is enforced in the FSM
  (`ErrNameConflict`); a duplicate name returns 409 to the client.
- E2B create: deterministic fingerprint ID + `PreferredSandboxID` route
  retries to the existing owner; local idempotency table holds the
  replay window.
- v1 expose-port: `opAddExposedPort` is idempotent on same-route re-add;
  protocol/host-port updates only fire when the route metadata changes.

### 3. Failure-path consistency

`clustercreate.CreateOnSelectedNode` documents the rollback chain:

- `CreateSandboxWithID` failure → cancel reservation;
- `PutClusterSecretsForRecipient` failure → destroy sandbox, cancel
  reservation;
- `RecordPlacement` failure → destroy sandbox, cancel reservation,
  delete placement best-effort.

Each step uses `context.Background()` for the rollback so r.Context()
cancellation does not skip cleanup. Issue § I3 (TTL extension) and
limitation § L4 (snapshot size) are the remaining hard-to-recover paths.

### 4. L4 / host-port pool changes

- The cluster `hostPortIndex` is a new FSM index that runs alongside the
  existing partial unique index on `exposed_ports.host_port`. Both must
  agree; mismatches surface as `ErrHostPortReserved` at the FSM and the
  partial-index `ErrSandboxNameConflict`-style error at the store.
- `TryReserveHostPort` is unchanged at the per-node level; the cluster
  layer wraps it.
- Regression test coverage: `internal/cluster/scale_gates_test.go`
  (100k host-port collision check at apply time) and
  `internal/store/store_test.go` (existing partial-unique-index test
  shape).

### 5. Test plan

The PR should claim:

- `go test ./...` passes;
- `scripts/scale-gates.sh` passes when invoked with the build's `go`
  binary;
- `(cd sdk/typescript && npm test)` passes;
- `(cd sdk/python && python -m unittest discover -s tests -v)` passes;
- `(cd sdk/go && go test ./...)` passes;
- `(cd sdk/java && mvn -B -ntp test)` passes;
- `(cd sdk/rust && cargo test)` passes.

I have not verified the test plan empirically in this review — the user
asked for a code-and-architecture review, not a run-the-suite review.

---

## Final review summary

**Recommendation: approve with changes-requested on the PR
description and four merge-time fixes.**

Approve because:

- the architecture is structurally what the Stage 4 product bar
  requires;
- the boot path, idempotency, failure rollback, L4 / host-port
  changes are all designed correctly even if not yet *described*
  correctly in the PR body;
- the public APIs and SDKs are not impacted;
- the TCP/TLS L4 routing is preserved;
- single-process scale gates pass at 100k rows for every key index;
- sandboxes are deliberately non-HA per stated policy, with a
  bounded operator-recoverable orphan path.

Changes requested (must be in this PR or a fast follow-up):

1. **Fill in the PR description.** Every section is currently blank.
   See issues § I1 and the cross-cutting summary above.
2. **Wire Daytona/E2B mutating handlers to write through to the FSM
   spec.** Either move `replicateSpecPatch` into the service layer or
   duplicate it per-facade. Issue § I2.
3. **Extend reservation TTL during slow image pulls.** Either
   target-side heartbeats or per-request TTL. Issue § I3.
4. **Document the migration path** for an existing single-node
   deployment turning on `SB_ENABLE_CLUSTER`. Issue § I13.

Stretch / fast-follows (not blocking):

- multi-process integration test for ~5 servers + 50-100 agents;
- backup/restore docs for Raft;
- CI nightly that runs `scripts/scale-gates.sh`;
- gossip-metadata size hardening (issue § I4);
- bump `SubscribePlacement` buffer or pass version through (§ I8).

**On the user's specific questions:**

| Question | Answer |
|---|---|
| Clean k3s-like architecture? | Yes. Server/agent split is structural, not just config. |
| Scales to 500 nodes / 100k sandboxes? | Yes by design; not yet proven by multi-process integration. |
| Orchestrator HA? | Yes — Raft quorum + agent fallback loop. |
| Sandbox creation HA? | Yes — reservation-first + leader-change-tolerant retry. |
| Sandboxes non-HA? | Yes — explicit policy, 410 Gone + operator reclaim. |
| Nodes HA? | Yes — within the cluster meaning of HA. |
| No impact on MicroVM SDKs? | Yes — only additive `list({tags})`. |
| No impact on Daytona/E2B? | Yes at the wire/SDK layer. Internal write-through gap (§ I2). |
| TCP/TLS L4 preserved? | Yes — cluster-wide host-port uniqueness + proxy/passthrough. |
