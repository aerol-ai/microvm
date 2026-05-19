# 07 — Improvement Proposals

Concrete proposals, sized and sequenced. Each one references the
critique that motivates it.

Priority bands:

- **P0** — required to make 200×50 functional at all.
- **P1** — required to make 200×50 *operationally healthy*.
- **P2** — nice-to-have at 200×50; necessary if scale grows beyond.
- **P3** — speculative / future.

The expected order to land them is: P0s in parallel, then P1s, then
P2s. P3s are written so they're not forgotten, not because they need
to ship.

---

## P0 — Server / Worker roles

**Motivates:** [`02 §A1`](./02-assumptions-challenged.md#a1),
[`03 §1`](./03-scale-200x50.md#1-the-raft-commit-hot-path),
[`04 §1`](./04-control-plane-critique.md#1-raft-as-currently-configured-not-enough),
[`06 F2 / F7 / F13`](./06-failure-modes.md).

Today every node is a raft voter. Replace that with the K3s shape:

- **`sandboxd --mode server`** (3 or 5 fixed nodes):
  - Runs raft, holds full FSM.
  - Owns placement decisions, leader-side reconciliation, scheduler.
  - Does **not** run sandboxes (or optionally does in `--mode mixed` for
    laptop / 3-node deployments).
  - Exposes a `/v1/internal/...` RPC surface that workers use.
- **`sandboxd --mode worker`** (rest of the fleet):
  - Does **not** run raft. Doesn't hold the FSM in memory.
  - Connects to the control plane via mTLS to one of the configured
    server addresses.
  - Heartbeats capacity + running-sandbox list to the control plane
    every 2–5 s.
  - Long-polls or streams "placements assigned to me" from the control
    plane.
  - Runs Docker, Caddy (for local routes only), the SSH gateway, the
    local SQLite.

### Code shape

- New: `internal/cluster/server.go` (control-plane role).
- New: `internal/cluster/worker.go` (worker role: heartbeat client,
  placement watch).
- Reuse: existing `internal/cluster/fsm.go`, `raft.go`, `forward.go`,
  `gossip.go` — all move into the server role.
- New internal RPCs on `:7002`:
  - `POST /v1/internal/heartbeat` — worker → server.
  - `GET  /v1/internal/placements?since=<version>` — long-poll watch.
  - `POST /v1/internal/placements/<id>:complete` — worker
    acknowledges placement (or reports failure).
- `cmd/sandboxd/main.go` switches on `SB_NODE_ROLE`.

### Bootstrap

- `cluster-init.sh` brings up the first server.
- `cluster-join.sh --role server` joins additional servers (up to 5).
- `cluster-join.sh --role worker` joins workers (no upper bound).

### Migration path

- Today's 3-node cluster (all voters) becomes a 3-server cluster
  unchanged. Existing tests survive.
- Adding more nodes uses `--role worker` rather than auto-voter
  promotion.
- Document "if you started as 3 voters and want to scale, the
  upgrade is: re-install each node past the first 3 in worker mode."

### Effort

- Medium-large. New RPC surface, two new boot paths, new bootstrap
  flags. ~1 quarter for one engineer.

---

## P0 — Ingress tier

**Motivates:** [`02 §A6 / A7`](./02-assumptions-challenged.md#a6),
[`03 §7`](./03-scale-200x50.md#7-caddy-config-size),
[`05`](./05-data-plane-and-load-balancer.md).

Two paths, listed in order of effort. Ship the cheap one first if
needed; ship the durable one for the actual answer.

### P0a — Per-node URLs (Shape E in `05`)

**What:** Encode the owner node in the sandbox URL:
`<id>.<node>.sandbox.example.com`. Each node solves DNS-01 for its
own `*.node-X.sandbox.example.com` wildcard.

**Pro:** Days of work. No new component. Failover-changes-URL is
acceptable for the non-HA-sandbox product semantics.

**Code:** small change to `pkg/caddy/client.go` URL builders. New cert
prefix. New per-node wildcard A records in operator setup.

**Operator changes:** one DNS record per node added at install time.

### P0b — Ingress mode (Shape D in `05`)

**What:** New `sandboxd --mode ingress` (or a separate small Envoy
binary). Reads placements from the control plane via the same RPC
workers use. SNI-routes sandbox-URL traffic to the right worker.

**Pro:** Stable URLs across failover. The "real" answer at scale.

**Con:** Operator now runs three modes. Capacity planning for the
ingress tier. More TLS handshakes (one to ingress, one to worker)
or SNI-passthrough complexity.

**Code shape:**

- New: `internal/cluster/ingress.go` — placement watch + caddy admin
  driver.
- Reuse: existing Caddy + caddy-l4 binary.
- New: `cmd/sandboxd` `--mode ingress`.

### Recommendation

Ship **P0a now** (it's small) and *plan* **P0b** for the next
quarter. Many users will be happy with P0a; P0b becomes pressing only
once public sandbox URLs are a primary product surface.

---

## P0 — Stop auto-promoting every joiner to voter

**Motivates:** [`02 §A1`](./02-assumptions-challenged.md#a1),
[`06 F7`](./06-failure-modes.md#f7-leader-churn-under-load).

Even if the worker/server split is the long-term answer, the
immediate hardening is: **make voter promotion explicit**.

- Default: gossip-joining nodes stay **non-voters**.
- Voter promotion is a deliberate operator action: API call or CLI
  command.
- The auto-promote loop becomes auto-`AddNonvoter` (the joiner gets
  the raft log streamed but doesn't vote until promoted).

This is a 1-day change that immediately makes a 200-node cluster
*tolerable* even before the proper P0 split lands.

**Code:** flip `AddVoter` to `AddNonvoter` in
`voter_autojoin.go:67`. Add a `POST /v1/cluster/voters` admin API.
Add an `aerolvm cluster promote <node-id>` operator command.

**Migration:** existing 3-node clusters use the new admin path to
promote node-b and node-c after upgrade. Document loudly.

---

## P1 — Failover storm control

**Motivates:** [`02 §A5`](./02-assumptions-challenged.md#a5),
[`03 §9`](./03-scale-200x50.md#9-the-dead-owner-reconcile-burst),
[`06 F1 / F2`](./06-failure-modes.md).

Three sub-pieces, all small.

### P1a — Per-owner recreate parallelism cap

A new owner runs at most `SB_RECREATE_CONCURRENCY` (default 4)
parallel `RecreateSandbox` calls. The rest queue.

Code: a buffered semaphore in `owner_watcher.recreateOwnedSandboxes`.

### P1b — Spread reassigns across owners

In `evictDeadOwner`, after picking targets, cap "reassigns to one
target" to `ceil(dead_count / live_count)` — so 50 reassigns over 10
live peers go 5 each, not 50 to the leanest.

Code: replace per-sandbox `SelectPlacement` with a batch-aware
assignment in `dead_owner.go:166-201`.

### P1c — Image cache hints in pull RPC

Workers report a list of cached image hashes in their heartbeat /
pull RPC (already proposed for the worker/server split). Scheduler
prefers cache-local nodes for failover recreates only — not for
fresh placements.

Code: extend `nodeMeta` if it fits, or move it to the slow pull RPC.
New filter in `selectRecreationTargetExcluding`.

---

## P1 — Drain mode & graceful shutdown

**Motivates:** [`02 §A8`](./02-assumptions-challenged.md#a8),
[`06 F10`](./06-failure-modes.md).

- `POST /v1/cluster/drain` (per-node admin call): marks the node as
  "draining."
- Scheduler skips draining nodes.
- Background loop on the draining node: for each owned sandbox,
  proactively `opReassign` to a live peer, then locally destroy.
- Drain completes when no sandboxes own.
- `systemctl stop sandboxd` should call drain implicitly.

Code: new admin endpoint, new background loop in
`internal/cluster/worker.go` (post-split), new gossip taint flag.

---

## P1 — Reservation-on-placement

**Motivates:** [`02 §A3`](./02-assumptions-challenged.md#a3),
[`04 §5`](./04-control-plane-critique.md#5-the-reservation-pattern-is-missing).

Today's order: pick → forward → create → commit. Race window: two
schedulers see the same gossip and pick the same target.

Proposed order: pick → reserve in FSM → forward → create →
upgrade-reservation-to-placement (or release).

- New FSM op: `opReserve(sandbox-id, target-node, expiry=10s)`.
- Reservations appear in the replicated FSM and count against the
  target's `Reserved` accounting for subsequent decisions.
- On create success: `opPlace` upgrades the reservation.
- On create failure or expiry: `opReleaseReservation`.

Worker-side reaper sweeps expired reservations every minute.

**Effort:** small to medium. One new op, one new bookkeeping field.

---

## P1 — Admission shedding at the API edge

**Motivates:** [`02 §A9`](./02-assumptions-challenged.md#a9),
[`03 §1`](./03-scale-200x50.md#1-the-raft-commit-hot-path).

The leader exposes a `raft.ApplyBacklog()` signal (count of pending
applies). API edge nodes (or the server itself, post-split) consult
this on every create and return **503 with `Retry-After`** when the
backlog exceeds a threshold.

This is back-pressure that stops the cluster from collapsing under a
burst. Honest-to-god rate-limit + jitter on retry, client-side.

**Effort:** tiny.

---

## P2 — Batch create API

**Motivates:** [`02 §A9`](./02-assumptions-challenged.md#a9),
[`03 §1`](./03-scale-200x50.md#1-the-raft-commit-hot-path),
[`04 §3c`](./04-control-plane-critique.md#3c-no-batching-for-bursts).

```
POST /v1/sandboxes:batch
[ {spec_1}, ..., {spec_N} ]

→ scheduler scores N at once, distributes across nodes
→ leader writes one batched raft entry (single commit) with N opPlace records
→ owners run their slices in parallel
→ response: per-spec result with sandbox id or error
```

Throughput win for burst workloads. Self-contained API addition.

**Effort:** medium (touches scheduler + raft command + API + SDKs).

---

## P2 — Node labels & taints

**Motivates:**
[`04 §4`](./04-control-plane-critique.md#4-missing-scheduler-features).

- `nodeMeta` gets a small `map[string]string` for labels and a
  `[]string` for taints.
- `CreateSandboxRequest` gets optional `node_selector` (map) and
  `tolerations` ([]string).
- Scheduler filter: drop nodes that don't match selector or that have
  taints the request doesn't tolerate.

This is the minimum scheduling sophistication a heterogeneous
fleet needs (GPU vs CPU, AZ pinning, drain markers).

**Effort:** small.

---

## P2 — Hourly rebalancer

**Motivates:** [`04 §3b`](./04-control-plane-critique.md#3b-no-rebinning).

Periodic loop on the leader (every hour): compute per-node load
skew; if max/min > threshold, pick the most-skewed pair (most-loaded
+ least-loaded), pick the longest-running sandbox on the loaded node,
issue `opReassign` (with proactive local destroy, then recreate on
new owner).

Behind a feature flag with conservative defaults. Operator can disable.

**Effort:** small.

---

## P2 — Post-partition reconciliation

**Motivates:** [`06 F3`](./06-failure-modes.md#f3-network-partition-split-brain).

After raft reconverges post-partition, the new leader runs:

- For every placement, ask each "live" peer (the new owner per FSM)
  to confirm the sandbox is running locally.
- If a worker reports a container locally that isn't in the FSM
  (orphan from no-quorum side), instruct it to destroy.
- If FSM has placement to node-X but node-X says "I don't have it,"
  treat as failed-recreate and re-pick target.

**Effort:** small to medium.

---

## P2 — Health-aware scheduling

**Motivates:** [`04 §2`](./04-control-plane-critique.md#2-gossip--swim-keep-narrow),
[`06 F4`](./06-failure-modes.md#f4-slow--flapping-gossip-on-one-node).

Workers report a `health` enum in heartbeat: healthy / degraded /
draining / dead. Degraded factors in: disk near full, recent OOM
kills, gossip flap-rate above threshold, container runtime errors.

Scheduler weight: degraded nodes get a 0.5× score multiplier (still
admissible, but only when better options are full).

**Effort:** small-medium.

---

## P2 — Leader self-step-down on latency

**Motivates:** [`06 F8`](./06-failure-modes.md#f8-slow-disk-degradation-on-the-leader).

Leader monitors its own raft commit latency p95. If above threshold
for sustained interval, calls `raft.LeadershipTransfer` to yield to
another voter.

**Effort:** tiny.

---

## P2 — Cert expiry & rotation

**Motivates:** [`06 F9`](./06-failure-modes.md#f9-mtls-material-expired-or-rotated).

- `/v1/cluster/members` includes per-node cert expiry date.
- Documented rolling rotation procedure (mint new bundle, run a
  one-node-at-a-time rotation script).
- Alert (log-level WARN) when any node's cert is within 30 days of
  expiry.

**Effort:** small.

---

## P3 — Anycast / BGP

Skip. Anycast routes to the *nearest* node, not the *owner* node.
Doesn't solve the data-plane problem. Listed only so future
contributors don't reopen the question.

---

## P3 — Multi-tenant fairness

Per-tenant rate limits, quotas, isolation. Out of scope until the
product has multi-tenant in scope.

---

## P3 — UDP exposure

Today `ValidExposedPortProtocol` rejects UDP. Adding it requires
caddy-l4 UDP support (exists) plus port-pool changes plus SDK plumbing.
Modest effort; gated on whether any user asks.

---

## P3 — Snapshot replication

Per the operator brief, deferred. When picked up:

- Snapshots become replicated through raft (large blob in FSM is
  expensive; probably a separate blob store with raft holding the
  manifest).
- Snapshot recreation joins the failover-recreate path.

This is its own design doc, not part of this critique.

---

## Sequencing

A reasonable quarter looks like:

**Weeks 1–2:**
- P0 hot patch: auto-non-voter (1 day).
- P0a per-node URLs (1 week).
- P1 admission shedding (3 days).
- P1c image cache hints (3 days).

**Weeks 3–8:**
- P0 server/worker split (the big one).

**Weeks 9–12:**
- P1 drain mode.
- P1 reservation-on-placement.
- P1 failover storm control (parallelism cap + reassign spreading).

**Next quarter:**
- P0b ingress tier (if public URLs become a priority).
- P2 batch create, labels/taints, rebalancer.

The product is *credible at 200×50* after the week-1–2 work and the
P0 server/worker split. Everything after that is hardening rather
than enabling.
