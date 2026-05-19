# 06 — Failure Modes

This page walks through specific failure scenarios at 200×50 and asks:
*what does the system do, and does that answer match what an operator
would want?* Each scenario lists what's covered today, where the gaps
are, and the cost of leaving them open.

The operator brief is explicit: **sandboxes don't have to be HA. If a
sandbox crashes, it's gone.** So the bar is *cluster survives*, not
*every sandbox survives*. That changes which gaps matter.

---

## F1. Single worker node power-loss

**What happens today:**

1. Gossip marks node-X suspect (~5 s), then dead (~5 s).
2. Leader's dead-owner reconciler starts the grace timer (default 30 s).
3. After ~30 s grace, leader runs `evictDeadOwner` for X:
   - For each of X's ~50 placements: `pickRecreationTarget(spec)` →
     `opReassign` raft commit (serial).
   - `RemoveServer(X)` (raft config change).
4. New owners' owner-watchers fire on their next 5 s tick.
5. Each new owner does docker-pull → docker-run → re-expose-ports.

**Wall clock from death to first sandbox back:**

- Gossip detection: ~10 s
- Grace: 30 s
- Reassign commits (50 × ~30 ms commit p99 at 200 voters): ~1.5 s
- Watcher tick: 0–5 s
- Image pull on cold cache (1 GB image): 30–120 s
- Container start + caddy admin: a few seconds

**Total: ~80–180 s** for the first sandbox to come back; the last one
finishes minutes later if the new owner has to pull a fresh image.

**Coverage:** the path *exists*. Correctness is fine: sandboxes that
had specs get recreated; sandboxes without specs become orphans
(`owner=""`, returns 410 Gone). Tests in
`dead_owner_test.go`, `assert_ownership_test.go`,
`owner_watcher_test.go` cover the FSM state machine.

**Gaps at 200×50:**

- **Image pull stampede on the new owners.** If X's 50 sandboxes used
  10 distinct images and spread across, say, 5 new owners → 10 cold
  pulls per new owner, in parallel. Each new owner saturates its
  network. Bandwidth caps create a serialization queue invisible to
  the cluster.
- **No image cache warming.** Workers don't gossip *what images they
  already have cached*. The dead-owner reconciler picks recreation
  targets by capacity headroom, not by cache locality. Sending a
  Python-image sandbox to a node that already has Python pulled saves
  60 s; today the placement is blind to that.
- **No back-pressure on the new owner.** If 20 of X's sandboxes
  reassign onto one new owner Y, Y does 20 parallel
  RecreateSandbox calls. The owner watcher loop says *"if recreate
  latency becomes a problem we can fan out, but typical failover
  bursts are <100 sandboxes"* — that's the wrong sizing comment for
  the 200×50 target where one node = 50 recreates.
- **Caddy admin API queue on the new owner.** 20 concurrent
  RecreateSandbox calls = 20 sequential Caddy admin calls. Caddy's
  admin reload is serial.

**Mitigations to add:**

- **Worker image-cache signal.** Pull RPC carries a small list of
  cached image-ref hashes. Scheduler scores cache-local nodes higher
  for failover recreates (not for fresh placements — that biases load
  unfairly).
- **Per-owner recreate concurrency cap.** New owner serializes
  recreates with a configurable parallelism (default 4–8). Slower
  total recreation but no thrashing.
- **Spread reassigns intentionally.** `evictDeadOwner` today uses
  `pickRecreationTarget` per-sandbox. With 50 placements that's 50
  independent power-of-two-choice calls — they tend to converge on
  the same handful of lightly-loaded nodes. Cap "reassigns onto one
  target per eviction batch" to (say) ceil(50 / 5) = 10.

These are all worker-side changes; no raft semantics touched.

---

## F2. Rack PDU outage (3 adjacent nodes die at once)

**What happens today:**

- 3 simultaneous gossip-leave events.
- 3 simultaneous dead-owner grace timers.
- After grace, leader's reconcile tick processes them. The dead-owner
  loop iterates per dead-node sequentially (`dead_owner.go:144-152`).
- 150 placements to reassign, plus 3 `RemoveServer` config changes.

**Total raft commits: ~153 in one tick.**

At 200 voters, p99 commit is several hundred ms. 153 × 200 ms = ~30 s
of pure leader-serialized work. Other writes block.

**Coverage:** the path is correct. The orphan / reassign logic is
idempotent. After the burst, the cluster converges.

**Gaps:**

- **Quorum risk** if the 3 nodes were strategic voters. With 200
  voters, losing 3 doesn't break quorum (3 << 100). With a fixed 3- or
  5-server control plane, **losing 3 servers does break quorum.**
  This is why the worker/server split also requires careful server
  placement: spread the 3 servers across 3 AZs.
- **Leader thrash.** If the dead nodes included the leader (1/N
  chance), election happens. With 200 voters, leader election under
  load is slow. With 3 servers, election is sub-second.
- **150 simultaneous reassigns is a heavy thundering herd.** Same
  per-owner mitigations as F1 apply at 3× scale.

---

## F3. Network partition (split brain)

**What happens today:**

Two subsets of nodes lose connectivity to each other but both stay up
and serve requests on their own.

- The subset *with* raft quorum keeps writing. Placements proceed.
- The subset *without* quorum stalls writes. Reads from the FSM
  continue (stale but available).
- Gossip on each side marks the other side dead.
- After grace, each side's leader tries to reassign the other side's
  placements. **Only the quorum-holding side actually commits.** The
  no-quorum side can't run config changes (no leader).
- When partition heals, raft converges. The no-quorum side discards
  its in-flight (uncommitted) state. Conflicts: a sandbox might have
  been reassigned twice and the no-quorum-side's reassign is silently
  dropped.

**Coverage:** raft itself does the right thing — single-leader =
single source of truth for placements.

**Gaps:**

- **Data plane during partition.** Workers on the no-quorum side
  still hold their containers. Clients hitting those workers via
  direct IP keep working. Clients hitting through the LB get
  unpredictable behaviour because the LB's view of "owner" is
  whatever the LB's control-plane feed shows — possibly stale on the
  no-quorum side.
- **Recreates on both sides.** If both sides decide the other is dead
  and start grace timers, both sides try to recreate the same
  sandboxes. The quorum-holding side wins on raft. The no-quorum side
  might *start* a docker run that never commits to raft. After heal,
  that container is orphaned (FSM doesn't know about it).
- **No "pause when no quorum" mode for workers.** A worker on the
  no-quorum side keeps serving sandbox traffic; that's actually
  correct (containers are still up). But it also keeps accepting
  *new* SDK calls on those sandboxes — which mutate local state that
  raft can't see. After heal, the no-quorum side's mutations are
  invisible to the rest of the cluster's FSM, and `replicateSpecPatch`
  failures get swallowed.

**Mitigations to consider:**

- Workers should *block placement changes* (creates) when their
  control-plane connection is down. Already true today by accident:
  raft commit on the no-quorum side fails, the create rolls back.
- Workers should still serve **read** SDK calls and existing-sandbox
  hot-path calls. That's the right product behaviour: a partition
  shouldn't kill running sandboxes.
- After heal, the leader should run a reconcile that detects
  duplicate placements and resolves (delete the loser's container).
  Today: not built. Manual operator cleanup is the only path.

**Verdict:** the system survives partition correctly enough; the
post-heal cleanup is the gap, and at 200×50 with the rare partition
event the cost is acceptable.

---

## F4. Slow / flapping gossip on one node

**Scenario:** node-X has a GC pause / disk-stall every few minutes,
causing memberlist to mark it suspect → alive → suspect repeatedly.

**What happens today:**

- Each suspect → alive transition fires `cancelDeadOwnerWatch` on the
  reconciler.
- Each suspect → dead transition fires `handleMemberLeave`, starting a
  grace timer.
- If the timer never elapses (node always recovers before 30 s), no
  reassign happens. Good.
- But: every flap triggers gossip-wide `UpdateNode` propagation, and
  scheduler decisions read the flapping node's capacity as either
  "alive and healthy" or "missing" depending on tick alignment.

**Coverage:** the grace timer prevents pathological reassigns.

**Gaps:**

- **A flapping node still receives placements.** Its capacity snapshot
  looks fine when it's alive; placement decisions land work on it.
  That work then experiences the same flap.
- **No "suspect doesn't get new work" rule.** A node that has been
  flapping for an hour should be quarantined.

**Mitigation:** track per-node "alive ratio" over a sliding window in
the scheduler; deprioritize or exclude nodes below a threshold (say
80%). This is the "degraded but alive" signal from
[`04 §2`](./04-control-plane-critique.md#3-things-gossip-should-not-carry).

---

## F5. Image registry outage

**Scenario:** Docker Hub or your private registry is down. New
placements can't pull images.

**What happens today:**

- `clusterCreateWrap` runs placement, forwards to target T, T calls
  `CreateSandbox` → docker pull fails.
- Local create returns error.
- The forwarding wrapper writes a non-2xx response back to the
  client.
- No raft commit, no placement record. Good.

But:

- **Failover recreate on dead owner**: target T tries to recreate, pull
  fails, owner-watcher increments failure counter. After 5 failures
  (~25 s), placement reassigns to *another* node. That node tries to
  pull, also fails, …
- The cluster cycles the orphan placement through every node looking
  for someone who can pull.

**Coverage:** the giveup logic exists
(`maxRecreateFailuresBeforeReassign`). But the *cycling* behaviour at
scale is bad: 50 placements × 5 nodes each × 25 s = ~6 minutes of
pure churn while every node fails the same way.

**Gaps:**

- **No global circuit-breaker.** If the same image is failing to pull
  on N consecutive nodes, the cluster should give up sooner and mark
  the placement as needing operator intervention.
- **No exponential backoff per placement.** 5 tries × 5 s each is
  fixed.

**Mitigation:** add a `pull_failure_count` to the placement; once it
hits a higher threshold (say 20) the placement is *parked* (no further
recreates) until an operator intervenes via API.

---

## F6. Sandbox creates with a malformed spec that always crashes

**Scenario:** a user creates a sandbox with a command that segfaults at
container start. The container exits immediately. Then it gets
recreated (failover or not), exits, etc.

**What happens today:**

- Sandbox state lives in the local store; container exits are
  observed via Docker events (`pkg/docker/events.go`).
- The cluster FSM doesn't know about exits — only about ownership.
- Owner watcher doesn't re-create on exit; it only creates when FSM
  says "owned by me" *and* local store says "not present."
- So an exited-but-known-locally sandbox stays exited.

**Coverage:** correct — exits don't cause loops.

**Gap:** none here. The "no auto-restart" is exactly what the operator
brief asks for.

---

## F7. Leader churn under load

**Scenario:** a 200-voter cluster under burst load. The leader's
follower-ack latency is high, an election times out, leadership
changes. New leader catches up.

**What happens today:**

- During election: no commits accepted. Writers see 503.
- After election: new leader has the full FSM (it's a voter, it has
  everything).
- Forwarder retries to the new leader.

**Coverage:** raft handles this.

**Gaps at 200 voters:**

- **Election takes longer with more voters.** RequestVote fan-out and
  the "got a majority?" calc scale with N. Election timeout default
  is ~1 s; under load can take longer.
- **Burst writers all retry to the new leader at once.** If 100
  concurrent creates were in flight, they all retry. The new leader
  processes them in some order. No backoff.

**Mitigation:** worker/server split shrinks the election surface from
200 voters to 5. Election in 50–200 ms. Then leader churn is a
non-issue.

---

## F8. Slow-disk degradation on the leader

**Scenario:** the leader's BoltDB raft log is on a disk that's
degrading (high latency, low throughput, occasional EIO).

**What happens today:**

- Raft commit p99 spikes because the leader can't fsync fast.
- Followers wait for AppendEntries acks but the leader is slow to
  *issue* them.
- Eventually election timeout fires, leadership moves.
- During the slow phase, the cluster looks "alive but slow."

**Coverage:** raft will eventually elect a healthier leader.

**Gaps:**

- **No proactive leader-step-down on disk latency.** A leader that
  notices its own fsync p99 above a threshold should yield leadership.
- **No leader CPU/disk health in gossip.** Followers can't ask "is
  the leader healthy?" without observing election timeouts.

**Mitigation:** add a periodic self-health check on the leader that
issues `raft.LeadershipTransfer()` if local fsync latency exceeds a
threshold. Small addition; large operator-experience win.

---

## F9. mTLS material expired or rotated

**Scenario:** the cluster TLS material is set to expire in 1 year.
Nobody renews. Or someone rotates the CA without distributing the new
bundle.

**What happens today:**

- Raft transport refuses peer connections.
- Internal RPC refuses peer connections.
- Followers can't reach the leader; new leader can't be elected because
  the elections fail mTLS.
- Cluster goes read-only. Sandboxes keep running on each node's local
  state.

**Coverage:** failure is loud — `ClusterTLS.serverConfig()` /
`clientConfig()` errors propagate.

**Gaps:**

- **No cert expiry monitoring.** The daemon doesn't proactively warn
  when cluster certs are within 30 days of expiry.
- **No rolling cert rotation.** Today the only path is "shut down,
  redistribute bundle, restart."

**Mitigation:** add cert expiry to `/v1/cluster/members` so monitoring
can scrape it. Document a rolling rotation procedure. Both small.

---

## F10. Operator runs `cluster-init.sh` on the wrong node

**Scenario:** operator misreads the docs and runs `cluster-init.sh` on
a node that's already joined a cluster. The script re-bootstraps the
raft state.

**What happens today:**

- Raft on that node now thinks it's a standalone single-voter cluster.
- Gossip with peers still works.
- Voter auto-join might or might not converge depending on which side
  becomes the leader of the conflict.

**Coverage:** the script does some safety checking but the surface is
big enough that bad outcomes exist.

**Gap:** common operator-error class with bad blast radius.

**Mitigation:** `cluster-init.sh` should refuse to run on a node that
already has raft state on disk unless `--force` is passed. Tiny
hardening; high operator-trust value.

---

## F11. Caddy admin API blocked on the new owner

**Scenario:** the new owner's Caddy is doing a long ACME renewal when
50 failover recreates need to write routes.

**What happens today:**

- Caddy admin is one-config-at-a-time per node. Writes serialize.
- Each `service.CreateSandbox` includes a Caddy admin call.
- The 50 recreates queue at the Caddy admin port.

**Coverage:** the writes will eventually drain. No data loss.

**Gap:** during the drain, sandboxes are "owned but unreachable" for
seconds-to-minutes per sandbox depending on queue position.

**Mitigation:** the ingress tier in
[`05`](./05-data-plane-and-load-balancer.md) makes per-worker Caddy
state much smaller (only local sandboxes, no cross-node stubs), so the
admin queue stays short.

---

## F12. Hot SDK client floods one node

**Scenario:** one tenant's SDK hammers one node with 10 RPS of
mutating calls (creates, port-forwards) against the same sandbox.

**What happens today:**

- Every mutating call leader-forwards.
- Leader's raft applies serialize per-sandbox by hash collision in
  the FSM (same `Apply` lock).
- No rate-limiting per tenant; no rate-limiting per sandbox.

**Coverage:** the cluster handles it — raft applies as fast as it can.

**Gap:** a noisy tenant can starve quiet ones. No fairness.

**Mitigation:** out of scope until multi-tenant is real; the brief
isn't asking for it. Naming it for completeness.

---

## F13. Daemon OOM on the leader

**Scenario:** leader sandboxd hits its memory limit (FSM grew, plus
in-flight requests). systemd kills it.

**What happens today:**

- Restart picks up where it left off (raft log is on disk).
- Followers detect leader gone, elect a new one.
- ~election timeout window of read-only.

**Coverage:** restart is graceful.

**Gap:** if the FSM size itself is the reason for OOM, the new leader
will OOM too. Cluster goes into a restart loop. **Worker/server split
keeps this scoped to 3–5 servers, all of which can be sized
adequately.** Today the same issue could hit any of 200 nodes.

---

## F14. Failover with no spare capacity

**Scenario:** every node is at 95% capacity. A node dies. Reassign
target lookup finds nobody with room for the dead node's sandboxes.

**What happens today:**

- `pickRecreationTarget` calls `SelectPlacement` which filters by
  `nodeFits`. If nobody fits → returns self (which doesn't fit
  either) → returns "" → placement orphaned (no spec, owner="").
- API returns 410 Gone for those sandbox IDs.

**Coverage:** the orphan path is correct — observable, not silent
failure.

**Gap:** no autoscaling integration. The cluster knows it can't fit
work; it can't *ask* for more nodes.

**Mitigation:** expose a `/v1/cluster/capacity-pressure` endpoint that
an external autoscaler (cloud autoscaling group webhook, k8s HPA-like
controller) can poll. Out of scope for the cluster itself but worth a
hook.

---

## F15. The "everything that involves snapshots" hole

The operator brief explicitly defers snapshot-cluster support. Today,
the snapshot endpoints (`/v1/snapshots/...`) write only to the local
store — they're not replicated.

Implication: a sandbox built from a snapshot can only be recreated on
the node that holds the snapshot. If that node dies, the recreate path
can't find the snapshot, and the sandbox is orphaned.

**Coverage:** the existing failover code already has the orphan path
for "no spec" — snapshots will hit the same code path.

**Gap:** documented and accepted per the brief.

---

## Summary of operational risks

| # | Failure mode | Severity at 200×50 | Mitigation cost |
|---|---|---|---|
| F1 | Single worker death | Med | Low (concurrency cap + cache locality) |
| F2 | Rack outage (3 nodes) | High (raft commit storm) | Worker/server split (P0) |
| F3 | Network partition | Low (raft correct) | Add post-heal reconcile (med) |
| F4 | Flapping node | Med (degraded scheduling) | Sliding-window alive ratio (med) |
| F5 | Registry outage | Med (placement cycling) | Circuit-breaker on pull failures (low) |
| F6 | Sandbox always crashes | None — correct | n/a |
| F7 | Leader churn under load | High (200 voters) | Worker/server split (P0) |
| F8 | Slow-disk leader | Med | Self-step-down on fsync latency (low) |
| F9 | Cert expiry | Med (silent timebomb) | Expiry monitoring (low) |
| F10 | Operator misruns cluster-init | High (data loss) | `--force` guard (low) |
| F11 | Caddy admin queue | Low after LB tier | LB tier (P0) |
| F12 | Hot tenant flood | Low (single-tenant brief) | Defer |
| F13 | Leader OOM | Med | Worker/server split + sizing |
| F14 | No spare capacity | Med | Autoscaler webhook (med) |
| F15 | Snapshot in cluster | Accepted | Deferred per brief |

The pattern: most of the medium-severity issues collapse to "fix the
worker/server split and the LB tier; the rest are tractable hardenings."
That's the agenda for [`07`](./07-improvement-proposals.md).
