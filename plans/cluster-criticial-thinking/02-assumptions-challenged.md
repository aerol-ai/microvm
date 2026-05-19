# 02 — Assumptions Challenged

Every architecture rests on assumptions that are never written down. This
page names the ones embedded in `internal/cluster/`, then pressure-tests
each one against the 200×50 target.

Format per assumption:

> **A#. The assumption (one sentence).**
> Where it shows up in code (so it's not me strawmanning).
> Why it's plausible.
> Where it breaks.
> Verdict (keep / qualify / replace).

---

## A1. "Every node should run raft."

**Where:** `cmd/sandboxd/main.go` wires `cluster.New` for every node when
`SB_ENABLE_CLUSTER=true`. `voter_autojoin.go:30-38` promotes every
gossip-joining node to a voter unconditionally.

**Why it's plausible:** Single-binary, "any node serves any request" is a
real product property. If every node has the FSM in RAM, `OwnerOf` is a
pure local read and forwarding is a one-hop reverse-proxy. That's
genuinely simpler than K8s's etcd-on-three-nodes-and-everyone-else-
watches model.

**Where it breaks at 200 nodes:**

- **Raft quorum becomes (N+1)/2 = 101.** Every leader commit waits for
  101 acks. The slowest 100 voters set commit latency. p99 latency goes
  from ~5 ms to ~50–200 ms even on a perfectly healthy LAN, because the
  long tail of 200 sequential acks dominates.
- **Raft replication fan-out is O(N).** The leader serializes the log to
  199 followers per commit. Even at 100-byte log entries that's ~20 KB
  of egress per write, and the leader's outbound bandwidth becomes the
  global write rate cap.
- **Joining a 200-voter raft cluster requires log-replay of the whole
  FSM.** Snapshot transfer + log catchup on a fresh node is now a
  multi-minute operation when you bring a node up. That's painful for
  autoscaling.
- **Memberlist SWIM is O(N²) for full-mesh probing.** memberlist
  mitigates with random partial probes, but at 200 nodes the gossip
  layer alone is doing thousands of UDP packets per second cluster-wide.
- **Disk amplification.** Every raft entry hits BoltDB on every voter.
  10K placements + churn means O(200 × N_writes) BoltDB writes for
  every state change.

**Verdict: REPLACE.** This is the single most important change. The K3s
shape is the right model: a small fixed control-plane set (3 or 5 voter
nodes) that holds raft, and the rest of the fleet runs in a "worker"
role that consumes the placement map via the existing internal RPC
without participating in consensus.

Concrete proposal in [`07`](./07-improvement-proposals.md#p1-server--worker-roles).

---

## A2. "The placement map is small enough to keep in every node's RAM."

**Where:** `fsm.go:67-77` — the FSM map is in-memory; the code comment
says *"even a 10K-node fleet with 100 sandboxes/node fits comfortably in
RAM"* — i.e. 1M sandboxes, ~150 B/row → 150 MB. That's the
*placement-map-only* number; with Spec replication it climbs sharply.

**Why it's plausible:** At today's 3-node, ~hundreds-of-sandboxes scale,
the map is in the MBs. Read-from-self is cheap.

**Where it breaks:**

- The 150 B/row estimate **does not include the replicated Spec.** A real
  `CreateSandboxRequest` with env, mounts, lifecycle scripts is 1–4 KB.
  At 10K sandboxes that's 20–40 MB just for specs.
- The estimate **does not include SealedSecrets.** Sealed registry creds
  + per-mount creds add another ~1 KB/sandbox when used. Conservatively
  another 10 MB at 10K.
- The estimate **does not include the raft log** between snapshots.
  Snapshot threshold is 1024 entries; the BoltDB log can hold many
  multiples of that on disk.
- **At 200 voters × ~30 MB FSM, that's 6 GB of cluster-wide duplicated
  state.** Not catastrophic, but a notable cost when 195 of those copies
  exist only because every node is a voter.

**Verdict: KEEP, with caveat.** The FSM-in-RAM property is fine *if* the
node holding it is a voter (it would have to hold it for raft anyway).
Force-holding the FSM on every worker is the actual waste. With the A1
fix, FSM-in-RAM stays only on the 3–5 server nodes; workers cache only
the placements relevant to *them* (sandboxes they own) plus an
eventually-consistent owner-lookup view, like a kubelet caching pods
assigned to that node.

---

## A3. "Power-of-two-choices placement converges to good load spread."

**Where:** `placement.go:21-58`.

**Why it's plausible:** The result is real and well-known — picking the
less-loaded of two random servers gives ~exponentially better load
spread than uniform random. For a homogeneous fleet making independent
placement decisions, it works.

**Where it breaks:**

- **Stale capacity signal.** Gossip refresh is 5 s. SWIM dissemination
  adds another few hundred ms. At a 200-node cluster doing many
  concurrent placements, two nodes scoring a third both see *the same
  stale snapshot* and both place onto it. The "self always loses ties"
  hack helps a little but doesn't solve the herd.
- **No reservation-on-decision.** The placement decision doesn't write
  anything to the chosen node before forwarding. If 50 concurrent
  placements all see node-C as the leanest, all 50 forward to C, and C
  admits them one at a time. The losing ones discover "actually I'm
  full" after a round trip. There's no claim-token.
- **Power-of-two only filters down to ~optimal when sample size matches
  imbalance variance.** With 200 nodes, picking 2 random ones often
  picks two "average" nodes; the truly empty ones get visited only when
  the random draws happen to land on them. Bin-packing here is what an
  actual scheduler does.
- **Heterogeneous fleets are not modeled.** Real clusters have nodes
  with 8 cores and nodes with 64. `headroomScore` normalizes by budget
  but doesn't differentiate "fits comfortably on a small node" from
  "wastes capacity on a big node." A 0.5-core sandbox going onto a 64-
  core machine when a half-empty 8-core machine exists is a waste.

**Verdict: KEEP for steady state, QUALIFY for hot spots.** Power-of-two
is fine as the default. But there needs to be:

1. A **reservation token** the scheduler writes before forwarding, so
   admission isn't a race.
2. A **rebalancer** that periodically looks at the cluster's bin-pack
   error and migrates marginal sandboxes (the operator said sandboxes
   don't have to be HA, so a migration that destroys+recreates is
   allowed). At scale, the dominant placement quality factor isn't
   *initial placement* — it's the long-term skew after churn.
3. A **batch placement** API so a burst of 50 creates from one client
   gets scored together, not 50 independent scores against the same
   stale snapshot.

---

## A4. "Gossip captures enough to make placement decisions."

**Where:** `nodeMeta.Capacity = capacity.Snapshot` in `gossip.go:20-31`,
read in `placement.go:21`.

**Why it's plausible:** Capacity is the only thing the scheduler scores
on, so capacity is what gets gossiped. Anything bigger blows the 512 B
memberlist NodeMeta cap.

**Where it breaks:**

- **NodeMeta size limit is real.** `gossip.go:80-92` already has a
  truncation-fallback. Any future signal we want — image cache state,
  network bandwidth, disk IOPS, runtime version, geographic zone — has
  to fit inside that budget or go elsewhere.
- **5 s freshness is fine for slow load, terrible for spikes.** A node
  that admits 30 sandboxes in 2 seconds (a real spike from one client)
  doesn't get a new capacity snapshot to peers until the next refresh
  tick.
- **No signal for "this node is unhealthy."** Gossip says alive/dead.
  Real ops needs "alive but degraded" — disk near full, kernel OOM kills
  recent, container runtime in a bad state. Today a degraded node still
  scores well because its `capacity.Snapshot` looks healthy.

**Verdict: QUALIFY.** Keep gossip for liveness + capacity. Move scheduler
inputs that exceed NodeMeta budget into a small periodic RPC
("`/v1/internal/node-state`") pulled by the schedulers from the workers.
At 200 nodes pulled every 5 s with 3 schedulers, that's 200 × 0.6
RPS = 120 RPS cluster-wide — trivial.

---

## A5. "Failover-recreate from spec is enough."

**Where:** `owner_watcher.go:77-120`, `dead_owner.go:166-201`. The new
owner pulls the spec from FSM, unseals creds, `docker run`. Container
filesystem and exec sessions are lost.

**Why it's plausible:** The operator brief is explicit: sandboxes are not
HA. If you want durable state, use a mount. The product makes this
explicit in `setup/cluster.md:178-186`.

**Where it breaks at 200×50:**

- **Image pull stampede.** If node-X dies owning 50 sandboxes using 10
  different images, the new owners collectively do up to 50 docker pulls
  against the user's registry — in some cases the same image to the
  same new owner 5 times in a row. Docker dedupes, but only after the
  first pull *completes*. The first 30 seconds after a node death is a
  network-and-registry-saturation event.
- **Caddy admin API stampede on the new owner.** A node that gets 50
  failover-recreates does 50 sequential `caddy admin` API calls to add
  routes. Caddy is single-threaded on the admin port; queueing depth
  matters.
- **No back-off for repeated failover.** If a sandbox keeps failing on
  the new owner (image gone from registry, mount cred expired),
  `maxRecreateFailuresBeforeReassign = 5` means 25 s of pure churn per
  sandbox before reassign. With 50 such sandboxes that's a 50-sandbox
  reassignment storm on every reconcile tick.
- **Sandbox state survives only if it's externalized.** Most users will
  *think* their session state is preserved because it's not obvious from
  the API surface that an owner-death silently destroys filesystems. The
  docs say so but no API response carries a "this is a recreate"
  indicator a client could observe.

**Verdict: KEEP, but treat the stampede as a first-class load problem.**
The semantics ("you lose container fs") are right for this product. The
*operational behaviour* of failover-recreate at 50 sandboxes-per-failed-
node is not addressed. The fixes are:

1. Spread reassignments across the cluster (not 1:N onto the leanest
   node — that just transfers the failure).
2. Pace recreates per new owner (cap concurrent recreates per node).
3. Pre-warm image caches on neighbours via gossip-driven hinting.

Detail in [`06`](./06-failure-modes.md) and
[`07`](./07-improvement-proposals.md#p4-failover-storm-control).

---

## A6. "DNS round-robin / NLB plus per-node Caddy is acceptable ingress."

**Where:** `setup/cluster.md:418-518`. The doc is *honest* about this —
Topology A (NLB + round-robin) is recommended only for SDK-only use,
where the 1/N sandbox-URL hit rate is "acceptable" because the SDK calls
forward at the application layer anyway.

**Why it's plausible:** API plane is the dominant traffic for an
SDK-driven product. If you only ever touch the sandbox through the SDK,
sandbox URLs barely matter.

**Where it breaks at 200 nodes:**

- **1/200 = 0.5% hit rate.** Even by the doc's own logic, "acceptable"
  was a 3–5 node argument. At 200 nodes the failure rate of public
  sandbox URLs goes from ~67% to ~99.5%. That isn't "use mostly the SDK"
  — that's broken.
- **Any URL the operator publishes externally — webhooks, OAuth
  callbacks, shareable preview links, `iframe` embeds in a dashboard —
  is unreliable.** The product loses a real feature.
- **Failover changes the answer.** Even if you wire up Topology B
  (per-sandbox DNS, not built), DNS TTL caches mean a 60 s gap on every
  failover. At 200×50 with periodic node turnover, that gap is hit a
  lot.

**Verdict: REPLACE.** The cluster needs a real ingress tier. Options and
tradeoffs are the entirety of [`05`](./05-data-plane-and-load-balancer.md).
The short answer: **a small Envoy/HAProxy tier that reads the placement
map via xDS or HTTP polling and routes per-SNI to the owner**. The
existing every-node-is-Caddy stays for local termination; the new tier
sits in front and replaces the dumb L4 NLB.

---

## A7. "Worker nodes can double as routers for peers."

**Where:** Implicit. The doc envisions a future "Option 2 — cross-node
Caddy stub routes" in `plans/fucked-up-design-in-cluster.md`. The idea:
every node's Caddy has a route for every sandbox; non-owner Caddys
pass-through to the owner.

**Why it's plausible:** Reuses code that already exists. No new
component. Every node already has the placement map.

**Where it breaks at 200×50:**

- **Caddy config explosion.** 10K sandboxes × 200 nodes = 2M route
  entries in aggregate. Each node holds 10K routes. Caddy can do that,
  but cold start time, admin-API reload time, and the JSON config blob
  size all grow with it. Each node's Caddy is now O(total cluster
  sandboxes), not O(local sandboxes).
- **Update fan-out.** Every placement change must be reflected in every
  node's Caddy. A 100-sandbox failover from one dead node = 100 ×
  (N-1) = 19,900 Caddy admin API calls cluster-wide just to update
  routes. Caddy's admin API is one-config-at-a-time per node.
- **One extra hop on (N-1)/N of all traffic.** At 200 nodes that's
  99.5% of sandbox-URL traffic taking a hairpin: client → entry node →
  owner → entry node → client. Inside a VPC the latency is small; the
  bandwidth cost is real (every byte travels twice on the cluster
  network).
- **Trust posture.** Every node now terminates TLS for traffic it
  doesn't own. The peer hop must re-establish TLS to the owner.
  That's two TLS handshakes per request unless you proxy at L4 with SNI
  pass-through — which then means the entry node can't do anything
  smart with the traffic.
- **A dead routing node fails (N-1)/N of all routes through it.** If
  node-A dies, every cached client connection that resolves to A's IP
  fails; DNS hasn't refreshed; clients don't fail over until TTL.

**Verdict: REPLACE for serious deployments; KEEP as an option for
small.** "Every worker is also a router" works at 3–5 nodes. At 200 it
turns the whole cluster into a giant mesh of cross-node proxies. The
real shape at scale is: **dedicated ingress tier (3–10 nodes), workers
don't route for peers, ingress reads placement and routes per-SNI.**

---

## A8. "The 30 s dead-owner grace is the right tunable."

**Where:** `dead_owner.go:114`, default 30 s.

**Why it's plausible:** Long enough to absorb GC pauses and short
network blips; short enough that "node really dead" failover finishes
in well under a minute. Consul's experience was that <10 s grace
triggers false positives during GC pauses.

**Where it breaks:**

- **Doesn't compose with the 5 s owner-watcher tick.** Total wall-clock
  time from death to recreate-attempt is ≥30s grace + 0–5s tick + image
  pull + container start. Realistic recreate latency is 60–120 s for a
  cold image cache. That's fine for the product semantics (sandboxes
  aren't HA) — but it means *anything depending on a sandbox URL
  resolving* sees a minute-plus blackout per failover. At 200×50, with
  even modest node turnover (1 node down/week), that's noticeable.
- **No per-sandbox grace.** A long-lived analytics sandbox and a 30 s
  CI sandbox both wait the same 30 s.
- **No graceful drain.** A planned restart looks like a death because
  there's no `node drain` API that says "I'm going down, please
  reassign my sandboxes first." So planned maintenance triggers the
  same dead-owner storm as a power loss.

**Verdict: KEEP for unplanned death, ADD for planned drain.** A
`POST /v1/cluster/drain` admin endpoint that proactively reassigns this
node's placements while the node is still alive (sandboxes get cleanly
destroyed locally and recreated elsewhere with state-loss accepted)
removes the storm pattern from the planned-maintenance case.

---

## A9. "Single-leader raft is fast enough for all cluster mutations."

**Where:** Every mutating call funnels through `leaderForwardApply`
(`internal/cluster/client.go`'s forwarding to `:7002`) → leader raft
log.

**Why it's plausible:** Raft is fast on a healthy LAN, and the actual
throughput of placements should be modest.

**Where it breaks at 200×50:**

- **Write rate from steady-state.** If 1% of sandboxes churn per minute
  (a low estimate for a CI/AI-agent product), that's 100 placements/min
  destroy + 100 create + ~200 port intents = ~400 raft commits/min, or
  ~7 commits/s. Each commit needs 101 acks. Healthy raft can do this,
  but the leader is the global serialization point.
- **Write rate during failover.** 50 sandboxes from one dead node
  reassign in one tick = 50 sequential `opReassign` commits + 50
  `opPlace` for spec touchup. That's 100 commits in <5 s. Tolerable —
  but if 3 nodes die together (rack PDU outage), you get 300 commits
  in <5 s, and the leader log is now the failover latency.
- **Write rate during burst create.** A client launching 1000 sandboxes
  via the SDK in parallel = 1000 placement raft commits, single-leader.
  No batch API.
- **Leader churn.** With 200 voters and any flaky one, the election
  storms; during a leadership transition all writes block.

**Verdict: QUALIFY.** Raft can handle the steady-state. The fix is:

1. **Batch raft commits** for grouped operations (bulk create from one
   client, mass reassign on failover).
2. **Shed work** at the API: if the leader's apply backlog grows past
   a threshold, return 503 Retry-After so clients pace themselves.
3. With the A1 worker/server split, leader CPU is no longer competing
   with 199 other voters' worth of TLS termination, container
   management, etc.

---

## A10. "The same domain works for everything."

**Where:** Every sandbox public URL is `<id>.sandbox.example.com`.
DNS-01 wildcard cert. Single Caddy.

**Why it's plausible:** Single hostname is the cleanest UX. Wildcard
DNS-01 sidesteps Let's Encrypt rate limits.

**Where it breaks:**

- **Wildcard cert distribution is replicated work.** Every node solves
  DNS-01 for `*.sandbox.example.com`. That's 200 nodes racing to write
  the same `_acme-challenge` TXT record. Cloudflare API rate limits
  push back (typically ~1200 ops / 5 min / zone). And every node
  duplicates renewal effort.
- **Cert revocation is hard.** No way to revoke "the cert on node-X"
  without revoking the wildcard cluster-wide.
- **No tenant isolation.** Every sandbox shares one wildcard. A
  compromised single sandbox shares an origin with all others.

**Verdict: KEEP for the SDK API endpoint, REPLACE the per-sandbox
wildcard.** Two options:

- **Per-node wildcard.** `*.node-c.sandbox.example.com` instead of
  `*.sandbox.example.com`. Each node owns its own cert. The
  "node-c" baked into the URL makes the URL change on failover —
  which is documented as a real trade in
  `plans/fucked-up-design-in-cluster.md`. For a non-HA-sandbox
  product, this is *fine* and the simplest path.
- **Ingress-tier wildcard.** The new LB tier holds the wildcard;
  workers serve plaintext or terminate against an internal CA. Cleaner
  trust posture; bigger lift.

---

## Summary table

| # | Assumption | Verdict | Priority |
|---|---|---|---|
| A1 | Every node runs raft | REPLACE (server/worker split) | P0 |
| A2 | Placement map in every RAM | KEEP, narrows after A1 | — |
| A3 | Pow2c placement is enough | QUALIFY (token + rebalance + batch) | P2 |
| A4 | Gossip captures scheduler inputs | QUALIFY (RPC for non-capacity) | P3 |
| A5 | Failover-recreate from spec | KEEP, storm-control needed | P1 |
| A6 | DNS RR / NLB is good enough | REPLACE (real LB) | P0 |
| A7 | Workers can route for peers | REPLACE for scale | P0 (rolls up into A6) |
| A8 | 30 s grace is the tunable | KEEP, ADD drain API | P2 |
| A9 | Single-leader raft is fast | QUALIFY (batch + shed + split) | P1 |
| A10 | One wildcard for everything | REPLACE per-node or per-ingress | P2 |

The 200×50 target requires moving on A1, A6, A7 first. The rest are
hardenings.
