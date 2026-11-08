# Cluster phase 2: ownership epoch, warm pools, routing default, release gates

Status: draft, 2026-11-08. Follows `plans/cluster-correctness-and-create-latency.md`
(#1000), whose items C1–C8, D1, E2, E3a, L1, L2 and L5 merged on 2026-11-08
(#1032). Base: `main` at c07400319e4ce1aa1a7b3bfa7f8c49cb7e5d1d14.

The last live run of that work, `cluster-hetero-lite-routing` on the merged
tree, finished after the merge: 290 pass, 167 skip, 0 missing, and 3 fail,
none from the work (UC-124 was a test bug, fixed in #1034; UC-285 and
UC-171 were my laptop's network).

## 0. Scope and decisions

The owner picked these from #1000's "not started" list:

| Item | Section |
|---|---|
| C4 part 4, ownership epoch (I2) | 1 |
| E3b, skip the owner's own lookup | 1 |
| L3, warm pool for creates that carry env | 2 |
| L4, warm pool in cluster deploys | 3 |
| Turn `SB_INGRESS_PROXY_ROUTING` on by default | 4 |
| Release-gate tools: failpoint, recovery time, soak driver | 5 |

L6 (smaller `containerd_create`) and E1 (combined multi-reserve) stay out.

Decisions already made (2026-11-08):

- **AWS:** only the cheap runs: one L4 measurement (about $0.20) and the
  final live runs (about $2), plus about $1 for the routing gate on t3.medium.
  Not approved now: the 72-hour soak (about $4) and the c5.metal flagship
  run (about $15–20).
- **Routing flag:** run the churn gate and an A/B on t3.medium, from inside
  AWS (not a laptop). If churn shows 0 failures and the A/B shows no
  slowdown, turn the default on. Otherwise report and keep it off.
  Firecracker public URLs with the flag on stay untested live, because only
  the metal run has a Firecracker host.

## 1. Ownership epoch and the owner's own lookup (C4 part 4, E3b)

### 1.1 What happens today

A routed call for sandbox X reaches the edge (the node the client called),
which looks X up and forwards it to the owner. The owner looks X up again
before it serves (`clusterroute.Wrap`). On a server node a lookup is a local
FSM read. On a worker or ingress node it is a round trip to the server tier
(`Agent.OwnerOf`, `Agent.PlacementOf`). So one call costs 2 server round
trips for an operator token and 4 for a tenant token
(`aerolvm_cluster_route_lookups_total` counts them). The owner cache (E3a,
`SB_CLUSTER_OWNER_CACHE`) saves the edge's lookups, but the owner still looks
itself up on every cached forward, because the cache entry may be up to 30 s
old.

Nothing carries an ownership number (I2). The incarnation does not change on
a move, so "X on P" before and after a move away and back looks the same.

### 1.2 Design

**The epoch (C4 part 4).** `Placement.OwnerEpoch` (uint64) is the Raft log
index of the entry that last changed `OwnerNodeID`, including the entry that
created the row and an orphaning. It is set in apply, in
`setPlacementOwner` (every owner change of an existing row already goes
through it) and where a new row is written. It is derived from the log, so
every server and every replay computes the same value; it needs no new op.
A log index only grows, so a later owner change always has a larger epoch,
even across leader changes (a leader's clock could go backwards; an index
cannot).

**The edge stamps it.** `OwnerInfo` gains `Epoch`. The internal placement
lookup returns it, the owner cache stores it, and `StampForward` sets
`X-Cluster-Owner-Epoch` on every forward. The edge deletes a client-supplied
copy of the header before anything else, as it does for the route hint.

**The owner knows its own epochs.** The ownership lease (C4 part 1) already
reads its placements from the leader every 5 s
(`AuthoritativePlacementsByIDs`, answered only by the leader). With the flag
on, it reads every local sandbox, not only recreate-policy ones, and keeps
`id → (epoch, incarnation)` from the last successful read.

**The owner's rule for a forward carrying epoch e** (no change for a call
without one):

| Owner's last authoritative read (within the lease) | Action |
|---|---|
| Names this node for X with epoch e, same incarnation, X not fenced | Serve. No lookup (E3b). |
| Names this node for X with an epoch newer than e, on a cache-routed forward | 421 "not here": the edge's entry is older than the owner's reading. The edge drops it and routes once more from a fresh lookup (the E3a retry path), so its next entry carries the current epoch. |
| Anything else (no entry, older epoch, other owner, read too old) | Today's path: look X up, and serve, forward or answer 421 as now. |

C4 part 4 alone (before E3b) already applies the second row using the
owner's own lookup: a cache-routed forward whose epoch is older than the
owner's lookup gets the "not here", even when the owner does own X now
(it moved away and back). A forward from a fresh edge lookup is served
when the owner's lookup says it owns X, as today.

The lookup path stays the source of truth: the fast path only skips a lookup
when two authoritative readings agree.

**Why this does not weaken routing safety (I7).** Today the owner serves after
its own lookup, which a lagging follower may answer up to 2 s late (the
stale-read bound, C4 part 2). With the fast path, the owner serves when the
leader's own answer, at most one lease interval old, agrees with the edge's
lookup. A move that lands between the reading and the serve is possible in
both cases, and in both the old owner still runs the copy until it notices.
The one wider window: a cached forward (route hint) whose entry agrees with
an owner read up to 5 s old. To keep the old bound there, the owner uses the
fast path for a hinted forward only when its read is under 2 s old;
otherwise it looks up as today.

**Flag.** Behind `SB_CLUSTER_OWNER_CACHE` (E3a), so one setting turns on both
halves. Off by default.

**Mixed versions.** An old owner ignores the header and looks up. An old edge
sends no epoch, so the new owner looks up. A server on an older build returns
epoch 0, which means "unknown": look up. A snapshot written by an older server
has no epochs, so two new servers can briefly disagree on a row's epoch; a
disagreement only ever sends the owner down the lookup path. No flag day.

### 1.3 Tests

- `internal/cluster/fsm_owner_epoch_test.go`: the epoch equals the index of
  the owner-changing entry for create, reassign, orphan, claim and WASM
  migrate; it does not change on spec, port or drain entries; replaying the
  log and restoring a snapshot give the same epochs; an entry applied by
  `apply` with no log index (tests) records 0.
- `pkg/api/clusterroute`: the rule table above, one case per row, with a fake
  cluster that counts lookups; a hinted forward with a read older than 2 s
  looks up; a client-supplied epoch header is dropped at the edge.
- `internal/service/ownership_lease_test.go`: with the flag on, the lease
  reads every local sandbox and records epochs; with it off, the read set is
  unchanged.
- Offline fault harness (`internal/cluster`): a move during a burst of
  forwarded calls never has the old owner serve after the leader's read shows
  the move; route lookups per call drop to near 0 with the flag on.
- Live: `cluster-hetero-lite-routing` with the flag on; UC-470 (partition)
  and the existing routing UCs; a new UC that drains the owner during a call
  burst and checks no call is served by the old owner after the move.

### 1.4 Cluster-correctness call-out

- **Split brain:** none added; the epoch is read-only state derived from the
  committed log.
- **Replay:** deterministic (log index).
- **Leader change:** indexes keep growing across terms.
- **Single node:** `Noop` has no forwards; nothing runs.

## 2. Warm pool for creates that carry env (L3)

### 2.1 Today

A create can adopt a parked container only when it carries no env, no
mounts, no custom command, no registry credentials, no GPU and runs as root
(`pkg/docker/docker_pool.go` `poolEligible`-style checks around lines
102–137, `internal/runtime/containerd/warm_adopt.go` lines 28–60). Env the
service adds on its own (egress inspect rules, withheld-key placeholders,
cloud identity) also forces a miss.

A parked container runs toolboxd as PID 1 with the image's command held
back (`SB_POOL_PARKED=1`). The command starts only after adoption, from
toolboxd's `childEnviron()`. So "PID 1 never sees the env" is narrower than
`plans/docker-warm-pool.md` §10 says: if toolboxd learns the env before it
starts the held command, the image's entrypoint sees it too.

### 2.2 Design: send the env in the adopt frame

- The adopt frame gains the env. toolboxd loads it into its env store first,
  then takes the identity, then starts the held command. Exec and sessions
  read the same store. Firecracker already does the same over vsock
  (`set_env` into toolboxd's in-memory store, before adoption on its warm
  pool).
- The ack carries a digest of the env keyed with the adopt nonce. An old
  toolboxd drops the unknown field silently, so a missing or wrong digest
  fails the adopt: the slot is destroyed, its capacity released, and the
  create goes cold. No partial env is ever served.
- The frame size limit (4 KiB today, `readyproto.go`) is raised for adopt
  frames only.
- A restart re-adopts and re-sends the env from the sealed row, as a cold
  start re-reads it today.

**Where the plaintext lives.** sandboxd memory (as today), the root-only
ready socket that already carries the sandbox token, toolboxd memory and
the children's env. It is never written to disk, never in the engine's
container metadata (`docker inspect`), never in a snapshot or commit. That
is fewer copies than a cold create, whose env sits in the engine's
metadata on the host.

**Still off the pool:**

- Everything on today's list except env.
- Env that sets an `SB_*` key, `AEROLVM_EGRESS_CA*`, `USER`, `LOGNAME`, or
  the gVisor pids key: toolboxd reads those itself at boot.
- Env bigger than the new frame limit.
- The **docker engine**, until its SSH exec path stops using `docker exec`
  (which reads the engine's env and would not see the user's). The
  containerd engine's SSH already goes through a toolbox session. So L3
  ships for the containerd engine (the default for servers) first.

### 2.3 Tests

- readyproto: env round trip; the larger limit applies to adopt frames
  only; an empty key or a NUL is refused; no error message contains a value.
- toolboxd: the held command sees the env; bad env means no ack and no
  command; exec and sessions see it; a re-adopt drops removed keys; no log
  line contains a value.
- containerd driver: the eligibility table (reserved keys, oversize env);
  digest check; a missing digest destroys the slot and falls back cold;
  restart re-sends; container spec and snapshots hold no user value.
- service: start passes the loaded env; withheld keys go as placeholders; a
  failover recreate with env can use the pool.

## 3. Warm pool in cluster deploys (L4)

### 3.1 Measure first

A parked container holds toolboxd's memory and the files it writes at
start; the user's command does not run. The cost per waiting sandbox is
still unknown. One run on `single-node-containerd` (one spot t3.medium,
about an hour, no code change):

1. Boot with the pool off; record `MemAvailable`.
2. Set `extra_sandboxd_env` to turn the pool on at depth 4 for three images:
   `alpine:3.20`, `python:3.12-slim` and one large agent image.
3. Wait for 12 parked containers (`aerolvm_containerd_pool_parked`). For
   each, read `memory.current`, `memory.peak` and `memory.stat` from its
   cgroup, the shim's RSS, and the `MemAvailable` drop divided by 12.
4. Run 5 eligible creates; confirm adopts (`Server-Timing`
   `containerd_pool;desc=hit`) and refill.
5. Destroy (`--destroy-only`).

### 3.2 Then the deploy settings

Copy the docker pool's path end to end: `config/cluster.yml` →
`Terraform/locals.tf` → `Terraform/nodes.tf` →
`Terraform/templates/bootstrap.sh.tftpl` → `/etc/sandboxd/cluster.env`, and
`Ansible/playbooks/configure-ops.yml`; a harness capability in
`integration-tests/run.sh` and `harness/usecases.go`; the rows in
`setup/config-defaults.md`. The default comes from the owner after 3.1.

**Notes from the code:** a parked container reserves a full default shape
of capacity, which a real create takes back when the node is full; it also
holds one of the node's 256 network namespace slots. The live memory floor
(`SB_MEMORY_FLOOR_RATIO`) cannot be met by taking parked containers back,
which is why their real memory matters.

## 4. Turn the routing flag on by default

### 4.1 Why it was off

With the flag on, Caddy keeps a fixed config and a loopback sandboxd DNS
responder answers where each host goes; raw TCP moves to kernel DNAT. A
create or expose then writes nothing to Caddy, so nothing reloads. It was
off by default because:

- it needs host setup older installs lack: the `~rt.internal` resolver
  domain on ingress nodes (`install.sh --ingress-proxy-routing`), iptables,
  and `SB_AUTO_RECONCILE` on workers. A node without them refuses to engage
  and keeps Caddy routes (after up to 60 s of probes on an ingress node);
- its plan's gate (0 failures under route churn, plus a latency and
  throughput A/B, on the flagship) never finished.

Private-by-default (`allow_public_traffic` off unless asked) is a separate,
already-on decision: it keeps Caddy off the create path for sandboxes that
are not public.

### 4.2 The gate (t3.medium, from inside AWS)

- **Churn:** UC-171 (fresh HTTP and raw TCP connections during route churn)
  and UC-357 (the same through each ingress). The test binary runs on one of
  the three server nodes of `cluster-hetero-lite-routing` (Raft voters, not
  on the public data path), built with `go test -c -tags integration` and
  driven over SSH. Pass: 0 failed connections in each.
- **A/B:** UC-171 records latency too: expose to first 200, and p50/p99 of
  fresh-connection requests. Run it with the flag on, set the flag off on
  every node and restart (the marker rolls each node back in one Caddy
  load), run again, and repeat the pair once (t3 CPU credits add noise).
  Pass: flag-on p50 and p99 no worse than flag-off beyond the noise of the
  repeated pair.

### 4.3 The flip

- **Go default** on, with a quiet skip (no ERROR line, no 60 s probe) when
  the node has no Caddy domain, so local and IP-mode installs stay silent.
- **install.sh:** default on when `--domain` is given.
- **Terraform: not flipped by default.** Nodes use
  `user_data_replace_on_change = true`, so a changed default would replace
  every node of a running cluster on the next `terraform apply`. New
  clusters set `default_ingress_proxy_routing = true`; the example config
  and docs say so. Open question 1 asks the owner.
- **Docs:** `setup/config-defaults.md`, `installer-options.mdx`, the
  `TODOS.md` entry that blocks the flip, and `plans/ingress-proxy-routing.md`
  (the gate moved from the flagship to t3.medium).
- `protocol=tls` port routes still reload Caddy (a known follow-up); UC-171
  does not cover them.

## 5. Release-gate tools

None exist today: no failpoint mechanism, no recovery-time measurement, no
soak driver. The 72-hour soak is not approved now; the tools ship and run
as short smoke runs inside the final live runs.

### 5.1 Failpoint

- `internal/failpoint`: `Hit(name, key)`. Under the build tag
  `itest_failpoints` it checks `/run/sandboxd/failpoints/<name>` (which
  holds a sandbox-name prefix); on a match it removes the file (fires once),
  writes `<name>.hit` and blocks. Without the tag it is an empty function,
  so the create path pays nothing.
- Call site: between the runtime start and `persistSandboxCreate`
  (`internal/service/service.go`).
- `integration-tests/lib/build.sh` passes `AEROL_GO_TAGS` and puts the tags
  in the build id. Release builds are unchanged.
- **UC-480:** arm the file on the workers, create one sandbox, wait for
  `.hit`, SIGKILL sandboxd on that node. Pass: within the convergence bound
  the sandbox runs nowhere, has no placement, answers 404, and its network
  slot is free (I6, I8). If `.hit` never appears the binary has no tag:
  skip.

### 5.2 Control-plane recovery time

- **UC-481:** SIGKILL sandboxd on all three servers at once
  (`AEROL_CHAOS_RTO_MODE=leader` kills only the leader). A 1 s prober records
  when `/v1/cluster/leader` answers, when a placement read for an existing
  sandbox returns its owner, and when a new create starts. Recovery time is
  the latest of the three.
- Pass: placements match the snapshot taken before the kill; creates made
  during the outage end as `chaosCheckCreates` expects; recovery time under
  `AEROL_CHAOS_RTO_BUDGET_SECONDS`. The budget is set from the first
  measured run (open question 3).

### 5.3 Soak driver

- `integration-tests/suite/harness/soak.go` (sample script, parser and the
  growth rule, unit-tested offline) and `suite/z_cluster_soak_test.go`
  (UC-482).
- N closed-loop workers create, probe and delete for `AEROL_SOAK_MINUTES`
  (15 for the smoke run), sampling every node every
  `AEROL_SOAK_SAMPLE_SECONDS`: goroutines (a new `aerolvm_go_goroutines`
  expvar), sandboxd RSS and fds, SQLite and WAL size, Raft directory size,
  containerd tasks and snapshots, netns slots in use, host ports, routes,
  placements.
- Pass: counts return to the baseline after the drain plus one reconcile
  interval; for goroutines, RSS, fds, WAL and Raft size, the median of the
  last third is within a margin of the median of the first third.
- The 72-hour run later is the same case with a longer
  `AEROL_SUITE_TIMEOUT`.

## 6. PR order

| # | PR | Area |
|---|---|---|
| 1 | C4 part 4: ownership epoch on placements and forwards | `internal/cluster`, `pkg/api/clusterroute` |
| 2 | E3b: owner serves from its lease reading | `internal/service`, `pkg/api/clusterroute` |
| 3 | L3: env in the adopt frame (containerd) | `cmd/toolboxd`, `internal/runtime/containerd`, `internal/service` |
| 4 | Release-gate tools: failpoint, UC-480, UC-481, UC-482, goroutine expvar | `internal/failpoint`, `integration-tests` |
| 5 | Routing gate: latency in UC-171, run-from-a-server option | `integration-tests` |
| 6 | Routing default on (Go, installer, docs) | `internal/config`, `scripts/install.sh`, docs |
| 7 | L4 deploy settings (after the measurement and the owner's default) | `config/`, `Terraform/`, `Ansible/`, `integration-tests` |

Like #1000: one PR per item, a test that fails first, offline suites green,
then one local branch with all of them for the live runs, and nothing merges
until those pass.

## 7. Live runs (approved: about $3 in all)

| Run | What it proves | Est. cost |
|---|---|---|
| L4 measurement, `single-node-containerd` (spot, ~1 h) | Memory per waiting sandbox | ~$0.05–0.20 |
| `cluster-chaos` with UC-480, UC-481 and a 15-minute UC-482 | Failpoint, recovery time, no leak in a short soak; C1–C7 still hold | ~$0.65 |
| `cluster-hetero-lite-routing` with the routing gate and A/B run from a server node | Epoch, E3b, routing gate | ~$1.20 |
| `single-node` | Nothing breaks single-node mode | ~$0.03 |

## 8. Open questions for the owner

1. **Terraform routing default:** keep it off and tell new clusters to turn
   it on (recommended, because a changed default replaces every node on the
   next apply), or flip it with a release note telling operators to pin
   `false` first?
2. **L4 default** (after 3.1): which images, how deep, how much memory per
   node for waiting sandboxes, and gVisor too or not.
3. **Recovery-time budget:** set from the first UC-481 run, or a number you
   want (for example 60 s)?
