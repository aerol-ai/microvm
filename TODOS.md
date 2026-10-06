# TODOS

Deferred work items with enough context to pick up cold. Each entry says
what, why, the caveat that motivated capturing it, and where to start.

## Enterprise boot can fail its own witness check (audit) — FIXED

- **What:** `ValidateSecretAuditWitness` looked the witnessed head up under
  the node id `"standalone"` while the shipping path published it under the
  real cluster node id, so the comparison failed against a head that WAS
  witnessed.
- **Why it mattered:** the daemon failed CLOSED — an enterprise node refused
  to start. Observed on a live single-node box with `SB_ENTERPRISE_MODE=true`:

      secret audit witness mismatch:
        local_head="7334bf03cb2b4ab7bc858bba55a44e3c3fda66031837eb079026503240e7ce7b"
        witnessed_head=""

  The witness had that EXACT head stored, under
  `aerolvm-itest-single-node-node1`. Only the lookup key was wrong. It
  reproduced intermittently, which is worse than a deterministic failure: a
  node that refuses to start only sometimes reads as flake.
- **Fix:** all four `nodeID` derivations in
  `internal/service/secret_audit_witness.go` now go through
  `witnessNodeID()`, which prefers `cfg.NodeID` and falls back to the cluster
  handle. `cfg.NodeID` is the same value `pkg/daemon` builds the real cluster
  from (`daemon.go` → `cluster.Config.NodeID` → `agent.go` / `client.go`), so
  the preference is invisible on a healthy node and the race window is gone.
  This is the second of the two options this entry originally proposed —
  resolving the id from config rather than deferring the check — because it
  removes the ordering dependency instead of relying on a new one.
- **Regression tests:** `secret_audit_witness_nodeid_test.go`, including a
  guard that fails if any witness call site reads `c.SelfNodeID()` directly
  again. Mutation-checked.

## A partitioned node keeps serving: /health ignores cluster membership — ROOT CAUSE FIXED; readiness gap OPEN

- **Status (verified 2026-09-29 on `plans/secrets-hardening`):**
  - **The partition below is fixed.** node1 was the SEED (`seed = true` in
    the S3 scenario). It was the restarted-seed-cannot-rejoin bug from the
    next entry: fixed in #487 (gossip peer cache), and UC-170 is green on
    three live runs.
  - **Still open: `/health` is cluster-blind.** `handleHealth`
    (`pkg/api/server.go`) always answers 200. `Service.Health` only marks
    the body `"degraded"` for runtime, Caddy, SSH or topology faults, never
    for "no raft leader" or "not a raft member". `/ready` still does not
    exist. A node that falls out of the cluster for any OTHER reason would
    still be routed to. The design constraints below still apply.

- **What:** a node that has fallen out of the cluster still answers
  `/health` with 200, so the ingress keeps routing traffic to it. Every
  request that lands there fails, because the node cannot reach a leader.
- **Measured** (S3 `cluster-3-mixed-secrets-kms`, 2026-09-27). node1 was
  `active`, `NRestarts=0`, and `/health` = 200, while:
  - the cluster's member list contained only node2 and node3;
  - node1's OWN member list contained only node1 — a clean 1 + 2 split;
  - node1 was stuck `entering candidate state`, node3 was leader.
- **Effect:** roughly one request in three failed across the whole run.
  Measured directly on S4's `/v1/audit/verify`: 4 of 5 calls returned 502,
  1 returned 200. In the suite it surfaced as 18 unrelated-looking failures,
  nearly all `cluster: reserve placement failed: cluster: not raft leader`,
  plus `503: cluster: peer InternalURL required (mTLS fail-closed)` when a
  forward targeted the partitioned node.
- **Why it matters most:** every one of those reds looks like a bug in
  whatever test happened to run. The cluster is *degraded but advertising
  itself as healthy*, which is the failure mode that costs the most
  debugging time per incident.
- **The fix needs design, not a one-liner.** Naively failing `/health` when
  there is no leader would take an ENTIRE cluster out of rotation during any
  routine election — worse than the bug. It needs: readiness distinct from
  liveness, a grace period so elections do not flap it, and a decision about
  whether a partitioned node should still serve reads.
- **Note:** `/ready` currently 404s, so there is no readiness endpoint to
  gate on yet. That is probably where this starts.
- **Start:** the health handler in `pkg/api`, `cfg.EnableCluster` gating, and
  the Caddy upstream health config in `pkg/caddy` / `packaging/`.

## A restarted seed could never rejoin the cluster — FIXED, PROVEN LIVE (UC-170 green x3)

- **Was recorded as:** "losing the seed leaves the survivors without a
  leader". **That diagnosis was wrong.** The S2 journals (2026-09-26) show the
  survivors elected node2 3s after the seed stopped (`election won: term=4
  tally=2`) and, after the 30s dead-owner grace, evicted the seed from Raft
  (`RemoveServer ... node1`) — both correct.
- **Actual bug:** the seed runs `SB_CLUSTER_BOOTSTRAP=true` with no
  `SB_CLUSTER_PEERS`. memberlist keeps no state across a restart, so the
  restarted seed came back as a gossip island (`cluster gossip started without
  bootstrap peers`). The leader only re-admits a server it can see in gossip,
  so the seed stayed a lone Raft candidate forever — the new leader logged
  `rejecting pre-vote request since node is not in configuration` every ~1.5s
  until teardown — while its `/health` still said 200. Requests the ingress
  sent to it failed `not raft leader`, which is what the suite saw. The same
  hole strands any joiner whose only configured peer has been replaced.
- **Fix:** `internal/cluster/gossip_peer_cache.go` — each node persists the
  gossip addresses of the live control-plane peers it sees
  (`<raft dir>/gossip-peers.json`, ≤8, never overwritten with an empty set),
  and the existing background rejoin loop dials configured ∪ remembered
  peers. Not dialled on the boot path (a vanished host costs a TCP timeout).
- **Tests:** `TestRestartedSeedRejoinsAfterEviction` replays the live failure
  on loopback (3 real nodes: stop seed → survivors elect + evict → restart
  seed with no peers → must be re-admitted as a voter). Mutation-checked: with
  rejoin ignoring the cache it fails "seed never appeared ... as Voter".
- **Proven live:** UC-170 passed on three T18 runs (both profiles). Survivors
  elected a new leader in 7s; the seed, restarted after eviction with no
  peers, followed it 13s after restore.
- **The S3 "partitioned node" (entry above) was this bug**: node1 was the
  seed. What remains open there is only the readiness gap: a node with no
  leader still answers `/health` 200. That gap is what turned this bug into
  user-visible errors.

## UC-145b (retention prune) cannot run on any scenario — needs a seam

- **What:** UC-145b forces a prune with `SB_SECRET_AUDIT_RETENTION_DAYS=0`
  and needs the audit witness. The witness only exists on enterprise
  scenarios, and enterprise refuses zero retention at config load
  (`internal/config/config.go`, "retention must be non-zero when
  SB_ENTERPRISE_MODE=true"). So the only path that legitimately destroys
  evidence has no live coverage at all; S4 and T18 both "failed" it by
  taking a node down, and T18's ingress stayed down afterwards.
- **Now:** the case skips on enterprise with that reason (it is not a pass).
- **Unblock:** a test-only way to make records prunable under enterprise —
  e.g. an `itestretention` build tag (same pattern as `itestwitness`) that
  lets retention be expressed in minutes. Do not relax the enterprise
  validator for it.

## Draining a node records no visible storage-retirement obligation — FIXED, PROVEN LIVE (UC-160 green)

- **Design (two patterns other systems use, no third):**
  - **One job per leaving node** (Cassandra decommission / CockroachDB
    decommission / Nomad drain). `opSetNodeDrainState` opens it in the FSM
    when the node still holds a sealed copy (read from placement
    `SecretRecipients`, which the FSM already has) or is owed a delete by an
    owner report. Uncordon withdraws it; an attestation discharges it. A
    delete ACK never closes it.
  - **Owners report a current total on a timer** (Kubernetes node status,
    Ceph recovery). Every sandbox-owning node sends, every 30s when changed
    and every 5 min regardless, "the nodes my delete outbox still owes, and
    how many rows each". The leader REPLACES that owner's report (per-owner
    Seq rejects retries and reordering) and folds all reports into one raft
    entry per second, dropping ones the FSM already reflects.
- **View:** `GET /v1/cluster/storage-retirements` adds `obligations`, from the
  local FSM (an ingress/worker asks one server). An expected reporter (live
  sandbox-owning member) with no report in 15 min, or a silent owner that
  still owes, is listed stale and the job is `complete: false` — never shown
  as all-clear.
- **Not done, deliberately:** no fan-out on read, no +1/-1 tally, no raft
  write per secret copy, no same-transaction "report due" slip (the periodic
  full snapshot makes it redundant; it would only buy latency).
- **Code:** `internal/cluster/storage_obligations.go`,
  `internal/service/storage_obligations.go`,
  `internal/store` `SecretDeleteOwedByRecipient`.
- **Status:** passed live on hetero-lite (`e65c9cbc`) and on both T19
  metal scenarios (2026-09-28).

## Ingress route changes reset in-flight TLS connections on :443 — IMPLEMENTED behind `SB_INGRESS_PROXY_ROUTING` (#503–#512)

- **Shipped 2026-09-28 (`plans/ingress-proxy-routing.md`, eng-reviewed).**
  - A static Caddy config, with sandboxd answering *where* via a loopback
    DNS responder (Caddy `dynamic a` + caddy-l4 placeholder dial).
  - Bytes stay in Caddy. Raw TCP host ports are **kernel-DNATed**, so
    sessions live in conntrack.
- **Proven live:**
  - `cluster-3-mixed-routing`: 77 pass / 0 fail.
  - `cluster-hetero-lite-routing`: 125 pass / 0 fail.
  - UC-171 churn gate: **0** failed fresh HTTP/raw-TCP connections under
    sandbox churn (was ~2.6%).
  - UC-172: established sessions survive sandboxd restarts on the ingress
    and the owner.
  - UC-173: no per-sandbox Caddy routes on any node.
- **Remaining before the default flips on:** a run on the metal flagship with
  the flag on, and a latency/throughput A/B. The flag is off by default
  (`setup/config-defaults.md`). The history below is the evidence behind the
  design.

- **What:** Stop an unrelated sandbox's route add/delete from resetting
  client connections that are mid-handshake through the ingress.
- **Why:** Seen in T19 S6 (UC-09). The test's TLS dial to the apex was
  reset 0.5s in; 0.41s in, `DELETE /id/sandbox-…-ingress-sni` for another
  test's sandbox had made Caddy reload. Every route change reloads the
  config, including the layer-4 `tls-mux` server that fronts :443. At
  cluster scale (100k sandboxes, constant expose/unexpose churn) that is a
  steady rate of dropped client connections, not a test flake.
- **Evidence:** 153 reloads/admin writes in ~20 min on one ingress during
  S6; the correlation is in the T19 notes (plans/integration-test-security.md §7.12).
- **Reproduced locally (2026-09-28), Caddy v2.11.4 + caddy-l4 master:**
  `scripts/dev/caddy-reload-repro.py`, 8 clients, one fresh TLS connection per
  request, ~18 route add+delete reloads/s:

  | Path | No churn | Churn |
  |---|---|---|
  | via layer4 `tls-mux` (the ingress) | 0 / 39,841 | **2.6%** fail (~1,500 empty replies, ~220 resets/broken pipes/TLS EOF, a few refused) |
  | straight to the http server | 0 / 45,434 | **2.2%** fail (almost all empty replies, ~15 resets) |

  The kind of route churned (layer4 SNI or http) makes no difference: any
  admin write reloads the WHOLE config. The dominant failure is a completed
  TLS handshake followed by a clean close with **zero bytes**, which is the
  old http server's graceful shutdown closing connections that have not
  sent a request yet. The layer4 mux adds ~15x more hard resets on top.
  caddy-l4's `App.Stop` only closes its (pooled) listener, so the resets
  come from the listener handoff and the upstream shutdown, not from l4
  killing connections itself.
- **Fix options (a design decision, not a patch):**
  1. Coalesce route writes (debounce and batch per reconcile). This cuts the
     reload rate, so the loss shrinks proportionally, but does not remove it.
  2. Stop reloading Caddy per sandbox: one static wildcard route into
     `sandboxd`'s in-process ingress proxy (`127.0.0.1:21213`, already
     running), which looks up the sandbox itself. This removes the loss, but
     moves routing out of Caddy config.
  3. Fix it upstream in Caddy (don't close StateNew connections on reload
     while a grace period is set).
- **Start:** `pkg/caddy/client.go` (route PATCH/DELETE against `/id/…`),
  `pkg/api/ingressproxy`. Related, and possibly the same mechanism: the
  admin-side EOF entry below.

## First boot Caddy config lacks S3 certificate storage

- **What:** Make the first Caddy config an ingress loads already carry the
  S3 certificate storage, not a later reload.
- **Why:** T19 S6's first config (06:28:50) had no S3 storage. The cert jobs
  failed with "failed storage check: context canceled" and were not retried
  until Caddy reloaded with S3 storage at 06:33:35. HTTPS was down for ~5 min
  after boot. At the same boundary `sandboxd` got a 500 installing the
  on-demand TLS policy ("on-demand TLS cannot be enabled without a
  permission module"); it retried on reconcile.
- **Correction (2026-09-28):** two later "slow HTTPS" runs were NOT this.
  The ingress was serving a valid cert, but the harness Mac's system resolver
  held a cached NXDOMAIN for the freshly leased hostname (negative TTL 1800s),
  while `host`/`dig` in `wait_for_dns` bypassed that cache. That was fixed in
  the harness (`direct_resolve_args`, `GODEBUG=netdns=go`). Some of S6's
  delay may be the same artifact, so re-check this item on the next run before
  investing: the Caddy "failed storage check" errors above are real, but
  whether they delayed HTTPS is now unproven.
- **Start:** the ingress Caddyfile / bootstrap in `packaging/` and the
  on-demand policy install in `pkg/caddy`.

## Owner-side protocol=tls port routes behind a static route

- **What:** Replace the per-exposure owner layer4 `…-port-{p}-tls` routes,
  where the owner terminates non-HTTP TLS, with a static SNI route whose
  target comes from the sandboxd route responder, like HTTP.
- **Why:** After `plans/ingress-proxy-routing.md` these are the last
  per-sandbox Caddy writes: one full reload per TLS-port expose or unexpose.
- **Pros:** truly zero lifecycle writes. **Cons:** it needs an L4
  TLS-terminate route with a placeholder dial, which the 2026-09-28 spike did
  not cover.
- **Context:** plan §2 non-goals; `pkg/caddy/client.go` `UpsertTLSSNIRoute`
  (:1276), `UpsertWakeTLSSNIRoute` (:1328).
- **Depends on:** the plan's route responder (task T3).

## IP mode on the ingress router

- **What:** Serve IP-mode path routing (`/{id}/*`, `/{id}/proxy/{p}/*`)
  through the static route plus the responder and router, instead of
  per-sandbox Caddy routes.
- **Why:** IP mode still reloads Caddy per sandbox. That matters for
  single-node and dev installs without a domain.
- **Pros:** one routing model everywhere. **Cons:** path dispatch plus prefix
  stripping, for low churn in practice.
- **Context:** the IP-mode branch of `UpsertSandboxRoute` (`client.go:177`)
  and `UpsertSandboxRouteToPeer` (:273).
- **Depends on:** the plan's tasks T3 and T6.

## Delete the old per-sandbox route code after the ingress-routing default flips

- **What:** Remove the flag-off caddy `publicRouteWriter`, the per-sandbox
  `Upsert*`/`Delete*` route methods, and their reconcile and GC paths.
- **Why:** Two routing paths double the test and maintenance surface. The old
  one exists only for rollback.
- **Pros:** a large deletion and a single path. **Cons:** it removes the
  rollback lever, so do it only after a soak at default-on.
- **Context:** plan §3.6. Every call site already goes through the 4A choke
  point, so the cut is clean.
- **Depends on:** `SB_INGRESS_PROXY_ROUTING` defaulting to true, plus a soak
  of about one release cycle.

## L4 splice drops the response after a client half-close — FIXED (egress P1-0)

- **What it was:** `spliceConns` (`internal/service/l4proxy.go`) returned
  when the first direction ended and closed both sides. A client that sent its
  request and then half-closed its write side never received the response
  (netcat-style, some database and RPC clients). Found while testing the 3A
  extraction (2026-09-28).
- **Fix:** the splice and the connection limiter moved to `internal/netsplice`
  (egress plan P1-0, D12/D17) as `netsplice.Splice` and `netsplice.Limiter`.
  `Splice` waits for both directions, forwards each EOF as a `CloseWrite`, and
  closes both conns only when both are done, on a copy error, or on an
  optional idle timeout (`WithIdleTimeout`). It still copies raw conn to raw
  conn, so splice(2) applies. Pinned by `TestSpliceHalfCloseDeliversTheRest`
  (both directions) and `TestSpliceIdleTimeout`.
- **Residual:** the L4 wake proxy passes no idle timeout, because wake-proxied
  database connections legitimately sit idle for hours. A peer that
  half-closes and whose other side never closes now holds its active slot
  until it does, where the old code dropped it at once. The egress proxy is
  expected to pass an idle timeout.

## Caddy route upsert does not retry a transport EOF (unconfirmed)

- **What:** Decide whether `upsertRoute` should retry a dropped connection the
  way it now retries a duplicate-ID 400.
- **Why:** Both are Caddy-config-reload transients, but only one is handled. A
  400 whose body names a duplicate id is retried as a PATCH; a reload that
  drops the admin connection mid-request returns a transport error from
  `httpClient.Do` and fails the caller immediately. Seen once as
  `start: PATCH http://127.0.0.1:2019/id/sandbox-…: EOF` failing UC-15.
- **Caveat — NOT confirmed as a product bug:** that observation happened while
  a daemon restart and concurrent sandbox churn were deliberately being driven
  against the box *during* the suite, i.e. self-inflicted. An immediate clean
  re-run with no interference was 58 pass / 0 fail. So this is a hypothesis
  about a real mechanism, not a reproduced defect — do not "fix" it without a
  reproduction, or the retry itself becomes untested code on the boot path.
- **Depends on / blocked by:** a reproduction. Cluster scenarios generate real
  concurrent route churn, so T12+ is the natural place for it to reappear.
- **Start:** `pkg/caddy/client.go` `upsertRoute` / `sendJSONDetail`; note the
  retry would have to be bounded and idempotency-safe, since PATCH-then-EOF may
  mean the write landed.

## A scenario destroy can need two passes (integration harness)

- **What:** Find out why `run.sh --destroy-only` returned non-zero with 3
  resources still standing, and either retry inside the teardown or make the
  failure name what it could not delete.
- **Why:** Observed 2026-09-23 tearing down `single-node` with
  `secret_kms_enabled = true`. The first destroy exited non-zero leaving 3
  resources; an immediate identical re-run destroyed them and exited 0, so it
  is a transient (most likely an eventual-consistency retry around the KMS key
  or an IAM detach), not a config error.
- **Caveat (why it matters, not just cosmetic):** run.sh's EXIT trap runs
  **one** destroy. When it fails the harness only prints "run
  `make integration-reap`" — and reap terminates **EC2 instances only**, not
  the VPC, IAM roles, S3 buckets or KMS aliases. So an unattended failing run
  silently leaves billable non-EC2 resources behind, and the message points at
  a tool that cannot clean them up.
- **Depends on / blocked by:** nothing. The root cause was not captured because
  the first run's output was consumed by a pipe; re-run a KMS-enabled scenario
  teardown with the full log kept.
- **Start:** `integration-tests/run.sh` teardown path and `--destroy-only`;
  consider one bounded retry plus surfacing terraform's own error, and widening
  `scripts/integration-reap.sh` or documenting that it is EC2-only.

## Warm-adopted (`park-*`) destroys fall to reconcile (containerd)

- **What:** Restore prompt row deletion for a warm-adopted container, or
  confirm the reconcile sweep is sufficient and close this out.
- **Why:** `internal/runtime/containerd/events.go` used to map `/tasks/delete`
  to `destroy`, which fired while the container still existed, so
  `StreamEvents`' `LoadContainer` could still read the `aerolvm.sandbox_id`
  label and name the real sandbox. That mapping was a bug (a manual stop
  deleted the sandbox — see the fix commit) and now only `/containers/delete`
  maps to `destroy`. By then the container is gone, so the label lookup fails
  and the event carries the `park-*` container id, which matches no store row.
- **Caveat (why it's a TODO, not a bug):** the outcome is correct, just
  slower — those rows are reclaimed by the reconcile orphan sweep instead of
  immediately. The alternative (caching container id → sandbox id before
  deletion) adds state to the event path for a latency win that may not
  matter. Measure how long a warm-adopted row actually lingers first.
- **Depends on / blocked by:** nothing. Needs a scenario that exercises
  warm-pool adoption plus destroy.
- **Start:** `internal/runtime/containerd/events.go` (`StreamEvents`'
  `sandboxIDFromContainer` call), then the sweep in
  `internal/service/service.go` (`removeOrphans`).

## Destroy events WARN about an already-deleted placement (cluster)

- **What:** Stop `handle docker event failed … cluster: unknown sandbox
  placement` from WARNing on every API-driven destroy.
- **Why:** `Driver.Destroy` ends with `container.Delete`, so the
  `/containers/delete` event now always arrives AFTER `DestroySandbox` has
  already removed the placement. `handleDestroyEvent` then tries its own
  `beginSelfOwnedClusterPlacementDeleteStrict` and logs a warning for work
  that is legitimately already done. Previously the (incorrectly mapped)
  `/tasks/delete` arrived earlier, so this rarely fired.
- **Caveat (why it's a TODO, not a bug):** purely cosmetic — the destroy
  succeeds and the placement is correctly gone. But it WARNs once per destroy,
  so it will be constant noise in cluster runs and could mask a real
  finalization failure, which is the actual risk.
- **Depends on / blocked by:** nothing.
- **Start:** `internal/service/events.go` `handleDestroyEvent` — treat "no
  such placement" as benign there the same way its `store.Delete` already
  treats `ErrNotFound`.

## Audit Firecracker outbound NAT path (networking)

- **Status (2026-10-06, egress Phase 4):** the static audit confirmed the
  gap: nothing in the daemon, `Terraform/` or `Ansible/` set up SNAT or
  FORWARD accepts for the TAP subnet (`internal/network/hostport` is ingress
  DNAT only), and dockerd's FORWARD DROP policy would drop guest traffic
  anyway. Fixed in-repo: `tap.EnsureNAT` (a `MASQUERADE` for
  `SB_FIRECRACKER_TAP_BASE_CIDR`, comment `aerolvm-fc-masq`), the
  `AEROLVM-FC` netrules chain with FORWARD accepts for the subnet, and strict
  `rp_filter` per TAP, wired at boot by `pkg/daemon/firecracker_egress_wiring.go`
  and proven on a real kernel with a veth stand-in
  (`internal/network/tap/fc_egress_kernel_test.go`).
- **Hostname filtering** (part 2): the gateway serves the TAP pool on
  wildcard listeners behind its input guard (setup/runbooks/egress-gateway.md
  "Firecracker"), proven on a real kernel by `TestKernelTapPool`.
- **Still to do:** confirm on a live Firecracker host that a guest reaches
  the internet and that block-all / CIDR lists and a hostname allowlist hold
  (`iptables -t nat -S POSTROUTING | grep aerolvm-fc-masq`,
  `iptables -S AEROLVM-FC`, `nft list set inet aerolvm_egress fqdn_src`).
  Needs a Firecracker bench host; operator-run.

## NVMe/io2 data-dir option (infra) — `plans/nvme-datadir.md`

- **What:** Terraform instance-type + volume variables (`Terraform/nodes.tf`)
  plus a bootstrap template that mounts an instance-store NVMe (c5d/m5d/m6id)
  or io2 volume at the sandboxd data dir when present.
- **Why:** gp3 fsync (~1ms) is the floor under every remaining fsync on the
  warm-create path: both Raft stores AND the single-writer SQLite WAL behind
  `svc_persist` and the secrets ref. NVMe drops fsync to ~0.1ms (Raft commit
  ~1–2ms, `svc_persist` sub-ms); io2 is the safer middle (~0.5ms).
- **Caveat (the reason this is its own plan, not a phase):** it is **not
  semantics-preserving.** Instance-store evaporates on stop, and the data dir
  holds the local SQLite sandbox store too (`internal/service/service.go`
  `s.store.Create`), not just Raft logs. A single-node loss recovers via
  rejoin, but a **full-cluster stop loses everything.** Gate the topology on
  the lost-quorum recovery runbook and document the durability trade in
  `Terraform/` docs.
- **Depends on / blocked by:** nothing (operator opt-in, no code dependency on
  the latency phases). Split out of `plans/warm-create-latency-tier1.md` at
  eng review 2026-07-11.
- **Start:** `Terraform/nodes.tf` + the node bootstrap template; add one
  optional NVMe bench scenario for the stretch gate (≤25ms).

## netrules Manager mutex head-of-line blocking — DONE (PR #306)

Shipped as per-IP refcounted locks in `pkg/docker/netrules/manager.go`
(`lockIP`). Same-IP Exists+Insert mutual exclusion preserved; different IPs
no longer serialize. See `ip_lock_test.go`.

## cluster_promote is recovery-replication-bound, not fsync-bound (latency)

- **What:** live bench 2026-07-11 (3× t3.medium, branch build, netlink):
  `cluster_promote` p50 = 23ms on BoltDB and 25ms on raft-wal — the Phase 3
  log-store swap moved nothing. `applyCommand` runs
  `externalizeCommandRecovery` before every apply, which synchronously PUTs
  the recovery blob to **every other member** (wall clock = slowest peer) —
  the code comment in `recovery_replication.go` says it runs "twice per
  create (opReserve and opPlace)". That, not the raft fsync, owns promote.
- **Why it matters:** warm create;dur = create leg (~17ms, Tier 1 working) +
  promote (~23ms) — the ≤30ms Tier 1 gate fails at 40-44ms until promote
  sheds the sync replication. The api-side cost is bigger still: opReserve
  pays the same replication before the create even starts.
- **Plan:** `plans/warm-create-latency-tier2-recovery-replication.md` —
  inline small secret-free payloads in the Raft command (the original wire
  shape, so mixed-version-safe both directions); blob mesh remains only for
  legacy sealed bytes / oversized specs. Raft-quorum durability is strictly
  stronger than today's best-effort mesh for failover recreate.
- **Status:** IMPLEMENTED 2026-07-11 (PR #307, stacked on PR #306):
  `inlineRecoveryEligible` gate in `recovery_replication.go`, externalize-mode
  metric, determinism-parity + replay + threshold-crossing regression tests.
- **T4 bench re-run DONE 2026-07-12** (v0.6.0 release build, fresh 3×
  t3.medium, all-WAL, netlink, `AEROL_BENCH_EXPECT_NETRULES=netlink`):
  `cluster_promote` p50 **23–25ms → 10–11ms**; warm `create;dur` p50
  **40–44ms → 28ms sparse (gate ≤30ms PASS) / 32ms burst (2ms over)**.
  Externalize metric across all 3 nodes: inline=1043, blob=0 — 100% of
  cluster creates rode the Raft log; the blob mesh never fired. Artifacts:
  `integration-tests/reports/cluster-3-mixed-docker-bench.json` (idle burst),
  `-sparse-bench.json`, `-bench-suiteload.json` (under full-suite load).
- **Remaining 10–11ms promote is the raft round itself, not replication:**
  probe creates entered at the leader still measure 9.6–12.9ms with zero
  variance spikes — leader WAL fsync + follower ack + owner→leader forward
  on t3.medium/gp3. Closing this entry; shaving promote below ~8ms is a
  Tier 3 shape (e.g. the withdrawn promote-overlap with a durable Creating
  FSM state) and only matters if the burst 2ms overshoot matters.

## netrules backend switch on iptables-legacy hosts — DONE

Counter parity (`translator_linux.go`) makes exec↔netlink cleanup
interoperate on iptables-nft hosts. For iptables-legacy hosts: sandboxd now
logs a boot warning when `SB_NETRULES_BACKEND=netlink` meets a legacy
iptables (`netrules.WarnIfLegacyIptables`, wired in `pkg/daemon`), and the
drain-before-switch procedure is documented in `setup/single-node.md` +
`packaging/.env.template`.

## netlink live enforcement probe + bench backend gate — DONE (live-verified 2026-07-12)

Closed the two open PR #306 review findings 2026-07-11; both live-verified on
the T4 bench cluster (v0.6.0, netlink on all 3 nodes) 2026-07-12:
- **UC-98** (`integration-tests/suite/netrules_test.go`): egress deny rule
  must DROP real traffic from inside the sandbox — **PASS** on the netlink
  backend (control sandbox reached the target; denied sandbox timed out;
  unrelated egress flowed).
- **Bench backend gate**: `aerolvm_netrules_backend` expvar + benches fail
  when `AEROL_BENCH_EXPECT_NETRULES` doesn't match `/v1/metrics` — gate
  confirmed netlink on the burst, sparse, and suite-load runs.

With UC-98 + a full live soak now on record, flipping the server default
`SB_NETRULES_BACKEND` exec→netlink is unblocked (separate decision/PR).

## Promote-fail rollback can leave a ghost Placed row (latent, cluster)

- **Status:** fixed in Tier 1.5 (`OverlapCreateAndPromote` / self-wins
  promote-fail now always `DeletePlacement`). See
  `plans/warm-create-latency-tier1.5-seal-promote-overlap.md`.
- **What was wrong:** promote-fail rollback in `cluster_handler.go` used
  Destroy+CancelReservation only; `CancelReservation` is a no-op on Placed,
  so an errored-but-committed Raft place left a ghost row until reconcile
  (~5 min).
- **Fix:** every promote-fail path (overlapped reserved + sequential
  self-wins) calls `DeletePlacement`; reserved-path create-FAIL after
  promote-OK retracts the same way.
## netrules Manager mutex head-of-line blocking

- **What:** shard `Manager.mu` per-container-IP (or move to lock-free netlink
  ops) so concurrent creates don't serialize their Block/Clear/Apply calls.
- **Why:** `pkg/docker/netrules/manager.go` guards every Block/Clear/Apply with
  a single `Manager.mu` (`manager.go:46`). Under concurrent creates every
  sandbox's netrules op queues behind one lock.
- **Caveat / when it matters:** `plans/warm-create-latency-tier1.md` §6 scopes
  p99 / concurrency OUT — the plan's targets are p50 (single create), which
  never contends the mutex. Once the netlink backend lands, each op is sub-ms
  so the critical section shrinks. This only becomes the next bottleneck if
  concurrent-create p90/p99 throughput becomes a stated goal.
- **Note on correctness:** the mutex is load-bearing — it serializes the
  non-atomic `Exists`+`Insert` pair (`manager.go:51`). Sharding must preserve
  per-IP mutual exclusion, not remove it.
- **Depends on / blocked by:** Phase 1 netlink backend landing first (sub-ms
  ops are what make the mutex the next-visible cost).
- **Start:** `pkg/docker/netrules/manager.go`.

## Remove the legacy recovery-blob emit path (inline-only recovery) — DONE 2026-07-12

Executed after all three gates cleared (#306/#307 merged in v0.6.0, T4 bench
passed, zero-deployments premise re-verified in-tree). Branch
`refactor/inline-only-recovery`. What shipped:

- Deleted: `inlineRecoveryEligible` gate (inline is now the only path), blob
  emit + member PUT fan-out (`storeAndReplicateRecoveryBlob`,
  `replicateBlobToMembers`, both `putRecoveryBlobToMember`s, the PUT half of
  `PublicInternalRecoveryPath`), `command.SealedSecrets` +
  `command.Name`/`RecoveryRef`, `PlacementSecrets.LegacySealed`,
  `Placement.SealedSecrets`, `SealedSecretsOf` (no callers), command-level
  `hydrateCommandRecovery`, the `openPlacementSecrets` legacy branch, the
  externalize metric, and the dual-contract tests. Net ~1,650 lines removed,
  ~290 added.
- Kept (per plan §2): blob GET half + `fetchRecoveryBlob` +
  `resolveRecoveryRef` fetch-on-miss and the local recovery store — pinned
  FIRST by `TestFSMSnapshotJoinFetchOnMiss` (snapshot-joined voters get rows
  with refs but no local files).
- New product rule (§3): specs whose recovery record encodes >4KiB are
  rejected at create with a clean 400 (`cluster.ErrRecoveryPayloadTooLarge`,
  boundary-tested at exactly 4096); cluster mode only — single-node keeps no
  cap. Defensive re-check at command encode + on the leader-forward path.
- "No secrets in the Raft log" is now structural: no field exists to carry
  sealed bytes anywhere in cluster state.

## Shard the WASM resident net-host mutex (performance, P3)

- **What:** Shard `multiNetHost`'s single mutex (or split into per-map
  RWMutexes) that guards the `hooks` / `conns` lookups in the resident
  compile-once/instantiate-many WASM host (`pkg/wasm/engine_multi_network.go`,
  shipped in PR-A of `plans/wasm-resident-module-host.md`, 2026-07-17).
- **Why:** At very high co-tenant IO rates on one shared host process, the
  single lock on every `tcp_dial`/`read`/`write`/`close` map lookup could show
  up as contention.
- **Caveat (why it's a TODO, not built now):** the design already releases the
  lock BEFORE the blocking `conn.Read`/`Write`, so contention is only on
  microsecond map lookups — adequate for correctness and the default-flag flip.
  Building sharding now is premature optimization with no evidence it's needed.
- **Depends on / start:** PR-A landed (done) + a profile (`go test -bench` or a
  live cluster-3-mixed-wasm run) that actually shows lock contention. Eng-review
  2026-07-17 (D9).

## Metrics-scoped read-only token (security, `pkg/api` auth)

- **What:** Add a read-only / metrics-scoped bearer token to the auth layer so a
  scrape credential can `GET /v1/metrics` (+ read-only observability endpoints)
  but cannot mutate the cluster.
- **Why:** The investor-benchmark obs stack (`plans/investor-benchmark-observability.md`)
  scrapes `/v1/metrics` with the full-access cluster PAT, baked into the Prometheus
  config on `obs1` + in Terraform state. Any real Prometheus deployment wants this
  too — a leaked scrape token shouldn't be able to create/destroy sandboxes.
- **Caveat (why deferred, not built):** eng review 2026-07-19 (Arch-4) accepted the
  PAT-at-rest risk for the *disposable* itest cluster (leased domain + ttl=4 + reaper
  + SG-to-SG private scrape + operator-IP-scoped Grafana). Blast radius is a throwaway
  cluster destroyed the same day; building token scoping is server auth work well
  outside a benchmark PR.
- **Depends on / blocked by:** auth is single-PAT today (`pkg/api`, UC-10). Nothing
  blocks it; it's a standalone auth feature.
- **Start:** `pkg/api/` auth middleware + token model; the obs scrape
  (`setup/obs/prometheus.yml.tftpl`) is the first consumer.

## Native per-runtime metric labels (observability, `internal/service` + `internal/pool`)

- **What:** Add a `runtime=` label to the native create/pool metrics
  (`aerolvm_create_latency_seconds_bucket`, pool hit/miss) so live per-runtime
  slicing works from Prometheus directly.
- **Why:** eng review 2026-07-19 (CM-2) found native metrics carry no runtime label,
  so per-runtime dashboards can't be built from live metrics — the benchmark works
  around it by pushing runtime-labeled `benchReport` metrics to a Pushgateway. A real
  operator dashboard would want native per-runtime observability without that
  indirection.
- **Caveat (why deferred):** it's hot-path server work (extra expvar cardinality + a
  label on the create path) beyond the accepted §9 instrumentation scope, needs its
  own pr-review + regression test, and the pushed-benchReport approach already covers
  the benchmark's needs. Watch `histogram` cardinality (runtime × le_* buckets).
- **Depends on / blocked by:** rides naturally on the §9 create-stage instrumentation
  (`plans/investor-benchmark-observability.md` §9) once that lands.
- **Start:** `internal/service/metrics.go` (create), `internal/pool/{wasm,isolate,vmm,dockerpool}/metrics.go`.

## Flaky `internal/cluster` memberlist tests (testing, `internal/cluster`) — mitigated 2026-08-08

- **What:** Loopback port-binding flakiness in the `internal/cluster`
  memberlist/SWIM harnesses (`use of closed network connection` after
  push/pull sync).
- **Why it mattered:** The cluster suite is the only guard on the highest-risk
  package; intermittent red trained people to re-run rather than read failures.
- **Mitigation:** Serialize construct/Close of real raft/memberlist harnesses
  via `testClusterMu` + 50ms settle after Close in
  `newTestClusterWithAPI`, `newTestClusterWithRole`,
  `newTestClusterWithRoleAndGrace`, `newTestClusterWithTLSDir`,
  `newTestAgentWithRole`, and `newTestAgentWithTLS`. Lock is **not** held for
  cluster lifetime (multi-node tests still create two clusters concurrently).
- **Verify:** `go test -count=1 ./internal/cluster/` (and `-count=3` if chasing).
- **Residual:** Local machine contention can still surface; if flakes return,
  widen settle or serialize the whole short-lived gossip pair.
- **Depends on / blocked by:** nothing. Independent of secrets-hardening product
  code; fixed alongside the GAP follow-ups so cluster signal stays trustworthy.

## Per-node identity for cluster-internal HTTP (security, `pkg/api` + `internal/cluster`) — landed 2026-09-02

- **Landed:** Every cluster role exposes a dedicated TLS 1.3 internal listener;
  clients pin the peer to a required `node:<SB_NODE_ID>` SAN, servers bind that
  identity to live membership, and every delegated internal/public-shaped route
  is authorized before dispatch. The fleet PAT remains defense in depth.
- **Rotation:** atomically replaced leaf/key files hot-reload for new
  handshakes; expiry metrics and alerts are present. Automated issuance,
  revocation distribution, and coordinated CA rotation remain operator work.
- **Where documented:** `docs/src/content/docs/cluster-secrets.mdx` (known
  limitation), `setup/runbooks/secrets-and-audit.md`,
  `docs/designs/secrets-hardening.md` Deferred,
  `plans/secrets-hardening.md` re-review row #6.
- **Where:** `internal/cluster/{tls,internal_server,peer_dial}.go`, the global
  `pkg/api` cluster-control-header guard, config validation, docs, and runbook.

## Durable secret-delete outbox / ACK ledger (cluster secrets) — landed 2026-08-09

- **What:** Generation-scoped tombstones + persistent cleanup outbox so peer
  DELETE fan-out survives daemon crash, retries until every recipient ACKs,
  and rejects stale PUTs until a newer seal generation clears the tomb.
- **Landed:** originator tomb+row-delete+outbox in one SQLite TX; per-recipient
  pending shrink (offline peers stay pending, never treated as success);
  DELETE carries `generation`; peer tombs with seal_generation gating so stale
  DELETEs cannot wipe a reseal; boot + 30s periodic reconcile (O(1) per job);
  reseal stages retired-recipient cleanup atomically with the new sealed row,
  gates deletion on Raft promotion, and preserves older pending recipients.
- **Residual:** long partitions require operator action based on the shipped
  outbox age/backlog metrics; KMS CMK policy is separate. `failover_ready` now HEAD-probes
  remote holders for the current `seal_generation` (not ACK memory alone);
  member rejoin triggers outbox reconcile + re-fanout.
- **Where:** `internal/store` outbox/tombs, `internal/service/cluster_secrets.go`,
  `internal/cluster/secret_replication.go`, daemon boot + ticker.

## Indexed / central secret-audit store (scale) — parked residual 2026-08-09

- **What:** Replace full JSONL scan + sequential all-member fan-out with an
  indexed durable store or central sink; E2b witness.
- **Interim landed:** sidecar flock; Close/Prune `sendMu`; verified startup chain;
  authenticated, idempotent HTTPS batch export with durable watermark; gap markers with
  `kind=gap` (included in kind-filtered pages); compound cursor; malformed
  JSONL → gap event; wasm queue-full writes a durable gap marker; post-delete
  ACL via `sandbox_audit_acl` + Placement.OwnerRef.
- **Residual:** local fallback queries and startup verification still scan the
  JSONL file. Enterprise mode requires the external exporter/receiver; receiver
  indexing, WORM retention, and operational verification remain deployment gates.
- **Start:** `internal/service/secret_audit_query.go`; E2b witness sink may
  double as the central store.

## WASM egress audit via bounded IPC (not shared JSONL) — landed 2026-09-02

- **Landed:** Worker subprocesses enqueue through the daemon's
  authoritative audit writer (bounded channel, drop counter, gap markers)
  instead of opening `secrets.jsonl` themselves.
- **Mechanism:** authenticated Unix-socket ingest, bounded worker pool, durable
  acknowledgement through the authoritative writer, and explicit gap accounting
  under overload. Workers no longer open the audit JSONL directly.
- **Where:** `pkg/wasm/worker/egress_audit.go`, daemon spawn environment, and
  `internal/service/wasm_audit_ingest.go`.

## Isolate orphan sweep survives a daemon restart (runtime) — part 2

- **What:** Give `internal/runtime/isolate` a host-backed enumeration so
  `Reconcile`'s orphan sweep can find workerd groups leaked across a restart.
  Today `Driver.ListManaged` (`internal/runtime/isolate/driver.go:205-213`)
  returns the driver's in-memory `byID` map, and `HostSupervisor`
  (`internal/runtime/isolate/seams.go:48-50`) exposes only `SpawnGroup` — there
  is no way to ask the host what is running.
- **Why:** part 1 (wiring isolate into `mergeManagedRuntimes` + `removeOrphans`,
  `internal/service/service.go`) shipped with this change and covers the case
  `finalizeStaleLocalSandbox` depends on: a transient `Destroy` failure while
  the daemon stays up. It cannot cover a crash. A jailed group owns a cgroup
  under `SB_ISOLATE_JAIL_CGROUP_ROOT` and a uid-owned chroot tree under
  `SB_ISOLATE_JAIL_CHROOT_BASE`, so a leak across a restart strands host state
  permanently and invisibly.
- **Caveat (why it's a TODO, not part of the same change):** it needs a new
  seam (`ListGroups` on `HostSupervisor`) plus a real cgroup or chroot walk with
  its own failure modes — enumerate-while-spawning races, partial teardown, and
  a jail-off mode where neither directory exists. That is a design decision, not
  a mechanical addition.
- **Start:** `pkg/isolate/cgroup.go` + `chroot.go` already know the layout
  (`linkGroupJail`/`removeGroupJail` name the per-group dirs). Add `ListGroups`
  to `HostSupervisor`, implement it over the cgroup root, have
  `Driver.ListManaged` union it with `byID`, and extend
  `internal/service/reconcile_isolate_orphan_test.go`.

## Daytona facade cannot distinguish "no env" from "env withheld" (API)

- **What:** Decide and implement a Daytona-side signal for D9's withheld env.
- **Why:** under D9 `internal/service` returns a nil `Env` unless
  `GetSandboxOptions.IncludeEnv` is set, so the facade's default response
  serializes `"env": {}` (`pkg/api/daytona/dto.go`), which asserts the sandbox
  has no environment rather than that none was returned. `?include_env=true`
  now exists as the opt-in (`hydrateEnvIfRequested` in `handlers.go`), but the
  default is still ambiguous.
- **Caveat (why it's a TODO):** the obvious fix — `json:"env,omitempty"` — was
  tried and **reverted**: the Daytona SDK's deserializer rejects a sandbox
  payload with no `env` key, and `TestDaytonaSDKContracts` fails across the whole
  read surface. Any fix has to stay inside what the real SDK accepts, so it
  needs a Daytona-compatible convention, not a Go struct tag.
- **Start:** `pkg/api/daytona/contract_test.go` is the gate any change must
  pass; `pkg/api/daytona/include_env_test.go` covers the opt-in that exists now.

## SDK create retries can duplicate unnamed sandboxes (all SDKs)

- **What:** the Go SDK retries `POST /v1/sandboxes` on post-send transport
  errors ("EOF", "timeout", "connection reset", DeadlineExceeded) and on
  502/503/504 (`sdk/go/internal/apiclient/client.go:886-946`). Without a
  name, a lost reply creates a second sandbox. The TS, Python and Java SDKs
  have retry code too (`sdk/typescript/src/internal/client.ts`,
  `sdk/python/microvm/client.py`, `MicroVMConfig.java`); check them.
- **Why:** duplicate billed sandboxes that the caller never sees. The CLI and
  MCP avoid it with auto-generated names (`plans/mcp-server-and-agent-cli.md`
  §5.4, eng review D5); plain SDK users don't.
- **Start:** decide between (a) no retry for non-idempotent POSTs after the
  request may have been sent and (b) a create idempotency key (server + 5
  SDKs). Add a test per SDK: a fake server creates, then drops the
  connection, and exactly one sandbox must exist.
- **Depends on:** none.
