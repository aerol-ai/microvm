# containerd engine: dropping the dockerd tax (cold 274ms → ~110ms, warm 43ms → ~20ms)

Status: **proposed (not started)** (written 2026-07-11; revised 2026-07-12
after eng review — 9 review findings + 5 cross-model findings folded, §4
rebased on CNI, one store change admitted; see the GSTACK REVIEW REPORT at
the end). Companion to `plans/warm-create-latency-tier1.md` (which stays
fully valid — every Tier 1 phase applies under either engine) and
successor-in-spirit to `plans/docker-warm-pool.md` §10's "containerd work
out of scope" note. This plan brings it in scope, with measured justification.

Owner rules that apply: this is the largest fragile-area addition since
cluster mode — a new engine behind `CreateSandbox` (`/touch-create-sandbox`
on every boot-path PR), a new driver package that must land at the ~85%
coverage bar, and networking changes adjacent to the netrules/adopt path
that broke once already on iptables-nft. Ship-dark rules apply throughout:
the dockerd path remains the default until the exit gates in §8 pass.

## 1. Why: the dockerd tax, measured

dockerd is a management daemon *on top of* containerd. Both engines were
measured on the same host (t3.medium, node2 of the kept
`cluster-3-mixed-docker` cluster, 2026-07-11):

| Operation | dockerd (engine API) | containerd (`ctr`, incl. ~20ms CLI overhead) |
|---|---|---|
| create | ~110ms | ~50ms |
| start | ~115ms | ~70ms |
| create+start | **~225ms** | **~90-100ms CLI ⇒ ~75-80ms engine-side (gRPC)** |

Identical results for `alpine:3.20` and `python:3.12-slim` — post-pull,
layer count is irrelevant. `ctr` performs no network setup, which matches
our architecture: the netns pool prepays networking either way.

**Measurement honesty (Phase 0 re-verifies):** the `ctr` numbers exclude
everything the real boot path adds — netns handoff, resolv.conf/hosts
generation, spec assembly, log IO setup, labels, readiness wiring, lease
acquisition. Phase 0's spike is a *CreateSandbox-equivalent*, not a bare
gRPC create/start/destroy, precisely so the §1 economics can't erode one
unmeasured step at a time.

**dockerd adds ~150ms of pure overhead to every cold create** — libnetwork
bookkeeping, container-object state writes, name registry, API layering —
none of which we use: networking is prepaid (netns pool) or ours (netrules,
caddy), state lives in our store, and the name registry exists only to
serve the name=sandboxID convention.

On the warm path, dockerd costs the **~11ms rename** (measured; its own
container lock + state write). Under containerd the rename ceases to exist
as a concept — container IDs are immutable, adoption is our own store
mapping (the `container_id` column already exists) plus at most a ~1ms
label update. This delivers Tier 3's "async rename" win **without the
semantics risk**, because the name convention it endangers is a dockerd-ism
that disappears with dockerd.

Projected results (see §8 for gates):

| Metric | today (dockerd) | dockerd + Tier 1 | containerd + Tier 1 **+ Tier 2** |
|---|---|---|---|
| Cold create p50 | 274ms | ~260ms | **~100-120ms** |
| Warm hit p50 (cluster) | 43ms | ~30ms | **~18-20ms** |
| Warm hit (single-node) | ~30ms | ~20ms | **~8-10ms** |
| p99 (miss ⇒ cold fallback) | 377ms | ~350ms | **~130-150ms** |

**The cluster warm-hit rows depend on Tier 2, not just Tier 1.** Cluster
warm = create leg + promote, and promote is recovery-replication-bound
(~23ms) until Tier 2's inline-recovery work (PR #307, shipped; T4 bench
re-run pending) proves out. Even a ~8ms containerd create leg cannot reach
18-20ms against an unchanged ~23ms promote. Single-node rows have no
promote leg and hold on Tier 1 alone. Triage rule for the flip: a warm-hit
miss with promote >10ms points at Tier 2, not at this driver.

The p99 row is the strategic one: Tier 1 barely touches the cold path, so
p99 stays hostage to the miss penalty. containerd cuts that penalty 3×,
and parking a slot drops from ~225ms to ~75ms — refill keeps pace with
bursts, so the effective hit rate improves too. This is the only lever on
the table that moves p99 materially.

## 2. Design decision: an engine choice, not a new runtime

The user-facing `runtime:` values (`docker`, `gvisor`) do not change. The
engine that realizes them is a **host-level operator choice**:

```
SB_CONTAINER_ENGINE=docker|containerd     (default: docker)
```

`pkg/daemon` wires `service.docker` to either the existing `pkg/docker`
client or the new driver — both satisfy `internal/runtime.ContainerRuntime`
(the seam built for exactly this). Zero API, SDK, or facade changes;
`models.ResolveOCIRuntime` keeps mapping `gvisor` → runsc, it just resolves
to a containerd runtime handler instead of a `HostConfig.Runtime` field.

**One store change (eng review D15): a per-sandbox `engine` column.**
`runtimeForSandbox` (`internal/service/service.go`) routes by runtime
*type* only — without engine ownership on the row, flipping the env var
would hand every pre-flip dockerd sandbox to the containerd driver, whose
inspect/stop/destroy would all fail against containers only dockerd knows.
The column defaults `'docker'` for existing rows; `runtimeForSandbox`
branches on it so a migrating node drives old sandboxes through the old
engine while new creates use the new one. `/add-store-column` mechanics +
`store_test.go` regression apply.

Both engines coexist on one host during rollout: dockerd already runs on
the system containerd (namespace `moby`); the driver uses the same
containerd through its own namespace (`aerolvm`). A node migrates by
flipping the env var — old sandboxes drain under dockerd (the engine
column keeps them driveable), new sandboxes boot under containerd. Rolling
node replacement remains the fallback ops pattern. Coexistence risks are
enumerated in §7.6-7.9.

**Mixed-fleet visibility (eng review D18):** nodes advertise their engine
as an observability tag — capacity heartbeat field + expvar/Server-Timing
label — so benches, dashboards, and the Phase 5 soak compare engines
like-for-like and a canary node is identifiable without ssh. Deliberately
NOT a placement attribute: placement/FSM is a fragile area and the need is
migration-transient. Canary = bring up N tagged nodes, watch split
metrics, drain on regression (existing Ansible drain playbook).

## 3. What ports, what's reimplemented, what disappears

**Ports unchanged (engine-agnostic):** netrules manager (host iptables —
but see §4 for chain ownership), caddy routing (dials container IP from
the host for both L7 and L4-TCP — engine-agnostic by construction),
toolboxd + readiness socket (bind mounts work identically; toolboxd stays
host-bind-mounted so no version skew), warm-pool *state machine*
(`internal/pool/dockerpool` — review-verified interface-decoupled: depends
only on its own `Spawner`/`SpawnerHandle` interfaces + `pkg/models`),
admission, store (plus the one new column, §2), mounts, secrets, SSH
gateway, the service layer's business logic.

**Seam relocation (cross-model D16 — prerequisite Phase 1 plumbing).**
Four places assume "dockerd always exists" and must grow seams before the
driver can wire in:
- `Service.events` is a concrete `*docker.Client` (`service.go` — the
  comment says intentionally so). Becomes an `EventsSource` interface
  covering the die-event stream AND the PID lookup netstats requires
  (`netstats requires the docker events client for PID lookup` is a boot
  error today). containerd impl: events subscription + task `Pids()`.
- `pkg/daemon` unconditionally constructs the docker client and passes it
  as both lifecycle runtime and events client. Becomes engine-selected
  construction.
- `wireDockerWarmPool` (`pkg/daemon/docker_warm_wiring.go`) takes
  `*docker.Client` concretely. Parameterizes over the `Spawner`
  implementation.
- Runtime-compatibility guards (gvisor+privileged, GPU-on-gvisor, DiskGB
  warning — `pkg/docker/client.go:340-360,553-560`) extract to a shared
  `ValidateRuntimeRequest` next to `ResolveOCIRuntime` in `pkg/models`
  (eng review 7A): one table-driven test, both drivers call it, runtime
  policy cannot fork per engine. (kata, if it ever lands, is a third
  caller.)

**Reimplemented against containerd gRPC:**
- Task lifecycle: create/start/stop/destroy/inspect — the measured ~75ms
  path. Bind mounts, resource limits (runc cgroup options replace
  dockerd's `Resources` update — the warm-adopt no-op-update optimization
  carries over), env, user.
- **Task IO (eng review 3A):** every task gets a bounded per-sandbox log
  file (LogURI), size-capped/truncated by us (~50 lines we own —
  containerd does not rotate), reaped on destroy and counted by the orphan
  reconcile. Never FIFO-without-reader (an undrained FIFO blocks the
  container's stdout writes once the pipe fills); never NullIO (boot
  failures must leave a breadcrumb — nothing consumes container logs
  programmatically today, so this is purely the operator postmortem
  story).
- Image service: pull with the existing single-flight dedup pattern,
  lease-based GC (cleaner than the current TTL sweep — leases pin images
  in use by definition, including during create; tested against the
  create-while-GC race), registry auth, and the mirror config
  (`registry-mirrors` in daemon.json becomes a `hosts.toml` per registry).
- **Snapshot & template flows (cross-model D17 — was missing entirely).**
  `CreateSnapshot` is mandatory on the `Runtime` interface
  (`internal/runtime/runtime.go:49`, docker-commit semantics). containerd
  gives no `commit` for free: the driver implements pause/freeze →
  snapshotter diff → new image in the `aerolvm` namespace, under a lease.
  Snapshot push / template push / template pull port onto their existing
  narrow interfaces (`SnapshotPushDocker` et al. are already injection
  seams), backed by containerd's resolver-based push/pull.
- Events: containerd's events API replaces the `/events` stream via the
  `EventsSource` seam above; the die-event reconcile hook is a port PLUS
  subscription-drop handling (resubscribe + missed-event catch-up poll —
  named test, §6 Phase 1).
- Build/tag flows: `docker build` compatibility requires BuildKit
  (buildkitd speaks containerd natively). Scoped as its own phase — the
  built-image namespace and tag flush hooks port onto it. Hosts without
  buildkitd degrade with a clear error (§7.4), tested.
- **Security envelope (runc, Phase 1):** dockerd applies seccomp, cap
  drops, masked/readonly paths, and (on Ubuntu) an AppArmor profile to
  every non-privileged container without our client setting anything —
  see `pkg/docker/client.go` (`Privileged` is the only security field we
  pass today). containerd applies *none* of that unless the OCI spec
  carries it. Phase 1 driver work (all via `oci.SpecOpts`, skipped when
  `SB_CONTAINER_PRIVILEGED=true`):
  - seccomp: `contrib/seccomp` default profile (Docker-equivalent syscall
    filter; never ship runc unconfined on the default path).
  - capabilities: explicit `CapDrop: ["ALL"]` + minimal `CapAdd` set
    matching dockerd's default non-privileged container (audit with the
    spec-diff harness below — do not guess from memory).
  - namespaces hardening: `NoNewPrivs`, masked paths (`/proc/acpi`,
    `/proc/kcore`, `/proc/keys`, `/proc/latency_stats`, `/proc/timer_list`,
    `/proc/timer_stats`, `/proc/sched_debug`, `/sys/firmware`, …) and
    readonly paths (`/proc/asound`, `/proc/bus`, `/proc/fs`, `/proc/irq`,
    `/proc/sys`, `/proc/sysrq-trigger`, `/sys/devices/virtual/powercap`) —
    mirror dockerd's default spec, not a hand-rolled subset.
  - AppArmor: **decide in Phase 0/1**, not at flip time — either load a
    `docker-default`-equivalent profile by name or document a deliberate
    `unconfined` choice with operator-facing rationale (Ubuntu hosts are
    the production default). SELinux labeling is out of scope unless a
    customer topology requires it.
- **Security envelope (runsc, Phase 4):** Sentry is the boundary, but
  runsc flags are ours once they move off daemon.json. Pin every flag
  install.sh currently sets — especially `--host-uds=open` (UC-96* socket
  attribution) — in containerd runtime options + runsc config (prefer the
  no-config.toml registration path, §7.7); Phase 4 gVisor matrix re-runs
  the spec-diff where applicable.

**Disappears:** the rename (§1), the pause-container netns hack (§4), the
image-ID cache's reason to exist may shrink (containerd image resolution
is a local metadata read, not a ~45ms engine round-trip — re-measure
before keeping the cache).

**Daemon-restart survivability:** containerd shims are detached processes;
tasks survive daemon restarts natively — this *replaces* the
`live-restore: true` behavior we depend on in daemon.json, it doesn't
lose it.

## 4. Networking ownership

The one genuinely new responsibility, and the plan's largest risk surface.
dockerd's libnetwork provided **eight** distinct services, not three; the
netns pool already bypasses the per-create cost with pause containers, so
we are close to owning slot *lifecycle* — but lifecycle was never the
whole job. The full parity inventory (eng review D5 + 1A):

```
 dockerd service (today)                     owner under containerd
 ───────────────────────                     ──────────────────────
 1. bridge + veth creation              →    CNI bridge plugin (aerolvm0)
 2. IPAM + lease persistence            →    CNI host-local (on-disk state,
                                             survives daemon restart)
 3. outbound NAT (POSTROUTING           →    CNI ipMasq: true
    MASQUERADE) + ip_forward
 4. DOCKER-USER chain + FORWARD jump    →    ours: AEROLVM-USER via netrules
                                             EnsureChain (below)
 5. FORWARD-policy interplay            →    ours: our accepts must survive
                                             dockerd restarts on coexist hosts
 6. br_netfilter / bridge-nf-call-      →    ours: ensure sysctl, or netrules
    iptables sysctl                          silently stops filtering
                                             sandbox↔sandbox bridge traffic
 7. /etc/resolv.conf + /etc/hosts +     →    ours: generate + bind-mount in
    /etc/hostname generation                 driver Create (sanitize
                                             systemd-resolved 127.0.0.53)
 8. conntrack flush on IP release,      →    ours: flush on slot release or
    MTU selection                            reused IPs blackhole; MTU parity
                                             with the host uplink
```

- **Bridge + IPAM + NAT: CNI plugins** (bridge + host-local + `ipMasq`),
  not bespoke netlink (eng review D5, reversing the original draft). The
  plugins are decade-hardened, persist IPAM state on disk (restart-safe by
  construction), and handle veth/bridge/NAT wholesale — precisely the
  items nothing in this repo does today (review-verified: zero
  NAT/`ip_forward`/`br_netfilter` handling exists anywhere in the tree;
  the tap allocator covers link/addr management only). The original
  exec-cost objection dissolves: the netns pool prepays networking on the
  *refill ticker*, so CNI's ~30-50ms exec lands off the boot path for
  every warm hit and every pooled cold — only pool-empty colds pay it, and
  Phase 0(d) confirms the refill-rate math. New runtime dependency: CNI
  plugin binaries ship via install.sh/Ansible (§6 Phase 5).
- **netns pool goes native — with an explicit lifecycle state machine
  (eng review 4A).** Native slots have no dockerd garbage-collector
  backstop: a crash mid-build leaks a namespace, veth pair, IPAM lease,
  and conntrack entries with no process whose death frees them. The design
  follows the tap allocator's `pool.go`/`host.go` split (bookkeeping vs
  realization, idempotent Ensure/Remove) plus the **Firecracker driver's
  deferred-with-committed-flag LIFO cleanup** in Create — explicitly NOT
  docker Create's ad-hoc error paths, which have no host-side cleanup
  pattern to copy:

```
            reserve            realize (CNI ADD)          adopt
  [empty] ────────► [reserved] ─────────────────► [realized] ────► [adopted]
     ▲                  │ crash/error                  │ crash          │
     │                  ▼ LIFO teardown                │                ▼ destroy
     │              (reverse build order:              │           [released]
     │               CNI DEL, netns del,               │            conntrack
     │               lease release)                    ▼            flush
     └─────────────────────────────────────  boot reconcile: walk live
        reap orphans (counters feed the      netns + CNI host-local state
        §8 orphan gate)                      dir + store rows; unmatched
                                             entries torn down in reverse
                                             build order
```

  Boot reconcile is the janitor: it walks live netns, the CNI host-local
  state dir, and store rows; anything unmatched is torn down in reverse
  build order and counted (the §8 orphan gate covers these counters).
  Crash-consistency is tested by killing between each pair of steps (named
  tests, §6 Phase 2). This shape extends to gVisor (§5), which the
  pause-container hack cannot.
- **`AEROLVM-USER` chain — ownership, not just a name (eng review 6A).**
  dockerd creates `DOCKER-USER` (hardcoded 15× in
  `pkg/docker/netrules/manager.go`) and its FORWARD jump; for our chain
  both jobs move to us. netrules gains an `EnsureChain` bootstrap —
  idempotent chain-create + jump-insert, latched with the `atomic.Bool` +
  single-flight pattern (`EnsureLayer4Ready` precedent) — routed **through
  the existing `RuleBackend` seam** so Tier 1's netlink translator
  implements it once too (the backend is iptables-argv-shaped; a bootstrap
  outside the seam would recreate the memorialized iptables-nft class of
  break). Jump-position rule: our jump stays ahead of docker's rules on
  coexistence hosts and is re-asserted if a dockerd restart reshuffles
  FORWARD. Regression tests run the manager against BOTH chain names so
  the docker path cannot rot. Tier 1 Phase 1 (netlink backend) lands with
  the chain parameterized so the two plans compose.
- **DNS/hosts/hostname generation:** driver Create writes per-sandbox
  `resolv.conf` (host upstream resolvers, sanitizing loopback stubs like
  systemd-resolved's `127.0.0.53`, which is unreachable from a netns),
  `/etc/hosts`, and `/etc/hostname`, bind-mounted the same way dockerd
  did. Table-driven tests over host resolv.conf shapes (§6 Phase 2).

## 5. gVisor on containerd

gVisor is a first-class runtime here (`runtime: gvisor` → runsc via
`HostConfig.Runtime`, `--with-gvisor` node toggle in Terraform/bootstrap).
The instinct that an engine migration endangers it is reasonable — and
wrong in direction. **containerd + `io.containerd.runsc.v1` is gVisor's
canonical deployment**: GKE Sandbox runs exactly that shape, and it is the
integration Google builds and tests against first. Docker+runsc — our
current path — is the secondary route.

**What the engine swap does NOT change:** everything that makes gVisor
gVisor is a runsc property, identical under either engine — Sentry,
netstack, the gofer filesystem (so the readyproto socket bind-mount
behaves the same), the privileged refusal, the GPU refusal, the ignored
`StorageOpt` disk quota. The guard branches move to the shared
`ValidateRuntimeRequest` validator (§3) — both drivers call one function,
so runtime policy cannot drift between engines.

**What improves:**
- Per-container runtime handlers (`WithRuntime("io.containerd.runsc.v1")`)
  replace the daemon.json runtime registration — cleaner selection, and
  runc/runsc sandboxes mix freely on one node as they do today.
- **The netns prepay trick becomes available to gVisor for the first
  time.** Today `docker_netns` is gated to the plain docker runtime
  because joining a foreign pause-container netns is not a supported
  runsc shape. Under containerd the driver creates the netns + veth and
  hands it to the shim at create — runsc's netstack attaches to the veth
  inside it. That is the GKE flow — but it is also the single assumption
  the §4 networking design and this section both stand on, so **Phase
  0(c) proves it** (runsc boots and serves traffic in a driver-built
  netns+veth) before Phase 2 builds on it. gVisor colds get the same
  prepaid-networking discount runc colds already enjoy.
- Warm pool: pool keys already include runtime, so parked runsc slots
  (toolboxd running under Sentry) work the same, minus the rename like
  everything else.

**What it honestly costs:**
- **The validation matrix doubles.** Every driver behavior needs a runsc
  variant: cold, warm adopt, netrules, readiness socket, resource limits,
  events/reconcile. gVisor-specific pins become ours: platform choice
  (systrap default; KVM where nested virt allows), cgroup handling under
  shim v2, and the runsc↔containerd shim-API compat matrix.
- Config plumbing: runsc flags move from daemon.json to containerd runtime
  options + a runsc config — install.sh, Ansible, and bootstrap all touch.
  The `--host-uds=open` pin is named in §3's runsc security envelope
  (prior incident: daemon.json `runtimeArgs` don't transfer; runsc default
  is `host-uds=none` and the readiness socket dies silently without it).
  UC-96* in §8 is the regression gate.
- **Latency expectations must stay honest:** Sentry boot (~100-200ms
  estimated on this instance class) is engine-independent and dominates a
  gVisor cold create. The ~150ms dockerd tax comes off in absolute terms
  (rough estimate: ~450ms → ~300ms cold), but warm pools remain the real
  gVisor latency answer. **We have zero measured runsc numbers** — the
  bench topology doesn't install gVisor. Phase 0 fixes that before any
  gVisor design is finalized.

## 6. Phases

Each phase ships dark behind `SB_CONTAINER_ENGINE=docker` (default
untouched) and lands with its package at the coverage bar.

**Mandatory dark-default regression (iron rule, every phase):** with
`SB_CONTAINER_ENGINE=docker`, behavior is byte-identical to today —
netrules still writes `DOCKER-USER`, the pause-netns pool still runs, no
drift. This is the "cluster mode must remain a no-op" rule applied to this
flag.

- **Phase 0 — measure & spike (hardened exits, cross-model D19).**
  (a) Bench topology variant with `with_gvisor=true`: measure docker+runsc
  cold/warm today (Sentry boot, park-slot viability) so gVisor gains are
  projected from data, not estimates. (b) Driver spike that is a
  **CreateSandbox-equivalent** — netns handoff, resolv/hosts generation,
  spec assembly (incl. the §3 security envelope), log IO, labels, lease —
  against the system containerd in an `aerolvm` namespace, via API (no
  `ctr`). (c) **runsc-in-driver-netns proof**: runsc boots and serves
  traffic in a netns+veth we built — the load-bearing bet for §4 and §5.
  (d) CNI refill-cost confirmation: CNI ADD latency × pool depth vs burst
  refill rate. (e) **Decide** shared vs dedicated containerd (promoted
  from §9 — config.toml ownership, mirrors, runsc options, and upgrade
  cadence all hang on it); confirm config.toml-less runsc registration
  (shim binary on containerd's PATH + per-container runtime options) so
  coexistence hosts avoid a containerd restart (§7.7); make the AppArmor
  call from §3. Exit: measured runsc table + spike within 15% of §1 +
  runsc-netns proof + engine/AppArmor decisions recorded.
- **Phase 1 — core driver + seams.** `internal/runtime/containerd/`
  implementing `ContainerRuntime`: task lifecycle, image pull + dedup,
  bind mounts, resource limits, events→reconcile, readiness socket,
  registry mirror, task log files (§3), snapshot commit (§3), and the
  runc security envelope from §3 (`internal/runtime/containerd/security.go`
  or equivalent — one place all `SpecOpts` assemble). Seam relocation
  lands here (cross-model D16): `EventsSource` interface + netstats
  containerd impl (task `Pids()`), engine-selected daemon wiring,
  parameterized warm wiring, shared `ValidateRuntimeRequest` (7A), and the
  `engine` store column (D15). Table-driven tests against a fake
  containerd API (the `poolFakeDaemon` pattern from `docker_pool_test.go`)
  assert the spec carries seccomp/caps/masks.
  **Spec-diff harness:** `integration-tests/suite/security_spec_diff_test.go`
  (behind the `integration` tag): create the same minimal sandbox on a
  host with both engines available, `exec` a probe that prints
  `/proc/self/status` fields (`CapEff`, `NoNewPrivs`, `Seccomp`) and
  mountinfo for masked paths; fail if containerd is strictly weaker than
  dockerd. This is the permanent parity contract — not a one-time audit.
  **Named tests (eng review 8A):** adopt idempotency under concurrent
  duplicate calls; error mid-create → LIFO teardown; event-stream drop →
  resubscribe + catch-up poll; lease-pins-image vs GC race; log
  cap/truncate + destroy reap; guard-validator table (in its shared home).
- **Phase 2 — networking.** CNI wrapper (ADD/DEL idempotency) + native
  netns pool FSM (§4 diagram) + `AEROLVM-USER` `EnsureChain` + netrules
  chain parameterization (coordinate with Tier 1 Phase 1); br_netfilter
  ensure; resolv.conf/hosts/hostname generation; conntrack flush on
  release; MTU parity. Regression tests at the tap-allocator standard —
  this is a new fragile allocator and gets the same treatment.
  **Named tests (eng review 8A):** crash injected between netns → CNI ADD
  → record → boot reconcile reaps (namespace, veth, lease); conntrack
  flushed on IP reuse; resolv.conf sanitization table (incl. 127.0.0.53);
  dual-chain netrules regression; br_netfilter sysctl verified set.
- **Phase 3 — warm pool + park/adopt + snapshots.** Rename-free adoption
  (store mapping + label), park spawn via the driver, lease-based image
  GC, snapshot/template push-pull ports (§3), re-measure whether the
  image-ID cache still pays for itself. BuildKit for build/tag flows (can
  trail the rest of Phase 3). **Named test:** buildkitd-absent → clear
  error, not a hang.
- **Phase 4 — gVisor.** Runtime-options plumbing (incl. the `--host-uds=open`
  pin from §3), netns prepay for runsc (proof carried from Phase 0(c)),
  the doubled test matrix from §5, spec-diff re-run where applicable.
  Gated on Phase 0's measured baseline.
- **Phase 5 — ops & rollout.** install.sh/Ansible/Terraform engine toggle
  + CNI plugin distribution, packaging, engine tag in capacity heartbeat +
  expvar/Server-Timing (§2), integration bench scenario for the containerd
  topology, coexistence runbook (disk math §7.6), runbook updates.
  **Named integration UCs (eng review 8A — each tied to a §8 gate):**
  neighbor-isolation UC; sandboxd-restart reconcile UC (live sandboxes +
  parked slots + netns slots); containerd-restart UC (shims survive,
  events resubscribe); dockerd-coexistence UC (AEROLVM-USER jump survives
  dockerd restart); the cross-engine spec-diff harness from Phase 1.
  Default flip is a separate release after a full-suite soak; dockerd path
  is retained indefinitely for operators who want stock Docker on their
  hosts.

## 7. Risks & parity items

1. **Security profile parity (runc).** Functional and bench tests will not
   detect a weaker seccomp/cap/AppArmor envelope — only the §3 spec-diff
   harness and the §8 gate catch it. Treat any `SpecOpts` refactor as
   high-risk; the harness must stay green on every PR touching the driver.
2. **Disk quota (`DiskGB`).** dockerd's `StorageOpt size` needs
   xfs+pquota backing; the containerd overlayfs snapshotter has its own
   quota story. Parity must be verified on our actual filesystem layout —
   and while we're there, verify what dockerd is *actually* enforcing
   today (gVisor already ignores it silently; runc on non-xfs may too).
3. **New fragile surface.** A second engine implementation doubles where
   container-lifecycle bugs can live. Mitigation: ship dark, same
   Server-Timing stages (now engine-tagged, §2) so benches compare engines
   like-for-like, and the integration suite runs the same UC scenarios
   against both topologies.
4. **BuildKit is a new daemon dependency** for build flows only — degrade
   gracefully (build endpoints return a clear error on containerd hosts
   without buildkitd rather than blocking the engine flip). Tested (§6
   Phase 3).
5. **Snapshotter future** (upside risk): stargz/SOCI lazy pull could turn
   the 4-6s first-pull tail into sub-second starts; crun could shave
   ~20-30ms off task start. Both are containerd-only doors — out of scope
   here, noted as follow-ups this plan unlocks.
6. **Coexistence disk doubling (eng review 5A).** dockerd's graph driver
   and the `aerolvm` containerd namespace do not share image content —
   during drain, every image both engines run is stored twice, on nodes
   where the 4-6s first-pull tail already says disk isn't overprovisioned.
   Phase 5 runbook carries the disk math + a monitoring threshold for the
   drain window.
7. **containerd config.toml ownership (eng review 5A).** The file belongs
   to the containerd.io package (upgrade clobber risk) and editing it
   restarts containerd under live dockerd workloads. Preference:
   no-config.toml runsc registration (shim binary on PATH + per-container
   runtime options) — Phase 0(e) confirms; config.toml edits only if that
   fails.
8. **containerd version pin (eng review 5A).** The Go client must speak
   the system containerd's API (Ubuntu LTS ships 1.7.x; current client
   libs are 2.x-era). Pin a supported containerd version range + a CI
   check against the pinned API; record with Phase 0(e).
9. **Artifact migration (cross-model D17).** Nothing migrates local
   images, built images, snapshots, or template artifacts from `moby` to
   `aerolvm` on drain. Registry-backed artifacts (AOCR snapshots/
   templates) re-pull cleanly; post-flip first creates pay full pull
   latency — stated in the runbook; local-only built images need an
   explicit warm-up or rebuild note.

## 8. Exit gates (default-flip criteria)

| Gate | Threshold |
|---|---|
| Cold create p50 (standard bench topology, runc) | ≤ 130ms |
| Warm hit p50 (cluster, with Tier 1 **+ Tier 2 T4-proven**) | ≤ 22ms |
| p99 (docker row, full bench) | ≤ 180ms |
| gVisor cold p50 vs docker+runsc baseline | ≥ 100ms improvement |
| Full integration suite on containerd topology | green, incl. UC-96* socket attribution |
| **Neighbor isolation (eng review 1A)** | egress-blocked sandbox cannot reach a neighbor sandbox on the same bridge |
| Orphan/stale counters after bench + reconcile | 0 (now includes netns slots, IPAM leases, task log files) |
| Coverage: `internal/runtime/containerd/` + networking pkg | ≥ 85% |
| runc security spec-diff (`integration-tests/suite/security_spec_diff_test.go`) | green; containerd not weaker than dockerd on CapEff/Seccomp/NoNewPrivs/masked paths |

The warm-hit gate is conditional on Tier 2 (PR #307) proving its ≤30ms
promote via the pending T4 bench — see §1 for the triage rule.

## 9. Open questions

1. Exec surface: toolboxd owns in-sandbox exec, but reconcile/debug paths
   may use engine exec — audit actual usage before scoping the driver's
   exec support.
2. Does the image-ID cache (and its Tier 1 refill-warming rider) survive
   Phase 3, given containerd image resolution is a local metadata read?
   Keep both until measured.
3. Kata: `ResolveOCIRuntime` reserves the name. containerd's runtime
   handlers make a kata shim (`io.containerd.kata.v2`) the same shape as
   runsc — free option value, explicitly not scoped here. (The shared
   guard validator from §3 is where kata's policy would slot in.)

(Resolved by review: shared-vs-dedicated containerd moved to Phase 0(e);
direct-netlink vs CNI decided for CNI, §4.)

## 10. What already exists (review-verified reuse map)

| Sub-problem | Existing code | Plan's use |
|---|---|---|
| Engine seam | `internal/runtime.ContainerRuntime` | reused — driver implements it |
| Reach sandbox from host | caddy dials `containerIP:port` (L7 + L4) | reused unchanged |
| Warm-pool state machine | `internal/pool/dockerpool` (interface-decoupled, verified) | reused; new `Spawner` impl |
| Slot allocator shape | `internal/network/tap` pool/host split | pattern reused for netns FSM |
| Cleanup-on-error pattern | FC driver deferred-committed-flag LIFO | required pattern for driver Create |
| Latch pattern | `EnsureLayer4Ready` | reused for netrules `EnsureChain` |
| Adoption identity | store `container_id` column | reused; + new `engine` column |
| Pull dedup | docker client single-flight | pattern ported |
| Fake-daemon test harness | `poolFakeDaemon` (`docker_pool_test.go`) | pattern ported to fake containerd API |
| Push/pull seams | `SnapshotPushDocker` etc. narrow interfaces | reused — containerd impls |
| Bridge/IPAM/NAT | — (nothing in the repo does NAT today) | CNI plugins, NOT bespoke |

## 11. NOT in scope (considered and deferred)

- **stargz/SOCI lazy pull + crun** — containerd-only upside doors;
  separate follow-ups this plan unlocks (§7.5).
- **Kata containers** — free option value via runtime handlers; explicitly
  unscoped (§9.3).
- **Placement-aware engine routing** — observability tag only (cross-model
  D18); placement/FSM is fragile-area code and the need is
  migration-transient.
- **Migrating moby-namespace artifacts to aerolvm** — documented re-pull
  cost instead (§7.9); a content-store migration tool is not worth
  building for a one-way transition.
- **dockerd path removal** — retained indefinitely for operators who want
  stock Docker hosts (§6 Phase 5).
- **IPv6 on the sandbox bridge** — the dockerd path doesn't offer it
  today; parity is IPv4; revisit post-flip if requested.
- **Firecracker/WASM runtimes** — untouched; their drivers don't route
  through the container-engine seam.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 2 | ISSUES ABSORBED (outside voice) | 12 findings; 5 promoted to cross-model decisions (D15-D19), rest overlapped review findings |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 3 | CLEAR (PLAN) | 14 issues (9 review + 5 cross-model), 0 critical gaps remaining, all folded into plan |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CODEX:** outside voice ran on this plan (2026-07-12): engine-ownership column,
  dockerd seam relocation, snapshot/template scope, canary visibility, Phase 0
  hardening — all five accepted and folded (D15-D19); stale direct-netlink text
  removed with the D5 CNI rebase.
- **CROSS-MODEL:** review found the networking/security blind spots (§4 parity
  inventory, seccomp envelope, netns FSM); Codex found the wiring/state-model
  blind spots (engine column, EventsSource seam, snapshots) — complementary,
  zero contradictions after D18 settled tag-vs-routing.
- **VERDICT:** ENG CLEARED — ready to implement (Phase 0 first; scope decisions
  D5 + 1A-9A + D15-D19 are settled, do not re-litigate).

NO UNRESOLVED DECISIONS
