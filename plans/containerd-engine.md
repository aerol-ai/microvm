# containerd engine: dropping the dockerd tax (cold 274ms → ~110ms, warm 43ms → ~20ms)

Status: **proposed (not started)** (written 2026-07-11). Companion to
`plans/warm-create-latency-tier1.md` (which stays fully valid — every Tier 1
phase applies under either engine) and successor-in-spirit to
`plans/docker-warm-pool.md` §10's "containerd work out of scope" note.
This plan brings it in scope, with measured justification.

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

Projected results (Tier 1 assumed landed; see §8 for gates):

| Metric | today (dockerd) | dockerd + Tier 1 | containerd + Tier 1 |
|---|---|---|---|
| Cold create p50 | 274ms | ~260ms | **~100-120ms** |
| Warm hit p50 (cluster) | 43ms | ~30ms | **~18-20ms** |
| Warm hit (single-node) | ~30ms | ~20ms | **~8-10ms** |
| p99 (miss ⇒ cold fallback) | 377ms | ~350ms | **~130-150ms** |

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
(the seam built for exactly this). Zero API, SDK, facade, or store changes;
`models.ResolveOCIRuntime` keeps mapping `gvisor` → runsc, it just resolves
to a containerd runtime handler instead of a `HostConfig.Runtime` field.

Both engines coexist on one host during rollout: dockerd already runs on
the system containerd (namespace `moby`); the driver uses the same
containerd through its own namespace (`aerolvm`). A node migrates by
flipping the env var and letting existing dockerd sandboxes drain —
sandboxes are ephemeral and rolling node replacement is the established
ops pattern anyway.

## 3. What ports, what's reimplemented, what disappears

**Ports unchanged (engine-agnostic):** netrules manager (host iptables —
but see §4 for the chain), caddy routing, toolboxd + readiness socket
(bind mounts work identically), warm-pool state machine
(`internal/pool/dockerpool` — keyed on image+runtime, engine-neutral),
admission, store, mounts, secrets, SSH gateway, the whole service layer.

**Reimplemented against containerd gRPC:**
- Task lifecycle: create/start/stop/destroy/inspect — the measured ~75ms
  path. Bind mounts, resource limits (runc cgroup options replace
  dockerd's `Resources` update — the warm-adopt no-op-update optimization
  carries over), env, user.
- Image service: pull with the existing single-flight dedup pattern,
  lease-based GC (cleaner than the current TTL sweep — leases pin images
  in use by definition), registry auth, and the mirror config
  (`registry-mirrors` in daemon.json becomes a `hosts.toml` per registry).
- Events: containerd's events API replaces the `/events` stream; the
  die-event reconcile hook is a straight port.
- Build/tag flows: `docker build` compatibility requires BuildKit
  (buildkitd speaks containerd natively). Scoped as its own phase — the
  built-image namespace and tag flush hooks port onto it.

**Disappears:** the rename (§1), the pause-container netns hack (§4), the
image-ID cache's reason to exist may shrink (containerd image resolution
is a local metadata read, not a ~45ms engine round-trip — re-measure
before keeping the cache).

**Daemon-restart survivability:** containerd shims are detached processes;
tasks survive daemon restarts natively — this *replaces* the
`live-restore: true` behavior we depend on in daemon.json, it doesn't
lose it.

## 4. Networking ownership

The one genuinely new responsibility. dockerd's libnetwork gave us bridge,
veth, IPAM, and the `DOCKER-USER` chain; the netns pool already bypasses
the per-create cost with pause containers, so we are close to owning this
anyway.

- **Bridge + IPAM:** own bridge (`aerolvm0`) + host-local IPAM, either via
  the CNI bridge plugin or directly (the `internal/network/tap` allocator
  is precedent for direct netlink management; the netns pool's slot
  bookkeeping is precedent for the pool shape). Recommendation: direct
  netlink, matching the tap allocator's idempotent Ensure/Remove style —
  CNI's plugin/exec model reintroduces the exec cost Tier 1 Phase 1
  removes.
- **netns pool goes native:** create network namespaces directly — no
  pause containers, no `NetworkMode: container:<id>` adoption. Cheaper
  slots, and the shape extends to gVisor (§5), which the pause-container
  hack cannot.
- **`DOCKER-USER` chain:** created by dockerd; hardcoded 15× in
  `pkg/docker/netrules/manager.go`. The driver installs its own chain
  (`AEROLVM-USER`) with the same FORWARD-jump position, and the manager
  takes the chain name as a parameter. Tier 1 Phase 1 (netlink backend)
  should land with the chain parameterized so the two plans compose.

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
`StorageOpt` disk quota. The three guard branches in
`pkg/docker/client.go` port to the driver as-is.

**What improves:**
- Per-container runtime handlers (`WithRuntime("io.containerd.runsc.v1")`)
  replace the daemon.json runtime registration — cleaner selection, and
  runc/runsc sandboxes mix freely on one node as they do today.
- **The netns prepay trick becomes available to gVisor for the first
  time.** Today `docker_netns` is gated to the plain docker runtime
  because joining a foreign pause-container netns is not a supported
  runsc shape. Under containerd the driver creates the netns + veth and
  hands it to the shim at create — runsc's netstack attaches to the veth
  inside it. That is literally the GKE flow. gVisor colds get the same
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
- Config plumbing: runsc flags move from daemon.json to containerd
  `config.toml` runtime options + a runsc config — install.sh, Ansible,
  and bootstrap all touch.
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

- **Phase 0 — measure & spike.** (a) Bench topology variant with
  `with_gvisor=true`: measure docker+runsc cold/warm today (Sentry boot,
  park-slot viability) so gVisor gains are projected from data, not
  estimates. (b) gRPC driver spike: create/start/destroy against the
  system containerd in an `aerolvm` namespace, confirming the ~75-80ms
  engine-side number holds via API (no `ctr`). (c) Decide direct-netlink
  vs CNI (recommendation in §4). Exit: measured runsc table + spike
  numbers within 15% of §1 projections.
- **Phase 1 — core driver.** `internal/runtime/containerd/` implementing
  `ContainerRuntime`: task lifecycle, image pull + dedup, bind mounts,
  resource limits, events→reconcile, readiness socket, registry mirror.
  Table-driven tests against a fake containerd API (the `poolFakeDaemon`
  pattern from `docker_pool_test.go`).
- **Phase 2 — networking.** Bridge + IPAM + native netns pool +
  `AEROLVM-USER` chain; netrules chain parameterization (coordinate with
  Tier 1 Phase 1). Regression tests at the tap-allocator standard —
  this is a new fragile allocator and gets the same treatment.
- **Phase 3 — warm pool + park/adopt.** Rename-free adoption (store
  mapping + label), park spawn via the driver, lease-based image GC,
  re-measure whether the image-ID cache still pays for itself. BuildKit
  for build/tag flows (can trail the rest of Phase 3).
- **Phase 4 — gVisor.** Shim config + runsc options plumbing, guard
  ports, netns prepay for runsc, the doubled test matrix from §5. Gated
  on Phase 0's measured baseline.
- **Phase 5 — ops & rollout.** install.sh/Ansible/Terraform engine
  toggle, packaging, integration bench scenario for the containerd
  topology, runbook updates. Default flip is a separate release after a
  full-suite soak; dockerd path is retained indefinitely for operators
  who want stock Docker on their hosts.

## 7. Risks & parity items

1. **Disk quota (`DiskGB`).** dockerd's `StorageOpt size` needs
   xfs+pquota backing; the containerd overlayfs snapshotter has its own
   quota story. Parity must be verified on our actual filesystem layout —
   and while we're there, verify what dockerd is *actually* enforcing
   today (gVisor already ignores it silently; runc on non-xfs may too).
2. **New fragile surface.** A second engine implementation doubles where
   container-lifecycle bugs can live. Mitigation: ship dark, same
   Server-Timing stages so benches compare engines like-for-like, and the
   integration suite runs the same UC scenarios against both topologies.
3. **BuildKit is a new daemon dependency** for build flows only — degrade
   gracefully (build endpoints return a clear error on containerd hosts
   without buildkitd rather than blocking the engine flip).
4. **Snapshotter future** (upside risk): stargz/SOCI lazy pull could turn
   the 4-6s first-pull tail into sub-second starts; crun could shave
   ~20-30ms off task start. Both are containerd-only doors — out of scope
   here, noted as follow-ups this plan unlocks.

## 8. Exit gates (default-flip criteria)

| Gate | Threshold |
|---|---|
| Cold create p50 (standard bench topology, runc) | ≤ 130ms |
| Warm hit p50 (cluster, with Tier 1) | ≤ 22ms |
| p99 (docker row, full bench) | ≤ 180ms |
| gVisor cold p50 vs docker+runsc baseline | ≥ 100ms improvement |
| Full integration suite on containerd topology | green, incl. UC-96* socket attribution |
| Orphan/stale counters after bench + reconcile | 0 |
| Coverage: `internal/runtime/containerd/` + networking pkg | ≥ 85% |

## 9. Open questions

1. Dedicated containerd instance vs shared system containerd with our own
   namespace? (Shared is simpler and how dockerd already coexists;
   dedicated isolates upgrade cadence. Lean shared until proven painful.)
2. Exec surface: toolboxd owns in-sandbox exec, but reconcile/debug paths
   may use engine exec — audit actual usage before scoping the driver's
   exec support.
3. Does the image-ID cache (and its Tier 1 refill-warming rider) survive
   Phase 3, given containerd image resolution is a local metadata read?
   Keep both until measured.
4. Kata: `ResolveOCIRuntime` reserves the name. containerd's runtime
   handlers make a kata shim (`io.containerd.kata.v2`) the same shape as
   runsc — free option value, explicitly not scoped here.
