# Native Firecracker with Snapshot-Clone Fast Boot

## What this plan is

A commitment to add **native Firecracker** as a **second, opt-in
runtime** alongside the existing Docker-based runtime (runc and
gVisor), and to deliver the snapshot-clone fast-boot property as a
first-class product capability for sandboxes that select it.

Target on the Firecracker path: <100ms end-to-end sandbox creation
from snapshot clones, <20MB marginal memory per sandbox via CoW page
sharing.

## This is additive, not a replacement

**The existing Docker ecosystem stays untouched.** Every sandbox that
runs on Docker today continues to run on Docker exactly as it does
today. The new Firecracker runtime is selected per-sandbox via the
existing `Runtime` field on `CreateSandboxRequest`. The dispatch is
trivial — one branch in `CreateSandbox`:

```
req.Runtime           →   Path
─────────────────────────────────────────────────────────
"" (host default)     →   Docker (today's behavior)
"docker"              →   Docker + runc
"gvisor"              →   Docker + runsc
"firecracker" (new)   →   Native Firecracker, snapshot-clone path
"kata" (reserved)     →   still ErrRuntimeNotImplemented
```

This means:

- **No code on the Docker path changes.** `pkg/docker/`,
  `pkg/docker/netrules/`, the runc and gVisor handling, the existing
  bridge networking — all of it stays as-is.
- **No customer's existing sandbox behavior changes.** A sandbox
  created without specifying a runtime gets exactly what it gets
  today.
- **The `internal/runtime.Runtime` interface stays unchanged.** It
  was already designed for this — a second implementation lands
  beside the existing Docker driver. The service layer doesn't know
  which one it's talking to.
- **Workloads that don't fit Firecracker (GPU, privileged, unusual
  device passthrough) stay on Docker.** The dispatch isn't a
  migration — it's a fork that customers pick based on workload.
- **Operators run hosts in either mode or both.** A cluster can have
  Docker-only hosts, Firecracker-only hosts, or mixed hosts.
  Placement (`internal/cluster/placement.go`) considers runtime
  capability as a new dimension.

The phrase "we replace X from Docker" later in this document means
*"we build the same capability on the Firecracker side of the fork,"*
not *"we remove X from the Docker side."* The Docker side keeps using
Docker for that capability.

## Why native Firecracker, not Kata-with-Firecracker

Two paths use Firecracker as the hypervisor. They are different things
and only one of them delivers the property we want:

- **Kata-with-Firecracker.** Kata Containers configured with
  `hypervisor = "firecracker"`. Goes through containerd → Kata shim →
  Firecracker. Gives us the VM isolation boundary, but the Kata shim
  abstracts away the Firecracker snapshot API. We don't get
  first-class control over the snapshot/resume primitive, which is
  the entire point of this plan.
- **Native Firecracker.** What this plan describes. `sandboxd` talks
  directly to the Firecracker REST API over a Unix socket. We own
  VMM lifecycle, snapshot/restore, and the CoW page-sharing
  primitive. This is the AWS Lambda / Fly Machines / CubeSandbox
  architecture.

`RuntimeKata` stays reserved for the Kata-with-something path —
that's a separate future runtime option, not what we're building
here. The constant we add is `RuntimeFirecracker`.

## What this buys us, on the new path

For sandboxes that opt into `RuntimeFirecracker`:

- **Docker leaves the TCB for that sandbox.** No dockerd process
  involved in its lifecycle, no Docker socket, no image-format CVE
  surface. The sandbox is supervised by `sandboxd` and a Firecracker
  VMM. Nothing else.
- **Snapshot/restore is first-class.** Hypervisor-level, not
  container-level. The trust boundary is the VCPU, not the host
  kernel.
- **CoW page sharing.** A hundred Firecracker sandboxes from the
  same template share the template's physical pages. Per-sandbox
  RSS is the delta, not the nominal guest RAM.
- **<100ms cold starts.** Because we're not booting a VM — we're
  memory-mapping the snapshot of one and resuming it.

This is the same architectural bet AWS Lambda made, the same one
CubeSandbox made, and the same one Fly Machines made. It's a large
build — 6 to 9 months of focused work — but the prize is a tier of
sandboxes that the Docker path fundamentally cannot deliver.

## The core mechanism

A "VM cold start" is mostly the guest kernel and userspace doing real
work, not the hypervisor allocating resources:

1. Hypervisor allocates a VM. (~ms)
2. Virtual firmware initializes virtual hardware. (~tens of ms)
3. Guest kernel boots: decompress, init drivers, mount rootfs, start
   init. (~hundreds of ms)
4. Guest userspace: init, agent, network. (~hundreds of ms)
5. Sandbox reachable.

Snapshot-clone skips steps 2–5. They already happened, once, for a
template VM. Each new sandbox:

1. Allocate a TAP device + IP from pre-warmed pool. (~hundreds of μs)
2. Spawn (or grab pre-warmed) Firecracker VMM. (~ms)
3. `PUT /snapshot/load` against the template's memory + state files.
   (~ms — the memory file is mmap'd, not read.)
4. Resume the VCPU. (~ms)
5. Confirm agent reachable via vsock handshake. (~ms)

Total wall-clock target: 60–100ms. Achievable because:

- **mmap is constant-time.** A 512MB snapshot file is "loaded" in
  microseconds. Pages fault in lazily as the guest touches them.
- **CoW makes pages shared until written.** A sandbox that just runs
  `print("hello")` touches maybe a few MB of the snapshot. The rest
  costs no physical RAM.
- **The agent is already running** inside the snapshotted guest. It
  was accepting connections when the snapshot was taken; it
  immediately accepts them on resume.

## 15 use cases first

The target shape is "sandbox creation is fast enough and dense enough
that latency and host capacity disappear from the product story."

### 1. Per-request agent invocation

| # | Use case | Why fast-clone matters | Symptom without it |
|---:|---|---|---|
| 1 | LangChain-style agent that spawns a fresh sandbox per tool call | Boot tax compounds over a 30-step agent loop; fast-clone makes per-step sandboxes invisible. | Agent loops feel sluggish; users blame the LLM when sandbox boot is the bottleneck. |
| 2 | Stateless code-execution API behind a public endpoint | Customers expect "submit code, get result" to feel like a function call. | p99 latency dominated by sandbox creation; the actual code runs in ms. |
| 3 | Agent that branches sandboxes to explore alternative tool paths | Fan-out cost = boot cost × N; fast-clone makes "try 5 alternatives in parallel" viable. | Agents avoid branching because each branch costs a second; reasoning quality drops. |

### 2. Eval and RL workloads

| # | Use case | Why fast-clone matters | Symptom without it |
|---:|---|---|---|
| 4 | SWE-Bench-style eval running thousands of patches in parallel | Eval wall-clock dominated by sandbox spawn when tasks are short. | 2000-task eval takes hours instead of minutes; model iteration speed drops. |
| 5 | RL training loop that scores each rollout in a fresh sandbox | Rollout cost = boot + execution; if boot >> execution the loop is sandbox-bound. | Training step time is gated by sandbox boot, not by the model. |
| 6 | Adversarial fuzzer that needs a clean sandbox per input | Throughput = `1 / (boot + run)`; for short inputs, boot dominates. | Fuzzing throughput is an order of magnitude below what the eval host could sustain. |

### 3. Interactive notebook / IDE workloads

| # | Use case | Why fast-clone matters | Symptom without it |
|---:|---|---|---|
| 7 | "New notebook" button in a notebook product | Users expect a notebook in well under a second, like opening a tab. | Create-notebook feels like a deploy; users learn to wait. |
| 8 | Inline code-execution chip in a chat UI | The chat UX promises "you can run code"; the sandbox should be invisible. | First run in a session has a noticeable pause; users adjust expectations down. |
| 9 | Live-collab pair-programming sandbox per session | Sessions should feel like joining a room, not building one. | Session-start friction kills throwaway usage that should be cheap. |

### 4. Sandbox-per-test / per-build / per-PR workloads

| # | Use case | Why fast-clone matters | Symptom without it |
|---:|---|---|---|
| 10 | Sandbox-per-test in a CI matrix with thousands of tiny tests | Test cost dominated by sandbox boot for small tests. | CI throttled by sandbox provisioning, not test execution. |
| 11 | PR preview that boots on every push | Preview freshness is a product feature; perceived freshness = boot speed. | Preview links feel stale because they're slow to come up; reviewers stop using them. |
| 12 | Snapshot-on-failure for flaky-test diagnosis | If snapshotting is cheap, every failure can keep its state for inspection. | Snapshots are too expensive to keep around; users lose evidence. |

### 5. High-density multi-tenant surfaces

| # | Use case | Why fast-clone + CoW matter | Symptom without it |
|---:|---|---|---|
| 13 | Multi-tenant SaaS where each customer gets a sandbox on first request | First-touch latency dominates; CoW lets us keep many warm tenants per host. | First-time customers churn at first-touch; density per host caps tenant economics. |
| 14 | Serverless HTTP wake (`plans/serverless-sandbox-http-wake.md`) extended to *create* on wake | With fast-clone, wake-on-HTTP can mint a fresh sandbox just-in-time instead of starting a stopped one. | Wake latency floor is full Kata boot; the "serverless" promise breaks at high spawn rates. |
| 15 | Free-tier sandboxes that GC aggressively and need to come back fast | If creation is cheap, GC is cheap; users don't notice their sandbox was reclaimed. | Free-tier UX degrades in proportion to creation cost; conversion to paid tier suffers. |

## What we replace from Docker, piece by piece

This is the part that's easy to underestimate. Docker isn't just
"start a container" — it's a stack of features. Going direct means
owning each of them. The table is the build inventory.

| Capability Docker gives today | Our replacement under native Firecracker | Where it lands in the repo |
|---|---|---|
| Image pull + storage | `containerd`'s content store as a library (no daemon) **or** `skopeo` + `umoci` to convert OCI → ext4 | `pkg/oci/` (new) |
| Image → rootfs conversion | Mount each layer's contents into a thin ext4 file built per template; we keep one image per template, no live layering | `internal/templates/` (new) |
| Container lifecycle | One Firecracker VMM process per sandbox, supervised by `sandboxd` | `internal/runtime/firecracker/` (new) |
| `docker exec` | Vsock channel from `sandboxd` to in-VM toolbox agent | `cmd/toolboxd/` (extended) |
| `/events` stream | Process supervision: we own the VMM process group; exit is observable directly | `internal/runtime/firecracker/supervisor.go` (new) |
| Bind mounts | virtio-fs for shared directories; virtio-block for per-sandbox writable overlays | `internal/runtime/firecracker/devices.go` (new) |
| Bridge networking | Per-sandbox TAP device + Linux bridge or routed L3 + iptables egress rules | `internal/network/tap/` (new) |
| Image GC | Template GC (drop unused templates and their snapshots), overlay GC (drop dead-sandbox overlays) | `internal/service/template_gc.go` (new) |
| Seccomp / AppArmor / caps | Firecracker's `jailer` for the VMM process; in-guest policy is the guest kernel's problem | `internal/runtime/firecracker/jailer.go` (new) |
| Cgroups | `jailer` handles VMM cgroups; per-sandbox resource limits go to Firecracker's `machine-config` | Same |
| StorageOpt / disk quota | Thin-provisioned overlay file per sandbox with a hard size cap | `internal/runtime/firecracker/devices.go` |

The header insight: **once Firecracker is our runtime, Docker's
features are unbundled.** Most of them are smaller than they look —
we're not rebuilding "Docker" but the subset of it we actually use.

## The four hard pieces

### Piece 1 — The Firecracker runtime driver

Implements the existing `internal/runtime/runtime.go` interface against
Firecracker's REST API. The interface stays unchanged; the
implementation is entirely new code. The runtime is per-process: each
sandbox is its own `firecracker` binary, supervised by `sandboxd`.

Key sub-pieces:

- **VMM lifecycle.** Spawn a `firecracker` process under `jailer`,
  point it at a unique API socket under `/run/sandboxd/<sandbox-id>/`,
  configure it via `PUT /machine-config`, `PUT /boot-source`,
  `PUT /drives/...`, `PUT /network-interfaces/...`, then
  `PUT /actions { action_type: "InstanceStart" }`. For snapshot
  resumes: `PUT /snapshot/load` instead of the boot-source +
  InstanceStart pair.
- **Agent channel.** Use **vsock** (virtio-vsock device) between host
  and guest for the toolbox channel. Vsock survives snapshot/resume
  cleanly (it's a hypervisor-managed device, not a TCP socket with
  external state).
- **Process supervision.** When the VMM process exits unexpectedly,
  surface it to the service layer the same way Docker's `/events`
  stream does today. The supervisor goroutine pattern in
  `pkg/docker/events.go` is the model; we just watch process
  signals instead of an HTTP stream.

Effort: **6–8 weeks** for a Firecracker driver good enough to replace
Docker for a single sandbox lifecycle, no snapshots yet. This is the
foundation — everything else builds on it.

### Piece 2 — The image and template pipeline

Two distinct steps:

**Image → rootfs.** Take a user-provided OCI image, pull it without
Docker, flatten its layers into an ext4 image file. Tools that exist:
`skopeo copy` + `umoci unpack` + `mkfs.ext4 -d <dir>`. Each step is a
subprocess call. The output is a single rootfs file that Firecracker
can attach as a block device.

**Rootfs → template snapshot.** Boot a Firecracker VM with the rootfs
and our kernel, wait for the toolbox agent to be reachable, issue
`PUT /snapshot/create`, store the resulting memory + device-state
files alongside the rootfs in the template store. Mark template
`READY`.

A template is a tuple of artifacts on disk:

```
templates/<template-id>/
  kernel                    # vmlinux we ship (small custom kernel)
  rootfs.ext4              # the base image, read-only at runtime
  snapshot.memory          # mmap'd into each clone's guest RAM
  snapshot.state           # VCPU regs, virtio queue state
  manifest.json            # source image, agent port, validity, checksums
```

Store-side: a new `templates` table in `internal/store/store.go`. For
cluster mode, replicate template artifacts via the existing image
distribution path in `internal/service/image_distribution.go` — same
content-addressed model, different blob types.

Effort: **4–6 weeks**. Most of the time is in the boring parts —
handling images that don't boot cleanly as a VM rootfs (anything
expecting systemd init when we want a stripped init), getting the
kernel command line right, getting the agent to come up identically
every time so the snapshot is deterministic.

### Piece 3 — The snapshot-clone create path

When a sandbox is requested with a `TemplateID`:

1. Allocate a sandbox ID, a TAP device + IP from the network pool, a
   per-sandbox writable overlay file (small ext4 image,
   thin-provisioned).
2. Pull a VMM from the warm pool (Piece 4) or spawn a fresh one.
3. Configure the VMM with the new TAP and overlay (as a second drive
   above the read-only template rootfs).
4. `PUT /snapshot/load { mem_file_path: ".../snapshot.memory",
   snapshot_path: ".../snapshot.state", enable_diff_snapshots: true,
   resume_vm: true }`.
5. Confirm agent reachable over vsock — single handshake.
6. Write the sandbox row to the store, attach caddy routes, return the
   URL.

The critical Firecracker flag is `enable_diff_snapshots: true` on
load. It tells Firecracker to keep the template's memory file as the
base and write CoW diffs into a per-VM dirty bitmap, rather than
copying the memory file. This is what gives us the <5MB-per-sandbox
property.

Wall-clock target: **150–300ms without the pool, 60–100ms with it.**

Effort: **3–4 weeks** assuming Pieces 1 and 2 are solid. The hard
parts are operational, not API-level — handling resume failures,
detecting snapshot corruption, getting the network wiring done before
the guest's first packet.

### Piece 4 — The VMM pool

A warm-VMM pool is what closes the gap between "snapshot-clone is
fast" and "snapshot-clone is *instant*."

Per host, per template, keep `N` Firecracker VMM processes
pre-spawned, configured, and **paused immediately after
`PUT /snapshot/load`** — that is, ready to resume but not yet running
guest code. On a sandbox request, the orchestrator grabs one, attaches
the per-request TAP and overlay, calls
`PUT /actions { action_type: "Resume" }`, and triggers the pool to
refill in the background.

The state machine for pool entries:

```
Spawning → Loaded (paused, no TAP/overlay attached) → Allocated → Running
                                                          ↓
                                                       Released
                                                          ↓
                                                      [destroyed,
                                                       pool refill triggers]
```

Pool design follows the host-port pool in
`pkg/docker/netrules/` and `internal/store/store.go` — a SQLite table
with a partial unique index, single-flight allocator, periodic refill
loop. Touching this table follows the same rules as the TCP host-port
pool: regression test required, PR call-out required (see
`pr-review.md` §5).

Effort: **3–4 weeks**, plus follow-on tuning of refill rate, pool
depth per template, and admission rules.

## Operational concerns that bite

Eight things that will absolutely come up. Each one is a small fire if
not designed in.

1. **Guest time on resume.** Restored guest thinks it's whenever the
   snapshot was taken. Firecracker has a wallclock device; enable it.
   Toolbox agent must re-sync time on resume (call `clock_gettime` and
   compare to the host time it gets over vsock).

2. **Entropy reuse across clones.** Snapshot includes the kernel's
   entropy pool state. Two clones share entropy at resume. Add a
   virtio-rng device to the VM config; the kernel reseeds from it on
   resume. The agent should also call
   `getrandom(GRND_INSECURE)` once to force a reseed before serving
   any client.

3. **Network identity.** Each clone has its own TAP and IP. The guest
   learns its IP via DHCP from a tiny DHCP responder we run on the
   host side of the TAP, **or** via a virtio-config-block we populate
   per clone. The latter is the CubeSandbox pattern and avoids a DHCP
   round-trip.

4. **Disk identity.** The rootfs is read-only across clones. Each
   clone gets a per-sandbox writable overlay as a second virtio-block
   device. The guest mounts it at boot (already done in the template),
   so on resume it's already mounted; we just need to swap the host
   backing file between clones.

5. **Memory overcommit accounting.** Hundred sandboxes × 512MB
   nominal = 51.2GB advertised, but real RSS is the sum of CoW
   deltas. Admission has to use real RSS, not nominal. New axis in
   `pkg/capacity/`:
   `EffectiveMemoryAvailable = HostMem - sum(actual RSS per VMM)`.
   Refuse new creates when this drops below a watermark; refuse
   *aggressively* because RSS can spike under load.

6. **Snapshot corruption.** Templates can go bad: kernel mismatch,
   partial writes, format changes across Firecracker upgrades.
   Checksum the snapshot files on create; verify on load. On load
   failure, mark template `DEGRADED` and either rebuild it
   automatically (boot a fresh VM, re-snapshot) or refuse creates
   pointing at it.

7. **Agent compatibility across snapshot/resume.** The toolbox agent
   has to survive the cycle. Two hooks needed in `cmd/toolboxd/`:
   - **Pre-snapshot:** drain in-flight requests, close external TCP
     connections, flush any host-time-derived caches. Triggered by a
     vsock command from the host.
   - **Post-resume:** re-sync time, re-derive any sandbox identity that
     was templated (UUIDs, hostnames), re-establish any host-side
     channels.
   This is a real chunk of work. Plan ~2 weeks just for the agent
   side.

8. **Vsock cid allocation.** Each VM needs a unique vsock context ID
   on the host. CIDs are u32. Allocate from a SQLite pool with the
   same pattern as the host-port pool.

## What lands in the repo, by file

Concrete touchpoints, in the order they get hit. New packages marked
(new); existing packages get additions.

| File / package | Change |
|---|---|
| `pkg/models/types.go` | Add `RuntimeFirecracker` constant. Add `TemplateID`, `SnapshotPolicy`, `OverlaySizeGB` fields to `CreateSandboxRequest`. Add `Template` and `TemplateStatus` types. |
| `pkg/firecracker/` (new) | Firecracker REST API client. Thin Go wrapper over the Unix socket. Mirrors `pkg/caddy/client.go` in spirit. |
| `pkg/oci/` (new) | OCI image pull + flatten. Wraps `skopeo` and `umoci` as subprocess calls initially; can be replaced with library code later. |
| `internal/runtime/firecracker/` (new) | Implements `runtime.Runtime` against Firecracker. `vmm.go`, `jailer.go`, `devices.go`, `supervisor.go`, `vsock.go`. |
| `internal/templates/` (new) | Template lifecycle: create from image, snapshot, store, list, GC. |
| `internal/network/tap/` (new) | TAP device allocation, IP allocation, bridge/routed wiring, egress firewall hooks. Replaces what `pkg/docker/netrules/` does today for Firecracker sandboxes. |
| `internal/pool/vmm/` (new) | The warm-VMM pool. Per-template, per-host. SQLite-backed state. |
| `internal/store/store.go` | New tables: `templates`, `vmm_pool`, `vsock_cids`. New columns on `sandboxes`: `template_id`, `overlay_path`, `vsock_cid`, `tap_name`. |
| `internal/service/template.go` (new) | Template service: `CreateTemplate`, `WatchTemplate`, `DeleteTemplate`. |
| `internal/service/service.go` | `CreateSandbox` dispatches to the Firecracker path when `req.Runtime == RuntimeFirecracker` (or when `req.TemplateID != ""`, since templates imply Firecracker). The Docker path stays for non-snapshot workloads. |
| `pkg/api/v1/routes.go` | New routes: `POST /v1/templates`, `GET /v1/templates`, `GET /v1/templates/{id}`, `DELETE /v1/templates/{id}`. |
| `pkg/api/v1/handlers.go` | Handlers that decode → call template service → encode. Thin per the existing pattern. |
| `pkg/capacity/` | New `EffectiveMemoryAvailable` axis. Real-RSS sampling. New admission rules. |
| `cmd/toolboxd/` | Vsock listener as a primary transport. Pre-snapshot / post-resume hooks. Time/entropy re-sync. |
| `cmd/sandboxd/main.go` | Wire the Firecracker runtime alongside Docker. Make the choice config-driven and per-sandbox. |

## Phased build

Each phase is independently shippable. Each one produces a
demonstrable property before the next phase is needed.

### Phase 1 — Single Firecracker VM, no snapshots (6–8 weeks)

Goal: prove we can boot a sandbox in a Firecracker VM with no
Docker in the path, with the toolbox agent reachable over vsock,
and have it pass the same lifecycle tests Docker sandboxes pass
today.

Deliverables:
- `pkg/firecracker/` API client.
- `pkg/oci/` image-to-rootfs converter.
- `internal/runtime/firecracker/` driver, implementing the full
  `runtime.Runtime` interface.
- `internal/network/tap/` basic TAP per VM.
- Vsock-based toolbox channel.
- One-image template (kernel + ext4 rootfs) hardcoded, hand-built.
- Integration test that creates, execs into, and destroys a sandbox
  entirely on the Firecracker path.

Visible property at end of phase: **a sandbox runs on Firecracker
with no Docker process on the host**. Boot time will be ~500ms-1s;
not the win, just the foundation.

### Phase 2 — Template pipeline and image conversion (4–6 weeks)

Goal: users can submit an OCI image and get a `READY` template they
can create sandboxes from. Still no snapshots — templates are just
defined and have their rootfs prepared.

Deliverables:
- Template lifecycle: image pull, layer flatten, ext4 build,
  manifest write.
- `templates` table in the store.
- `/v1/templates` API routes.
- Template GC: drop templates not referenced by any sandbox or VMM
  pool entry for >7 days.

### Phase 3 — Snapshot create and load (4 weeks)

Goal: the template pipeline ends with a snapshot, and sandbox
creation can resume from it instead of booting.

Deliverables:
- `PUT /snapshot/create` integration in the template builder.
- `PUT /snapshot/load` with `enable_diff_snapshots: true` in the
  sandbox creator.
- Snapshot checksums and integrity checks.
- Agent pre-snapshot / post-resume hooks in `cmd/toolboxd/`.
- Per-sandbox overlay (writable ext4 above the read-only template
  rootfs).

Visible property: **boot time drops from ~500ms to ~150–300ms**.
Memory per sandbox drops to the CoW delta. This is the inflection
point — the product story changes here.

### Phase 4 — Warm VMM pool (4 weeks)

Goal: <100ms create latency.

Deliverables:
- `internal/pool/vmm/` pool manager, per-template.
- Pool state machine (Spawning / Loaded / Allocated / Running /
  Released).
- Per-template pool depth config.
- Pool refill background loop.
- Pool metrics (depth, refill latency, miss rate, allocation latency
  p50/p99).

Visible property: **typical create latency is 60–100ms**. Pool depth
becomes an operational knob.

### Phase 5 — Memory overcommit admission (3–4 weeks)

Goal: safely run many sandboxes per host without OOM.

Deliverables:
- Real-RSS sampling per VMM (cheap; `/proc/<pid>/statm` is fine at
  ~1Hz).
- New admission axis in `pkg/capacity/`.
- Per-host RSS budget config.
- Refusal path with a clear `models.ErrCapacityExhausted` shape that
  the API surfaces correctly via `apihttp.WriteStoreAwareError`.
- Tests for the admission curve under bursty creates.

### Phase 6 — Production hardening (4–6 weeks, ongoing)

- Snapshot corruption recovery (rebuild on load failure).
- Cluster-mode replication of templates (use existing image
  distribution path).
- Cross-host template prewarm (templates land on all hosts in a
  cluster before any sandbox using them is scheduled).
- Snapshot rotation (recreate templates periodically to absorb
  kernel/agent updates without rebuilding the source image).
- Metrics, alerts, runbooks.

**Total: roughly 6 to 9 months.** Aggressive but plausible for a
focused two-person team. Slower with one person; faster with three is
unlikely because the pieces have natural sequential dependencies.

## What stays on the Docker path (re-emphasizing)

The Docker ecosystem is untouched. Every existing sandbox shape keeps
working exactly as it does today. Specifically:

- **Default sandboxes** (no runtime specified) keep running under
  runc via Docker.
- **`runtime: "gvisor"` sandboxes** keep running under runsc via
  Docker.
- **GPU workloads** keep running on Docker. Firecracker doesn't do
  GPU passthrough; NVIDIA workloads stay where they work today.
- **Privileged containers** keep running on Docker. Firecracker's
  guest is a VM, not a privileged container; the concept doesn't
  translate.
- **Unusual mounts and device passthrough.** Same reason.
- **Anything that doesn't have a template yet.** Templates are
  opt-in per-image, built ahead of time. A sandbox request that
  doesn't reference a template stays on Docker by default.

Operators who don't want Firecracker can simply never enable it.
The Firecracker driver registers itself only when
`SB_ENABLE_FIRECRACKER=true` (new env var); otherwise `sandboxd`
behaves identically to today.

The dispatch lives in `internal/service/service.go` in
`CreateSandbox`, right after runtime validation. It's one switch
statement and an interface call — adding the case does not perturb
the existing path.

## Cluster-mode integration

`internal/cluster/` is fragile and load-bearing (see CLAUDE.md). Two
considerations:

1. **Placement.** Templates live on specific hosts. The placement
   selector (`internal/cluster/placement.go`) needs to consider
   "does this host have a `READY` template for this request?" alongside
   capacity. Without this, a Firecracker create could land on a host
   that has to build the template from scratch — slow path, defeats
   the win.
2. **Template distribution.** Use the existing content-addressed
   image distribution flow (`internal/service/image_distribution.go`).
   Templates are content-addressed by (rootfs hash, snapshot hash,
   kernel hash). Same primitives, new blob types.

Cluster-mode changes carry the standard tax — regression tests next to
the FSM / placement files, PR call-outs per CLAUDE.md.

## What success looks like

Concrete, measurable properties at end-state:

- **Cold start latency p50 < 100ms, p99 < 200ms** for template-based
  creates with a warm pool.
- **Per-sandbox marginal RSS < 20MB** for typical Python sandboxes
  (CubeSandbox claims <5MB; we'd take 20MB and call it a win).
- **>500 concurrent sandboxes per 64GB host** for stateless workloads
  (compared to ~50–100 today under Docker, gated by per-container
  overhead).
- **No `dockerd` process on hosts running only Firecracker sandboxes.**
  The Docker package and Docker socket are absent from the trust
  boundary for those hosts.
- **Snapshot/resume idempotent under retry.** Same create-request ID
  returns the same sandbox; double-resume of a paused VMM is rejected
  cleanly.

## What to read while building

- **Firecracker snapshot docs:**
  `firecracker-microvm/firecracker/blob/main/docs/snapshotting/snapshot-support.md`
  — the canonical reference for the API and operational gotchas.
- **Firecracker jailer:**
  `firecracker-microvm/firecracker/blob/main/docs/jailer.md`
  — what we use to sandbox the VMM itself.
- **CubeShim source:**
  `/Users/sumansaurabh/Documents/startup-3/opensource-repos/CubeSandbox/CubeShim/shim/src/`
  — production reference for the sandbox / disk / pmem / snapshot data
  model. Rust, but the shape transfers.
- **CubeVS network model:**
  `/Users/sumansaurabh/Documents/startup-3/opensource-repos/CubeSandbox/docs/architecture/network.md`
  — for when we want to replace iptables egress with eBPF (a
  Phase 7+ topic).
- **AWS Lambda SnapStart docs:** the canonical writeup of "what
  happens when you snapshot a running process and clone it" — the
  uniqueness / entropy / network identity concerns are well documented
  there.

## One-page summary

| Question | Answer |
|---|---|
| Is this replacing the Docker ecosystem? | **No.** It's a second, opt-in runtime alongside the existing Docker (runc + gVisor) ecosystem. Both live in the same `sandboxd`. |
| How does a sandbox end up on the new path? | The caller sets `runtime: "firecracker"` on the create request. Otherwise, the existing Docker path is used. |
| What about the existing `RuntimeKata` constant? | Stays reserved for Kata Containers (a future, third option). The new constant is `RuntimeFirecracker` and is distinct from Kata-with-Firecracker. |
| Why not Kata-with-Firecracker? | Kata abstracts the Firecracker snapshot API away. We lose the first-class control over snapshot/resume that makes the fast-clone property work. |
| What changes in existing code? | The `runtime.Runtime` interface stays unchanged. The Docker driver stays unchanged. A second driver lands beside it. One switch in `CreateSandbox` picks between them. |
| What do users on the Docker path notice? | Nothing. Their sandboxes behave exactly as they do today. |
| What do users on the Firecracker path get? | <100ms cold starts via snapshot clone, <20MB per-sandbox RSS via CoW, hypervisor-grade isolation, Docker out of their sandbox's trust boundary. |
| How is it enabled on a host? | `SB_ENABLE_FIRECRACKER=true` env var. Off by default. Hosts that don't enable it run pure Docker, exactly as today. |
| How long to build? | 6–9 months for a focused team, phased so each phase ships a product property. |
| What's the first phase? | One Firecracker VM, no snapshots, end-to-end. Proves the runtime abstraction holds with a second implementation. |
| What's the inflection point? | Phase 3 — snapshot/resume lands. Boot time on the new path drops from ~500ms to ~150–300ms. After Phase 4 (the pool), it's <100ms. |
