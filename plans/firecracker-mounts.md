# Plan: Mounts & platform volumes on Firecracker

Status: **DRAFT — awaiting eng review**
Owner: firecracker runtime + service + mounts
Stacks on: `plans/e2b-volume-mounts.md` (platform volumes, Docker/gvisor today),
`plans/snapshot-clone-fast-boot.md` (the Firecracker driver)

---

## 1. Problem statement

Firecracker sandboxes reject **all** mounts today — external storage (S3/NFS/
SSHFS/rclone) and the new platform volumes alike:

```go
// internal/service/service.go:1296 (createFirecrackerSandbox)
if len(req.Mounts) > 0 {
    // Phase 1 explicitly rejects mounts on the firecracker path
    // rather than silently dropping them. When virtio-fs support
    // lands, this branch becomes a call into a new mount adapter.
    return nil, fmt.Errorf("runtime %q does not yet support mounts ...")
}
```

The Docker path realizes a mount as a **bind-mount** (`HostConfig.Binds`): the
host mount tool produces a host directory, Docker binds it into the container's
mount namespace. Firecracker has no container and no bind seam — it boots a
guest kernel with an **ext4 rootfs on a virtio-block device**. Getting host
(or host-FUSE-mounted) storage into the guest needs a guest-visible device or a
proxy. This plan makes mounts — and therefore platform volumes — work on the
Firecracker runtime.

The translation layer already produces a backend-agnostic `models.MountSpec`
(`pkg/volumes`, `pkg/mounts`), and the driver's `Create` **already receives**
`binds []mounts.ContainerBind` and ignores them — so the seam exists; what's
missing is a guest-side realization.

---

## 2. The hard constraint (read before choosing an approach)

**Upstream Firecracker (the v1.15.1 binary this platform ships — see
`Ansible/README.md` `firecracker_version`) has no virtio-fs device.** Its API
exposes only `PutDrive` (virtio-block), `PutNetworkInterface` (virtio-net),
`PutVsock` (virtio-vsock), balloon, and rng (`pkg/firecracker/client.go`).
virtio-fs was deliberately rejected upstream for the minimal-device-surface
security posture Firecracker is built on.

So "add virtio-fs" is **not** a `PutVirtioFS` call. It means one of:
forking/patching the VMM (a maintained Firecracker fork — a large, ongoing
innovation-token spend), or realizing mounts through a device Firecracker
*does* support. This plan rules out forking the VMM for v1 and builds on the
supported devices.

---

## 3. Approaches considered

### Approach A — vsock-proxied filesystem (host-mediated), **RECOMMENDED**

Realize the mount as a **FUSE filesystem inside the guest whose operations are
proxied over the existing vsock channel** to a host-side handler that reads/
writes the host mount directory (the S3/NFS FUSE mount `pkg/mounts` already
produces).

```
guest:  app → /vol (in-guest FUSE client) ──vsock──▶ host handler → /var/lib/sandboxd/mounts/<id>/<i>/ (S3/NFS FUSE)
```

- **Preserves every platform-volume semantic.** The host directory IS the
  shared S3/NFS mount, so persistence, re-attach-by-name, cross-node source of
  truth, and concurrent sharing all hold exactly as on Docker — the guest is
  just another consumer of the same host mount.
- **Reuses existing infra.** The Firecracker driver already runs a per-sandbox
  vsock UDS for the in-guest toolbox handshake (`PutVsock`, `VsockDialer`). The
  WASM runtime already implements host-mediated file/exec over a channel
  (`internal/runtime/wasm/toolhost/`) — that handler is the template for the
  host side.
- **No VMM fork, no extra block device, no image management.**
- ❌ **Cost: throughput + latency.** Every FS syscall is a vsock round-trip.
  Fine for config/workspace files and code; poor for heavy random IO. Mitigate
  with attribute/dentry caching in the guest FUSE client.
- ❌ **New code: an in-guest FUSE-over-vsock client** (shipped in the guest
  rootfs/toolbox) **+ a host-side FS handler** (extend the wasm toolhost
  pattern). This is the bulk of the work.

### Approach B — virtio-block image-backed volumes

Back each volume with a **raw ext4 image file**; attach it as a non-root drive
via `PutDrive(IsRootDevice:false)`; the guest mounts it.

- ✅ Native block IO — fast, no per-syscall proxy.
- ✅ Small driver change — `PutDrive` already exists; the overlay drive path
  (`driver.go` overlay handling) is the working template.
- ❌ **Breaks the platform-volume model.** An ext4 image is not a live S3/NFS
  share. To keep "shared backend / re-attach on any node" you'd have to sync
  the image to/from S3 around the sandbox lifecycle (download on attach, upload
  on detach) — slow for large volumes, and racy.
- ❌ **No concurrent sharing.** A read-write block device cannot be safely
  mounted by two VMs at once — kills the shared-volume use case (UC-83).
- ❌ A different storage backend from Docker/gvisor volumes → two code paths,
  two consistency models, two operator stories.

### Approach C — fork/patch Firecracker for virtio-fs

Maintain a Firecracker fork (or out-of-tree virtiofsd integration) exposing a
`virtio-fs` device, run `virtiofsd` per sandbox sharing the host mount dir.

- ✅ Near-native shared-FS performance, preserves all semantics.
- ❌ **Maintained VMM fork** — security review burden, rebase tax on every
  Firecracker release, jailer/seccomp integration for `virtiofsd`. A very large
  innovation-token spend for one feature. Out of scope for v1; revisit only if
  IO performance on Approach A proves blocking at scale.

### Recommendation

**Approach A (vsock-proxied FS).** It is the only option that keeps Firecracker
volumes behaviorally identical to Docker/gvisor volumes (shared S3/NFS backend,
re-attach by name, concurrent sharing, cross-node correctness) without forking
the VMM. Accept the IO-throughput tradeoff for v1 and document it; Approach C is
the escape hatch if a workload needs native FS performance. **This is the
load-bearing decision — confirm in eng review before building (§8 Q1).**

---

## 4. Architecture (Approach A)

```
                    create (runtime=firecracker, req.Mounts present)
                                   │
  service: DROP the §1296 reject ──┤  keep the runtime gate for UNSUPPORTED
                                   │  mount types if any; pass binds through
                                   ▼
  mounts.MountAll(ctx, id, req.Mounts)         ← run on the firecracker path too
        └─ host S3/NFS FUSE mount at /var/lib/sandboxd/mounts/<id>/<i>/
                                   │  []ContainerBind  (HostPath, ContainerPath, RO)
                                   ▼
  firecracker driver.Create(... binds)         ← already in the signature
        ├─ per bind: register {ContainerPath → HostPath, RO} with the host FS handler
        ├─ ensure the in-guest FUSE-over-vsock client is told to mount each
        │  ContainerPath (via the existing toolbox vsock control channel)
        ▼
  guest: in-guest FUSE client mounts /vol; every op → vsock → host handler → HostPath
```

Boot ordering: mounts are established on the host (`MountAll`) **before**
`InstanceStart`, same as Docker. The guest mounts arrive once the toolbox vsock
handshake completes (the driver already waits for that — `driver.go` step 6).

Snapshot/resume: the host FUSE mount is re-established by `Reestablish` on
start/reconcile (already true). The in-guest FUSE client must re-mount after a
snapshot resume — wire it into the existing `post_resume` vsock signal
(`PostResumeTimeout`, `driver.go`).

---

## 5. Files to modify

### 5.1 Service
- **`internal/service/service.go`** — in `createFirecrackerSandbox`, replace the
  blanket `len(req.Mounts) > 0` reject with: run `mounts.MountAll` (as the
  docker path does) and pass the resulting binds to `driver.Create`. Keep
  rejecting any mount **type** the guest FS handler can't serve yet, if any.
  **Read `pr-review.md` — this touches a create boot path.**
- Platform-volume runtime gate (`internal/service/platform_volumes.go`): drop
  `RuntimeFirecracker` from `ErrPlatformVolumesUnsupportedRuntime` once the
  driver path lands (keep wasm rejected). The synthesized `MountSpec` flows
  unchanged — `pkg/volumes` needs **no change**.

### 5.2 Firecracker driver
- **`internal/runtime/firecracker/driver.go`** — consume the `binds` arg in
  `Create` (and the resume path): register each bind with the host FS handler
  and instruct the guest to mount it over the toolbox vsock control channel.
- **`internal/runtime/firecracker/fshost/`** (new) — host-side FS handler that
  serves FUSE ops against the registered `HostPath` for a sandbox, scoped so a
  guest can only reach its own binds. Model on
  `internal/runtime/wasm/toolhost/`.

### 5.3 Guest agent
- **`cmd/toolboxd/`** (the in-guest agent) — add the **FUSE-over-vsock client**:
  mount each requested `ContainerPath`, translate VFS ops to vsock RPCs, honor
  read-only. This is the largest new component and ships in the guest rootfs /
  toolbox image, so it must build for the guest arch.

### 5.4 Protocol
- **`pkg/firecracker/` or a new `pkg/fsproto/`** — the vsock FS RPC wire format
  (lookup/getattr/open/read/write/readdir/release + error mapping). Keep it
  small and versioned; reuse vsock framing already used for the toolbox channel.

### 5.5 Docs
- **`docs/src/content/docs/platform-volumes.mdx`** — once it lands, update the
  "supported on docker/gvisor only" note to include firecracker, and document
  the IO-performance characteristic.
- **`docs/src/content/docs/external-storage.mdx`** — same runtime-support note.

---

## 6. Phasing

- **Phase 0 — spike (de-risk the recommendation).** Prove a single read-only
  bind served over vsock FUSE into a Firecracker guest: `cat /vol/file` works.
  Measure round-trip latency + sequential read throughput. If unacceptably slow
  for the target workloads, stop and reconsider Approach C. *Gate the rest of
  the plan on this.*
- **Phase 1 — read-write single bind.** Full FS op set, read-only honored,
  per-sandbox isolation, established before `InstanceStart`, torn down on
  destroy. Platform volumes + external mounts both ride it on cold boot.
- **Phase 2 — snapshot/resume.** Re-mount in-guest after `post_resume`; reconcile
  re-establishes host + guest mounts after daemon restart.
- **Phase 3 — hardening + perf.** Guest-side attr/dentry caching, concurrency
  limits, large-file behavior, fault injection (host mount drops mid-op).

---

## 7. pr-review.md axes (pre-filled)

1. **Idempotency.** Re-create / retry converges; binds are derived
   deterministically from `req.Mounts`. ✅
2. **Boot-path latency.** Adds `MountAll` (host FUSE mount) + guest FUSE-mount
   handshake to the firecracker boot path. The host mount cost already exists on
   Docker; the new cost is the guest mount RPC. **Must be measured (Phase 0) and
   called out** — Firecracker's whole value is fast boot. ⚠️
3. **Lazy bootstrap.** The host FS handler is a per-sandbox goroutine started on
   first bind; no global latch.
4. **Failure-path consistency.** A failed guest mount must roll back the host
   `MountAll` (mirror the docker cleanup) and fail the create, not boot a VM
   with a missing volume.
5. **TCP host-port pool & L4.** Untouched. ✅
6. **Cluster.** Volumes stay shared-storage-backed, so cross-node correctness is
   unchanged; no FSM/placement change. ✅
- **Security.** The host FS handler is the new trust boundary: a guest must
  reach **only** its own registered binds, never another sandbox's host paths or
  the broader host FS. Path-scope every RPC to the sandbox's bind set; deny
  symlink/`..` escape. Operator creds never enter the guest (the FUSE mount runs
  on the host; the guest sees a filesystem, not credentials) — same property as
  Docker today. This handler needs the same threat-model rigor as
  `pkg/mounts` (see `pr-review.md` §5) plus the WASM toolhost's tenant scoping.

---

## 8. Open questions for review

1. **Approach A vs B vs C** — confirm the recommended vsock-proxied FS over
   block-image or a VMM fork. This decides everything downstream. (Plan leans A.)
2. **Reuse vs new vsock channel** — multiplex FS RPCs on the existing toolbox
   vsock connection, or open a second vsock port for FS traffic (isolates
   throughput, avoids head-of-line blocking against control RPCs)? (Lean:
   separate port.)
3. **In-guest FUSE client: build vs library** — use a Go FUSE library
   (`hanwen/go-fuse`) in `toolboxd`, or a minimal hand-rolled client? Library is
   faster to build but adds a guest dependency + attack surface. (Lean: library
   behind a thin interface.)
4. **Performance bar** — what sequential read MB/s and metadata-op latency make
   Phase 0 a pass? Define the number before the spike so the go/no-go is
   objective.
5. **Scope: volumes-only or all mount types** — ship platform volumes on
   firecracker first (the motivating case), or external S3/NFS/SSHFS/rclone too?
   They share the host-mount → bind → guest-FS path, so it's mostly free, but
   each type widens the test matrix.

### Verified-against-code (grounded)
- Reject point: `internal/service/service.go:1296` (firecracker mounts). ✅
- Driver already takes binds: `driver.Create(..., binds []mounts.ContainerBind)`
  (`internal/runtime/firecracker/driver.go:416`). ✅
- Supported devices only (no virtio-fs): `pkg/firecracker/client.go`
  (`PutDrive`/`PutNetworkInterface`/`PutVsock`/balloon/rng). ✅
- vsock already wired per sandbox: `PutVsock`, `VsockDialer`, `PostResumeTimeout`
  (`driver.go`). ✅
- Host-mediated FS precedent: `internal/runtime/wasm/toolhost/`. ✅
- Firecracker v1.15.1 deployment: `Ansible/README.md` `firecracker_version`. ✅

---

## 9. Test plan

### Unit (offline, `make test`)
- Service: firecracker create with mounts no longer rejects; binds passed to a
  fake driver; failed guest-mount rolls back host `MountAll`.
- FS protocol: encode/decode round-trip for every RPC; error-code mapping.
- Host FS handler: path-scope enforcement — a sandbox cannot read outside its
  registered binds; `..`/symlink escape denied; read-only bind rejects writes.
- Platform-volume runtime gate: firecracker now allowed, wasm still rejected.

### Integration (`integration` tag, operator-run — extends `plans/e2b-volume-mounts.md` §12)
- New capability `CapFirecracker` + `CapPlatformVolumes` UCs mirroring UC-81..84
  on the firecracker runtime: write+read-back, persistence across destroy +
  re-attach, shared volume across two firecracker sandboxes, read-only rejects
  writes. Plus a **snapshot-resume re-mount** UC and a **cross-node re-attach**
  UC (cluster).
- Phase 0 perf probe recorded in `integration-tests/reports/`.

---

## 10. Out of scope (v1)
- Forking/patching Firecracker for native virtio-fs (Approach C) — revisit only
  if Phase 0 perf is blocking.
- Block-image-backed volumes (Approach B).
- Mounts on the WASM runtime (structurally host-mediated already; different
  model, no container FS).
- Per-volume IO rate limiting on firecracker (Firecracker block RateLimiter
  doesn't apply to the vsock FS path; a future axis).
