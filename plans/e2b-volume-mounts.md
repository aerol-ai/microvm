# Plan: E2B volume mounts — named persistent volumes

Status: **DRAFT — awaiting review**
Owner: server + E2B facade + 5 SDKs + docs
Stacks on: nothing (off current `main`)

---

## 1. Problem statement

The E2B facade hard-rejects `volumeMounts` at create:
`pkg/api/e2b/handlers.go:546` → `notImplemented("E2B volume mounts are not implemented yet")`.

The E2B create DTO is:

```json
{ "templateID": "base", "volumeMounts": [ { "name": "data", "path": "/workspace" } ] }
```

A **volume** is *named, persistent storage mounted at a path inside the
sandbox*. Unlike AerolVM's existing external mounts (`pkg/mounts`, which are
per-sandbox and ephemeral — torn down on stop/destroy), a volume:

- has a **name**, not a per-sandbox index;
- **persists across the sandbox lifecycle** (survives stop + destroy);
- can be **re-attached** to a later sandbox by the same name and see the same
  data;
- can be **shared** by multiple sandboxes (concurrently or over time).

This plan makes `volumeMounts` work end to end with the smallest correct
surface, by **reusing the existing mount pipeline** and adding one new mount
backend: a local, name-keyed persistent directory.

---

## 2. What already exists (reuse, don't rebuild)

Verified by code audit (`pkg/mounts/manager.go`, `pkg/mounts/adapters/`,
`pkg/models/mounts.go`, `internal/store/store.go`, `pkg/docker/client.go`):

- **MountSpec** (`pkg/models/mounts.go:27`) — `{Type, Target, Source, Options,
  Credentials, ReadOnly}`. Validated (max 8/sandbox, blocked targets, etc.).
- **Manager** (`pkg/mounts/manager.go`) — `MountAll → []ContainerBind`,
  `UnmountAll`, `HostBindsFor`, `Reestablish` (idempotent re-mount on
  start/reconcile), `Sweep` (orphan GC on boot). Adapter-per-type
  (`Adapters()` map in `adapters/adapter.go:44`).
- **Adapter** (`adapters/adapter.go`) — `Build(sandboxID, index, spec,
  hostTarget, credDir) → Plan`. A `Plan` describes a command to run; the
  manager owns spawning + supervision.
- **Store** — mounts are sealed (AES-GCM) into the `sandbox_mounts` table
  (`store.go:112`), reapplied on start via `Reestablish`. **So persistence +
  reconcile come for free** once a volume is a MountSpec.
- **Docker** (`client.go:303-426`) — turns `[]ContainerBind` into
  `HostConfig.Binds` (`host:container[:ro]`). **Volumes ride this unchanged.**
- **Service create path** (`service.go:1106`) — `mounts.MountAll(ctx,
  sandboxID, req.Mounts)` already runs on the boot path.

The external-mount machinery (FUSE supervision, credential files, S3/NFS/etc)
is **organizationally sandbox-owned**. The only gap is: a volume is
*name-owned and persistent*, not *sandbox-owned and ephemeral*.

---

## 3. Design decisions

### 3.1 Volume = a new `volume` MountType backed by a persistent host dir
Add `MountTypeVolume MountType = "volume"` (`pkg/models/mounts.go`). Its
`Source` is the **volume name**; its `Target` is the in-container path. A
`volumeMounts:[{name,path}]` entry maps to
`MountSpec{Type: "volume", Source: name, Target: path}`.

### 3.2 Persistent, name-keyed host layout (the crux)
External mounts live at `/var/lib/sandboxd/mounts/<sandboxID>/<index>/` and the
whole `<sandboxID>` tree is `RemoveAll`-ed on `UnmountAll` and swept on boot.
A volume must NOT live there. Instead:

```
/var/lib/sandboxd/volumes/<sanitized-name>/      ← persistent, shared by name
```

- **Realization** (a new `Volume{}` adapter, or a manager special-case): ensure
  the dir exists (`MkdirAll`, mode `0o770`), then return a `ContainerBind`
  pointing the container `Target` at it. **No process, no credentials, no
  supervision** (`IsKernelMount`-like: nothing to supervise).
- **`UnmountAll` / `Sweep` must never delete the volumes tree.** Tearing down a
  sandbox removes the bind (Docker does that on container destroy) but leaves
  the data. This is the persistence guarantee.
- Name → dir mapping is **sanitized + collision-safe**: lowercase, allow
  `[a-z0-9._-]`, reject path separators / `..`, cap length. Reject names that
  don't round-trip to a single dir component (no traversal). See UC-08/09.

### 3.3 Get-or-create on mount (no separate CRUD API in v1)
E2B references volumes by name at create time. v1 semantics: **first use of a
name creates the dir; reuse of the same name reattaches the same dir.** No
`/v1/volumes` CRUD endpoint in this PR — the volume's existence IS its
directory. This keeps the change to one PR and matches the dominant E2B usage
(attach at create). A management API (list/delete/quota) is future work (§8).

### 3.4 Runtime support: Docker only (v1)
- **Docker** — binds work; volumes work. ✅
- **Firecracker** — `Create(... binds)` ignores binds (rootfs is an ext4 block
  device; audit confirmed). A volume on a Firecracker sandbox would silently
  not mount → **reject** at the facade/service with a clear error (parity with
  how selective egress rejects on wasm). (UC-15.)
- **WASM** — host-mediated, no container FS → **reject** (the E2B facade
  already has a wasm branch; add the rejection there). (UC-14.)

### 3.5 Persistence + reconcile = free
Because a volume is a `MountSpec`, it is sealed into `sandbox_mounts` and
reapplied by `Reestablish` on start/reconcile — same path as every other
mount. No new persistence code. The host dir already persisting independently
means a stop→start re-binds the same data. (UC-04/05.)

### 3.6 Read-only + count limits
- `volumeMounts` entries count against `MaxMountsPerSandbox` (8) together with
  external mounts (shared cap; documented). (UC-13.)
- E2B's DTO has no read-only flag today, so volumes mount read-write. The
  `MountSpec.ReadOnly` plumbing exists if E2B adds it later.

### 3.7 Validation
- `name` required, non-empty after trim, sanitized (§3.2). (UC-07/08/09.)
- `path` runs through the **existing** `MountSpec.Validate` blocked-target list
  (`/`, `/proc`, `/etc`, …) — volumes inherit the same guard as external
  mounts for free. (UC-10.)
- Duplicate container paths across the mount set rejected (existing check, or
  add if absent). (UC-12.)

---

## 4. Files to modify

### 4.1 Models
- **`pkg/models/mounts.go`**
  - Add `MountTypeVolume MountType = "volume"`.
  - Accept it in the type switch (`mounts.go:94`) and `validateSource`
    (source = volume name, validated by the name rules, not a URI).
  - A helper `SanitizeVolumeName(string) (string, error)`.

### 4.2 Mount manager + adapter
- **`pkg/mounts/adapters/volume.go`** (new) — `Volume{}` adapter. `Build`
  returns a `Plan` with no `Argv` (nothing to spawn) — OR we special-case
  volumes in the manager before the adapter loop (cleaner, since there's no
  command). **Decision: manager special-case** (a volume needs a different
  *host path* than `rootDir/<sandboxID>/<index>`, which the adapter API can't
  express — `Build` only gets `hostTarget`). See §7 Q1.
- **`pkg/mounts/manager.go`**
  - `VolumesRoot` config (default `/var/lib/sandboxd/volumes`).
  - In `MountAll`/`Reestablish`: for `Type==volume`, compute
    `hostPath = VolumesRoot/<sanitized-source>`, `MkdirAll(0o770)`, append a
    `ContainerBind{HostPath, ContainerPath: Target, ReadOnly}` — skip the
    spawn/supervise path.
  - `UnmountAll`: skip volume entries (do NOT delete the shared dir).
  - `Sweep`: never descend into / delete `VolumesRoot`.
  - `HostBindsFor`: include volume binds so Docker re-binds on start.

### 4.3 Config + daemon wiring
- **`internal/config/config.go`** — `SB_VOLUMES_ROOT` (default
  `/var/lib/sandboxd/volumes`).
- **`pkg/daemon/`** — pass `VolumesRoot` into the mounts.Manager constructor.

### 4.4 Service
- **`internal/service/service.go`** — validate volume mounts on create
  (sanitize names, Docker-runtime gate); volumes flow through the existing
  `req.Mounts` MountAll path (the facade maps volumeMounts → Mounts, so the
  service may need no change beyond the runtime gate). Reject volumes on
  Firecracker.

### 4.5 E2B facade
- **`pkg/api/e2b/handlers.go`**
  - Remove the `notImplemented` at line 546.
  - Translate `req.VolumeMounts[{Name,Path}]` →
    `MountSpec{Type: volume, Source: Name, Target: Path}` appended to
    `serviceReq.Mounts`.
  - Reject volumes on the wasm branch (line ~626).
  - Echo volumes back in `listedSandboxResponse` / `sandboxDetailResponse`
    (`VolumeMounts` payload is already in the DTO) from the persisted specs.
- **`pkg/api/e2b/meta.go`** — carry volume mounts in the sealed compat blob so
  GET/list echo them after restart (mirror how network fields ride the blob).

### 4.6 SDKs — **no new field needed** (resolved)
**Confirmed:** all five SDKs target the native `/v1` API
(`client.ts:407` / `client.py:459` POST `/sandboxes`) and already serialize a
`mounts: MountSpec[]` array (`toApiMountSpec` / `_to_api_mount_spec`). A volume
is just a native `MountSpec{ type: "volume", source: <name>, target: <path> }`
— the `type` field is an opaque string on the wire, so **every SDK already
serializes it with zero code change**. The `volumeMounts:[{name,path}]` shape
is purely the **E2B facade's** sugar; SDK users use the existing `mounts` array.

Work here is therefore minimal:
- Optionally add a `"volume"` constant / typed helper to each SDK's mount-type
  enum for discoverability (TS `MountType`, Python, Rust, Java, Go `types`).
- Add/extend one serialization test per SDK asserting a `type:"volume"` mount
  round-trips (TS/Python/Go runnable locally; Rust/Java mirror for CI).
- No new transport fields, no client.ts/client.py request-mapping changes.

### 4.7 Docs
- **`docs/src/content/docs/`** — new `.mdx` (volumes are a top-level feature →
  new page per CLAUDE.md, registered in `content.config.ts`), five-language
  tabs: create a sandbox with a named volume, reattach it to a second sandbox,
  note persistence + Docker-only + shared-cap.

---

## 5. Use cases (verification matrix)

| # | Use case | Expected | Covered by |
|---|---|---|---|
| UC-01 | Create sandbox with `volumeMounts:[{name:"data",path:"/workspace"}]` | host dir `volumes/data` created, bind-mounted at `/workspace`, write succeeds | mounts + service test |
| UC-02 | Write a file in the volume, destroy the sandbox | host dir + file survive (not deleted) | mounts UnmountAll test |
| UC-03 | Create a 2nd sandbox with the same volume name | sees the file the 1st wrote (reattach) | integration-style test |
| UC-04 | Stop then start the same sandbox | volume re-bound via Reestablish, data intact | reconcile/start test |
| UC-05 | Daemon restart (reconcile) | volume re-bound from sealed specs | reconcile test |
| UC-06 | Two running sandboxes mount the same volume | both binds point at the same host dir | mounts test |
| UC-07 | Empty/whitespace volume name | 400 at create | validation test |
| UC-08 | Name with `/` or `..` (traversal) | 400 — sanitization rejects | validation test |
| UC-09 | Name with uppercase/odd chars | sanitized deterministically or rejected | validation test |
| UC-10 | Volume path = `/etc` (blocked target) | 400 via existing MountSpec.Validate | validation test |
| UC-11 | Volume path collides with an external mount target | 400 duplicate-target | validation test |
| UC-12 | Two volumeMounts with same path | 400 duplicate-target | validation test |
| UC-13 | 9 mounts total (volumes + external) | 400 — exceeds MaxMountsPerSandbox | validation test |
| UC-14 | Volume on a **wasm** sandbox | 501/400 rejected at facade | e2b handler test |
| UC-15 | Volume on a **firecracker** sandbox | rejected (binds unsupported) | service test |
| UC-16 | `Sweep` on boot with live + orphan sandbox mount dirs | volumes tree untouched; only ephemeral mount dirs swept | mounts Sweep test |
| UC-17 | E2B create with volumes returns 201 (was 501) | success, volumes plumbed | e2b handler test |
| UC-18 | GET/list sandbox echoes `volumeMounts` | persisted specs surfaced in the E2B payload | e2b handler test |
| UC-19 | Volume mount round-trips through sealed store blob | reload after restart preserves name+path | store/meta test |
| UC-20 | Read-only intent (if/when E2B adds it) | `ReadOnly` propagates to the bind | mounts test (plumbing ready) |
| UC-21 | Volume bind appears in Docker `HostConfig.Binds` | `host:container` entry present | docker client test |
| UC-22 | Volume name maps to exactly one dir component | no escape outside VolumesRoot | sanitize unit test |
| UC-23 | Concurrent create of two sandboxes referencing a new same-named volume | MkdirAll idempotent, no race/error | mounts test |
| UC-24 | A native `mounts:[{type:"volume",source,target}]` create (any SDK) | volume works via the existing `mounts` array, no new field | per-SDK serialization test |

(24 use cases; ≥20 satisfied.)

---

## 6. pr-review.md axes (pre-filled)

1. **Idempotency.** `MkdirAll` is idempotent; re-create / concurrent duplicate
   referencing the same volume converge on the same dir. No port/pool. ✅
2. **Boot-path latency.** Adds one `MkdirAll` per volume on the existing
   `MountAll` boot step — local stat/mkdir, no network, no spawn (cheaper than
   any external adapter). First-call case = create the dir once. Called out. ✅
3. **Lazy bootstrap.** N/A — no daemon-start latch; `VolumesRoot` is created on
   first use.
4. **Failure-path consistency.** Volume realization is a single `MkdirAll`; if
   a later mount in the set fails, `MountAll` already rolls back the
   sandbox-scoped state — and the volume dir is intentionally **left** (it's
   persistent and may be shared), which is the documented rule. ✅
5. **TCP host-port pool & L4.** Untouched. ✅
6. **Cluster mode.** Volumes are **host-local** in v1 — a volume lives on the
   node that created it; a sandbox placed on another node won't see it. This
   MUST be called out as a single-node/affinity limitation (multi-host volumes
   = future CSI work). No FSM/placement change; no-op when cluster off. ⚠️
   **call-out required.** (See §7 Q3.)
- **Store schema.** No new table in v1 (volumes ride `sandbox_mounts` + the
  E2B sealed blob). A `volumes` table is future work.
- **Security.** Volume dirs are `0o770`, sandboxd-owned; path traversal blocked
  by name sanitization; container target blocked-list reused. No credentials.

---

## 7. Open questions for review

1. **Adapter vs. manager special-case** — the `Adapter.Build` API only receives
   `hostTarget`, but a volume needs a *different* host root (`VolumesRoot`, not
   `rootDir/<sandboxID>/<index>`). Cleanest is a manager special-case for
   `Type==volume` before the adapter loop. Agree? (Plan assumes yes.)
2. ~~**Do the SDKs target `/v1` or `/e2b`?**~~ — **RESOLVED: native `/v1`.**
   All SDKs POST `/sandboxes` and already serialize `mounts: MountSpec[]`
   (`client.ts:407,1110` / `client.py:459`). A volume = native
   `MountSpec{type:"volume"}`; SDKs need no new field (see §4.6). The
   `volumeMounts` shape is E2B-facade-only.
3. **Cluster scope** — accept host-local volumes with a documented affinity
   limitation for v1, or block volume mounts entirely when `EnableCluster` is
   true until multi-host backing exists? (Plan leans: allow + document, since
   the open-source single-node path is the common case.)
4. **Management API** — is get-or-create-on-mount acceptable for v1 (no
   list/delete/quota), with a `/v1/volumes` CRUD + a `volumes` table as a
   follow-up? (Plan assumes yes.)
5. **Daytona volumes** — the Daytona facade has skeleton `/daytona/volumes`
   routes returning 405. Out of scope here, but the same backend would later
   serve both. Confirm we're not doing Daytona in this PR.

### Verified-against-code (grounded, not speculative)
- E2B reject point: `pkg/api/e2b/handlers.go:546`. DTO `sandboxVolumeMountCreate
  {Name,Path}` at `dto.go:28`; response `VolumeMounts` already in
  `listedSandboxResponse`/`sandboxDetailResponse`. ✅
- Mount pipeline reused: `MountAll`/`Reestablish`/`HostBindsFor`/`Sweep`
  (`manager.go`), `ContainerBind` (`types.go:6`), Docker binds
  (`client.go:410-425`), sealed store (`store.go:112`, `PutMounts`/`GetMounts`).
  ✅
- Firecracker ignores binds (rootfs ext4 block device) → volume reject needed.
  WASM has no container FS → reject in the existing facade wasm branch. ✅
- Validation reuse: `MountSpec.Validate` blocked-target list + `MaxMountsPerSandbox`
  (`models/mounts.go:57,69-84`). ✅

---

## 8. Future work (explicitly out of v1 scope)
- `/v1/volumes` CRUD + `volumes` store table (list, delete, metadata, quota).
- Multi-host / CSI-backed volumes for cluster mode.
- Daytona `/daytona/volumes` wired to the same backend.
- Per-volume size limits / metering.
- Read-only mounts once E2B's DTO exposes the flag.

---

## 9. Build & verification commands
```
make fmt && go build ./...
go test ./pkg/mounts/... ./pkg/models/... ./internal/service/... ./pkg/api/e2b/... ./pkg/docker/...
go test -count=1 -coverprofile=coverage.out ./cmd/... ./internal/... ./pkg/...
go tool cover -func=coverage.out | grep -E "mounts|service|e2b"
(cd sdk/typescript && npm ci && npm run build && npm test)
(cd sdk/python && python3 -m unittest discover -s tests -v)
(cd sdk/go && go test ./...)
make docs-build
# rust/java: CI only (no local cargo/mvn) — mirror existing field shape
```
