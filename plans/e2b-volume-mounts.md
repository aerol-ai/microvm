# Plan: Platform-managed named persistent volumes (E2B + Daytona + SDKs)

Status: **DRAFT v2 — awaiting review**
Owner: server + E2B facade + Daytona facade + 5 SDKs + docs + operator config
Stacks on: nothing (off current `main`)
Supersedes: the host-local `VolumesRoot` draft (v1 of this file). See §0.

---

## 0. What changed from v1 (and why v1 is dead)

v1 of this plan backed each named volume with a **host-local directory** at
`/var/lib/sandboxd/volumes/<name>/`. Eng review killed it on two grounds, both
of which are intrinsic to host-local storage and cannot be patched around:

1. **Cluster silent-data divergence.** A volume is a dir on *one* node.
   Placement (`internal/cluster/placement.go`, power-of-two-choices) can put a
   same-named sandbox on a *different* node. Get-or-create-on-mount then makes
   the second node create a **fresh empty dir** under the same name — the user
   reattaches `data` and silently sees an empty volume, no error. Silent data
   loss is worse than a hard failure.
2. **Disk-fill blast radius.** Volumes are designed never to be swept, so a
   client looping `create(volumeMounts:[{name: uuid()}])` writes unbounded
   persistent dirs until the node's filesystem fills — taking down **every**
   sandbox on the node, not just the abuser's.

**v2 fixes both at the root by making operator-configured shared external
storage (S3 first) the single source of truth.** Any node can mount the same
backing store, so cluster placement is irrelevant to correctness; quota +
S3 lifecycle policy bound the blast radius. A platform volume is no longer a
new storage primitive — it is a **synthesized S3 mount** that reuses the
already-shipped mount pipeline end to end.

---

## 1. Problem statement

Both compat facades hard-reject persistent volumes today:

- **E2B** — `pkg/api/e2b/handlers.go:546` → `notImplemented("E2B volume mounts
  are not implemented yet")`. Create DTO carries
  `volumeMounts: [{ name: "data", path: "/workspace" }]`
  (`sandboxVolumeMountCreate`, `dto.go:28`); responses already model
  `sandboxVolumeMountPayload` (`dto.go:105`) for echo-back.
- **Daytona** — `/daytona/volumes` (list/get/create/delete/by-name) all return
  405 via `volumesNotSupported` (`routes.go:79-87`); `volumes[]` on create
  returns `errVolumesUnsupported` (`handlers.go:136,990`).

A **platform volume** is *named, persistent storage that the operator backs
with shared external storage and the user references by name* — the user never
supplies a bucket URL or credentials. It:

- has a **name**, scoped per tenant;
- **persists across the sandbox lifecycle** (survives stop + destroy);
- can be **re-attached** by the same name from a later sandbox **on any node**;
- is backed by operator-owned storage the operator pays for and meters.

This plan makes platform volumes work end to end by **synthesizing an S3
`MountSpec` from operator config** and reusing `pkg/mounts` unchanged.

---

## 2. What already exists (reuse, don't rebuild)

Verified by code audit:

- **S3 adapter** (`pkg/mounts/adapters/s3.go`) — turns
  `MountSpec{Type:s3, Source:"bucket/prefix", Credentials, Options{region,
  endpoint}, ReadOnly}` into a `mount-s3` invocation, already supports
  `--prefix`, `--region`, `--endpoint-url`, `--read-only`. **This is exactly
  the shape a platform volume needs.**
- **Manager** (`pkg/mounts/manager.go`) — `MountAll`/`UnmountAll`/`Reestablish`/
  `HostBindsFor`/`Sweep`. Spawns + supervises the FUSE process, writes the
  cred file 0600 and unlinks it once ready, tears the mount down on stop while
  **the remote data (the S3 prefix) survives** — which is precisely the
  persistence semantics we want, for free.
- **Credential sealing** (`internal/service/service.go:1060`, `sealMounts`) —
  mount specs (incl. credentials) are AES-GCM sealed into `sandbox_mounts` and
  reapplied by `Reestablish` on start/reconcile. Operator creds injected into a
  synthesized spec inherit this at-rest encryption and the "never returned by
  read APIs" guarantee.
- **Boot path** (`service.go:1109`) — `mounts.MountAll(ctx, sandboxID,
  req.Mounts)` already runs on create. A synthesized volume mount is just one
  more entry in `req.Mounts`.
- **Validation** (`pkg/models/mounts.go`) — `MountSpec.Validate`
  blocked-target list + `MaxMountsPerSandbox` (8). Volume target paths inherit
  the blocked-target guard for free.
- **Config pattern** (`internal/config/config.go`) — `getEnv`/`getEnvBool`,
  `SB_MOUNTS_ROOT`, `SB_CREDENTIAL_ENCRYPTION_KEY`. Precedent for operator-level
  shared S3 exists in Terraform (`caddy_shared_cert_storage`).
- **Daytona volume CRUD routes** are already stubbed (`routes.go:79-87`) — we
  fill them in, we don't add routing.

**The only new code is the translation layer** (name → operator-scoped S3
source + operator creds, with tenant isolation and quota) plus config wiring,
facade un-rejection, SDK constants, and docs.

---

## 3. Design decisions

### 3.1 A platform volume is a synthesized `MountSpec` (s3 **or** nfs; no new MountType)
The facade/service maps a volume reference to an existing mount type chosen by
`SB_PLATFORM_VOLUMES_BACKEND`. S3 backend:

```
MountSpec{
  Type:        s3,
  Source:      "<SB_PLATFORM_VOLUMES_S3_BUCKET>/<prefix>/<tenant>/<name>",
  Target:      <in-container path>,
  Credentials: <operator creds from config>,
  Options:     {region, endpoint},
  ReadOnly:    <as requested>,
}
```

NFS backend (RESOLVED §7 Q5 — **also in v1**): synthesize
`MountSpec{Type:nfs, Source:"<server>:<export>/<tenant>/<name>", Options:{...},
ReadOnly}`. NFS is a kernel mount with **no credentials** (simpler than S3), but
the tenant-path mapping must be validated against the operator's export layout,
not an S3 prefix. The translation layer (§5.2) branches on backend; everything
downstream (seal, MountAll, the NFS adapter, Docker binds) is reused unchanged.

We do **not** add `MountTypeVolume`, and we do **not** add a host-local
adapter. Rejected alternatives, recorded:

- **Host-local `VolumesRoot` dir** (v1) — rejected, see §0.
- **New `volume` MountType + `Volume{}` adapter** — rejected: it would
  reintroduce a parallel storage primitive when the S3 adapter already does
  the job. The volume concept lives in the *translation* layer, not a new
  storage backend.

### 3.2 Name → storage path mapping + tenant isolation (the crux)
```
s3://<bucket>/<prefix>/<tenant-scope>/<sanitized-name>/
```

- **`tenant-scope`** is derived from the auth context (API token / client
  identity), NOT user-supplied. This is the load-bearing isolation boundary:
  two tenants using the name `data` must map to disjoint prefixes. The exact
  key is §7 Q1 (recommendation: the authenticated token's tenant/owner id;
  fall back to a stable hash of the API token when no richer identity exists).
- **`sanitized-name`**: lowercase, allow `[a-z0-9._-]`, reject `..` / path
  separators, cap length, must round-trip to a single path segment. Reject
  invalid names with **400** (UC-07/08/09).
- The mapping is deterministic, so first use creates the prefix implicitly
  (S3 has no real dirs) and reuse reattaches the same prefix.

### 3.3 Operator-gated; no silent host-local fallback
Platform volumes require the operator to configure shared storage. Gating
matrix:

| Condition | Behavior |
|---|---|
| `SB_PLATFORM_VOLUMES_ENABLED` false / unset | E2B `volumeMounts`, Daytona volumes, SDK platform volumes → **412 Precondition Failed** with a clear "platform volumes are not enabled on this deployment" message |
| Enabled but misconfigured (no bucket / bad creds) | **Fail fast at daemon boot** (preferred) or, if undetectable at boot, at first volume request with a clear error |
| Enabled + configured | Translate to a sealed S3 `MountSpec` and mount normally |

There is **never** a fallback to host-local dirs — that path does not exist in
v2.

### 3.4 Get-or-create-by-name on attach (no separate CRUD required for E2B v1)
E2B references volumes by name at create; the S3 prefix's existence IS the
volume. No `/v1/volumes` CRUD needed for the E2B surface. Daytona's SDK,
however, models explicit volume objects with ids — see §3.8 for the Daytona
scope decision (§7 Q2).

### 3.5 Runtime support: Docker only (v1)
- **Docker** — S3 FUSE bind works. ✅
- **Firecracker** — `Create(... binds)` ignores binds (ext4 block-device
  rootfs); reject platform volumes at the service with a clear error (parity
  with how other features reject on unsupported runtimes). (UC-15.)
- **WASM** — host-mediated, no container FS → reject in the existing facade
  wasm branch. (UC-14.)

### 3.6 Persistence + reconcile = free
A synthesized volume mount is a sealed `MountSpec`, so it round-trips through
`sandbox_mounts` and is reapplied by `Reestablish` on start/reconcile — same
path as every other mount. Sandbox destroy tears down the FUSE process and the
per-sandbox staging dir (`mounts/<sandboxID>/<index>/`) but **never touches the
S3 prefix** — Manager already has these semantics for S3 today. (UC-02/04/05.)

### 3.7 Cluster correctness (the whole point of v2)
S3 is the single source of truth. A sandbox referencing volume `data` mounts
`s3://bucket/prefix/<tenant>/data/` regardless of which node placement chooses
— **no node affinity needed, no FSM/placement change, no silent empty volume.**
This MUST be stated explicitly in the PR as the reason v2 supersedes v1's
host-local footgun. No-op when `EnableCluster` is false.

### 3.8 Daytona scope: full CRUD incl. delete (RESOLVED, §7 Q2)
Daytona's SDK models volumes as first-class objects (create → get id → attach
by id). **v1 implements all five `/daytona/volumes` routes**
(list/get/create/delete/by-name, currently 405 at `routes.go:79-87`). A volume
"object" = a named prefix + a **metadata row** (id, tenant, name, backend,
created_at, ...). This requires a new `volumes` store table — use
`/add-store-column` (idempotent CREATE, scanner, Create/Get/List/Delete,
regression test). `delete` is **reference-aware**: it returns **409 Conflict**
while any live sandbox has the volume attached, and only tears down the backing
prefix/export when no attachers remain (ties to §3.10). E2B continues to use
attach-by-name (no explicit object) against the same backend + table.

### 3.9 Quota / abuse bounding
Per-tenant **volume-count cap** and/or **total-bytes ceiling**, checked at
attach/create time, rejecting past the cap with a **4xx** (UC-13b). Configurable
(`SB_PLATFORM_VOLUMES_MAX_PER_TENANT`, optional bytes ceiling). S3 lifecycle /
expiry policies are an operator concern but the plan calls them out. This
replaces v1's per-host dir cap, scoped to the tenant where it belongs.

### 3.10 Concurrent sandboxes, same volume: document + allow (RESOLVED, §7 Q4)
E2B/Daytona allow sharing. `mount-s3` is **not** a strongly-consistent
multi-writer filesystem; concurrent writers to the same prefix can lose data.
**v1 policy: document + allow** — permit concurrent attach, document that the
S3 backend gives eventual consistency, no POSIX locking, last-writer-wins per
key. Do not pretend POSIX. The Daytona `delete` (§3.8) enforces the only hard
rule here: a volume with ≥1 live attacher cannot be deleted (409). Attacher
count derives from the `sandbox_mounts` specs referencing the volume + the
`volumes` metadata row.

---

## 4. Request flow

```
E2B create {volumeMounts:[{name,path}]}
        │
        ▼
e2b facade handler ── gate: SB_PLATFORM_VOLUMES_ENABLED? ──no──▶ 412
        │ yes
        ▼
translatePlatformVolume(name, path, authCtx)
        │   sanitize(name) ──invalid──▶ 400
        │   tenant = tenantScope(authCtx)
        │   quota check (count/bytes) ──over──▶ 4xx
        │   source = bucket/prefix/tenant/name
        │   creds   = operator config (sealed downstream)
        ▼
append MountSpec{type:s3,...} to serviceReq.Mounts
        │
        ▼
service.CreateSandbox
        │  runtime gate: firecracker/wasm ──▶ reject
        │  sealMounts(req.Mounts)            (service.go:1060)
        │  mounts.MountAll → S3 adapter      (service.go:1109)
        │       └─ spawn mount-s3 --prefix tenant/name … --foreground
        ▼
Docker HostConfig.Binds: <staging>:<path>   → sandbox sees the volume
```

Native SDKs reach the same `service.CreateSandbox` via `/v1` using a typed
platform-volume helper (§4.6) — NOT raw S3 creds.

---

## 5. Files to modify

### 5.1 Config + daemon wiring
- **`internal/config/config.go`** — new block (names to match repo style):
  `SB_PLATFORM_VOLUMES_ENABLED` (bool), `SB_PLATFORM_VOLUMES_BACKEND`
  (`s3` | `nfs`, both shipped in v1). S3: `_S3_BUCKET`, `_S3_PREFIX` (default
  `volumes`), `_S3_REGION`, `_S3_ENDPOINT` (optional, R2/MinIO), operator creds
  via access-key/secret OR instance role (follow existing secrets handling).
  NFS: `_NFS_SERVER`, `_NFS_EXPORT` (base export path), `_NFS_OPTIONS`.
  Shared: `SB_PLATFORM_VOLUMES_MAX_PER_TENANT`. Validate the active backend's
  required fields when enabled (fail fast at boot).
- **`pkg/daemon/`** — pass the platform-volume config into the service so the
  translation layer can read it.

### 5.2 Translation layer (new)
- **`pkg/volumes/` or `internal/service/platform_volumes.go`** (new) —
  `SanitizeVolumeName`, `tenantScope(authCtx)`, `BuildVolumeMountSpec(name,
  path, readOnly, cfg, tenant) (models.MountSpec, error)`, quota check. Pure +
  table-test friendly. Decide package placement per repo conventions (service
  is version-agnostic; a `pkg/volumes` keeps it reusable by both facades).

### 5.3 Service
- **`internal/service/service.go`** — accept synthesized volume mounts through
  the existing `req.Mounts` path; add the runtime gate (reject volumes on
  firecracker/wasm); ensure operator creds flow through `sealMounts`. No new
  persistence code. **Read `pr-review.md` — this touches the create boot path
  (idempotency, boot latency, failure rollback).**

### 5.4 E2B facade
- **`pkg/api/e2b/handlers.go`** — remove `notImplemented` (line 546); translate
  `req.VolumeMounts[{Name,Path}]` → platform-volume `MountSpec` appended to
  `serviceReq.Mounts`; gate on enabled (412); reject on wasm branch (~626);
  echo volumes back in `listedSandboxResponse`/`sandboxDetailResponse` from
  persisted specs.
- **`pkg/api/e2b/meta.go`** — carry volume name+path in the sealed compat blob
  (mirror the `NetworkAllowOut`/`NetworkDenyOut` fields, `meta.go:73,89`) so
  GET/list echo them after restart. **Store only name+path, never creds** (creds
  are operator-global, re-derived from config).

### 5.5 Daytona facade (full CRUD)
- **`pkg/api/daytona/handlers.go` + `routes.go`** — remove
  `errVolumesUnsupported`/`volumesNotSupported`; implement all five routes
  (list/get/create/delete/by-name) against the `volumes` store table +
  name→prefix mapping. `delete` is reference-aware (409 while attached, §3.8).
  Attach-at-create maps `volumes[{volumeId,mountPath}]` → resolve id → tenant +
  name → synthesized backend `MountSpec`.
- **`internal/store/store.go`** — new `volumes` table (`/add-store-column`):
  id, tenant, name, backend, created_at; unique on (tenant, name). Scanner +
  Create/Get/List/Delete + regression test.

### 5.6 SDKs — dedicated `platform_volumes` field (RESOLVED §7 Q3)
Platform volumes must NOT require users to pass storage creds. Add a dedicated
**`platform_volumes:[{name,path,read_only}]`** request field to
`models.CreateSandboxRequest` (`pkg/models`); the server owns
bucket/export/creds/tenant translation entirely, so no storage detail ever
reaches the client and the backing store can change without an SDK change. Add
the typed field/helper to all five SDKs (TS, Python, Go, Rust, Java).
- Serialization test per SDK (TS/Python/Go runnable; Rust/Java mirror for CI).
- This is a `pkg/models` wire-type addition — keep it lean and stable
  (CLAUDE.md), and it ripples to the facade DTOs that map into it.

### 5.7 Docs
- **`docs/src/content/docs/`** — new `.mdx` (top-level feature → new page),
  registered in `content.config.ts`, five-language tabs: create a sandbox with
  a named volume, reattach from a second sandbox, note persistence +
  Docker-only + shared cap + cluster-safe. **Operator setup section**: how to
  enable + configure shared S3 (bucket, region, endpoint, creds/role). No raw
  curl.
- **`Terraform/` / `packaging/` / `Ansible/`** — operator env template for the
  shared-storage config (if in scope; otherwise call out as follow-up).

---

## 6. Use cases (verification matrix)

| # | Use case | Expected | Covered by |
|---|---|---|---|
| UC-01 | E2B create with `volumeMounts:[{name:"data",path:"/workspace"}]`, volumes enabled+configured | S3 prefix `…/<tenant>/data/` mounted at `/workspace`, write succeeds | service + mounts test |
| UC-02 | Write a file, destroy the sandbox | S3 object survives; staging dir gone | mounts UnmountAll test |
| UC-03 | 2nd sandbox, same volume name, **different node** (cluster) | sees the file the 1st wrote (S3 source of truth) | cluster/integration test |
| UC-04 | Stop then start same sandbox | volume re-bound via Reestablish, data intact | reconcile test |
| UC-05 | Daemon restart (reconcile) | re-bound from sealed specs | reconcile test |
| UC-06 | Two running sandboxes mount same volume | both bind the same prefix; write-concurrency policy honored (§3.10) | mounts test |
| UC-07 | Empty/whitespace name | 400 | validation test |
| UC-08 | Name with `/` or `..` | 400 (sanitization) | validation test |
| UC-09 | Uppercase/odd chars | sanitized or 400 | validation test |
| UC-10 | Volume path = `/etc` (blocked target) | 400 via existing MountSpec.Validate | validation test |
| UC-11 | Volume path collides with external mount target | 400 duplicate-target | validation test |
| UC-12 | Two volumeMounts same path | 400 duplicate-target | validation test |
| UC-13a | 9 mounts total | 400 — exceeds MaxMountsPerSandbox | validation test |
| UC-13b | Tenant past `MAX_PER_TENANT` volume cap | 4xx | quota test |
| UC-14 | Volume on a **wasm** sandbox | rejected at facade | e2b handler test |
| UC-15 | Volume on a **firecracker** sandbox | rejected at service | service test |
| UC-16 | Platform volumes **disabled** | 412 on E2B/Daytona/SDK | gate test (all 3 surfaces) |
| UC-17 | Enabled but **misconfigured** | fail fast (boot or first request) with clear error | config/boot test |
| UC-18 | Tenant A name `data` vs Tenant B name `data` | disjoint prefixes, no cross-tenant read | tenant-isolation test |
| UC-19 | E2B GET/list echoes `volumeMounts` | persisted name+path surfaced; **no creds** | e2b handler test |
| UC-20 | Volume name+path round-trips sealed blob after restart | preserved | meta test |
| UC-21 | Operator creds sealed at rest, never in read API | `sandbox_mounts` ciphertext; redacted read view | store/seal test |
| UC-22 | Sanitized name maps to exactly one path segment | no prefix escape / traversal | sanitize unit test |
| UC-23 | Concurrent create, two sandboxes, same new name | idempotent; no error/race | mounts test |
| UC-24 | Daytona attach-at-create (in-scope routes) | volume mounts; out-of-scope routes still 405 | daytona handler test |
| UC-25 | Read-only volume request | `--read-only` propagates to the backend mount | mounts test |
| UC-26 | NFS backend: create + attach by name | export `<server>:<export>/<tenant>/<name>` kernel-mounted, no creds | mounts/service test |
| UC-27 | Backend switch (s3↔nfs) via config | translation branches on `BACKEND`; existing volumes under each layout untouched | translation unit test |
| UC-28 | Daytona create → get → attach by id | volume object persisted in `volumes` table, attaches the same prefix/export | daytona handler + store test |
| UC-29 | Daytona delete while a sandbox has it attached | 409 Conflict; prefix/export not torn down | daytona handler test |
| UC-30 | Daytona delete with no attachers | 200; backing storage reclaimed (S3 prefix delete / NFS dir removal) | daytona handler test |
| UC-31 | Daytona volume name collision within a tenant | unique(tenant,name) rejected at create | store test |

(31 use cases.)

---

## 7. Open questions for review
1. **Tenant-scope key** — **RESOLVED: auth owner id, hashed-token fallback.**
   Use `controlplane.AccessFromContext(ctx)` `ownerRef` as the scope segment
   when present (managed build = real per-tenant identity). The open-source
   build wires a **no-op controlplane Provider** (CLAUDE.md), so the only
   principal is the operator PAT (`middleware.go:50 isPATToken`) — fall back to
   a stable hash of the PAT, which collapses to a single self-host tenant
   (correct for single-tenant self-host). Verified both build modes are
   buildable. The fallback hash must be stable across restarts.
2. **Daytona scope** — **RESOLVED: full CRUD now** (all five routes incl.
   reference-aware `delete`), backed by a new `volumes` store table. See §3.8.
3. **SDK wire shape** — **RESOLVED: dedicated `platform_volumes` field.** Server
   owns all storage detail; no creds/bucket reach the client. See §5.6.
4. **Concurrent-writer policy** — **RESOLVED: document + allow** (mirror backend
   semantics); `delete` blocks at 409 while attached. See §3.10.
5. **NFS backend** — **RESOLVED: in v1.** Both `s3` and `nfs` backends ship;
   NFS is a credential-free kernel mount. See §3.1, §5.1.

### Verified-against-code (grounded)
- E2B reject `handlers.go:546`; DTOs `dto.go:28,105`. ✅
- Daytona stubs `routes.go:79-87`, `handlers.go:136,990,1163-1171`. ✅
- S3 adapter shape `adapters/s3.go` (`--prefix/--region/--endpoint-url/--read-only`). ✅
- Seal path `service.go:1060` (`sealMounts`), MountAll `service.go:1109`. ✅
- Config pattern `config.go` (`getEnvBool`, `SB_MOUNTS_ROOT`,
  `SB_CREDENTIAL_ENCRYPTION_KEY`). ✅

---

## 8. pr-review.md axes (pre-filled)
1. **Idempotency.** Attach-by-name is deterministic; S3 prefix is implicit;
   concurrent duplicate creates converge. No host-port/pool. ✅
2. **Boot-path latency.** Adds the S3 FUSE mount on the existing `MountAll`
   step — **first-attach incurs `mount-s3` startup + readiness probe** (network
   round-trips), unlike a local mkdir. Called out as the dominant new boot cost;
   warm-mount reuse across the sandbox lifecycle amortizes it. ⚠️ **call-out
   required.**
3. **Lazy bootstrap.** Config-gated; fail-fast at boot when enabled. No latch.
4. **Failure-path consistency.** A failed volume mount in the set is rolled back
   by existing `MountAll` rollback (`manager.go:120-126`); the S3 prefix is
   intentionally left (persistent). ✅
5. **TCP host-port pool & L4.** Untouched. ✅
6. **Cluster mode.** Shared S3 = correct across nodes; no FSM/placement change;
   no-op when cluster off. v2 explicitly removes v1's host-local footgun. ✅
- **Store schema.** E2B rides `sandbox_mounts` + sealed blob (no object). Daytona
  full CRUD adds a `volumes` metadata table (id, tenant, name, backend,
  created_at; unique on tenant+name) via `/add-store-column` with a regression
  test. SQLite single-writer rule applies — queue through the existing `*sql.DB`.
- **Security.** Operator creds sealed via `sealMounts`, never returned by read
  APIs, never enter the container (FUSE runs on host); tenant-scoped prefixes
  prevent cross-tenant reads; name sanitization blocks prefix traversal;
  container target blocked-list reused.

---

## 9. Future work (out of v1 scope)
- End-user billing / metering integration (design must not block it).
- User-supplied credentials for platform volumes (operator-only in v1).
- CSI / block storage.
- Firecracker / WASM platform volumes.
- Per-volume resize / strong multi-writer consistency / write-leasing.
- Per-tenant total-bytes quota (v1 ships count cap; bytes ceiling is optional).

---

## 10. Build & verification commands
```
make fmt && go build ./...
go test ./pkg/mounts/... ./pkg/models/... ./internal/service/... \
        ./pkg/api/e2b/... ./pkg/api/daytona/... ./internal/config/... ./pkg/docker/...
go test -count=1 -coverprofile=coverage.out ./cmd/... ./internal/... ./pkg/...
go tool cover -func=coverage.out | grep -E "mounts|service|e2b|daytona|volumes|config"
(cd sdk/typescript && npm ci && npm run build && npm test)
(cd sdk/python && python3 -m unittest discover -s tests -v)
(cd sdk/go && go test ./...)
make docs-build
# live S3 mount behavior → integration-tests/ behind the `integration` tag (never plain _test.go)
# rust/java: CI only
```

---

## 11. Implementation Tasks
Synthesized from this review's findings. Each derives from a specific decision
above. P1 blocks ship; P2 lands same branch; P3 is a follow-up. Effort uses the
AI-compression scale (human / CC).

- [x] **T1 (P1)** — config — platform-volume config block + fail-fast validation ✅ DONE
  - Surfaced by: §3.3, §5.1 — gating matrix + `BACKEND=s3|nfs`
  - Landed: `internal/config/config.go` (`PlatformVolumesConfig` + `Validate()` + loader + boot check), `internal/config/platform_volumes_test.go` (UC-17). **Still TODO:** `pkg/daemon/` wiring into the service (part of T3).
- [x] **T2 (P1)** — volumes — translation layer (sanitize, tenant-scope, backend mapping, quota) ✅ DONE
  - Surfaced by: §3.1, §3.2, §3.9, §7 Q1 — name→source mapping + tenant isolation + per-tenant cap
  - Landed: new `pkg/volumes/volumes.go` (`SanitizeVolumeName`, `TenantScope`, `BuildMountSpec` s3+nfs, `CheckQuota`), `pkg/volumes/volumes_test.go` — **98.5% coverage**, UC-07/08/09/13b/18/22/25/26/27. Pure package, no config/auth import. **Quota counting** (currentCount source) wires in at T3/T4.
- [ ] **T3 (P1, human: ~4h / CC: ~25min)** — service — wire synthesized volume mounts into create + runtime gate
  - Surfaced by: §3.5, §3.6, §5.3 — reject firecracker/wasm; operator creds through `sealMounts`
  - Files: `internal/service/service.go`
  - Verify: `go test ./internal/service/...`; UC-15, UC-21, boot-latency call-out in PR (`/touch-create-sandbox`)
- [ ] **T4 (P1, human: ~1d / CC: ~30min)** — store — `volumes` table + CRUD + unique(tenant,name)
  - Surfaced by: §3.8, §5.5, §8 — Daytona objects + reference-aware delete need persistence
  - Files: `internal/store/store.go` (`/add-store-column`)
  - Verify: `go test ./internal/store/...`; UC-28, UC-31; mandatory regression test
- [ ] **T5 (P1, human: ~4h / CC: ~25min)** — e2b — un-reject + translate + 412 gate + wasm reject + echo + sealed meta
  - Surfaced by: §1, §5.4 — remove `handlers.go:546`; carry name+path (no creds) in meta blob
  - Files: `pkg/api/e2b/handlers.go`, `pkg/api/e2b/meta.go`
  - Verify: `go test ./pkg/api/e2b/...`; UC-01, UC-14, UC-16, UC-19, UC-20
- [ ] **T6 (P1, human: ~6h / CC: ~35min)** — daytona — full /volumes CRUD + reference-aware delete (409 while attached)
  - Surfaced by: §3.8, §3.10, §5.5 — replace `volumesNotSupported`
  - Files: `pkg/api/daytona/handlers.go`, `pkg/api/daytona/routes.go`
  - Verify: `go test ./pkg/api/daytona/...`; UC-24, UC-28, UC-29, UC-30
- [ ] **T7 (P1, human: ~6h / CC: ~40min)** — sdk/models — `platform_volumes` field across models + 5 SDKs
  - Surfaced by: §5.6, §7 Q3 — dedicated request field, no creds on the wire
  - Files: `pkg/models` (CreateSandboxRequest), `sdk/{typescript,python,go,rust,java}`
  - Verify: per-SDK serialization test (UC asserting `platform_volumes` round-trips); `make test`
- [ ] **T8 (P2, human: ~3h / CC: ~20min)** — mounts — NFS backend translation + read-only propagation
  - Surfaced by: §3.1, §7 Q5 — second backend; export-layout mapping
  - Files: `pkg/volumes/` (backend branch), reuses `pkg/mounts/adapters/nfs.go`
  - Verify: `go test ./pkg/volumes/... ./pkg/mounts/...`; UC-25, UC-26, UC-27
- [ ] **T9 (P2, human: ~4h / CC: ~30min)** — docs — new `.mdx` (5 SDK tabs) + operator setup + sidebar
  - Surfaced by: §5.7 — top-level feature → new page
  - Files: `docs/src/content/docs/*.mdx`, `docs/src/content.config.ts`
  - Verify: `make docs-build`; no raw curl; five `syncKey="lang"` tabs
- [ ] **T10 (P2, human: ~4h / CC: ~30min)** — integration — live S3 + NFS scenarios behind `integration` tag
  - Surfaced by: §12 Test Plan — mocks can't prove real FUSE mount + cross-node reattach
  - Files: `integration-tests/suite/`, `integration-tests/suite/harness/`
  - Verify: `make integration-*` (operator-run); UC-03, UC-06, UC-26, UC-30

---

## 12. Test Plan (unit + integration)

Coverage goal is ~85% per touched package (CLAUDE.md). `make test` is offline —
**no AWS/NFS in plain `_test.go`.** Live backend behavior goes behind the
`integration` build tag.

### 12.1 Unit tests (offline, table-driven, `make test`)

```
PACKAGE / FILE                          UNIT TESTS (UC)
[+] pkg/volumes/  (new)
  ├── SanitizeVolumeName                 ★★★ valid/empty/traversal/uppercase/len  UC-07,08,09,22
  ├── tenantScope(authCtx)               ★★★ ownerRef present / PAT hashed fallback / stable across calls  UC-18
  ├── BuildVolumeMountSpec (s3)          ★★★ source/creds/options/read-only       UC-01,25,27
  ├── BuildVolumeMountSpec (nfs)         ★★★ server:export/tenant/name, no creds   UC-26,27
  └── quota check                        ★★  at cap / over cap                     UC-13b
[+] internal/config/config.go
  └── platform-volume block              ★★★ disabled / enabled+ok / enabled+misconfigured  UC-16,17
[+] internal/service/service.go
  ├── runtime gate                       ★★★ docker ok / firecracker reject / wasm reject  UC-15
  ├── sealMounts of operator creds       ★★  sealed at rest, redacted read view    UC-21
  └── duplicate/blocked target reuse     ★★  existing MountSpec.Validate path      UC-10,11,12,13a
[+] internal/store/store.go
  └── volumes table CRUD                 ★★★ create/get/list/delete + unique(tenant,name) [REGRESSION]  UC-28,31
[+] pkg/api/e2b/handlers.go + meta.go
  ├── translate volumeMounts→MountSpec   ★★★ 201 (was 501) / disabled 412 / wasm reject  UC-01,14,16
  └── echo + sealed-blob round-trip      ★★  name+path surfaced, no creds, survives restart  UC-19,20
[+] pkg/api/daytona/handlers.go
  ├── CRUD handlers                      ★★★ create/get/list                        UC-24,28
  └── reference-aware delete             ★★★ 409 attached / 200 unattached          UC-29,30
[+] sdk/{ts,py,go,rust,java}
  └── platform_volumes serialization     ★★  field round-trips on /v1 request       (per-SDK)

COVERAGE TARGET: ~85% per package. Mandatory regression: volumes table (host-port-pool-class rule).
```

### 12.2 Integration tests (live, `integration` build tag, operator-run)

These prove what mocks can't: a real `mount-s3`/`mount.nfs` FUSE mount, data
persistence across destroy, and **cross-node reattach** (the v2 correctness
claim). Live AWS/NFS — `integration-tests/suite/`, run via `make integration-*`.

| Scenario | Asserts | UC |
|---|---|---|
| INT-01 S3 attach + write + read-back | real mount-s3 mounts the tenant prefix; write visible in bucket | UC-01 |
| INT-02 Persistence across destroy | destroy sandbox → S3 object survives → new sandbox same name reads it | UC-02,03 |
| INT-03 **Cross-node reattach (cluster)** | 2nd sandbox placed on a different node sees the 1st's data (proves S3-as-source-of-truth, the v2 raison d'être) | UC-03 |
| INT-04 Concurrent shared mount | two live sandboxes mount same volume; both read; last-writer-wins documented behavior | UC-06 |
| INT-05 NFS backend end-to-end | mount.nfs against a real export; attach + persist | UC-26 |
| INT-06 Daytona delete reclaim | delete with no attachers actually removes the S3 prefix / NFS dir | UC-30 |
| INT-07 Reconcile after daemon restart | sealed specs re-mount the volume on sandboxd restart | UC-04,05 |
| INT-08 Tenant isolation (live) | tenant A cannot read tenant B's same-named volume's objects | UC-18 |

Harness: add scenarios to `integration-tests/suite/harness/` use-case registry;
per-scenario `.md`/`.json` matrices land in `reports/`. `make integration-reap`
cleans leaked instances. These cost money — operator-run, not in `make test`.

---

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR | architecture redirected to v2; 8 decisions resolved, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 1 | N/A | no UI scope — not applicable |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

**Architecture verdict:** v1 (host-local `VolumesRoot`) **superseded**. Two
intrinsic flaws found and designed out: cluster silent-empty-volume divergence
and unbounded host-disk DoS. v2 backs volumes with operator-configured shared
S3, reusing the shipped `pkg/mounts` S3 pipeline (synthesized sealed
`MountSpec{type:s3}`), making S3 the cross-node source of truth. Three prior
host-local decisions (localize-to-mountOne, per-host cap, cluster reject) are
folded in as superseded. Tenant isolation via `controlplane.AccessFromContext`
ownerRef (hashed-PAT fallback for open-source single-tenant) — verified
buildable in both build modes.

**Resolved this session (8 decisions):** v1→v2 architecture redirect
(host-local → shared-storage); localize-to-mountOne (superseded); per-host cap →
per-tenant quota; cluster reject → S3/NFS source-of-truth; tenant-scope key =
auth ownerRef + hashed-PAT fallback; Daytona = full CRUD with reference-aware
delete (+ `volumes` table); SDK = dedicated `platform_volumes` field;
concurrent = document+allow (delete 409 while attached); NFS backend ships in v1.

**Scope note:** Q2 (full Daytona CRUD) and Q5 (NFS) each expand v1 beyond the
minimal surface — a `volumes` store table and a second backend. Both are
deliberate, build-actionable, and reflected in §3, §5, §6 (31 use cases).

**VERDICT:** ENG CLEARED — v2 plan complete, no open architecture questions.
Before coding: read `pr-review.md`; run `/touch-create-sandbox` (boot path),
`/add-store-column` (`volumes` table), and `/add-mount-adapter` threat-model
thinking (operator-cred handling). Implementation is the next step, not more
review.

NO UNRESOLVED DECISIONS
