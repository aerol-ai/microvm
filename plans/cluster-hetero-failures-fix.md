# Plan — Fix `cluster-hetero` integration failures

Status: reviewed (plan-eng-review + Codex outside voice) · Author: investigation
from live `make integration-cluster-hetero keep` run (2026-06-22) · Scenario
report: `integration-tests/reports/cluster-hetero.md` (pass 60 · fail 17 · skip 9).

This plan fixes the failing use cases in the `cluster-hetero` scenario. After
review it is partitioned into three lanes:

- **Fix-now** (located root cause, writable test): **B1** (done + daemon harden),
  **B2** (firecracker driver), **B4** (SSH gateway gate).
- **Investigate-first** (reproduce → locate → test → fix): **B5** (session-attach
  forward), **B6** (S3 volume mount).
- **Tickets** (separate work, not this plan's PRs): **B3** (template routing —
  blocked on a design decision), **B8** (WASM test-data triage). **B7** folds
  into B1 verification.

Cluster under test: 1 ingress, 3 Raft servers, 4 role-specialized workers
(`worker-docker`, `worker-fc`, `worker-gvisor`, `worker-wasm`).

```
                          fix-now            investigate-first        tickets
  B1 gvisor advertise  ──► install.sh ✅
                          daemon harden ►
  B2 fc mkfs           ──► driver MkdirAll ►
  B4 ssh gateway       ──► gate relax ►
  B5 session attach    ─────────────────────► reproduce → fix
  B6 s3 mount          ─────────────────────► instrument(mount-s3) → fix
  B3 template routing  ────────────────────────────────────────────► decide first
  B7 createWithImage   ──► verify after B1 (folds in)
  B8 wasm ref          ────────────────────────────────────────────► triage fixtures
```

---

## 1. Use-case / bug inventory (≥40)

Legend — **Class**: `BUG` product/code · `INFRA` install/bootstrap · `TEST`
harness/data · `REGRESS` must-not-break. **Lane**: `FIX` fix-now · `INV`
investigate-first · `TKT` ticket.

| # | UC | Behavior | Class | Bug | Lane | Current |
|---|----|----------|-------|-----|------|---------|
| 1 | UC-25 | gVisor sandbox runs in cluster | INFRA | B1 | FIX | ❌ no placement target |
| 2 | UC-74 | CreateWithImage lands on a worker | BUG | B1/B7 | FIX | ❌ no placement target |
| 3 | — | gVisor node advertises `gvisor` in gossip | INFRA | B1 | FIX | ❌ `[docker wasm]` |
| 4 | — | gVisor create routes to gVisor worker | BUG | B1 | FIX | ❌ filtered by placement |
| 5 | — | `--with-gvisor` install self-sufficient | INFRA | B1 | FIX | ❌ needs manual env |
| 6 | — | Node with `SB_RUNTIME=gvisor` advertises it | BUG | B1 | FIX | ❌ daemon ignores cfg.Runtime |
| 7 | UC-24 | Firecracker sandbox runs (cold boot) | BUG | B2 | FIX | ❌ `mkfs.ext4: No such file or directory` |
| 8 | — | OCI→ext4 build has an existing output dir | BUG | B2 | FIX | ❌ jailer chroot not yet created |
| 9 | — | Firecracker overlay path has its dir | BUG | B2 | FIX | ❌ same RunDir, same gap |
| 10 | UC-80 | FC template clones distinct RNG | TEST | B2/B3 | TKT | ❌ needs FC build + routing |
| 11 | UC-47 | Create template | BUG | B3 | TKT | ❌ requires FC on serving node |
| 12 | UC-48 | List + get template | BUG | B3 | TKT | ❌ same |
| 13 | UC-49 | Rebuild template | BUG | B3 | TKT | ❌ same |
| 14 | UC-50 | Delete template | BUG | B3 | TKT | ❌ same |
| 15 | — | Template ops route to FC-capable node | BUG | B3 | TKT | ❌ node-local only |
| 16 | — | GET/LIST/DELETE/rebuild after routed create | BUG | B3 | TKT | ❌ per-host design |
| 17 | — | Later sandbox lands on template-bearing node | BUG | B3 | TKT | ⚠️ template-aware placement (placement.go:220) |
| 18 | UC-43 | SSH per-sandbox key over `:2220` | BUG | B4 | FIX | ❌ connection refused |
| 19 | UC-67 | Cross-node SSH rejects forged key | BUG | B4 | FIX | ❌ no gateway listening |
| 20 | — | SSH gateway reachable via ingress | BUG | B4 | FIX | ❌ gateway worker-only |
| 21 | — | Ingress-hosted gateway bridges to owner | BUG | B4 | FIX | ❌ not wired |
| 22 | — | Multi-ingress shares SSH host key | INFRA | B4 | FIX | ⚠️ host-key churn risk |
| 23 | UC-45 | Sessions attach websocket streams | BUG | B5 | INV | ❌ unexpected EOF |
| 24 | UC-44 | Exec on every available runtime | BUG | B5/B1/B2 | INV | ❌ no output |
| 25 | — | Session attach forwards to non-owner node | BUG | B5 | INV | ❌ EOF on forwarded hop |
| 26 | — | Exec/stream websocket forward (local owner) | REGRESS | B5 | INV | ✅ works (status 101) |
| 27 | UC-81 | Attach volume; write + read-back | BUG | B6 | INV | ❌ s3 mount timeout |
| 28 | UC-82 | Volume persists across destroy | BUG | B6 | INV | ❌ s3 mount timeout |
| 29 | UC-83 | Two sandboxes share one volume | BUG | B6 | INV | ❌ s3 mount timeout |
| 30 | UC-84 | Read-only volume rejects writes | BUG | B6 | INV | ❌ s3 mount timeout |
| 31 | — | mount-s3 process completes within timeout | BUG | B6 | INV | ❌ never ready |
| 32 | — | mount-s3 stderr captured on failure | BUG | B6 | INV | ❌ swallowed |
| 33 | — | Mount timeout cleanup vs cmd.Wait race | BUG | B6 | INV | ⚠️ manager.go:266 |
| 34 | — | Cross-node volume metadata lookup reliable | BUG | B6 | INV | ⚠️ `context deadline exceeded` |
| 35 | UC-26 | WASM sandbox from registered module | TEST | B8 | TKT | ❌ snapshot ref not found |
| 36 | — | Identify scheduling-vs-resolution failure | TEST | B8 | TKT | ❓ unknown which hop |
| 37 | UC-85 | Volumes rejected on WASM | REGRESS | B6 | — | ✅ keep |
| 38 | UC-86 | Volumes rejected on Firecracker | REGRESS | B6 | — | ✅ keep |
| 39 | UC-53 | New sandbox gets a placement | REGRESS | B1 | — | ✅ keep |
| 40 | UC-54 | Non-owner request forwards to owner | REGRESS | B5 | — | ✅ keep |
| 41 | UC-55 | Sandbox index consistent across nodes | REGRESS | B7 | — | ✅ keep |
| 42 | UC-11/23 | Docker sandbox runs | REGRESS | B1 | — | ✅ keep (advertise change) |
| 43 | UC-61 | `/v1/capacity` reports host capacity | REGRESS | B1 | — | ✅ keep |
| 44 | UC-28 | GPU + gVisor rejected (negative) | REGRESS | B1 | — | ✅ keep |

---

## 2. Fix-now lane

### B1 — gVisor never advertised to placement  ✅ install.sh done · daemon harden pending

**Symptom:** UC-25 / UC-74 fail `cluster: no worker placement target available`.
`worker-gvisor` advertised `["docker","wasm"]` — no `gvisor`.

**Root cause:** gVisor has no `SB_ENABLE_*` flag.
`supportedRuntimesForConfig` (`pkg/daemon/daemon.go:1397`) builds the advertised
list from `SB_HOST_RUNTIMES` (default `["docker"]`) plus firecracker/wasm enable
flags — it consults neither gVisor nor `cfg.Runtime`. `install.sh --with-gvisor`
installs `runsc` + registers it in docker but never writes `SB_HOST_RUNTIMES`.

**Fix (two parts):**

1. **install.sh (done, verified live):** `write_environment()` appends
   `SB_HOST_RUNTIMES=docker,gvisor` when `WITH_GVISOR == "true"`.
2. **Daemon harden (pending — review decision):** in `supportedRuntimesForConfig`,
   advertise gvisor when `cfg.Runtime == models.RuntimeGvisor`, so any deploy
   path (hand-set `SB_RUNTIME`, pre-installed runsc) advertises correctly — not
   just `--with-gvisor`. Keeps the flag-driven pattern for wasm/firecracker;
   adds default-runtime inference for the one runtime that has no flag.

```go
// supportedRuntimesForConfig (sketch)
runtimes := cfg.HostSupportedRuntimes
if len(runtimes) == 0 { runtimes = []string{models.RuntimeDocker} }
if cfg.Runtime == models.RuntimeGvisor { // no enable flag exists for gvisor
    runtimes = appendRuntimeIfMissing(runtimes, models.RuntimeGvisor)
}
if cfg.EnableFirecracker { runtimes = appendRuntimeIfMissing(runtimes, models.RuntimeFirecracker) }
if cfg.EnableWasm        { runtimes = appendRuntimeIfMissing(runtimes, models.RuntimeWasm) }
```

**Files:** `scripts/install.sh` (done), `pkg/daemon/daemon.go` (harden),
`pkg/daemon/daemon_test.go` (cases: `gvisor_install_advertises_gvisor` done;
add `default_runtime_gvisor_advertises_gvisor`).

**Verified live:** `worker-gvisor` → `host_supported_runtimes=[docker gvisor wasm]`;
leader saw it via gossip; `runtime:"gvisor"` create returned `status=started`.

**PR call-out:** cluster-correctness — gVisor nodes were silently unschedulable;
single-node unaffected. No FSM/placement code change.

**B7 folds in here:** UC-74 (`CreateWithImage` "no placement target") is the same
error class. After B1, re-run UC-74. If it still fails, the create-placement
path differs from plain create — and note there are **two** create-placement
implementations (`pkg/api/v1/cluster_handler.go` and
`pkg/api/clustercreate/clustercreate.go`); fix both or confirm one delegates to
the other, so native / Daytona / E2B don't split.

---

### B2 — Firecracker driver doesn't create the jailer chroot before rootfs staging

**Symptom:** UC-24 fails
`oci: mkfs.ext4 ... /srv/jailer/firecracker/sb-XXX/root/rootfs.ext4 ...:
mkfs.ext4: No such file or directory while trying to determine filesystem size`.
On the host, `/srv/jailer/firecracker/` did not exist (only an empty
`/srv/jailer/`).

**Root cause:** in `internal/runtime/firecracker/driver.go`, Step 3 stages the
rootfs at `rootfsPath := filepath.Join(handle.RunDir(), rootfsFileName)`
(driver.go:553). The Step 2 comment claims "spawn ... creates the runDir we need
before staging" (driver.go:515) — but with `UseJailer=true` (the fc node's
config), `RunDir()` returns the **jailer chroot root**, which the jailer binary
creates only when it execs firecracker, *after* staging. So the directory
doesn't exist when mkfs runs.

**Fix (review decision: driver, not the OCI builder):** in the driver, after
`d.spawn(...)` and before Step 3, `os.MkdirAll(handle.RunDir(), 0o755)`. This
keeps chroot-lifecycle ownership in the driver/jailer layer (the OCI builder
stays a generic "write to OutPath" tool) and also covers the overlay path, which
uses the same `RunDir()` (driver.go:668, :683). Confirm the pre-created dir
doesn't conflict with the jailer's own chroot setup (ownership/chown); if the
jailer chowns the chroot to the jailed UID after the fact, a root-created empty
dir is fine.

**Files:** `internal/runtime/firecracker/driver.go` (MkdirAll after spawn);
driver test asserting `handle.RunDir()` exists before `rootfs.Build` is invoked
(table-driven, matching the package's existing style). Note: the plan's earlier
`pkg/oci/builder.go` location is **rejected** — fix is in the driver.

**PR call-out:** boot-path — firecracker cold boot only; one `MkdirAll` before
the seconds-scale skopeo/umoci/mkfs pipeline (no latency concern).

---

### B4 — SSH gateway runs only on workers; public `:2220` (ingress) has none

**Symptom:** UC-43 `dial tcp <ingress>:2220: connection refused`; UC-67 observes
no auth failure. Live: nothing on `:2220` (only `sshd` on `:22`).

**Root cause:** `pkg/daemon/daemon.go:683` gates the gateway on
`cfg.EnableSSHGateway && cfg.IsWorker()`. Public DNS → ingress, which is not a
worker. (Pre-cluster-join boots logged "listening" because the role defaulted to
worker before the cluster drop-in set `ingress` — masking the gap.)

**Fix (review decision: Option B — run on ingress too):** relax the gate to
`cfg.EnableSSHGateway && (cfg.IsWorker() || cfg.IsIngress())`. Verified safe:
`sshgateway.New` takes a `DockerExec` **interface** (`pkg/sshgateway/gateway.go:90`),
and when `RemoteAPIBaseURL` is set (cluster mode, daemon.go:694) the remote
bridge path is used and the local docker client is bypassed
(`gateway.go:81`); the ingress has docker installed, so `New` gets a non-nil
client regardless. **No sshgateway change needed.** L4-proxy (Option A) rejected
as redundant — Terraform already opens `:2220` on ingress-bearing nodes.

**Host-key call-out (Codex):** a multi-ingress cluster needs **shared** SSH host
key material or clients see host-key churn between ingress nodes. Terraform has a
host-key variable; tie the daemon change to it (provision the same
`SB_SSH_HOST_KEY_PATH` material across ingress nodes). For single-ingress
(this scenario) it's a no-op, but the PR must state the multi-ingress
requirement so it isn't discovered in production.

**Files:** `pkg/daemon/daemon.go` (gate); a wiring test asserting the gate
returns true for the ingress role; Terraform/bootstrap note for shared host key.

**PR call-out:** cluster — SSH reachability in cluster mode; a connection landing
on a non-owner node bridges to the owner via the existing `RemoteAPIBaseURL`
path; single-node unchanged.

---

## 3. Investigate-first lane (reproduce → locate → test → fix)

### B5 — Session-attach websocket EOF when forwarded to a non-owner node

**Symptom:** UC-45 `attach ... /sessions/<id>/attach: unexpected EOF`. UC-44
partly downstream. exec/stream **does** upgrade (status 101) when owned locally.

**What's known:** both exec/stream and sessions/attach go through the same
`proxyToToolbox` → `ServeToolboxReverseProxy` (`pkg/api/v1/proxy.go:31`). The
working case was local-owner; the failing case was cross-node forwarded. The
drop point is **not located**.

**Investigation done (code-level, 2026-06-23) — two mechanical causes RULED OUT:**

1. **Not HTTP/2-vs-websocket.** The cluster-internal mTLS channel is HTTP/1.1 on
   both ends: `clientConfig()` / `serverConfig()` (`internal/cluster/tls.go:74,88`)
   set no `NextProtos`, and the mtls proxy transport (`client.go:204`) has a
   non-nil `TLSClientConfig` without `ForceAttemptHTTP2`, so Go does not
   auto-enable h2. HTTP/1.1 supports the 101 upgrade + hijack a websocket needs.
2. **Not a server write-timeout cutting the stream.** The owner's internal mTLS
   server (`internal_server.go:105`) sets only `ReadHeaderTimeout: 10s` — no
   `WriteTimeout` / `IdleTimeout` to kill a long-lived hijacked conn.

The forward proxy (`forward.go:47`) is a standard upgrade-capable `ReverseProxy`,
and the toolbox hop is the *same* `ServeToolboxReverseProxy` code that exec/stream
(UC-44) upgrades through fine when local. So the delta is purely the **cross-node
forward hop**, and the remaining suspect is the double-proxy 101 interaction:
the ingress `ReverseProxy` must surface the owner's switched-protocol conn while
the owner's internal server simultaneously hijacks for its own toolbox upgrade
(ReverseProxy-over-ReverseProxy for a 101). This needs a live/integration
reproduction to pin — not fixable blind.

**Reproduction recipe (next step):** a two-node integration test (or the live
cluster) that creates a session on node B, then dials
`wss://<nodeA>/v1/sandboxes/<id>/sessions/<sid>/attach` so the request is
forwarded A→B. Capture on both nodes whether the 101 is emitted by the toolbox,
reaches node B's internal server, and survives the mTLS hop back to A. Codex's
steer stands: it's the two-hop/close semantics, not generic proxy stripping.

**Test requirement once located:** an **end-to-end v1 route test** through
`clusterForwardWrap → sessionsProxy → ServeToolboxReverseProxy`, not just a
`forward.go` unit test. Add a `forward_test.go` upgrade case only if the located
cause is actually in the forward layer.

**Files (TBD after repro):** likely `pkg/api/v1` (sessionsProxy / toolbox proxy),
possibly `internal/cluster/forward.go`; tests at the v1 route level.

---

### B6 — S3 platform-volume mount never completes (mount-s3, not rclone)

**Symptom:** UC-81..84 `mount external storage: mount 0 (s3): timed out waiting
for mount at .../0`. Also `cleanup platform volume lookup failed ... GET
.../v1/cluster/internal/volume: context deadline exceeded`.

**Correction (Codex):** S3 platform volumes use AWS **`mount-s3`** (mountpoint-s3),
NOT rclone — `pkg/mounts/adapters/s3.go:29` shells out to `mount-s3`. (rclone is
installed for a *different* mount type.) The earlier plan's "capture rclone
stderr" was wrong and would not explain these failures.

**Instrumentation DONE (2026-06-23):**
1. ✅ Capture `mount-s3` stdout+stderr into a capped buffer and surface the tail
   in the returned error — `pkg/mounts/process.go` (new: `capturedOutput`,
   `spawnMountProcess`, `mountWaitError`), wired into `mountOne` and the
   supervisor restart in `pkg/mounts/manager.go`. The error keeps the
   backward-compatible "timed out waiting for mount" phrase and now appends
   `(mount tool output: …)`. Test: `pkg/mounts/process_test.go`.
   - Liveness hint (alive-vs-exited) was prototyped then **dropped**: on the
     failure path nobody reaps the process, so an exited tool lingers as a
     zombie that a signal-0 probe still reports as "running". The captured
     stderr is the reliable signal; a misleading hint is worse than none.

**Still investigate-first (needs the captured stderr from a live run):**
2. The fast-fail gap: a mount tool that exits immediately still burns the full
   `SB_MOUNT_WAIT_TIMEOUT` because `waitForMountProbe` only polls the mountpoint.
   Racing the probe against process exit needs a single-owner `cmd.Wait`
   refactor (the supervisor also calls `cmd.Wait`), so it's deferred until the
   stderr proves the actual failure is fast-exit vs. hang.
3. Cross-node volume metadata: the lookup's role matters — worker/agent reads go
   through the agent control-plane endpoint; voters read local FSM. Identify
   **which role timed out** before changing any timeout/retry; the "longer
   timeout" idea is a guess until then. (Server-side `/internal/volume` answered
   in microseconds in the captured logs, so the bare-timeout was the mount, not
   this lookup — but confirm with the new stderr.)

**Files (TBD after instrument):** `pkg/mounts/adapters/s3.go`,
`pkg/mounts/manager.go`, the volume-lookup client; tests in `pkg/mounts`.

**PR call-out:** mounts run host-side (pr-review §5); document the
partially-mounted-volume rollback rule.

---

## 4. Tickets (separate from this plan's PRs)

### B3 — Template ops are node-local; routing them is a real design problem (blocked on decision)

**Symptom:** UC-47..50 (+ UC-80) `template create requires SB_ENABLE_FIRECRACKER`
on a non-FC serving node; `worker-fc` advertises firecracker but never receives
the request.

**Why it's a ticket, not a quick fix (Codex):** templates are **per-host by
design** (`pkg/api/v1/template.go:9`). Forwarding only `POST /templates` breaks
`GET` / `LIST` / `DELETE` / rebuild unless there's template ownership, fanout, or
a cluster template catalogue. And creates with `TemplateID` are filtered by
**local template inventory** in placement (`internal/cluster/placement.go:220`) —
so a routed template create must guarantee that later sandbox placement targets
the same artifact-bearing node. This is cluster-FSM-adjacent work.

**Decision needed before coding:** product routing + template catalogue
(large, cluster-correctness work) vs. test-only (target a FC worker for
UC-47..50 + return a clear "no firecracker-capable node, candidates: …" error).
Recommend deciding via a focused design pass, not folding into this plan.

### B8 — WASM ref (UC-26): triage scheduling-vs-resolution before touching fixtures

**Symptom:** UC-26 `resolve module "aocr.aerol.ai/.../snapshots/python:latest--ttl-1h":
wasm module not found`.

**Why it's a ticket (Codex):** WASM placement has authoritative module-inventory
filtering; a bad ref can fail at **scheduling** (no node advertises the module)
or at **owner-local resolution** (scheduled, then resolver misses). Identify
which before changing test fixtures — otherwise the "register the module" fix may
not address the real path.

---

## 5. NOT in scope

- **B3 product routing / template catalogue** — deferred to its own design pass;
  blocked on the routing-vs-test decision.
- **Multi-ingress shared host-key provisioning automation** — B4 ships the daemon
  gate + the call-out; the Terraform automation for shared host keys is a
  follow-up unless multi-ingress is being deployed now.
- **B6 timeout/retry tuning** — explicitly NOT done until instrumentation proves
  the failing role/hop.
- **WASM reserved-module distribution to all roles** — the ingress "did not
  resolve" warning is benign (ingress runs no WASM sandboxes); not touched.
- **Rewriting the two create-placement paths into one** — B7 fixes behavior in
  both; consolidating them is separate tech-debt.

## 6. What already exists (reused, not rebuilt)

- **Capacity advertising + gossip** (`pkg/capacity`, `internal/cluster`) — B1
  reuses the existing `SupportedRuntimes` advertisement; no new mechanism.
- **Cross-node SSH bridge** (`RemoteAPIBaseURL`, daemon.go:694) — B4 reuses it;
  the ingress gateway forwards to the owner exactly like the worker path.
- **Jailer chroot lifecycle** (`internal/runtime/firecracker/jailer.go`) — B2
  fixes ordering within it, doesn't add a new path.
- **Reverse-proxy upgrade forwarding** (`ServeToolboxReverseProxy`) — B5 keeps
  it; the bug is in the two-hop/context path, not a new proxy.
- **mount-s3 adapter** (`pkg/mounts/adapters/s3.go`) — B6 instruments it, doesn't
  replace it.

## 7. Failure modes (fix-now codepaths)

| Codepath | Realistic failure | Test? | Error handling? | User sees |
|---|---|---|---|---|
| B1 daemon harden | `cfg.Runtime` empty → no gvisor advertised | yes (new case) | n/a (pure fn) | clear (placement error) |
| B2 MkdirAll(RunDir) | jailer later chowns chroot, root-owned dir conflicts | driver test | spawn/Build error returned | clear (create fails with reason) |
| B4 ingress gateway | multi-ingress host-key churn | wiring test (gate) | n/a | **host-key warning** — call-out, not silent |
| B4 ingress gateway | ingress has no docker client (non-cluster) | wiring test | `New` error surfaced | clear |

No fix-now failure mode is both untested and silent → **no critical gaps in the
fix-now lane.** (B5/B6 silent-timeout failures are exactly why they're
investigate-first: instrumentation removes the silence before any fix.)

## 8. Parallelization

| Step | Modules | Depends on |
|---|---|---|
| B1 daemon harden | `pkg/daemon` | — |
| B2 driver mkdir | `internal/runtime/firecracker` | — |
| B4 gateway gate | `pkg/daemon` | — |
| B5 investigate | `pkg/api/v1`, `internal/cluster` | repro |
| B6 investigate | `pkg/mounts` | instrument |

```
Lane A: B1 → B4 (sequential — both edit pkg/daemon)
Lane B: B2 (independent — internal/runtime/firecracker)
Lane C: B6 (independent — pkg/mounts)
Lane D: B5 (independent — pkg/api/v1 + cluster)
```

Launch A, B, C, D in parallel worktrees. **Conflict flag:** B1 and B4 both touch
`pkg/daemon/daemon.go` — keep them in one lane (sequential), not parallel.

## 9. Implementation Tasks

Synthesized from this review. P1 blocks the scenario; P2 same-branch; P3 follow-up.

- [x] **T1 (P1)** — pkg/daemon — Harden `supportedRuntimesForConfig` to advertise gvisor when `cfg.Runtime == RuntimeGvisor` ✅ DONE
  - Surfaced by: Code-quality review — B1 couples advertising to install flag (daemon.go:1397)
  - Files: `pkg/daemon/daemon.go`, `pkg/daemon/daemon_test.go` (3 new cases)
  - Verify: `go test -run TestSupportedRuntimesForConfig ./pkg/daemon/` ✅ pass. install.sh half shipped + verified live.
- [x] **T2 (P1)** — firecracker driver — `MkdirAll(handle.RunDir())` after spawn, before Step 3 staging ✅ DONE
  - Surfaced by: Architecture review — jailer chroot not created until firecracker exec (driver.go:515,553)
  - Files: `internal/runtime/firecracker/driver.go`, `internal/runtime/firecracker/create_rundir_test.go` (new)
  - Verify: `TestCreate_CreatesRunDirBeforeStaging` ✅ pass; integration UC-24 (live)
- [x] **T3 (P1)** — pkg/daemon — Relax SSH gateway gate to `IsWorker() || IsIngress()` (extracted `shouldStartSSHGateway`) ✅ DONE
  - Surfaced by: Architecture review — public :2220 → ingress has no gateway (daemon.go:683)
  - Files: `pkg/daemon/daemon.go`, `pkg/daemon/daemon_test.go`; host-key call-out in code comment
  - Verify: `TestShouldStartSSHGateway` ✅ pass; integration UC-43/67 (live)
- [x] **T4 (P2)** — pkg/mounts — Capture mount-s3 stdout+stderr, surface in error ✅ INSTRUMENT DONE
  - Surfaced by: Performance/Code review + Codex — stderr swallowed; tool is mount-s3 not rclone (s3.go:29)
  - Files: `pkg/mounts/process.go` (new), `pkg/mounts/manager.go`, `pkg/mounts/process_test.go` (new)
  - Verify: `TestMountWaitErrorSurfacesToolOutput` ✅ pass. Fast-fail refactor + cross-node lookup still deferred to live re-triage.
- [~] **T5 (P2)** — pkg/api/v1 — Locate session-attach forward drop 🔎 INVESTIGATED, not fixed
  - Surfaced by: Test review + Codex — root cause not located; forward unit test passes vacuously
  - Findings: ruled out h2 (both ends HTTP/1.1) and server write-timeout; narrowed to the double-proxy 101 interaction on the cross-node hop. Needs a 2-node reproduction.
  - Files: TBD (`internal/cluster/forward.go` / internal server / `pkg/api/v1`)
  - Verify: two-node integration test dialing a forwarded `/sessions/<id>/attach`; integration UC-45
- [ ] **T6 (P3, human: — / CC: —)** — verify — Re-run UC-74 after B1; if still failing, fix both create-placement paths
  - Surfaced by: Codex — `cluster_handler.go` vs `clustercreate/` divergence
  - Files: `pkg/api/v1/cluster_handler.go`, `pkg/api/clustercreate/clustercreate.go`
- [ ] **T7 (P3 ticket)** — design — Decide B3 template routing (product catalogue vs test-only)
- [ ] **T8 (P3 ticket)** — test — B8 triage WASM scheduling-vs-resolution before changing fixtures

## 9b. New integration regression guards (added 2026-06-23)

Behind the `integration` build tag in `integration-tests/suite/regression_fixes_test.go`,
registered in `harness/usecases.go`. These pin the fixes more tightly than the
broad full-suite UCs they sit beside:

| UC | Guards | Asserts |
|----|--------|---------|
| UC-87 | B1 | every specialized runtime the scenario has a capability for (gvisor/firecracker/wasm) appears in some member's gossiped `capacity.supported_runtimes` — the layer that was broken, vs UC-25 which only checks a gVisor create happens to succeed |
| UC-88 | B2 | a firecracker sandbox cold-boots from a plain OCI image (no template) and execs — forces the `mkfs.ext4` → jailer-chroot path UC-24 may skip via the template fast-path |
| UC-89 | B4 | a raw TCP dial to the ingress public host `:2220` returns an `SSH-…` banner — proves a gateway is bound on the ingress, independent of sandbox routing/retry that UC-43 hides behind |

Run on a live cluster via the existing `make integration-cluster-hetero` path; they
SKIP where the scenario lacks the capability (e.g. UC-88 on a non-firecracker
scenario). B6's error-surfacing is covered offline by `pkg/mounts/process_test.go`;
a live negative volume test is deferred until the mount-s3 stderr from a real run
confirms the failure shape.

## 10. Landing order

1. **B1 daemon harden** (T1) — install.sh already shipped + verified.
2. **B2** (T2) — self-contained driver fix.
3. **B4** (T3) — sequential after B1 (same file).
4. **B6 instrument** (T4) — surface mount-s3 stderr, then re-triage.
5. **B5 reproduce** (T5) — locate before fixing.
6. **B7 verify** (T6); **B3/B8 tickets** (T7/T8).

B5/B6 do **not** become normal fix PRs until the failing hop/process is proven.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 4 | issues_found | 12 problems, all folded |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 4 | reviewed | 5 issues, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CODEX:** caught one factual error (B6 uses `mount-s3`, not rclone — verified at `s3.go:29`) plus 11 enrichments (B3 per-host template + placement.go:220 inventory filter, B7 dual create-placement paths, B4 multi-ingress host-key churn, B5 two-hop not generic-proxy). All folded with user approval.
- **CROSS-MODEL:** No tension — Codex's points were corrections/enrichments, not conflicts. The B6 mount-s3 correction reversed a wrong assumption in the original plan.
- **VERDICT:** ENG CLEARED — plan partitioned (fix-now B1/B2/B4 · investigate-first B5/B6 · tickets B3/B8), 5 decisions resolved, 0 critical gaps. Ready to implement the fix-now lane.

Decisions resolved this review: scope partition (fix-now vs investigate); B2 fix site (firecracker driver, not OCI builder); B4 topology (Option B gate relax, no sshgateway change); B1 depth (also harden daemon `cfg.Runtime`); B5 reclassified investigate-first.

NO UNRESOLVED DECISIONS
