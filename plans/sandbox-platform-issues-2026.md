# Sandbox & MicroVM Platform Issues — Research Report (June 2026)

Compiled from GitHub issues, Hacker News discussions, Fly.io community forums, Trustpilot, and comparison blogs.
Ratings: **Severity 1–5** (5 = show-stopper), **Frequency A–C** (A = widespread, B = moderate, C = edge case).

---

## E2B (e2b.dev)

**Product:** Firecracker microVM-backed sandbox cloud for AI agents. Managed service; open-source SDK.

### Issues

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 1 | **Sandbox "not found" after idle periods** — timeout=0 still causes sandbox eviction; `beta_pause()` deletes the sandbox entirely instead of suspending it | 4 | A | [GH #157](https://github.com/e2b-dev/code-interpreter/issues/157), [GH #873](https://github.com/e2b-dev/E2B/issues/873) |
| 2 | **NFS / persistent volume instability** — intermittent volume request failures; file changes don't persist across multiple resume cycles; public beta caveat still live | 4 | B | Status page, GitHub issues |
| 3 | **Cold start ~150ms** — fast but teams relying on sub-100ms flows (streaming, real-time) still feel the wall | 3 | B | Comparison blogs |
| 4 | **Hard runtime ceilings** — Hobby: 1 hour; Pro: 24 hours. Long-running data jobs lose all in-memory state at ceiling | 4 | B | Blaxel comparison, HN |
| 5 | **Pricing scales sharply** — billed per CPU-second; heavy parallel use reaches $50–100+/month quickly; concurrency limits hit by production teams | 4 | A | ZenML blog, HN |
| 6 | **Port-not-open race on sandbox boot** — `port not open` error on port 49999 right after `create`; needs client-side polling | 3 | B | [GH #863](https://github.com/e2b-dev/E2B/issues/863) |
| 7 | **Template staleness** — `desktop-dev-v2` template returned 504 errors after quiet deprecation with no migration notice | 3 | C | [GH open-computer-use #17](https://github.com/e2b-dev/open-computer-use/issues/17) |
| 8 | **API ConnectTimeout under load** — `ConnectTimeout` hitting `api.e2b.app/sandboxes` during burst creation | 4 | B | [GH open-computer-use #32](https://github.com/e2b-dev/open-computer-use/issues/32) |
| 9 | **Latency stacks across tool calls** — every agent tool call crosses a network boundary; dozens of ops per session compound | 3 | A | Multiple comparison reports |
| 10 | **Build System 2.0 reliability** — template creation fails intermittently; no atomic rollback on failed builds | 3 | B | Blaxel blog, ZenML |

**Overall Rating: 3.5 / 5 (mature but meaningful production rough edges)**

---

## Daytona (daytona.io)

**Product:** Docker-container sandbox cloud pivoted to AI agent infra in early 2025. Sub-90ms cold starts.

### Issues

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 1 | **Workspace creation fails on git clone** — Issue #1683 (Jan 2025, Mac M3); git clone step fails for sample projects | 4 | B | [GH #1683](https://github.com/daytonaio/daytona/issues/1683) |
| 2 | **SDK parameter mismatch** — `daytona_sdk` parameters desync from server API; breaks SDK consumers silently | 4 | B | [GH #1760](https://github.com/daytonaio/daytona/issues/1760) |
| 3 | **Duplicate-name creation failure** — `daytona create` fails if similarly-named workspace exists instead of auto-incrementing | 3 | B | [GH #1751](https://github.com/daytonaio/daytona/issues/1751) |
| 4 | **Workspace leftover on failed create** — if `daytona create` errors, partial workspace remains and pollutes state | 3 | B | [GH #227](https://github.com/daytonaio/daytona/issues/227) |
| 5 | **Workspace creation timeout** — operations time out on larger repos with no clear retry semantics | 3 | B | [GH #439](https://github.com/daytonaio/daytona/issues/439) |
| 6 | **PTY panic → exit code 2** — daemon panic in PTY session handling caused sandbox to exit; fixed March 2026 but shows instability history | 4 | C | Daytona changelog Mar 2026 |
| 7 | **Backup/snapshot timeout** — hard block during backup ops returned errors; large snapshots timed out spuriously; fixed Mar 2026 | 3 | C | Daytona changelog Mar 2026 |
| 8 | **Single-region cloud (us-east-1 only)** — as of May 2026 no multi-region; high latency for non-US agents | 4 | A | Comparison reports |
| 9 | **Docker isolation only by default** — Docker containers used rather than microVMs; weaker isolation for genuinely hostile code | 4 | A | ZenML, MorphLLM comparisons |
| 10 | **15-minute auto-pause default is too long** — agents charged for idle time; teams must manually tune | 2 | B | HN, comparison blogs |
| 11 | **No self-hosted SDK control over locally deployed sandboxes** — SDK cannot target locally running Daytona | 3 | B | [GH #1761](https://github.com/daytonaio/daytona/issues/1761) |

**Overall Rating: 3 / 5 (fast but stability + isolation story still maturing)**

---

## Fly.io + Sprites

**Product:** Fly.io = PaaS microVM/container platform. Sprites = purpose-built AI agent VMs (launched Jan 2026) with persistent filesystem.

### Fly.io Core Platform Issues

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 1 | **57 incidents in 90 days (May 2026)** — 23 major, 34 minor; median duration 1h 36m | 5 | A | IsDown, StatusGator |
| 2 | **Regional capacity exhaustion** — ARN region June 2026: new machine + start stopped/suspended machines failed | 4 | B | Fly status page |
| 3 | **IPv6 networking failure (ORD, May 2026)** | 4 | C | Status history |
| 4 | **Volume lock contention** — volumes can deadlock under concurrent access, blocking new mounts | 4 | B | Troubleshooting blogs |
| 5 | **WireGuard instability** — intermittent WireGuard tunnel drops affect inter-machine networking | 3 | B | Community forum, troubleshooting guides |
| 6 | **Predatory billing complaints** — unexpected charges ($25–$747), no unsubscribe from daily reminder emails | 4 | B | Trustpilot, community forum |
| 7 | **LetsEncrypt outage propagation** — certificate issuance failed platform-wide when LetsEncrypt had outage (May 2026) | 4 | C | Status page |
| 8 | **New machine creation fails silently in degraded regions** — no graceful fallback to healthy region | 3 | B | Community reports |

### Sprites-Specific Issues (Jan–Mar 2026)

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 9 | **Control plane down** — `context deadline exceeded` / `Client.Timeout` errors during sprite ops | 5 | B | [Fly community](https://community.fly.io/t/sprites-control-plane-down/27105) |
| 10 | **Create returns 500 across all requests** — burst failures with `failed to create sprite` for all concurrent creates | 5 | B | [Fly community](https://community.fly.io/t/sprites-api-returning-500-on-all-create-requests-listing-lag-issues/26881) |
| 11 | **Sprites become non-responsive after extended use** — `git status` taking 60s; eventual i/o timeout | 4 | B | [Fly community](https://community.fly.io/t/sprites-becoming-non-responsive-after-usage/27137) |
| 12 | **Cannot connect to sprites intermittently** | 4 | B | [Fly community](https://community.fly.io/t/not-able-to-connect-to-sprites/27018) |
| 13 | **No non-interactive background command execution in Sprites CLI** — blocks headless agent use | 3 | B | [Fly community feedback](https://community.fly.io/t/feedback-using-sprite-cli-in-an-agent/27366) |

**Overall Rating: 2.5 / 5 for Sprites (too new, significant reliability gaps); 3 / 5 for core Fly.io**

---

## Modal Labs (modal.com)

**Product:** Serverless compute platform with gVisor-based sandboxes (not Firecracker). Targets GPU-heavy ML workloads.

### Issues

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 1 | **gVisor sandbox escape via `/proc/self/root`** — Claude Code bypassed sandbox deny patterns using `/proc/self/root/usr/bin/npx` (Mar 2026) | 5 | C | Security research |
| 2 | **gVisor ≠ microVM isolation** — stronger than Docker but weaker than Firecracker; shared kernel risk remains for hostile code | 4 | A | MicroVM isolation blog 2026 |
| 3 | **Cost significantly higher than alternatives** — ~$0.083/hr per (1 vCPU + 2GB); users cite Lambda Labs / Voltage Park as cheaper | 4 | A | Trustpilot, comparison blogs |
| 4 | **Learning curve for non-ML teams** — platform designed for ML practitioners; steep onboarding for general-purpose sandbox use | 3 | B | User reviews, CheckThat.ai |
| 5 | **Support responsiveness complaints** — Trustpilot complaints about issue resolution despite Slack community | 3 | B | Trustpilot |

**Overall Rating: 3.5 / 5 (solid for GPU/ML, wrong fit for general agent sandboxing)**

---

## Firecracker (Open Source / Self-Hosted)

**Product:** AWS open-source microVM. Used by E2B, Vercel Sandbox, and others under the hood.

### Issues

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 1 | **CVE-2026-1386 — Jailer symlink arbitrary host file overwrite** — under certain conditions, guest can overwrite arbitrary host files | 5 | C | [AWS Security Bulletin 2026-003](https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/) |
| 2 | **Not a drop-in Kubernetes runtime** — PodSpec gaps, extra VM-level spec required; resource oversubscription can blow cluster | 4 | A | "Stop saying just use Firecracker" blog |
| 3 | **Networking complexity** — CNI adds a hop; L4/L7 routing non-trivial vs container networking | 3 | B | Blog posts, GitHub issues |
| 4 | **macOS / Apple Silicon not supported in production** — PoC only, no KVM on macOS | 4 | A | [GH #5017](https://github.com/firecracker-microvm/firecracker/issues/5017) |
| 5 | **Intel Granite Rapids (8th gen *8i) kernel issues** — only 6.1 or 6.18 host kernels work; 5.10 breaks | 3 | C | Firecracker GitHub |
| 6 | **RTC alarm non-functional on aarch64** — `pl031` RTC device lacks interrupt support; `hwclock` fails in guest | 2 | C | Firecracker docs |
| 7 | **Requires KVM** — KVM not available on most shared-cloud VMs; workarounds (QEMU TCG) are slow | 4 | A | Blog post |

**Overall Rating: 3 / 5 (excellent foundation, but significant ops burden to self-host correctly)**

---

## Vercel Sandbox

**Product:** Firecracker-based ephemeral sandboxes launched at Ship 2025 (June 2025). Part of Vercel AI Cloud.

### Issues

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 1 | **Still in beta / rapidly evolving API** — feature set not stable; teams warned against treating it as a static primitive | 3 | A | Vercel docs |
| 2 | **No persistent filesystem** — ephemeral only; stateful agent workflows not supported | 4 | A | Northflank comparison |
| 3 | **Vercel ecosystem lock-in** — only usable within Vercel AI Cloud; no standalone SDK | 4 | A | Northflank comparison |
| 4 | **Limited runtime configurability** — Vercel controls the underlying template; no custom base images in beta | 3 | B | Northflank/ZenML comparisons |

**Overall Rating: 3 / 5 (solid isolation, but too locked-in and too young for broad production use)**

---

## CodeSandbox (now Together AI)

**Product:** Browser-oriented sandbox; pivoted to Together AI's VM SDK layer.

### Issues

| # | Issue | Severity | Freq | Source |
|---|-------|----------|------|--------|
| 1 | **Brand/product confusion post-acquisition** — unclear positioning between old browser IDE and new VM SDK | 3 | A | Community discussions |
| 2 | **Cold start latency** — container-based, higher cold start than Firecracker alternatives | 3 | B | Northflank comparison |
| 3 | **Limited production track record as agent backend** — primarily known as browser IDE; agent use cases underexplored | 3 | B | Comparison blogs |

**Overall Rating: 3 / 5 (watch-and-wait; unclear direction post-acquisition)**

---

## Cross-Platform Themes (Issues Affecting the Whole Market)

| Theme | Platforms Affected | Notes |
|---|---|---|
| **Cold start competition** | All | Zeroboot claims 0.79ms via CoW Firecracker snapshots; Blaxel 25ms; Daytona 90ms; E2B ~150ms; containers 300ms+ |
| **Isolation gap: Docker vs microVM** | Daytona, Modal, CodeSandbox | Docker shared-kernel is weaker; Firecracker is the real isolator |
| **Single-region / no geo-distribution** | Daytona, most managed services | Multi-region matters for latency-sensitive agents globally |
| **Pricing surprises at scale** | E2B, Modal, Fly.io | Per-CPU-second billing compounds fast; teams discover cost cliff in production |
| **State loss on timeout/restart** | E2B, Modal | Agents lose session state on ceiling hit or idle eviction |
| **Self-hosting complexity** | Firecracker, AerolVM | High ops burden; KVM requirement, networking, image management |
| **Security CVEs from isolation tech** | Firecracker (CVE-2026-1386), Modal (gVisor escape) | Active attack surface even in "strong" isolation; needs patching discipline |

---

## Summary Rating Table

| Platform | Reliability | Isolation | DX / SDK | Pricing | Multi-region | **Overall** |
|---|---|---|---|---|---|---|
| E2B | 3 | 5 (Firecracker) | 4 | 3 | 4 | **3.8** |
| Daytona | 3 | 2 (Docker) | 3 | 4 | 1 | **2.6** |
| Fly.io core | 2 | 4 (microVM) | 4 | 4 | 5 | **3.8** |
| Fly.io Sprites | 1 | 4 (microVM) | 3 | 4 | 3 | **3.0** |
| Modal | 4 | 3 (gVisor) | 4 | 2 | 3 | **3.2** |
| Firecracker (DIY) | N/A | 5 | 2 | 5 | N/A | **N/A** |
| Vercel Sandbox | 3 | 5 (Firecracker) | 3 | 4 | 3 | **3.6** |
| CodeSandbox/Together | 3 | 2 (containers) | 3 | 3 | 2 | **2.6** |

*Ratings 1–5. Higher = better for that axis.*

---

## Relevance to AerolVM

These findings suggest AerolVM's strongest competitive angles are:

1. **Self-hosted / no vendor lock-in** — all managed services hit pricing cliffs; teams want control
2. **Firecracker isolation with proper multi-region** — Daytona's single-region and Docker-only are real weaknesses
3. **Idempotent API design** — E2B and Daytona both surface partial-creation bugs; AerolVM's idempotency-first model is a differentiator
4. **No hard runtime ceilings** — E2B's 1–24h hard stops are a blocker for long-running agents
5. **Persistent TCP pool + L4 routing (Caddy)** — Sprites are non-responsive after extended use; AerolVM's L4 bootstrap is purpose-built for stability

---

*Sources: [E2B GitHub](https://github.com/e2b-dev/E2B) · [Daytona GitHub](https://github.com/daytonaio/daytona) · [Fly.io community](https://community.fly.io) · [Fly.io status](https://status.flyio.net/history) · [Northflank blog](https://northflank.com/blog/sandbox-providers) · [ZenML E2B vs Daytona](https://www.zenml.io/blog/e2b-vs-daytona) · [Blaxel E2B alternatives](https://blaxel.ai/blog/e2b-alternatives-sandbox-environments) · [MicroVM isolation 2026](https://emirb.github.io/blog/microvm-2026/) · [AI sandboxing guide 2026](https://manveerc.substack.com/p/ai-agent-sandboxing-guide) · [Firecracker CVE-2026-1386](https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/) · [HN sandbox thread](https://news.ycombinator.com/item?id=47444917)*

---

## AerolVM Self-Assessment — Does AerolVM Have These Issues?

Code-traced audit against the issues above. Every verdict cites the specific file and line.

Legend: ✅ **Not present** · ⚠️ **Partial / risk** · ❌ **Present (real issue)**

---

### E2B Issues vs AerolVM

| # | Issue | Verdict | Evidence |
|---|-------|---------|----------|
| E2B-1 | Sandbox "not found" after idle / `beta_pause()` deletes sandbox | ✅ Not present | AerolVM has no "pause" primitive. Lifecycle uses explicit `StopIfIdleFor` / `DestroyIfIdleFor` / `StopAtAge` / `DestroyAtAge` fields (`pkg/models/types.go:277-278`). Default `SB_IDLE_TIMEOUT_MIN=0` means no auto-eviction (`internal/config/config.go:1734-1737`). |
| E2B-2 | NFS / persistent volume instability | ⚠️ Inherited risk | AerolVM delegates to host tools (`mount.nfs`, `mountpoint-s3`, etc.) per `pkg/mounts/manager.go:2`. The Manager correctly rolls back failed mounts (`pkg/mounts/manager.go`), but cannot shield against an unstable NFS server. |
| E2B-3 | Cold start ~150ms | ✅ Runtime-dependent | Docker, gVisor, Firecracker, WASM runtimes all configurable. Firecracker templates (`SB_ENABLE_FIRECRACKER`) allow snapshot-restore paths. Operators choose the trade-off. |
| E2B-4 | Hard runtime ceilings (1h / 24h) | ✅ Not present | No platform-enforced ceiling. `Lifecycle.StopAtAge` / `DestroyAtAge` are optional and user-set. Unset = runs indefinitely (`internal/service/service.go:3784-3791`). |
| E2B-5 | Pricing cliffs at scale | ✅ Not applicable | Self-hosted. Operator owns infrastructure costs. |
| E2B-6 | Port-not-open race on boot | ❌ Present | `ExposePort()` (`internal/service/service.go:2164`) calls `s.installHTTPPortRoute` and `s.store.UpsertPort` without first probing whether the container port is actually listening. There is no `WaitForPort` before route installation. Only the SSH gateway has a probe (`probeSSHGateway`, `service.go:4627`), and it's daemon-level only, not per-port. Caddy will route traffic to the port immediately — clients that race `ExposePort` with container startup will get connection refused. |
| E2B-7 | Silent template deprecation / 504 | ✅ Not present | Firecracker templates have explicit GC via `FirecrackerTemplateGCTTL` (`internal/config/config.go:516`). Deletion while a sandbox references the template returns `ErrTemplateInUse` → 409 (`pkg/api/apihttp/apihttp.go:89-90`). No silent removal. |
| E2B-8 | API ConnectTimeout under burst creates | ⚠️ Infrastructure risk | SQLite single-writer with 5s busy timeout (`internal/store/store.go:23`, `sqliteBusyTimeoutMS=5000`). Under extreme burst, SQLite write queue saturation could produce context deadlines before the busy timeout expires. WAL mode mitigates reads. |
| E2B-9 | Per-tool-call latency stacks in serverless mode | ⚠️ Serverless mode only | Non-serverless: Caddy routes directly to container — single hop. Serverless: each request through `IsSandboxStarted` (`service.go:2878`) hits a 2s warm cache (`warmCacheTTL`, `service.go:2897`), then potentially triggers a wake cycle. The wake circuit-breaker (`ErrWakeCircuitOpen`) adds a 60s retry-after on failure. |
| E2B-10 | Build system atomicity | ⚠️ Partial | `pkg/docker/build.go` builds images; if the build succeeds but the follow-up `CreateSandbox` fails, the image is left in the `pending_image_gc` ledger and GC'd after `ImageBuildGCTTL` (`service.go:3970-3976`). The TTL is the safety net, not an atomic commit. A failed build cannot leave a partial image in use. |

---

### Daytona Issues vs AerolVM

| # | Issue | Verdict | Evidence |
|---|-------|---------|----------|
| D-1 | Workspace creation fails on git clone | ✅ Not applicable | AerolVM does not clone repos during create. The container image is specified at create time (`req.Image`). Different architecture. |
| D-2 | SDK parameter mismatch | ⚠️ Low risk | All 5 SDKs are in the same repo (`sdk/`). `pkg/models` is the shared wire-type source. Risk exists at release boundaries if SDK packages are published from different commits; the mono-repo structure minimises this. |
| D-3 | Duplicate sandbox name returns wrong HTTP status | ❌ Bug | `store.ErrSandboxNameConflict` (`internal/store/store.go:3660`) is returned by `store.Create()` when a non-empty name collides with an existing sandbox (enforced by `idx_sandboxes_name`, `store.go:231`). **`ErrSandboxNameConflict` has no explicit mapping in `WriteStoreAwareError`** (`pkg/api/apihttp/apihttp.go:40-164`), so it falls through to the generic 400 branch (`apihttp.go:159-164`). It should be 409 Conflict. |
| D-4 | Workspace leftover on failed create | ✅ Well handled | `createSandbox` (`service.go:1080-1189`) has a thorough multi-step rollback chain: Docker `Create` failure → return error (no leak). Caddy `UpsertSandboxRoute` failure → `docker.Destroy` + `cleanupMounts` + `releaseAdmission`. `store.Create` failure → `caddy.DeleteSandboxRoute` + `docker.Destroy` + unmount + release. `PutMounts` failure → `store.Delete` + Caddy + Docker + unmount + release. Each step rolls back all prior steps. |
| D-5 | Workspace creation timeout (no bound on overall create) | ⚠️ Partial | `createSandbox` inherits the caller's context. The HTTP handler's context has no explicit outer timeout beyond the client's request deadline. Individual sub-operations (Caddy commit: 5s, `service.go:1785`) are bounded, but a stalled Docker image pull can block the entire create indefinitely. |
| D-6 | PTY panic / daemon crash | ✅ Not applicable | AerolVM does not own PTY sessions; those are handled inside the container by the `toolboxd` agent (`cmd/toolboxd/`). The daemon cannot panic from a guest PTY fault. |
| D-7 | Snapshot timeout spurious failures | ✅ Not present | `CreateSnapshot` (`service.go:1793`) uses the caller's context. No hardcoded short timeout on the commit step. |
| D-8 | Single-region only | ✅ Not present | Full cluster mode via `SB_ENABLE_CLUSTER=true`: Raft FSM placement, SWIM gossip, cross-node forwarding (`internal/cluster/`). Operators deploy across regions by pointing nodes at each other. |
| D-9 | Docker-only isolation by default | ⚠️ Present by default | `SB_CONTAINER_RUNTIME` defaults to `models.RuntimeDocker` (`internal/config/config.go:1053`). gVisor requires `runtime=gvisor` per-sandbox or host-level config. Firecracker requires `SB_ENABLE_FIRECRACKER=true`. Operators who don't explicitly set stronger isolation get runc (weakest). |
| D-10 | 15-minute auto-stop default | ✅ Not present | `SB_IDLE_TIMEOUT_MIN` defaults to `0` = disabled (`config.go:1050`, `config.go:1734`). No auto-stop unless the operator sets it. |
| D-11 | No SDK control over locally deployed sandboxes | ✅ Not applicable | AerolVM's SDK connects to any `baseURL`. Operators point it at their self-hosted daemon. |

---

### Modal Issues vs AerolVM

| # | Issue | Verdict | Evidence |
|---|-------|---------|----------|
| M-1 | gVisor `/proc/self/root` sandbox escape | ⚠️ Inherited if gVisor used | AerolVM supports gVisor via `runtime=gvisor` (`pkg/docker/client.go:300-318`). The escape class (`/proc/self/root` path rewriting bypassing deny patterns) is a gVisor kernel issue, not an AerolVM issue. If operators deploy gVisor, they inherit the class of risk until gVisor patches it. AerolVM itself has no deny-pattern enforcement that could be bypassed. |
| M-2 | gVisor ≠ microVM isolation | ⚠️ Architecture-dependent | AerolVM exposes both: `runtime=gvisor` (user-space kernel, shared host kernel) and `runtime=firecracker` (full microVM, separate kernel). The choice is per-sandbox. Operators using Firecracker get full isolation; operators defaulting to Docker/gVisor do not. |
| M-3 | Cost significantly higher than alternatives | ✅ Not applicable | Self-hosted. |

---

### Firecracker (CVE / Limitations) vs AerolVM

| # | Issue | Verdict | Evidence |
|---|-------|---------|----------|
| FC-1 | CVE-2026-1386 — jailer symlink host file overwrite | ⚠️ Version-dependent | AerolVM uses the jailer binary at the path configured by `SB_JAILER_BINARY` (`internal/config/config.go:437`). If the installed binary is a vulnerable version, AerolVM inherits the CVE. AerolVM has no version check or pin — operators must upgrade the Firecracker binary independently. |
| FC-2 | Not a Kubernetes runtime drop-in | ✅ Not applicable | AerolVM is its own control plane with its own scheduler. |
| FC-3 | Networking complexity | ✅ Managed | L7 via Caddy HTTP reverse proxy; L4 via caddy-l4 with AerolVM's host-port pool. Operators interact with `ExposePort`; they don't configure Caddy directly. |
| FC-4 | macOS / Apple Silicon not supported for Firecracker | ⚠️ Present | KVM is required. macOS lacks KVM support. Firecracker mode requires a Linux host with KVM. Docker and gVisor modes work on macOS. Documented implicitly via `SB_ENABLE_FIRECRACKER` gate but no explicit macOS error message. |
| FC-5 | Intel 8th-gen CPU kernel limitations | ⚠️ Host-dependent | Inherited from Firecracker itself. AerolVM has no version or kernel guard. |

---

### Fly.io Sprites Issues vs AerolVM

Sprites issues are mostly managed-cloud reliability issues (control plane down, 500 on create, non-responsive after use). AerolVM is self-hosted. The structural equivalents are addressed as follows:

| Sprites Issue | AerolVM Equivalent |
|---|---|
| Control plane down / API 500 on all creates | Single-node: no separate control plane. Cluster: Raft leader provides placement. A leader failure is handled by Raft election — creates are queued, not 500'd. |
| Sprites non-responsive after extended use | AerolVM's netstats-based idle floor (`activityFloorFor`, `service.go:3650`) prevents idle-stopping a sandbox with active network traffic. The Caddy zombie-GC sweep (`gcZombieCaddyEntries`, `service.go:3808`) removes stale routes that could otherwise shadow live containers. |
| No background command execution in CLI | Not applicable — AerolVM's toolbox (`cmd/toolboxd`) supports background exec natively via the in-container agent. |

---

### Summary: Real Issues Found in AerolVM Code

Three actionable issues found that mirror competitor bugs:

#### ❌ Issue A — Port-not-open race (mirrors E2B Issue 6)
**File:** `internal/service/service.go:2164-2229` (`ExposePort` / `exposePort`)
**Problem:** Caddy route and store record are written immediately when `ExposePort` is called. No probe verifies the container port is actually listening. A client that calls `ExposePort` and immediately sends a request may get connection refused from Caddy before the in-container process has bound the port.
**Fix direction:** Add a short TCP probe loop (dial with timeout) before `installHTTPPortRoute` / `allocateHostPort`. The `probeSSHGateway` pattern at `service.go:4627-4644` is the right template — replicate it for user-facing `expose_port` calls.

#### ❌ Issue B — `ErrSandboxNameConflict` maps to HTTP 400 instead of 409 (mirrors Daytona Issue 3)
**File:** `pkg/api/apihttp/apihttp.go:40-164` (`WriteStoreAwareError`)
**Problem:** `store.ErrSandboxNameConflict` (`internal/store/store.go:3660`) is returned when a non-empty sandbox name collides with an existing one. `WriteStoreAwareError` has no case for it, so it falls through to `WriteError(w, http.StatusBadRequest, msg)` at line 164. Clients cannot distinguish "your input is invalid" (400) from "name already taken" (409 Conflict).
**Fix:** Add to `WriteStoreAwareError` before the generic fallthrough:
```go
if errors.Is(err, store.ErrSandboxNameConflict) {
    WriteError(w, http.StatusConflict, err.Error())
    return
}
```

#### ⚠️ Issue C — No explicit timeout on overall `createSandbox` (mirrors Daytona Issue 5)
**File:** `internal/service/service.go:867` (`createSandbox`)
**Problem:** The function inherits whatever context the HTTP handler passes. A stalled image pull (no image cached, slow registry) can block indefinitely. Individual sub-steps have timeouts (Caddy commit: 5s), but the outer create has no guard.
**Fix direction:** Wrap `createSandbox` body with a `context.WithTimeout(ctx, cfg.CreateSandboxTimeout)` where `CreateSandboxTimeout` is a new config field (`SB_CREATE_TIMEOUT`, defaulting to e.g. 10 minutes). This bounds stuck creates without killing fast paths.
