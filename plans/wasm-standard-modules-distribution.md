# WASM Standard Modules & OCI Distribution Plan

Status: **Draft / not started**
Owner: @sumansaurabh
Created: 2026-06-12

## 1. Problem statement

Today a WASM sandbox is created with a `module_ref` that the create-path resolver
(`pkg/wasmmod/resolver.go`) can only interpret as a **local file** on the daemon
host (`file://`, absolute path, or a bare name under `SB_WASM_MODULES_DIR`).

That is unworkable for a multi-tenant SaaS:

- A customer using the SDK cannot know or reference a path on our server disk.
- There is no way to pull a module from a registry at create time. The ORAS code
  that exists (`pkg/wasmmod/oras_pull.go`, `oras_push.go`) is **checkpoint-only**
  (`PushSnapshotArtifact` / `PullSnapshotArtifact` operate on `mem.snap`
  directories for failover), not general module distribution.
- We ship **no standard language modules**. There is no `python.wasm`,
  `quickjs.wasm`, etc. baked into the platform.

We already operate **AOCR** — an authenticated OCI-distribution registry backed by
S3 (`registry/config.yml`) whose mirror proxy already accepts
`application/vnd.oci.image.manifest.v1+json` (`mirror/proxy.go:24`). So AOCR can
store WASM as ORAS artifacts today; only the consumption side is missing.

### Goal

Two complementary distribution channels, end to end (server + SDK + docs + IaC):

1. **Standard modules** — a curated set of language-interpreter `.wasm` modules
   (Python, JS/QuickJS, Ruby, etc.) **pre-staged onto every sandboxd node via
   Ansible/Terraform**, referenced by a short stable alias
   (`module_ref: "python"`), with **zero per-create network cost**.
2. **Bring-your-own (BYO) modules** — customers `push` their own `.wasm` to AOCR
   and `pull` it by an `oci://` ref, resolved + content-addressed + cached at
   create time.

Both must flow through the **snapshot/checkpoint** machinery so that a created
WASM sandbox (whether from a standard module or a BYO module) can be passivated,
checkpointed, pushed to AOCR, and rehydrated on failover — the "default way WASM
is created" in both the snapshot and runtime cases.

## 2. Current-state findings (grounded)

| Area | Finding | File |
|---|---|---|
| Module resolution | File-only: `file://`, abs path, bare name under modules dir | `pkg/wasmmod/resolver.go:25-64` |
| OCI pull | Exists but checkpoint-only (`mem.snap` dirs) | `pkg/wasmmod/oras_pull.go` |
| OCI push | Exists but checkpoint-only | `pkg/wasmmod/oras_push.go` |
| Validation | Core wasip1 only; rejects components; 256MiB cap; sha256 digest | `pkg/wasmmod/validate.go` |
| Module catalogue | `CreateWasmModule` upserts a row keyed by digest; **create path does NOT look up by catalogue id** | `internal/service/wasm_module_api.go:29`, `internal/runtime/wasm/create.go:26-31` |
| Create resolution | Calls `resolver.Resolve(ref)` directly on `module_ref` | `internal/runtime/wasm/create.go:26-31` |
| Config | `SB_WASM_MODULES_DIR` default `/var/lib/sandboxd/wasm/modules`; required when `SB_ENABLE_WASM` | `internal/config/config.go:1190,1426` |
| SDK | `moduleRef` field present; a TS test references an `https://` ref the server can't honor | `sdk/typescript/src/MicroVM.ts:236`, `MicroVM.test.ts:1067` |
| AOCR | OCI-distribution + S3 + token auth; accepts OCI artifact manifests | `aocr.sh/registry/config.yml`, `aocr.sh/mirror/proxy.go:24` |
| Ansible | Playbooks only, no roles dir yet | `Ansible/playbooks/` |
| Terraform | `nodes.tf` + `templates/` for node provisioning | `Terraform/` |

### Gap summary

- **No `oci://` scheme** in the resolver.
- **No generic module pull** (only checkpoint pull).
- **No standard-module staging** in Ansible/Terraform.
- **No alias → module mapping** so `module_ref: "python"` resolves stably.
- **SDK/docs** assume a host file path.

## 3. Use cases (target: 50+)

### A. Standard module provisioning (operator / IaC)
1. Operator declares a list of standard modules in Terraform vars and they appear on every node.
2. Operator adds a new standard module (e.g. `php`) by editing one Ansible var, re-running the role.
3. Operator pins a standard module to an exact digest for reproducibility.
4. Operator upgrades a standard module version cluster-wide via a rolling Ansible run.
5. Operator removes a deprecated standard module from all nodes.
6. New node joins the cluster and is auto-provisioned with the full standard-module set on boot.
7. Standard modules are sourced from AOCR (single registry of record), pulled during provisioning.
8. Standard modules are alternatively sourced from a pinned upstream release URL (no AOCR round-trip).
9. Provisioning verifies each module's sha256 digest before activating it.
10. Provisioning rejects a WASI-component artifact early with a clear operator error.
11. Provisioning is idempotent — re-running the role does not re-download unchanged modules.
12. Standard modules land in `SB_WASM_MODULES_DIR` with correct perms/ownership for sandboxd.
13. A node missing a standard module surfaces a health/metric signal, not a silent failure.
14. Air-gapped install: modules are bundled in a local artifact store, no public egress needed.
15. Operator runs a single command to list which standard modules each node currently has.

### B. Standard module consumption (SDK user)
16. User creates a WASM sandbox with `module_ref: "python"` (alias) — no host path.
17. User lists available standard modules via the SDK and picks one.
18. User creates a Python sandbox and runs a user-supplied `.py` script via the toolbox.
19. User creates a JS sandbox (QuickJS) and runs user-supplied JS.
20. User creates a Ruby sandbox and runs a user-supplied `.rb` script.
21. User references a standard module by alias **and** gets a deterministic digest in the response.
22. User passes an unknown alias and gets a clear `module not found` error listing valid aliases.
23. User creates many sandboxes off the same standard module with warm-pool reuse (no cold pull).
24. Standard-module create has the same boot latency whether it is the first or Nth call.
25. User pins `module_ref: "python@<digest>"` to lock a version across a deployment.

### C. Bring-your-own module push (SDK user)
26. User pushes their own `.wasm` to AOCR via the SDK and gets back an `oci://` ref + digest.
27. Push validates core-wasip1 + size locally before upload (fast failure).
28. Push is idempotent — re-pushing identical bytes is a no-op returning the same digest.
29. Push to a tag (`myapp:latest`) and to an immutable digest both work.
30. User pushes a new version of an existing module; old digest remains pullable.
31. Push respects AOCR per-user auth (PAT) and tenant repository scoping.
32. User deletes their pushed module from AOCR via the SDK.
33. Push surfaces a clear error when the artifact is a WASI component.
34. Push surfaces registry auth failure distinctly from network failure.

### D. Bring-your-own module pull / create (SDK user)
35. User creates a sandbox with `module_ref: "oci://aocr.aerol.ai/<tenant>/myapp:latest"`.
36. First create pulls + caches the module; subsequent creates hit the local cache.
37. Pull is content-addressed; a tag re-pointed upstream is re-pulled on cache miss.
38. Concurrent duplicate creates of the same uncached oci ref pull once (single-flight), not N times.
39. Pull failure (auth/network/not-found) yields a precise, retryable error to the SDK.
40. A pulled BYO module is validated (core-wasip1, size) before it is allowed to run.
41. BYO module digest is recorded in the catalogue and sandbox record.
42. Cache eviction reclaims disk for unreferenced BYO modules without breaking running sandboxes.
43. Pull honors a configurable timeout so create boot-latency is bounded.
44. `oci://` ref with an explicit digest skips the tag→digest resolution round-trip.

### E. Snapshot / checkpoint / failover (the "default way" WASM is created)
45. A standard-module sandbox is passivated → checkpoint written → rehydrated on daemon restart.
46. A BYO-module sandbox is passivated and rehydrated identically.
47. A `durable` WASM sandbox pushes its checkpoint to AOCR and fails over to a peer.
48. Failover peer that lacks the **base module** pulls it from AOCR before rehydrating the checkpoint.
49. Checkpoint push/pull reuses the same AOCR auth + ORAS path as module distribution.
50. Snapshot-created and runtime-created WASM sandboxes share one create entry point (no version branching).
51. A standard module upgraded under a running passivatable sandbox does not corrupt its checkpoint (digest pinned to the instance).
52. Recreate-from-snapshot resolves the original module digest, not the current alias target.

### F. SDK / docs / DX
53. All five SDKs (TS, Python, Go, Rust, Java) expose `module_ref` alias + `oci://` + push/pull in lockstep.
54. Docs show "use a standard module" (alias) as the primary path, host paths as advanced.
55. Docs show the BYO push→create flow with five-language tabs.
56. Docs document the core-wasip1 requirement and how to produce one per language.
57. SDK `listModules()` distinguishes standard (operator-staged) vs BYO (tenant) modules.

> 57 use cases enumerated (≥50 target met). Sections E/F are the integration glue.

## 4. Architecture / approach

```
                 push (.wasm)                      pull (oci://)
  SDK user ───────────────────► AOCR (OCI/S3) ◄────────────────── sandboxd resolver
                                   ▲                                   │
                                   │ provisioning pull                 │ cache + validate
                          Ansible/Terraform                           ▼
                          stage standard modules ──► SB_WASM_MODULES_DIR ──► create/run
```

### Resolver extension (server)
Generalize `pkg/wasmmod` resolution to accept, in priority order:
1. `oci://host/repo[:tag|@sha256:...]` → ORAS pull into a content-addressed cache under `SB_WASM_MODULES_DIR/_oci/<digest>.wasm`, then validate.
2. Alias (no scheme, no slash, in alias map) → resolve to a staged standard module.
3. `file://` / abs / bare-name → existing behavior (unchanged).

Add a **generic module ORAS pull** (separate from the checkpoint pull): a
`PullModuleArtifact(ctx, cfg, ref, dstDir) (digest, path, error)` alongside the
existing `PullSnapshotArtifact`, sharing auth/host helpers.

### Alias map
Operator-controlled mapping `alias → {oci ref | filename}` provisioned by Ansible
into a config file (e.g. `SB_WASM_MODULES_DIR/aliases.json`) or env. The catalogue
(`CreateWasmModule`) is the natural store; provisioning calls the create-module
API per standard module so `module_ref: "python"` resolves via catalogue → digest.
**Decision needed** (see §7): alias map file vs. catalogue-backed lookup wired
into the create path.

### Single-flight + cache
`oci://` pulls use the lazy-bootstrap single-flight pattern (`atomic.Bool` latch +
`sync.Mutex`) per the repo's idempotency rule (CLAUDE.md hard rule 3), keyed by
ref/digest, so concurrent duplicate creates pull once. Boot-latency impact MUST be
documented in the PR (hard rule 2) — first-create pull cost called out explicitly.

## 5. Implementation phases

### Phase 0 — Spike & decisions (no code)
- Confirm ORAS artifact mediaType we will use for `.wasm` and that AOCR round-trips it (`oras push`/`oras pull` smoke test against a dev AOCR).
- Resolve §7 open questions.

### Phase 1 — Server: generic module pull + resolver `oci://`
- `pkg/wasmmod/oras_pull.go`: add `PullModuleArtifact` (single `.wasm`, content-addressed).
- `pkg/wasmmod/resolver.go`: add scheme dispatch (`oci://`, alias, file). Keep file path untouched.
- Cache dir `_oci/<digest>.wasm`; validate via existing `ValidateFile`.
- Single-flight latch; bounded timeout (`SB_WASM_PULL_TIMEOUT`).
- Tests: `resolver_test.go` (scheme matrix), pull single-flight, validation reject (component), cache hit/miss.
- **Touches create boot path** → follow `/touch-create-sandbox`, PR call-out on latency + idempotency.

### Phase 2 — Server: alias resolution + catalogue wiring
- Wire create path to resolve alias via catalogue (or alias file) → digest before `resolver.Resolve`.
- `CreateWasmModule` accepts an `alias` field; store an `alias` column (use `/add-store-column`, with host-port-pool-style regression test discipline).
- Recreate/snapshot path pins the instance's original digest (use case 52).

### Phase 3 — Server: module push + delete API
- `pkg/wasmmod`: `PushModuleArtifact` (generic, mirrors checkpoint push).
- New `/v1` routes: `POST /v1/wasm/modules/push`, `DELETE /v1/wasm/modules/{id}` (use `/add-v1-endpoint`).
- Idempotent push (digest-keyed), component rejection, auth error mapping via `apihttp.WriteStoreAwareError`.

### Phase 4 — SDK lockstep (all 5)
- Add to each SDK (use `/add-sdk-method`): `listModules`, `pushModule`, `deleteModule`; `create({ moduleRef })` already supports alias/oci string (string passthrough — verify each transport).
- Keep `pkg/models` DTO lean (CLAUDE.md convention).

### Phase 5 — IaC: standard module staging
- **Ansible role** `roles/wasm-standard-modules/`: var-driven list `wasm_standard_modules: [{alias, source(oci|url), ref, digest}]`; tasks: pull/fetch → verify digest → place in `SB_WASM_MODULES_DIR` (perms) → register via module API → idempotent.
- Hook role into the sandboxd install/update flow (`playbooks/update-sandboxd.yml` companion playbook).
- **Terraform**: expose `wasm_standard_modules` variable + render into the node provisioning template (`Terraform/templates/`), pass through to Ansible/cloud-init.
- Health: emit a metric/log when a declared standard module is absent (use case 13).

### Phase 6 — Docs
- Rewrite `docs/src/content/docs/wasm-sandbox.mdx`: alias as primary (`module_ref: "python"`), host path demoted to "advanced".
- New page `wasm-modules-distribution.mdx` (register in `content.config.ts`): standard vs BYO, push→create flow, five-language tabs, core-wasip1 callout. Follow `/add-docs-page` (no curl, all five SDK langs, `syncKey="lang"`).

### Phase 7 — Snapshot/failover integration
- Ensure failover peer pulls the **base module** (via Phase 1 `PullModuleArtifact`) before checkpoint rehydrate (use case 48).
- Regression tests next to `recovery_*` / `wasm_checkpoint_*`.

## 6. AOCR-side work (separate repo: `aocr.sh`)
- Confirm token-auth scoping allows per-tenant `wasm/<tenant>/<name>` repositories.
- Confirm reaper/TTL policy does not evict pinned standard-module digests (they must be `latest`-stable or digest-pinned).
- Verify `notifications`/hooks don't choke on artifact (non-image) manifests.
- Possibly publish the curated standard-module set to a well-known `wasm/std/*` namespace.

## 7. Decisions (resolved in /plan-eng-review 2026-06-12)

1. **Alias source of truth** — RESOLVED. Standard language modules are **reserved
   keywords** (`python`, `javascript`, `ruby`, …) resolved to staged filenames on
   disk, **staged identically on every node by Ansible**. The fleet contract comes
   from Ansible, NOT the per-node SQLite catalogue (which gossips local DB state and
   would drift — codex finding #1). BYO modules use the catalogue (inherently
   per-tenant, per-create with an explicit ref, so per-node state is acceptable).
2. **OCI mediaType** — Phase 0 spike must confirm the `.wasm` artifact mediaType
   round-trips through AOCR (gated live integration test covers this; `mirror/proxy.go:24`
   already accepts `application/vnd.oci.image.manifest.v1+json`).
3. **Cache eviction** — RESOLVED. Per-digest **reference counting**, evict at zero
   refs (codex finding #5). Eviction scans ONLY `SB_WASM_CACHE_DIR`, never checkpoint
   `<sandboxID>/` dirs.
4. **`oci://` at create vs pre-register** — RESOLVED: **support both**. Register-time
   pull (`CreateWasmModule`) AND lazy pull-on-create. Both go through the single
   `ResolveModule` chokepoint; both enforce the registry allowlist; pull-on-create
   uses a single-flight latch and bounded `SB_WASM_PULL_TIMEOUT`.
5. **Registry trust** — RESOLVED. `SB_WASM_REGISTRY_ALLOWLIST` (default: AOCR host
   only) enforced in the chokepoint before any network call; size cap enforced
   DURING the pull stream, not just post-download.
6. Standard-module **default set** (initial): `python`, `javascript` (QuickJS),
   `ruby` — confirm available core-wasip1 builds in Phase 0.

## 7a. Review resolutions (architecture / code-quality / perf)

| # | Decision | Rule |
|---|---|---|
| I1 | Pull happens at register-time AND lazily on create; both gated | rule 2/3 |
| I2 | `SB_WASM_REGISTRY_ALLOWLIST` (AOCR default) + streaming size cap | SSRF |
| I3 | Single `pkg/wasmmod.ResolveModule` chokepoint: classify → allowlist → fetch/find → ValidateFile → digest → atomic publish. All 4 ref kinds + both oci paths delegate to it. | DRY |
| I4 | Pulled modules in separate `SB_WASM_CACHE_DIR`; write `<digest>.tmp` → fsync → ValidateFile → atomic rename. Eviction never touches checkpoint dirs. | rule 4 |
| I5 | Extract shared ORAS transport core (`oras_core.go: newAuthedRepo`); module + checkpoint push/pull are thin callers. | DRY |
| I6 | Typed error taxonomy → HTTP via `WriteStoreAwareError`: ErrModuleNotFound(404+aliases), ErrRegistryNotAllowed(403), ErrRegistryAuth(401/502), ErrRegistryUnavailable(502+Retry-After), ErrComponentUnsupported(422), ErrModuleTooLarge(413). | explicit |
| I7 | Reserved-keyword standard aliases resolve via filesystem (no DB, no per-create query); BYO via catalogue + cached inventory. | rule 2 |

## 7b. Codex outside-voice gaps (folded in as required work)

| # | Gap | Fix |
|---|---|---|
| C2 | `StartSandbox`/`RehydrateSandbox` re-resolve `ModuleRef` every time → alias/tag move silently boots different bytes after restart/failover (`lifecycle.go:56-110`, `passivate.go:49-64`). **Correctness bug.** | Pin resolved digest onto the sandbox record at create; start/rehydrate/recreate boot the **frozen digest**, never re-resolve. Mandatory regression test. |
| C3 | Alias grammar collides with bare-file refs (`resolver.go:25-63`) — `python` alias vs a real `modules/python`. | Explicit precedence in `ResolveModule`: reserved keyword → catalogue id → bare file. Documented collision policy. |
| C4 | Private `oci://` modules have no failover auth lifecycle (`types.go:657-662`). Work on creator node, fail on next owner. | Persist per-module registry auth mirroring `RegistryAuthSealed`; hand to failover peer's `ResolveModule`. |
| C5 | Delete/GC keyed on `module_ref` not digest (`wasm_module_health.go:36-74`, `wasm_module_api.go:136-161`) → shared bytes stomp each other. | Per-digest reference accounting (same as I4 eviction); delete only at zero refs. |
| C6 | Non-SDK entrypoints bypass the new logic: `facadeutil.TranslateWasmCreate` (Daytona) + cluster capacity gossip off local inventory (`facadeutil/wasm.go:20-43`, `daemon.go:482-488`). | Route facade create through `ResolveModule`; verify gossip inventory reflects reserved keywords + catalogued modules. |
| C1 | (TENSION, resolved) DB-backed alias map drifts per node. | Sidestepped — standard modules are Ansible-staged reserved keywords, not DB rows (see §7.1). |

## 7c. NOT in scope

- **`wasm32-wasip2` / WASI Component Model support** — runtime executes core
  modules only (`validate.go:51`); components rejected, not lowered. Deferred.
- **In-server `.wasm` compilation** — users/operators bring compiled modules.
- **A web UI for module management** — API + SDK + IaC only.
- **Multi-registry federation** — allowlist supports >1 host but no mirroring/
  failover across registries; AOCR is the registry of record.
- **Automatic interpreter-module sourcing** — the curated standard set (`python`,
  etc.) is operator-provided; no auto-discovery of upstream builds.

## 7d. What already exists (reuse, don't rebuild)

- `pkg/wasmmod/resolver.go` — bare-filename resolution already works (standard
  modules need ZERO new resolution code; reserved keywords ARE staged filenames).
- `pkg/wasmmod/oras_pull.go` / `oras_push.go` — checkpoint ORAS; **factor** the
  shared transport (I5) rather than duplicate.
- `internal/service/wasm_module_api.go` — `CreateWasmModule` is the register-time
  ingest; extend it, don't replace.
- `RegistryAuthSealed` (`types.go:657`, `service.go:1451-1482`) — the exact pattern
  for C4 module-auth failover; mirror it.
- `localReadyWasmModuleIDs` cache (`wasm_module_api.go:105,181`) — reuse for BYO
  inventory; standard keywords skip it entirely.
- `AOCR` — OCI-distribution + S3 + token auth + artifact manifests already accepted.

## 7e. Failure modes (new codepaths)

| Codepath | Realistic failure | Test? | Error handling? | User sees? |
|---|---|---|---|---|
| pull-on-create | registry down mid-boot | yes (mock) | ErrRegistryUnavailable 502 + Retry-After | clear, retryable |
| pull atomic publish | process killed mid-pull | **mandatory** | tmp file discarded, never visible | n/a (invisible) |
| allowlist check | tenant passes internal IP | **mandatory** | ErrRegistryNotAllowed 403 | clear |
| start/rehydrate | alias retargeted post-create | **mandatory** | boots frozen digest | correct bytes (no surprise) |
| failover module pull | peer lacks private-module auth | **mandatory** | sealed auth handed to peer | rehydrate succeeds |
| GC/delete | shared digest, one alias deleted | **mandatory** | refcount > 0 blocks delete | other sandbox unaffected |

**Critical gap flagged:** C2 (silent code-swap on restart) had NO test and NO
error handling in the original plan — it would fail **silently** (sandbox boots
different code, no error). Now mandatory-tested + digest-pinned.

## 7f. Worktree parallelization

| Lane | Modules | Depends on |
|---|---|---|
| A | `pkg/wasmmod/` (ResolveModule, oras_core, push/pull module) | — |
| B | `internal/store/` (alias/digest columns, refcount) | — |
| C | `internal/service/` + `internal/runtime/wasm/` (create/start/rehydrate digest pin, GC refcount, auth seal) | A, B |
| D | `pkg/api/v1/` + `pkg/api/facadeutil/` (routes, Daytona) | C |
| E | `sdk/*` (5 SDKs, independent of each other) | D (API shape) |
| F | `Ansible/` + `Terraform/` (standard-module staging) | — (only needs filenames) |
| G | `docs/` | D (final API shape) |

Execution: **Launch A, B, F in parallel.** Merge A+B → build C. Then D → E (5 SDK
sub-lanes parallel) and G. F lands anytime. Conflict flag: C touches both service
and runtime/wasm — keep as one lane, no sub-split.

## 7g. Implementation Tasks
Synthesized from this review. P1 blocks ship; P2 same branch; P3 follow-up.

- [ ] **T1 (P1)** — wasmmod — Single `ResolveModule` chokepoint (classify/allowlist/validate/digest/atomic-publish)
  - Surfaced by: Arch I3. Files: `pkg/wasmmod/resolve.go`. Verify: `resolver_test.go` scheme matrix + allowlist reject.
- [ ] **T2 (P1)** — wasmmod — Registry allowlist + in-stream size cap
  - Surfaced by: Arch I2 (SSRF). Files: `pkg/wasmmod/resolve.go`, `internal/config/config.go`. Verify: rejects internal IP / non-allowlisted host.
- [ ] **T3 (P1)** — wasmmod — Extract shared ORAS transport; add Pull/PushModuleArtifact
  - Surfaced by: CodeQual I5. Files: `pkg/wasmmod/oras_core.go`, `oras_pull.go`, `oras_push.go`. Verify: module + checkpoint roundtrip via one auth path.
- [ ] **T4 (P1)** — service/runtime — Pin resolved digest at create; start/rehydrate/recreate boot frozen digest
  - Surfaced by: Codex C2 (correctness). Files: `internal/runtime/wasm/lifecycle.go`, `passivate.go`, store column. Verify: alias retarget → restart boots original bytes.
- [ ] **T5 (P1)** — store — alias + module_digest + refcount columns (host-port-pool test discipline)
  - Surfaced by: Test review + C5. Files: `internal/store/store.go`. Verify: `store_test.go`.
- [ ] **T6 (P1)** — service — Single-flight pull latch on create
  - Surfaced by: Test review (rule 3). Files: `internal/service/wasm.go`. Verify: N concurrent creates → 1 pull.
- [ ] **T7 (P1)** — cluster — Failover peer pulls base module (+ sealed auth) before rehydrate
  - Surfaced by: Codex C4 + rule 6. Files: `internal/cluster/recovery_*.go`, `internal/service`. Verify: peer-lacking-module test.
- [ ] **T8 (P2)** — service — Per-digest GC refcounting; delete only at zero refs
  - Surfaced by: Codex C5. Files: `wasm_module_api.go`, `wasm_module_health.go`. Verify: shared-digest delete blocked.
- [ ] **T9 (P2)** — service — Typed error taxonomy → WriteStoreAwareError
  - Surfaced by: CodeQual I6. Files: `pkg/models`, `pkg/api/apihttp`. Verify: status-code matrix test.
- [ ] **T10 (P2)** — api/facade — `POST/DELETE /v1/wasm/modules`; route `TranslateWasmCreate` through chokepoint
  - Surfaced by: Codex C6 + Phase 3. Files: `pkg/api/v1/`, `pkg/api/facadeutil/wasm.go`. Verify: Daytona create reaches alias/oci logic.
- [ ] **T11 (P2)** — sdk — `listModules`/`pushModule`/`deleteModule` across 5 SDKs
  - Surfaced by: Phase 4. Files: `sdk/*`. Verify: per-SDK transport tests.
- [ ] **T12 (P2)** — infra — Ansible role + Terraform var: stage reserved-keyword modules
  - Surfaced by: Phase 5. Files: `Ansible/roles/wasm-standard-modules/`, `Terraform/`. Verify: idempotent re-run; digest verify.
- [ ] **T13 (P2)** — docs — alias-primary `wasm-sandbox.mdx` + BYO `wasm-modules-distribution.mdx` (5 tabs)
  - Surfaced by: Phase 6. Files: `docs/`. Verify: no curl, all 5 langs.
- [ ] **T14 (P3)** — test — Gated live-AOCR integration suite (`-tags integration`)
  - Surfaced by: Test review. Files: `pkg/wasmmod/*_integration_test.go`. Verify: CI runs with creds.

## 8. Risks
- **Boot latency** on first `oci://` create (network pull) — mitigate with pre-staging + warm pool + bounded timeout; document per hard rule 2.
- **Idempotency** under concurrent duplicate creates — single-flight latch mandatory (hard rule 3).
- **Failure-path consistency** — partial pull/validate must not leave a half-written cache file referenced as ready (hard rule 4): write to temp, fsync, atomic rename, then mark ready.
- **Cluster fragility** — failover module pull path needs a regression test (hard rule 6).
- **Component artifacts** — validate early everywhere (push, pull, stage).

## 9. Definition of done
- `module_ref: "python"` works from all 5 SDKs against a stock-provisioned node.
- `pushModule` → `create({moduleRef: "oci://..."})` round-trips from all 5 SDKs.
- Standard modules are declared once in Terraform and present on every node.
- A `durable` WASM sandbox fails over to a peer that pulls the base module + checkpoint.
- Docs cover both flows in five languages; no curl.
- All new fragile paths (resolver, pull single-flight, alias, failover pull) have regression tests; PR call-outs per CLAUDE.md hard rules.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 1 | issues_found | 6 misses, 4 folded as required, 1 tension resolved, 1 absorbed |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | issues_open | 11 issues (4 arch, 2 code-qual, 1 perf, 4 codex) + 1 critical gap (C2 silent code-swap), all resolved/folded |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CODEX:** Caught the load-bearing correctness bug the review missed — start/rehydrate re-resolve `ModuleRef`, silently booting different bytes after restart (C2). Plus failover module-auth (C4), per-digest GC refcount (C5), Daytona/gossip entrypoints (C6). All folded in as P1/P2 tasks.
- **CROSS-MODEL:** Review and Codex agreed on the security/idempotency posture; the one tension (alias source of truth) resolved in the review's favor — standard modules are Ansible-staged reserved keywords, not DB rows, so the per-node SQLite drift Codex flagged doesn't apply to the fleet contract.
- **VERDICT:** ENG review complete, scope = FULL. Plan hardened: 14 implementation tasks (7×P1, 6×P2, 1×P3), 6 mandatory tests, 1 critical gap closed. Not CLEARED for ship — this is a plan-stage review; implement T1–T14 then run `/review` on the diff before landing.

**UNRESOLVED DECISIONS:**
- OCI mediaType for `.wasm` artifacts (decision §7.2) — deferred to Phase 0 spike; the gated live-AOCR integration test (T14) validates the round-trip before it can bite.
