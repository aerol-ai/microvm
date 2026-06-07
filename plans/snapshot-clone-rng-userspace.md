# Snapshot-clone RNG correctness: kernel reseed hardening + userspace gap

Status: Phases A and B implemented. Phase C in-repo parts (boot-args ACPI
invariant + operator docs) implemented; its load-bearing preconditions are
deploy-time artifacts (FC ≥ v1.8 binary, `CONFIG_VMGENID` guest kernel). Phase
D deferred (latent until virtio-net lands in forks).
Owner: runtime/firecracker + toolboxd.
Related: `plans/snapshot-clone-fast-boot.md`, `cmd/toolboxd/quiesce_linux.go`.

## Problem

Firecracker snapshot-clone (the "boot once, photograph memory, stamp out
fast clones" fast-boot path) duplicates the **entire** memory image of the
template VM into every clone. That includes every random-number generator's
internal seed state. Two clones that draw "random" bytes after resume can
get **identical** streams — duplicate UUIDs, session tokens, crypto nonces,
keypairs. For a security-positioned sandbox this is a disclosure-grade bug.

There are two seeds at two layers:

1. **Kernel CSPRNG** (`getrandom(2)`, `/dev/urandom`). Shared across clones
   from the photographed pool.
2. **Userspace PRNGs** inside long-lived processes baked into the snapshot
   (e.g. a preloaded `python` with `numpy`/`random`/`secrets` already
   imported). Their seed lives in *that process's* heap.

A separate process (toolboxd) **cannot** reach into another process's heap
to reseed #2. It can only fix #1 and signal #2 to fix itself.

## Current state (pre-Phase-A)

- Host `post_resume` vsock op fires on both clone paths
  (`driver.go:739` cold snapshot-load, `warmacquire.go:230` warm clone).
- Guest `OnPostResume` (`vsock.go:233`) calls `SetWallclock` +
  `ReseedRandom` (`quiesce_linux.go`).
- `ReseedRandom` does `RNDADDENTROPY` only — it *credits* the kernel input
  pool but does not *force* the CRNG to consume it. On kernels < 5.18 the
  CRNG may keep emitting the pre-snapshot stream until its own reseed
  interval elapses, leaving a window. No `RNDRESEEDCRNG`, no vmgenid.
- No userspace reseed of any kind.

## Severity (p0–p5; p0 = drop everything)

**Overall: P1.** Not P0 — the whole runtime is opt-in behind
`SB_ENABLE_FIRECRACKER` (default false) and the vulnerable branch only fires
for `runtime=firecracker` + snapshot-backed template + clone. No active
production fleet. But it's a silent, security-relevant correctness bug on the
feature's headline path; must be closed before snapshot-clone is marketed
production-safe.

| Component | Rating | Notes |
|---|---|---|
| Userspace PRNG dup in template-baked long-lived process | **P1** | Inherent to clone model; the advertised "preload Python+numpy" pattern |
| Kernel CRNG not force-reseeded (`RNDADDENTROPY` w/o `RNDRESEEDCRNG`) | **P2** | Mitigated on modern kernels; residual version-dependent + resume-race window |
| Kernel one-time secrets (ephemeral-port hash, TCP ISN) | **P3** | Latent — no virtio-net in forks yet |

### Who actually faces it

- **Implemented execution paths are safe after Phase A.** `exec_stream.go`
  and `daytona_code_run.go` spawn a *fresh* process per run; it seeds from
  the (now force-reseeded) kernel. The stateful Jupyter interpreter path is
  **501 Not Implemented** (`main.go:291`) — toolboxd hosts no persistent
  interpreter, so there is no in-product long-lived PRNG to leak.
- **Residual P1 is user-owned processes** a template author leaves running
  across the snapshot. toolboxd cannot fix those from outside; needs a
  signal + cooperation (Phase B) or kernel-driven reseed (Phase C).

## Plan

### Phase A — Force the kernel CRNG reseed (P2, DONE)

`quiesce_linux.go:ReseedRandom`: after `RNDADDENTROPY`, issue
`RNDRESEEDCRNG` (Linux >= 5.10) on the same fd to force the CRNG to consume
the freshly-credited entropy immediately. Tolerate `ENOTTY`/`EINVAL` on
older kernels (entropy is already credited; CRNG reseeds on schedule).
Ioctl factored behind a seam so a linux unit test asserts both ioctls fire
in order without a real kernel.

- Effect: closes the version-dependent window for any `getrandom` after
  `post_resume`. Makes every fresh process spawned post-resume safe — which
  is every implemented user-code path.
- Boot-path impact: **none**. This is in the post-resume control path, not a
  `CreateSandbox` boot-path callee. (Required PR call-out per CLAUDE.md.)
- Snapshot-correctness call-out: improves clone entropy isolation; no change
  to placement/FSM/host-port pool.

### Phase B — Userspace reseed signal + SDK accessor + docs (P1, DONE)

Key correction made during implementation: the five SDKs are **client-side**
(they drive the sandbox over HTTP from the developer's machine), so a client
SDK method **cannot** reseed an in-guest userspace PRNG. The load-bearing fix
is therefore the in-guest signal + a documented in-guest snippet; the SDK
method is a read-only clone *detector*. There is also no in-product
persistent interpreter to reseed — the Daytona Jupyter path is `501` — so the
residual exposure is strictly *user-owned* long-lived processes baked into a
template.

- **B1 — generation signal (`cmd/toolboxd/clonegen.go`).** A
  `cloneGeneration` token, seeded at startup and **bumped in `OnPostResume`**
  after the kernel reseed. Published two ways: the well-known guest file
  `/run/aerolvm/clone-generation` (the primary in-guest mechanism — local,
  no auth) and `GET /clone-generation` (unauthenticated like `/health`,
  reachable through the auth'd v1 toolbox proxy). The token only needs to
  *change* on clone; the reseed pulls clone-distinct entropy from the
  Phase-A-reseeded kernel. (vmgenid mirroring deferred to Phase C.)
- **B2 — `cloneGeneration()` read accessor in all five SDKs**
  (TS/Py/Go/Rust/Java), returning `{generation, resumedAt}` via a thin GET
  through the existing toolbox proxy. On both the client and the sandbox
  handle. Read-only clone/migration detector — explicitly *not* an in-guest
  reseed.
- **B3 — docs page** `randomness-in-cloned-sandboxes.mdx` (registered under
  the Snapshots group): the two-layer model, what AerolVM reseeds
  automatically, the residual gap, the SDK detector, and the **in-guest
  reseed snippet in all five languages** (read the token, reseed the stdlib
  PRNG + numpy for Python, etc.). Recommends lazy interpreter start over
  baking a started RNG-stateful process into a template.

### Phase C — vmgenid (P2, robust long-term; in-repo parts DONE)

Correction made during implementation: there is **no daemon "attach vmgenid
device" call**. Firecracker auto-manages the VM Generation ID — it regenerates
the value and notifies the guest over ACPI on every snapshot restore (support
landed in Firecracker v1.8). A guest kernel with `CONFIG_VMGENID` then reseeds
the kernel CSPRNG *inside the resume path, before userspace runs*, closing the
entropy window Phase A's reactive `post_resume` cannot. So "Phase C" is not a
`pkg/firecracker` device — it is one in-code invariant plus two deploy-time
artifact preconditions:

- **In code (DONE).** vmgenid rides ACPI, so ACPI must stay enabled on the
  kernel command line. `baseBootArgs`
  (`internal/runtime/firecracker/driver.go`) deliberately omits `acpi=off`
  (`pci=off` is unrelated and safe); a rationale comment records why and
  `bootargs_test.go` (`TestBootArgsKeepACPI`) fails the build if a future edit
  reintroduces a disabling flag. This is the only vmgenid lever the daemon
  controls.
- **In docs (DONE).** `engineering-snapshot-correctness.mdx` Hazard 2 gains a
  "Closing the entropy window: vmgenid" subsection (synchronous in-kernel
  reseed, composes with `post_resume` which still owns the clock); the
  "Entropy window" known-gap bullet now points at it. The operator
  precondition (FC ≥ v1.8 binary + `CONFIG_VMGENID=y` guest kernel) is stated
  there.
- **Deploy-time (operator, NOT daemon code).** `SB_FIRECRACKER_BINARY` ≥ v1.8
  and `SB_FIRECRACKER_KERNEL` built with `CONFIG_VMGENID=y`. The repo does not
  build the kernel or ship the FC binary (both are downloaded artifacts — see
  Terraform `firecracker.kernel_url` / `binary_url`), so these are verified at
  template-build / deploy time, not settable in Go. On a binary or kernel
  without support, the system silently falls back to `post_resume`-only
  (correct on the happy path; entropy window restored).

Optional follow-up (not done): a one-shot `firecracker --version` preflight in
`Driver.Ping` that warns when snapshot-clone is enabled against a pre-1.8
binary. Deferred — it runs a subprocess on the health path and asserts a
version constant; the doc precondition + boot-args guard cover the
correctness-relevant surface without that risk.

### Phase D — kernel one-time secrets (P3, latent)

Ephemeral-port hash key / TCP ISN secret are seeded once at boot and not
re-derived by entropy-add. Revisit when virtio-net lands in forks; likely
folds into Phase C or an explicit rekey.

## Sequencing

A (done) → B (done) → C in-repo (done; boot-args invariant + docs) with
deploy-time artifact preconditions to verify at rollout → D deferred until
virtio-net lands in forks.

## Tests (A + B)

- `cmd/toolboxd/quiesce_linux_test.go` (A): both ioctls fire in order;
  old-kernel `RNDRESEEDCRNG` tolerated; `RNDADDENTROPY` failure surfaced.
- `cmd/toolboxd/clonegen_test.go` (B1): token init/bump/persist, unwritable
  path non-fatal, concurrency, `GET /clone-generation` route, and
  `OnPostResume` bumps the generation.
- Per-SDK (B2): a `cloneGeneration()` test in each SDK asserting the
  `…/toolbox/clone-generation` GET path and the `{generation, resumedAt}`
  mapping.
- `make docs-build` (B3): the five-tab page renders and the sidebar entry
  is present.

## Tests

- `cmd/toolboxd/quiesce_linux_test.go` (Phase A): both ioctls fire in order;
  old-kernel `RNDRESEEDCRNG` failure tolerated.
- Existing `vsock_test.go` handler tests unchanged (interface untouched).
