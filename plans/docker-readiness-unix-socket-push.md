# Docker readiness via Unix-socket push ("vsock for Docker")

Status: **Proposed** — design plan, not yet implemented.
Owner: TBD. Boot-path change → must follow `/touch-create-sandbox` + `pr-review.md`.

## Problem

Today a Docker (and gVisor) sandbox create blocks on two **pull-based**
readiness loops at the tail of `pkg/docker/client.go`:

- `waitForRuntime` — polls `inspect` until the container is `Running` with an
  IP (300ms granularity).
- `waitForToolbox` — polls `http://<containerIP>:<toolboxPort>/health` until
  `200` (300ms granularity).

Both loops *round the true readiness time up to the next 300ms tick*, and
because they run back-to-back the quanta **stack** — a sandbox whose agent is
genuinely ready at ~350ms is reported at ~600ms+. Measured Docker server-side
create is ~628ms; the rounding is the dominant avoidable cost.

Firecracker already avoids this: its in-guest `toolboxd` exposes an
out-of-band **vsock** channel and the host handshakes over it
(`internal/runtime/firecracker/driver.go`), independent of the user network.
WASM waits on a local unix-socket `Ping`. **Docker is the only runtime that
polls the user data-plane network.**

This plan gives Docker an out-of-band, **push-based** readiness channel — a
per-sandbox **Unix domain socket** the host listens on and the in-container
`toolboxd` connects to the instant it is up. It is the "vsock for Docker": same
trust model as vsock (point-to-point host↔container, no network), without the
security and network-coupling problems of an HTTP webhook to sandboxd.

---

## 20 use cases this solves

Latency / performance
1. Removes the ~300ms toolbox-health rounding from every Docker create (push
   fires the instant the agent is up).
2. Collapses the p99 create tail caused by *multiple* missed 300ms polls on a
   slightly-slow boot.
3. Eliminates the `dockerd` inspect/`/health` request storm during
   high-concurrency bursts (e.g. the 200-at-once density probe), where tight
   polling otherwise fights the very create/start calls it waits on.
4. Removes ephemeral-port / TIME_WAIT churn from repeated *refused* health
   dials while the agent is still booting.
5. Makes create latency essentially independent of host CPU / instance type —
   kills the "provision a bigger box to go faster" misconception.
6. Cuts sandboxd CPU + goroutine pressure from many concurrent tight poll loops.

Correctness / robustness
7. Readiness no longer depends on having polled the *right* container IP yet
   (push is immune to IP-assignment lag after `/containers/start`).
8. Removes false-"healthy" flaps where `/health` returns 200 before the agent
   has finished initialising — the agent itself decides when to announce ready.
9. Detects a wedged / never-ready toolbox more cleanly: a single-shot accept
   with a deadline instead of an ambiguous repeated poll.
10. Provides a precise, attributable readiness timestamp for Server-Timing and
    metrics (the agent reports exactly when it came up).
11. Fences stale readiness on snapshot-clone / recreate paths via a
    per-create nonce + clone-generation in the handshake.
12. Reduces log noise from repeated "connection refused" health attempts on a
    normal boot.

Network / isolation
13. Readiness works when the sandbox is created with `NetworkBlockAll` — no
    data-plane network is required.
14. Readiness works under restrictive egress (`NetworkDenyOut`) without
    special-casing the boot window or ordering rule application around it.
15. Decouples the control signal from the user-controllable data plane entirely.

Architecture / security / ops
16. Unifies the readiness model across runtimes (Docker now out-of-band push,
    like Firecracker vsock and WASM socket) — one mental model, less special-casing.
17. Gives gVisor sandboxes the same fast readiness for free (they ride the
    docker client path).
18. Avoids exposing any host-facing readiness *network* endpoint to untrusted
    sandboxes (the failure mode of a webhook approach).
19. Backward compatible: toolbox images built before this change still come up
    via the existing `/health` poll fallback (no flag-day).
20. Establishes a reusable per-sandbox host↔container control channel that
    future features can extend (push quiesce/shutdown to Docker sandboxes,
    capability advertisement, agent-version negotiation) with **no** new
    network surface.

---

## Design / how it is solved

### Channel topology (host listens, guest connects = true push)

```
HOST (sandboxd)                                  CONTAINER (toolboxd, PID 1)
──────────────                                   ──────────────────────────
1. create  <dir>/<sandboxID>.sock, listen()
2. bind-mount that ONE socket file ──────────►   /run/aerol/ready.sock  (rw)
   set env SB_READY_SOCKET=/run/aerol/ready.sock
3. /containers/create, /containers/start
4. inspect once → container IP (tight retry
   only if not Running yet)                      5. on boot, FIRST action:
6. Accept() blocks (deadline = toolboxWaitTimeout)   dial unix:/run/aerol/ready.sock
7. read 1 JSON line, verify token+nonce ◄────────    write {ready, token, nonce, ...}
8. close listener, unlink socket → ready             then continue (HTTP/vsock listen)
```

Host **listens** (not the guest) so there is nothing for the host to poll: the
socket exists before the container starts, and `Accept()` returns the moment
`toolboxd` connects. The guest dial is a single best-effort connect; it never
blocks the agent's own startup.

### Readiness handshake (newline-delimited JSON, mirrors `vsock.go`)

```json
{"event":"ready","sandbox_id":"<id>","token":"<SB_TOOLBOX_TOKEN>","nonce":"<per-create>","agent_version":"<v>"}
```

Host validates: `sandbox_id` matches, `token` matches (constant-time), `nonce`
matches the value it minted for *this* create. Then the create returns
`status=started`.

### Graceful degradation (race, don't replace)

The host runs the socket-accept **and** the existing `/health` poll
(now with adaptive backoff) **concurrently**, first-ready-wins:

- New toolbox image → socket fires first (~immediately).
- Old toolbox image (no dialer) → socket never connects; the health poll wins
  as it does today. No flag-day, fully backward compatible (use case #19).
- Container never becomes ready → both lose; the existing
  `toolboxWaitTimeout` deadline still applies and Create fails as today.

### Metrics (expvar, mirroring pool metrics convention)

`docker_ready_socket_hit`, `docker_ready_socket_fallback_health`,
`docker_ready_socket_timeout`, plus a `ready_wait_ms` histogram — gives the
integration assertion hook and dashboards.

### Config knobs (`internal/config`)

- `SB_DOCKER_READY_SOCKET_ENABLED` (default `true`) — master switch; off =
  pure legacy behavior.
- `SB_DOCKER_READY_SOCKET_DIR` (default `<runtime-dir>/docker/ready`).
- Plus the fallback poll's backoff knobs (`SB_DOCKER_READINESS_POLL_INITIAL`,
  `_MAX`) carried over from the tight-poll plan.

The existing `SB_DOCKER_WAIT_TIMEOUT` / `SB_TOOLBOX_WAIT_TIMEOUT` (30s) stay as
the outer deadline, unchanged.

---

## Files CREATED

| File | Purpose |
|---|---|
| `pkg/readyproto/readyproto.go` | Shared wire shape (`ReadySignal` struct, `Event` constant, a bounded newline-JSON `Encode`/`Decode`). Imported by **both** the host (`pkg/docker`) and the guest (`cmd/toolboxd`), mirroring how the vsock protocol shape is isolated from its socket layer. |
| `pkg/readyproto/readyproto_test.go` | Encode/decode round-trip, oversize-line rejection, malformed-JSON rejection, unknown-field tolerance. |
| `pkg/docker/readysock.go` | Host side: `readyListener` — create+listen (unlink-before-bind), `Accept` with deadline, token/nonce verification (constant-time), bounded reader, single-shot, cleanup (`Close`+unlink). Plus `bindSpec()`/`envFor()` helpers the Create path uses to wire the bind and env. |
| `pkg/docker/readysock_test.go` | Unit tests (see test section). |
| `pkg/docker/readysock_metrics.go` | expvar counters/histogram for the readiness channel. |
| `cmd/toolboxd/readyclient.go` | Guest side: `announceReady()` — read `SB_READY_SOCKET`/`SB_TOOLBOX_TOKEN`/nonce env, dial the unix socket with a short deadline, write one `ReadySignal` line, close. Best-effort; never fatal. Portable (plain unix socket; no AF_VSOCK, builds on all platforms). |
| `cmd/toolboxd/readyclient_test.go` | Unit tests for the dialer. |
| `integration-tests/suite/docker_readiness_test.go` | New UC tests (UC-96/UC-97) — see integration section. |
| `plans/docker-readiness-unix-socket-push.md` | This document. |

## Files MODIFIED

| File | Change |
|---|---|
| `pkg/docker/client.go` | `Create`: (a) before `/containers/create`, construct the `readyListener` and append its bind to `binds` + its env to `envValues`; (b) after `/containers/start`, keep one `inspect` for the container IP, then **race** `readyListener.Accept()` against the (backoff) `waitForToolbox`; (c) on every failure path, `readyListener.Close()` + unlink (LIFO with the existing cleanup); (d) `Destroy`/`removeContainer` also unlink any stale socket. New struct fields (`readyDir`, `readyEnabled`) + `New()` wiring. `waitForToolbox`/`waitForRuntime` get the adaptive backoff. |
| `cmd/toolboxd/main.go` | Call `announceReady(logger)` early in boot — after env is read, *before* `serveHTTPFn` blocks (it can run in a goroutine so it never delays the HTTP/vsock listeners). |
| `internal/config/config.go` | Add `DockerReadySocketEnabled`, `DockerReadySocketDir`, `DockerReadinessPollInitial`, `DockerReadinessPollMax` with `getEnv*` defaults and validation (`initial>0`, `max>=initial`, dir non-empty when enabled). |
| `pkg/daemon/` (boot wiring) | Pass the resolved ready-socket dir/enable into the docker client constructor; ensure the dir is created (0700, sandboxd-owned) at boot and swept on startup for orphans. |
| `pkg/docker/client_test.go` | Extend the existing `roundTripFunc` fake + `newTestClient` so create-path tests assert the new bind + `SB_READY_SOCKET` env are present, and inject a temp ready dir. |
| `integration-tests/suite/harness/usecases.go` | Register `UC-96` (push readiness) and `UC-97` (legacy fallback) in `Registry`. |
| `integration-tests/suite/benchmark_test.go` | Optional: assert the Server-Timing `toolbox_wait` phase is near-zero when the push path is active, so a regression to polling is caught by the bench. |
| `pkg/api/v1/handlers.go` | (From the tight-poll plan) extend `setCreateServerTiming` to emit the `runtime_wait` / `toolbox_wait` sub-phases used by the assertion above. |
| `packaging/` + docs env table | Document the new `SB_DOCKER_READY_SOCKET_*` vars. |

> Note on the runtime seam: `pkg/docker/client.go` is the Docker
> `runtime.Runtime` implementation, so no `internal/runtime/docker` driver
> changes are needed beyond what flows through the client. If a thin wrapper
> exists there, only its constructor passthrough changes.

---

## Security issues & mitigations (≥10)

A host-owned socket bind-mounted into an **untrusted** container is sensitive
(cf. `docker.sock` escapes). Each risk and how this design closes it:

1. **Cross-sandbox access (confused deputy).** Could container A reach
   container B's readiness socket? → **Only the single socket file** is
   bind-mounted, into its own container, at a fixed guest path. The host
   parent directory (mode `0700`, sandboxd-owned) is **never** mounted. A
   container sees only its own socket inode.

2. **Readiness spoofing / premature ready.** Anything that can write to the
   socket could announce ready early or for another sandbox. → The handshake
   carries the per-sandbox `SB_TOOLBOX_TOKEN` (already injected, high-entropy);
   the host verifies it with `subtle.ConstantTimeCompare` and rejects mismatches.

3. **Socket file permissions vs. non-root container user.** The container's
   `toolboxd` (entrypoint, runs first) must be able to connect, but nothing
   else on the host should. → Socket created `0660`, sandboxd-owned, inside a
   `0700` dir; the host-side confidentiality rests on the dir mode + mount
   isolation, integrity on the token. Where userns/UID-mapping prevents connect,
   fall to `0666` *on the bind-mounted node only* — safe because the node is
   reachable solely from inside that one container. Documented explicitly; no
   silent world-writable host path.

4. **Connection-flood DoS (fd/goroutine exhaustion).** Untrusted code could
   open many connections. → The listener is **single-shot**: after the first
   *valid* ready (or the deadline) it `Close()`s and stops accepting. Small
   listen backlog; one accept goroutine per sandbox, bounded by the create's
   own lifetime.

5. **Slow-loris / connect-but-never-send.** → Every accepted conn gets a short
   read deadline (e.g. 2s); single-shot accept means a stalled connection
   cannot hold the channel open past the create deadline.

6. **Oversized / malformed payload (parser OOM).** → `bufio` reader with a hard
   line cap (e.g. 4 KiB) via `io.LimitReader`; one newline-delimited line; JSON
   decode of a bounded buffer; reuse the already-tested vsock JSON-line shape
   rather than new parsing code.

7. **Stale socket reuse / bind failure.** A leftover socket from a crashed
   sandbox could block `bind` or be reused. → Per-sandbox path keyed by
   validated `sandboxID` + create nonce; `os.Remove` (unlink) before `Listen`;
   cleanup on `Destroy` and a boot-time sweep of the ready dir for orphans.

8. **Path traversal / symlink on the socket path.** → Path is built only from
   `validateSandboxID`-checked IDs under a fixed sandboxd-owned dir; **no user
   input** in the path; create the dir with restrictive perms and refuse to
   follow symlinks for the parent.

9. **Container escape via the bind mount.** Bind-mounting host paths into
   untrusted containers is the classic escape vector. → Mount **only the socket
   node**, never its directory; a unix *socket* file does not let the container
   read/write arbitrary host files — connecting to it only yields the readiness
   channel. The host never mounts anything writable beyond this one node.

10. **Token leakage via logs/errors.** The ready line contains the token. →
    Never log the token or the raw line; compare constant-time; the token is
    already `os.Unsetenv`'d in `toolboxd` after read so user commands can't see
    it.

11. **Replay / cross-generation confusion (snapshot clones, recreate).** A
    recreated sandbox could receive a stale ready from a prior generation. →
    The host mints a fresh **nonce** per create and embeds the
    clone-generation; it accepts only a handshake echoing *that* nonce.

12. **Root-context parser hardening.** sandboxd may run as root; the socket
    reader is a root-context parser of attacker-influenced bytes. → Minimal,
    bounded, deadline-guarded parser reusing the vsock-proven shape; fuzz the
    `readyproto.Decode` path; no allocation driven by attacker-supplied length.

13. **Downgrade pressure to the fallback path.** Could an attacker force the
    weaker channel? → The fallback *is* today's `/health` behavior (not weaker),
    and both paths still require the agent to actually be up. There is no
    privileged action gated only behind the socket path.

14. **Listener lifetime leak.** A create that errors after listen but before
    accept could leak the listener/socket. → `readyListener.Close()` is in the
    same deferred-with-flag LIFO cleanup the Create path already uses for the
    TAP/VMM/registry resources (`pr-review.md §4`).

---

## Unit tests

### Created

`pkg/readyproto/readyproto_test.go`
- round-trip encode→decode of `ReadySignal`;
- oversize line (> cap) → error, no over-allocation;
- malformed JSON → error; unknown fields tolerated (forward-compat);
- empty/zero-value rejected.

`pkg/docker/readysock_test.go` (table-driven, matching `client_test.go` style)
- happy path: guest connects + sends valid signal → `Accept` returns ready
  before deadline;
- token mismatch → rejected, channel reports not-ready (forces fallback);
- nonce mismatch (replay) → rejected;
- never-connect → `Accept` times out at the deadline, returns the
  fallback-signal sentinel (not a hard error);
- slow-loris (connect, no data) → read deadline trips, treated as not-ready;
- oversize payload → rejected;
- single-shot: a second connection after the first ready is refused/ignored;
- cleanup: `Close()` unlinks the socket file; double-`Close` is safe;
- stale socket present → unlink-before-listen succeeds.

`pkg/docker/readysock_metrics.go` covered by `readysock_test.go` assertions on
the expvar counters (hit / fallback / timeout increment correctly).

`cmd/toolboxd/readyclient_test.go`
- dials a test listener and writes a signal with the env-sourced
  token/nonce/sandbox_id;
- `SB_READY_SOCKET` unset → no-op, no error (so non-Docker runtimes are
  unaffected);
- socket path present but unconnectable → logs + returns, never blocks boot;
- does not leak the token into the process env it passes to child commands.

### Modified

`pkg/docker/client_test.go`
- the create-path tests assert the new **bind** (`<dir>/<id>.sock:/run/aerol/ready.sock`)
  and **`SB_READY_SOCKET` env** are present in the `/containers/create` body;
- a test that drives the **race**: fake the container as ready via the socket
  and assert `waitForToolbox`'s health poll is *not* what completed the create
  (i.e. push wins); and the inverse (socket silent → health poll completes it);
- inject a `t.TempDir()` ready dir so tests never touch a real runtime dir.

`pkg/docker` coverage: keep the package at the ~85% bar (`/maintain-coverage`).

---

## Integration test updates

Register two UCs in `integration-tests/suite/harness/usecases.go`:

```go
{ID: "UC-96", Title: "Docker create readiness delivered via unix-socket push", Requires: []Capability{CapDocker}, Implemented: true},
{ID: "UC-97", Title: "Docker create falls back to health poll when push absent", Requires: []Capability{CapDocker}, Implemented: true},
```

`integration-tests/suite/docker_readiness_test.go` (behind the existing
`integration` build tag, run via the orchestrated suite):

- **UC-96 (push path):** create a Docker sandbox against a live node; assert it
  reaches `started`; then read the node's metrics/`Server-Timing` and assert the
  readiness came through the **socket** channel (`docker_ready_socket_hit`
  incremented and/or the `toolbox_wait` Server-Timing phase is near-zero). This
  is the regression guard that proves push is actually active, not silently
  falling back.
- **UC-97 (fallback path):** create a sandbox from an image whose toolbox does
  **not** dial (a pinned older toolbox, or a config toggle
  `SB_DOCKER_READY_SOCKET_ENABLED=false`); assert it still reaches `started`
  via the health poll (`docker_ready_socket_fallback_health` incremented). This
  guarantees the backward-compatibility promise (use case #19) is exercised on
  real infra.
- **Latency tie-in:** the existing `TestBenchCreateLatency` (UC-94) already
  measures docker server-side time; once this lands it should drop materially.
  Optionally tighten the bench to assert `toolbox_wait` ≈ 0 on the push path so
  a regression to polling shows up as a failing assertion, not just a slower
  number.

`integration-tests/README.md`: document the two new UCs and the
`SB_DOCKER_READY_SOCKET_*` knobs in the env table.

No live-AWS-specific wiring is required beyond the standard harness; these run
on any scenario advertising `CapDocker`.

---

## Rollout & PR rules

- **Boot-path change** → run `/touch-create-sandbox`, read `pr-review.md`, and
  the PR description must call out the create-latency impact (improvement, with
  before/after from the Server-Timing sub-phases), the idempotency story
  (readiness is single-shot + retry-safe; a retried create re-mints a nonce and
  re-listens), and the failure-path cleanup (listener `Close()`+unlink in LIFO).
- **Security review** required (new host↔container channel) — the section above
  is the checklist to walk in review.
- **Default on** (`SB_DOCKER_READY_SOCKET_ENABLED=true`) with the health-poll
  fallback always compiled in, so a problem can be disabled by config without a
  redeploy of new code.
- Ship behind the metrics so an operator can confirm hit-vs-fallback ratio in
  production before trusting it.

## Expected outcome

Docker server-side create drops from ~628ms toward the **true** agent-ready
time (push removes the double 300ms rounding and the fallback poll is only a
safety net). Under burst load the `dockerd` inspect/health storm disappears.
The readiness model converges with Firecracker/WASM, and a reusable per-sandbox
control channel exists for future Docker-side push features — all without
exposing any host network surface to untrusted sandbox code.

---

## Review decisions (locked 2026-06-30, /plan-eng-review + Codex outside voice)

These supersede the as-written design above where they conflict. Each is a
resolved decision; implementation follows these, not the earlier prose.

**Scope:** Build the full socket-push subsystem now (not the backoff-only
minimal version), bundled into ONE PR with the fallback backoff. The
Server-Timing sub-phases still ship in the same PR, so socket-vs-backoff
attribution comes from the per-phase timing even though bundled.

1. **Accept model — accept-until-valid, NOT single-shot.** The container runs
   untrusted code; a malicious in-container process can race `toolboxd` and
   connect first with a bad token. A single-shot listener would close on that
   first connection and silently suppress the real push (degrading that sandbox
   to the slow poll and skewing metrics). The listener keeps accepting until a
   connection carries a valid `token`+`nonce`, OR the deadline hits, OR a
   bounded `max-invalid-attempts` cap trips. Each accepted conn still has a read
   deadline + byte cap. (Replaces security items #4 and #5's single-shot.)

2. **Socket permissions — `0666` + mandatory token.** Connecting to a unix
   socket needs write permission on the node; sandboxd runs as root and many
   images run as a non-root uid, so a tight 0660 root-owned socket would make
   the push a silent no-op on those images. Create the socket `0666`; the
   per-sandbox `token` (constant-time compared) is the integrity gate, since the
   user's own code shares the container uid and file perms can never exclude it.
   Confidentiality rests on per-container mount isolation (only the one socket
   node is mounted) + the `0700` host dir. (Settles security item #3.)

3. **Race design — shared context, grace-delayed poll.** Socket-accept and the
   backoff health-poll run under ONE context bounded by `toolboxWaitTimeout`;
   first success cancels the other (no goroutine leak dialing a returned
   container). The health poll starts only after a short grace (~50ms) so a
   normal socket hit issues ZERO health dials — this is what actually delivers
   the dockerd-storm-elimination goal.

4. **Ready semantics — dial AFTER the HTTP listener is accepting.** `toolboxd`
   sends the ready signal once its HTTP server is bound and accepting, NOT as
   its literal first action. This preserves the exact guarantee today's
   `/health` 200 gives: when create returns `started`, the toolbox API
   (exec/files/sessions) is reachable. Dialing earlier would return `started`
   before the API serves and cause post-create connection-refused races — a
   regression hidden behind a faster metric.

5. **gVisor — needs `--host-uds=open`; NOT free, and off by default today.**
   Root cause (not just "virtualized AF_UNIX"): `runsc` gates host unix-socket
   passthrough behind `--host-uds` (default `none`). A gVisor sandbox can only
   `connect()` to a bind-mounted host socket when runsc runs with
   `--host-uds=open` (or `all`). **AerolVM's installer does not set it** —
   `scripts/install.sh` `register_gvisor_runtime` writes
   `{"runtimes":{"runsc":{"path":...}}}` with no `runtimeArgs`, so the default
   `none` applies and the push would silently fall back to the poll on every
   gVisor create. Sharing `pkg/docker/client.go` does **not** make it "free" —
   same Go code, different runtime *policy*. Resolution:
   - Drop use case #17's "for free" claim.
   - Add **UC-96c on cluster-hetero** (which has a gVisor-capable node): create
     under `runsc`, assert the push channel actually delivered (per-sandbox
     `Server-Timing source`), not fallback.
   - **If UC-96c is green with the flag**, add `"runtimeArgs":["--host-uds=open"]`
     to the runsc entry in `register_gvisor_runtime` (`scripts/install.sh`) +
     the Terraform/Ansible install path, and document it. Use `open`
     (connect-only), **not** `all` (which also permits the sandbox to *create*
     host sockets — broader than we need).
   - **Security note (review item):** `--host-uds=open` is a deliberate,
     fleet-wide relaxation of gVisor isolation — every gVisor sandbox gains the
     capability to connect to host UDSes that are bind-mounted into it. Exposure
     is bounded to exactly what we mount (the one readiness socket node); we
     mount nothing else host-UDS-wise. This must be an explicit security-review
     decision, not a silent flip.
   - Fallback guarantees correctness regardless of the flag, so this is a
     latency/claim issue, never a correctness one. If the security team rejects
     relaxing `host-uds`, gVisor stays fallback-only (still gets the backoff
     win) and use case #17 is dropped, not deferred.

6. **Bind-mount topology — scope to local Linux runc dockerd.** Rootless Docker,
   strict SELinux/AppArmor (:z/:Z), userns-remap, Docker Desktop, and remote
   daemons are **NOT in scope** (see below) — they're not AerolVM deployment
   targets and the fallback + hit/fallback metric keep them correct and visible.

7. **DRY — separate `pkg/readyproto`.** Do not unify with the Firecracker vsock
   protocol (different direction/ops/lifecycle; unifying drags the fragile
   snapshot path into this change). Accept the ~20-line wire-shape duplication.

8. **Config — 3 knobs, and the push is gated on cluster mode.**
   `SB_DOCKER_READY_SOCKET_ENABLED` + the two backoff knobs. Derive the socket
   dir from the runtime dir (drop `SB_DOCKER_READY_SOCKET_DIR`).

10. **Enablement gated on `EnableCluster` — OFF in local/self-install.** The
    socket push must NOT run on hosts we don't control (the open-source
    one-liner self-install on an arbitrary Docker setup). The effective gate is
    `SB_DOCKER_READY_SOCKET_ENABLED` (default `true`) **AND** `cfg.EnableCluster`.
    So:
    - Cluster deploys (`SB_ENABLE_CLUSTER=true`, e.g. cluster-hetero) → push ON.
    - Every self-install, `--local` install, and single-node deploy
      (`EnableCluster=false`) → push OFF → the (backoff-improved) health poll
      runs, which is safe on any topology.
    - The `_ENABLED` knob stays a kill switch (set `false` disables even in
      cluster) but can never force the push ON outside cluster mode.
    This is one line in `config.go` (no installer/IaC edits), and it makes the
    local-mode/single-node integration scenarios validate the OFF/fallback path
    for free (they're non-cluster). The fallback guarantees correctness, so a
    controlled single-node deploy simply uses the poll — not a regression.
    Rationale: "default-on" applies *within the deployments we control*
    (clusters); uncontrolled hosts get the safe poll.

9. **Cleanup is NEW wiring, not reuse.** The Docker `Create` (`client.go:303`)
   has no defer-flag stack (that's the *Firecracker* Create). Add an explicit
   committed-flag deferred closure (close listener + unlink socket on any
   pre-commit error) + `Destroy` unlink + a boot sweep. The sweep MUST be
   generation/nonce-keyed so it cannot race-delete a live create's socket.

**Folded hardening (from Codex, no separate decision needed):**
- **Nonce lifecycle:** inject as its own env var (e.g. `SB_READY_NONCE`)
  alongside the token; `toolboxd` reads both, dials, then the existing
  `os.Unsetenv` scrub runs — the dial MUST happen before the scrub. Cover in
  `readyclient_test.go` (token/nonce not leaked to child env).
- **PID1 safety:** the dial runs in a goroutine with a concrete bounded timeout,
  placed AFTER reaper setup and env scrubbing, never fatal — a blocked/crashed
  dial cannot regress create.
- **Test attribution:** integration UCs assert via the per-create `Server-Timing`
  `source` field (push vs fallback) for THAT sandbox, NOT a global expvar
  counter delta (counters are flaky under concurrent tests).
- **Sandbox-ID boundary:** the socket path derives only from a
  `validateSandboxID`-checked id; document the exact charset/length the path
  relies on.
- **Server-Timing assertion:** assert the readiness `source` is the socket, NOT
  that `toolbox_wait ≈ 0` (a correct agent still takes real init time).
- **Compat matrix collapses for Docker:** `toolboxd` is bind-mounted from the
  host (`client.go` `c.toolboxBinaryPath`), so host and guest are ALWAYS the
  same release — no old-toolbox/new-host skew. The fallback stays as
  defense-in-depth, but use case #19's "old image" framing is rewritten.
- **Claim corrections:** soften #13 (the create path's `/health` poll already
  precedes egress-block application, so `NetworkBlockAll` survival is not a
  differentiator); #17 (gVisor — verify); #20 (the listener closes after one
  line — it is NOT a reusable bidirectional channel without a different
  lifetime/auth/versioning model; state that honestly).

## NOT in scope

| Deferred | Rationale |
|---|---|
| Rootless Docker / Docker Desktop / remote daemon socket-push | Not AerolVM deployment targets; fallback keeps them correct, metric makes the slow path visible |
| Strict SELinux/AppArmor relabel handling (:z/:Z) | Same; add a one-line doc note that push falls back unless the node is relabeled |
| userns-remap chown of the socket | `0666` + token already works under remap; chown-to-uid (review option 1B) rejected as fragile |
| Unifying vsock + readiness into one shared control protocol | Premature abstraction across the fragile snapshot path (review decision #7); revisit only if a 3rd host↔guest channel appears |
| Bidirectional/reusable control channel (push shutdown/quiesce to Docker) | This design is one-shot readiness; a real control channel needs its own lifetime/auth/versioning design |
| Push on local-mode / self-install / any non-cluster host | Decision #10 — gated on `EnableCluster`; we don't control self-install hosts, fallback poll is correct everywhere |
| Push on a CONTROLLED single-node (non-cluster) deploy | Side effect of the `EnableCluster` gate; acceptable (poll fallback), revisit only if controlled single-node becomes a production shape |
| Splitting backoff into a separate PR | Considered (Codex); user chose one bundled PR — attribution preserved via Server-Timing sub-phases |
| Non-Linux runtime support for the dial | toolboxd runs in Linux containers; only a CI cross-compile build-tag guard is in scope, not real non-Linux behavior |

## What already exists (reused, not rebuilt)

- **Firecracker vsock readiness** (`internal/runtime/firecracker/driver.go`,
  `cmd/toolboxd/vsock.go`) — the out-of-band push model this mirrors. Wire
  *shape* is echoed in `readyproto`; code intentionally not shared (decision #7).
- **`toolboxd` bind-mount + env injection** (`pkg/docker/client.go` `binds` +
  `envValues`) — the readiness bind + `SB_READY_SOCKET`/`SB_READY_NONCE` ride
  the existing mechanism; no new mount machinery.
- **`SB_TOOLBOX_TOKEN`** (`cmd/toolboxd/main.go`) — reused as the handshake
  integrity gate; already high-entropy, already env-scrubbed post-read.
- **`waitForToolbox`/`waitForRuntime`** (`pkg/docker/client.go`) — the fallback
  path; modified in place (backoff), not replaced.
- **expvar pool-metrics convention** (`internal/pool/*/metrics.go`) — the
  readiness counters follow it.
- **`validateSandboxID`** — reused for the socket path boundary.
- **Server-Timing** (`pkg/api/v1/handlers.go`) — extended with sub-phases, not
  rebuilt.

## Failure modes (per new codepath)

| Codepath | Realistic failure | Test? | Error handling | User-visible? |
|---|---|---|---|---|
| `readyListener.Accept` | malicious in-container connect floods bad tokens | yes (cap test) | invalid-attempt cap + deadline | no (push just degrades to poll) |
| `readyListener.Accept` | gVisor blocks the connect (runsc `--host-uds` defaults to `none`) | yes (UC-96c) | grace-delayed poll wins | no (slower create only, until install adds `--host-uds=open`) |
| `announceReady` dial | dial blocks during PID1 boot | yes (unit) | goroutine + bounded timeout, never fatal | no |
| socket bind | stale socket from crashed sandbox blocks `Listen` | yes (unit) | unlink-before-listen + gen-keyed sweep | no |
| boot sweep | sweep races a live create's socket | **must test** | generation/nonce-keyed paths | **CRITICAL if unkeyed — would kill a live create** |
| race cancel | loser goroutine leaks dialing dead container | yes (unit) | shared ctx cancel | no |
| backoff poll (regression) | slow-ready container exceeds a too-tight cap | yes (regression, mandatory) | deadline unchanged at 30s | yes if it regressed (create fails) — guarded |

The boot-sweep-vs-live-create race is the one **critical** gap: unkeyed cleanup
could unlink a socket a concurrent create is mid-flight on. Generation/nonce-keyed
paths + a test are mandatory.

## Worktree parallelization strategy

| Step | Modules touched | Depends on |
|---|---|---|
| S1 readyproto | `pkg/readyproto/` | — |
| S2 host listener | `pkg/docker/` (readysock) | S1 |
| S3 guest dialer | `cmd/toolboxd/` | S1 |
| S4 config | `internal/config/` | — |
| S5 Create wiring + backoff + Server-Timing | `pkg/docker/`, `pkg/api/v1/`, `pkg/daemon/` | S2, S4 |
| S6 integration UCs | `integration-tests/` | S5, S3 |

- **Lane A:** S1 → S2 → S5 (sequential, shared `pkg/docker/`)
- **Lane B:** S3 (independent, `cmd/toolboxd/`, after S1)
- **Lane C:** S4 (independent, `internal/config/`)

Execution: S1 first (both lanes depend on it). Then A (S2→S5), B (S3), C (S4) in
parallel worktrees. Merge all. Then S6. **Conflict flag:** S2 and S5 both touch
`pkg/docker/` — keep them in one lane (sequential), do not parallelize.

## Implementation Tasks
Synthesized from this review's findings. Each derives from a specific finding.

- [ ] **T1 (P1, human: ~3h / CC: ~25min)** — readysock — accept-until-valid listener
  - Surfaced by: Codex tension #8 — single-shot is exploitable
  - Files: `pkg/docker/readysock.go`, `pkg/readyproto/readyproto.go`
  - Verify: `go test ./pkg/docker/ -run ReadySock`
- [ ] **T2 (P1, human: ~2h / CC: ~15min)** — readysock/toolboxd — 0666 socket + mandatory token+nonce (constant-time)
  - Surfaced by: Architecture #1 + Codex token/nonce
  - Files: `pkg/docker/readysock.go`, `cmd/toolboxd/readyclient.go`
  - Verify: `go test ./pkg/docker/... ./cmd/toolboxd/...`
- [ ] **T3 (P1, human: ~4h / CC: ~30min)** — docker Create — race (grace-delayed poll, shared ctx) + explicit cleanup + gen-keyed sweep
  - Surfaced by: Architecture #2, #3; Codex sweep-race
  - Files: `pkg/docker/client.go`, `pkg/daemon/`
  - Verify: `go test ./pkg/docker/ -run Create`
- [ ] **T4 (P1, human: ~2h / CC: ~15min)** — toolboxd — dial after HTTP listener up, goroutine + bounded timeout, never fatal
  - Surfaced by: Codex tension #10 + PID1 timing
  - Files: `cmd/toolboxd/main.go`, `cmd/toolboxd/readyclient.go`
  - Verify: `go test ./cmd/toolboxd/...`
- [ ] **T5 (P1, human: ~2h / CC: ~15min)** — docker — adaptive backoff + REGRESSION test (slow-ready container still succeeds)
  - Surfaced by: Test review IRON RULE (modifies path every create uses)
  - Files: `pkg/docker/client.go`, `pkg/docker/client_test.go`
  - Verify: `go test ./pkg/docker/ -run WaitFor`
- [ ] **T6 (P1, human: ~45min / CC: ~8min)** — config — 3 knobs + validation, derive socket dir, gate effective-enable on `EnableCluster`
  - Surfaced by: Code Quality #2 + decision #10 (off in local/self-install)
  - Files: `internal/config/config.go`
  - Detail: effective enable = `getEnvBool("SB_DOCKER_READY_SOCKET_ENABLED", true) && cfg.EnableCluster`; add a config test asserting non-cluster → disabled even with the knob true, and cluster+knob-false → disabled.
  - Verify: `go test ./internal/config/...`
- [ ] **T7 (P1, human: ~1h / CC: ~10min)** — api — Server-Timing sub-phases (runtime_wait/toolbox_wait/source)
  - Surfaced by: Phase-1 measure-first (Codex "wrong bottleneck")
  - Files: `pkg/api/v1/handlers.go`, `pkg/docker/client.go`
  - Verify: `go test ./pkg/api/v1/...`
- [ ] **T8 (P1, human: ~3h / CC: ~25min)** — integration — UC-96 / UC-96b (non-root) / UC-96c (gVisor) / UC-97 (fallback), assert per-sandbox Server-Timing source
  - Surfaced by: Test review (silent-fallback) + Codex gVisor + metric-flakiness
  - Files: `integration-tests/suite/docker_readiness_test.go`, `integration-tests/suite/harness/usecases.go`
  - Verify: `go test -tags=integration ./integration-tests/suite/ -run Readiness`
- [ ] **T9 (P2, human: ~1h / CC: ~10min)** — readyproto — bounded decode + fuzz
  - Surfaced by: Security #6/#12
  - Files: `pkg/readyproto/readyproto.go`, `pkg/readyproto/readyproto_test.go`
  - Verify: `go test ./pkg/readyproto/...`
- [ ] **T10 (P2, human: ~1h / CC: ~10min)** — metrics — expvar counters with per-sandbox attribution
  - Surfaced by: Codex metric-flakiness
  - Files: `pkg/docker/readysock_metrics.go`
  - Verify: `go test ./pkg/docker/ -run Metrics`
- [ ] **T11 (P2, human: ~1h / CC: ~10min)** — docs — env table, NOT-in-scope topologies, soften use-case claims #13/#17/#20
  - Surfaced by: Codex claim corrections
  - Files: `integration-tests/README.md`, `packaging/`, this plan
  - Verify: manual
- [ ] **T12 (P3, human: ~30min / CC: ~5min)** — toolboxd — build-tag guard if CI cross-compiles to non-Linux
  - Surfaced by: Codex non-Linux builds
  - Files: `cmd/toolboxd/readyclient_linux.go` / `_other.go`
  - Verify: `GOOS=darwin go build ./cmd/toolboxd/`
- [ ] **T13 (P2, human: ~1h / CC: ~15min, GATED on UC-96c green)** — install — add `runtimeArgs:["--host-uds=open"]` to the runsc daemon.json entry
  - Surfaced by: user — gVisor connect needs runsc `--host-uds=open`; default install omits it
  - Files: `scripts/install.sh` `register_gvisor_runtime` — **single source**; Terraform (`--with-gvisor` → install.sh) and Ansible (asserts install.sh ran) both route through it, so this one function is the only code change. BUT it has **three spots** that hard-set the runsc entry and ALL must add `runtimeArgs`: the `desired=` printf (~:1206), the `jq` merge (~:1214), and the `python3` fallback (~:1216) — miss the python branch and no-jq hosts silently omit the flag. Plus docs: `README.md` gVisor row, `docs/.../single-node-setup.md`, `setup/arch.md`.
  - Verify: `UC-96c` push delivered under gVisor on cluster-hetero; `docker info` / `cat /etc/docker/daemon.json` shows runsc with the arg; re-run installer is idempotent (the diff-check at ~:1237 detects the new arg and restarts docker once).
  - Note: security-review gate — `open` not `all`; isolation-relaxation decision must be signed off. Do NOT land before UC-96c proves it's needed and sufficient.

## Propagation map (where each change actually lands)

The repo has multiple install/provision paths; this maps each change to every
place it must reach so nothing is updated in one path and missed in another.

| Change | Single source? | Reaches Terraform | Reaches Ansible | Reaches integration tests | Action |
|---|---|---|---|---|---|
| gVisor `--host-uds=open` | **Yes** — `install.sh register_gvisor_runtime` (only `daemon.json` runsc writer) | ✅ via `--with-gvisor`→install.sh | ✅ relies on install.sh, no own registration | ✅ via the prod TF module | Edit the one function (3 spots: printf/jq/python) — T13 |
| `SB_DOCKER_READY_SOCKET_ENABLED` (gated `AND EnableCluster`) + backoff knobs | **config.go**, effective = default `true` AND `cfg.EnableCluster` | ✅ on in cluster bootstraps (EnableCluster=true), off otherwise | ✅ same | ✅ on for cluster-* scenarios, off for local-mode/single-node | One config.go line; no template edits. Self-install/local/single-node are non-cluster → OFF automatically |
| New `SB_READY_SOCKET` / `SB_READY_NONCE` env | host-side, set per-create by `pkg/docker/client.go` | n/a (not an operator env) | n/a | n/a | Injected by the daemon at create time, never in any `.env` template |
| New UCs (96/96b/96c/97) | `harness/usecases.go` Registry | n/a | n/a | ✅ cluster-hetero already has docker + gVisor nodes | Register in usecases.go — T8 |
| Docs (env table, gVisor flag, NOT-in-scope) | per-file | — | — | `integration-tests/README.md` | T11 + T13 |

**UC-97 (fallback path) — make it a unit test, not an env-toggled integration
test.** The plan originally suggested toggling `SB_DOCKER_READY_SOCKET_ENABLED=false`
on a node. That env var is NOT surfaced through the IaC (default-on, config.go
only), so toggling it per-scenario would require the full 4-place wasm-pool
plumbing just for one test. Cheaper and more robust: cover the disabled/fallback
path as a `pkg/docker` **unit test** (construct the client with the channel
disabled, assert the health poll completes the create). Reserve integration for
UC-96/96b/96c (proving the push *fires*), which run on cluster-hetero
(`EnableCluster=true`) where the gate is on. (Also: the "old toolbox image"
framing for UC-97 is moot for Docker — toolboxd is bind-mounted from the host,
so it's always current.)

**Bonus from decision #10:** because the push is gated on `EnableCluster`, the
non-cluster integration scenarios (`local-mode`, `single-node`) now exercise the
OFF/fallback path on real infra **for free** — a Docker create there must still
reach `started` via the poll, with `docker_ready_socket_*` untouched. Add that
assertion to the existing single-node lifecycle UC rather than a new scenario.

**Kill-switch surfacing — deliberately deferred (YAGNI).** Keeping
`SB_DOCKER_READY_SOCKET_ENABLED` config.go-default-on (not surfaced in
Terraform/Ansible/`config/cluster.yml`/run.sh) means a managed-fleet operator
who hand-edits `sandboxd.env` to disable it would have it overwritten on the
next provision. That's acceptable because the fallback guarantees correctness
and the switch is an emergency lever, not a routine knob. If ops ever needs it
first-class, surface it via the 4-place wasm-pool pattern as a fast-follow —
listed in NOT in scope.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | not run (infra change) |
| Codex Review | `/codex review` | Independent 2nd opinion | 1 | issues_found | 21 challenges; 5 promoted to forks, rest folded as hardening |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | clean | 11 issues + 5 cross-model forks, all folded; 1 critical gap (boot-sweep race) fix mandated |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | not run (no UI) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | not run |

- **CODEX:** outside voice surfaced 5 issues the inside review missed — single-shot accept is exploitable, gVisor passthrough unverified, ready-semantics timing, bind-mount portability, backoff-bundling scope. All resolved via decisions #1, #5, #4, #6, scope-bundle. Remaining Codex points folded as hardening (nonce lifecycle, PID1 timeout, per-sandbox metric attribution, sweep generation-keying, claim corrections).
- **CROSS-MODEL:** Claude + Codex converged on measure-first (Phase-1 instrumentation), 0666 caution, inspect/NetworkBlockAll claim weakness, and metric-as-assertion flakiness. Codex's single-shot-exploit catch was the highest-value addition; Claude's "toolboxd is bind-mounted from host" context collapsed Codex's compat-matrix concern.
- **VERDICT:** ENG CLEARED — ready to implement. All 11 findings + 5 cross-model forks folded into the plan; the one critical gap (boot-sweep racing a live create) has a mandated fix (generation/nonce-keyed paths + test). Scope confirmed: full socket-push, one bundled PR.

NO UNRESOLVED DECISIONS
