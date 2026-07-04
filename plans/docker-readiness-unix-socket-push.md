# Docker readiness via Unix-socket push ("vsock for Docker")

Status: **Implemented** — landed in [PR #271](https://github.com/aerol-ai/microvm/pull/271) (`docker-socket` branch). Live integration verification (UC-96/96b/96c on `cluster-hetero`) and operator docs are still pending before merge.

## Implementation status (2026-06-30)

| Area | State |
|------|--------|
| Core code (`readyproto`, `readysock`, Create race, toolboxd dial, config gate, Server-Timing) | ✅ Shipped |
| Unit tests | ✅ Shipped (`go test ./pkg/readyproto/... ./pkg/docker/... ./cmd/toolboxd/... ./internal/config/...`) |
| Integration tests (UC-96 / 96b / 96c written) | ⏳ Not yet run on live AWS |
| UC-97 fallback | ✅ Unit test (`TestCreate_FallbackWhenPushDisabled`) + non-cluster integration (`TestDockerReadinessFallbackOnNonCluster`) |
| gVisor `--host-uds=open` (cluster-init/join) | ✅ Code shipped (cluster-only gate; off on standalone hosts); ⏳ UC-96c + security sign-off pending |
| Docs (`integration-tests/README.md`, `packaging/`, gVisor operator docs) | ⏳ Pending (T11) |
| `readyproto` fuzz | ⏳ Pending (T9, P2) |
| Benchmark `toolbox_wait` regression | ⏳ Optional, not done |

Boot-path change → followed `/touch-create-sandbox` + `pr-review.md` in PR description.

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
9. Detects a wedged / never-ready toolbox via accept-until-valid deadline
   (invalid connects rejected; valid handshake or timeout).
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
17. gVisor can use the same push path when `runsc` runs with `--host-uds=open`
    (`install.sh`); otherwise fallback poll only (same backoff win).
18. Avoids exposing any host-facing readiness *network* endpoint to untrusted
    sandboxes (the failure mode of a webhook approach).
19. Backward compatible: toolbox images built before this change still come up
    via the existing `/health` poll fallback (no flag-day).
20. Establishes a **one-shot** per-create host↔container readiness channel (not a
    reusable bidirectional control plane without further auth/lifetime design).

### As-implemented claim notes

Eng review softened several bullets above; shipped behavior matches the locked
decisions section:

- **#9** — accept-until-valid (invalid connects are rejected, channel stays open).
- **#13** — not a unique win: health poll already completed before egress rules apply.
- **#17** — gVisor needs `runsc --host-uds=open`; otherwise fallback poll only.
- **#19** — toolboxd is bind-mounted from the host; fallback is defense-in-depth.
- **#20** — one-shot readiness only; listener closes after success or create ends.

---

## Design / how it is solved

### Channel topology (host listens, guest connects = true push)

```
HOST (sandboxd)                                  CONTAINER (toolboxd, PID 1)
──────────────                                   ──────────────────────────
1. create <dir>/<sandboxID>.<nonce>.sock, listen()
2. bind-mount that ONE socket file ──────────►   /run/aerol/ready.sock  (rw)
   set env SB_READY_SOCKET=/run/aerol/ready.sock, SB_READY_NONCE=<nonce>
3. /containers/create, /containers/start
4. inspect (backoff) until Running + IP         5. HTTP listener binds (tcp)
6. race: Accept() vs grace-delayed /health       6. goroutine dials ready.sock
7. read JSON line, verify token+nonce ◄────────    write {ready, token, nonce, ...}
8. close listener, unlink socket → ready
```

**Ready semantics (decision #4):** toolboxd dials **after** its HTTP listener is
accepting — same guarantee as `/health` 200 when create returns `started`.

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
`docker_ready_socket_timeout`, `docker_ready_socket_invalid_attempts`, plus
`ready_wait_ms` (atomic last successful wait — not a histogram). Integration
assertions use per-create `Server-Timing` (`readiness;desc=socket|health`), not
global expvar deltas (flaky under concurrency).

### Config knobs (`internal/config`)

- `SB_DOCKER_READY_SOCKET_ENABLED` (default `true`) — kill switch; effective only when `EnableCluster=true`.
- Socket dir **derived** at runtime: `{MountsCredentialsRuntimeDir}/docker/ready` via `Config.DockerReadySocketDir()` (no separate `SB_DOCKER_READY_SOCKET_DIR` env).
- Fallback poll backoff: `SB_DOCKER_READINESS_POLL_INITIAL` (default `20ms`), `SB_DOCKER_READINESS_POLL_MAX` (default `300ms`).

The existing `SB_DOCKER_WAIT_TIMEOUT` / `SB_TOOLBOX_WAIT_TIMEOUT` (30s) stay as
the outer deadline, unchanged.

---

## Files CREATED

| File | Purpose |
|---|---|
| `pkg/readyproto/readyproto.go` | Shared wire shape (`ReadySignal` struct, `Event` constant, a bounded newline-JSON `Encode`/`Decode`). Imported by **both** the host (`pkg/docker`) and the guest (`cmd/toolboxd`), mirroring how the vsock protocol shape is isolated from its socket layer. |
| `pkg/readyproto/readyproto_test.go` | Encode/decode round-trip, oversize-line rejection, malformed-JSON rejection, unknown-field tolerance. |
| `pkg/docker/readysock.go` | Host side: `ReadyListener` — accept-until-valid, `0666` socket, token/nonce verification, bounded reader, cleanup. |
| `pkg/docker/readysock_test.go` | Unit tests (`//go:build linux` — unix socket bind requires Linux). |
| `pkg/docker/readysock_metrics.go` | expvar counters + `ready_wait_ms` atomic. |
| `pkg/docker/create_timing.go` | `CreateTiming` context recorder for Server-Timing sub-phases. |
| `pkg/docker/ready_create_test.go` | Create-path wiring, socket-wins race, fallback-disabled, slow-ready backoff. |
| `cmd/toolboxd/readyclient_linux.go` | Guest dialer (`announceReady`, `dialReadySocket`). |
| `cmd/toolboxd/readyclient_other.go` | No-op stub for non-Linux builds. |
| `cmd/toolboxd/readyclient_test.go` | Dialer unit tests (`//go:build linux`). |
| `integration-tests/suite/docker_readiness_test.go` | UC-96 / 96b / 96c + non-cluster fallback assertion. |
| `plans/docker-readiness-unix-socket-push.md` | This document. |

## Files MODIFIED

| File | Change |
|---|---|
| `pkg/docker/client.go` | `Create`: (a) before `/containers/create`, construct the `readyListener` and append its bind to `binds` + its env to `envValues`; (b) after `/containers/start`, keep one `inspect` for the container IP, then **race** `readyListener.Accept()` against the (backoff) `waitForToolbox`; (c) on every failure path, `readyListener.Close()` + unlink (LIFO with the existing cleanup); (d) `Destroy`/`removeContainer` also unlink any stale socket. New struct fields (`readyDir`, `readyEnabled`) + `New()` wiring. `waitForToolbox`/`waitForRuntime` get the adaptive backoff. |
| `cmd/toolboxd/main.go` | `announceReady()` after HTTP `Listen`, before `Serve`; scrub `SB_READY_*` env. |
| `internal/config/config.go` | `DockerReadySocketEnabled`, poll backoff knobs, `DockerReadySocketEffective()`, `DockerReadySocketDir()`. |
| `pkg/daemon/daemon.go` | `EnsureReadyDir` + `SweepOrphanReadySockets` at boot when push enabled. |
| `pkg/api/v1/handlers.go` | Server-Timing: `runtime_wait`, `toolbox_wait`, `readiness;desc=`. |
| `pkg/api/v1/cluster_handler.go` | Pass `nil` timing on cluster placement path (worker returns timing when hit directly). |
| `integration-tests/suite/harness/usecases.go` | UC-96, UC-96b, UC-96c registered. |
| `integration-tests/suite/harness/timing.go` | `parseServerTimingReadinessSource`, `LastCreateReadinessSource`. |
| `scripts/cluster-init.sh`, `scripts/cluster-join.sh` | `ensure_gvisor_host_uds` appends gVisor `runtimeArgs: ["--host-uds=open"]` on cluster nodes only (idempotent; no-op without gVisor). `install.sh` deliberately leaves runsc at `--host-uds=none`. |
| `integration-tests/README.md` | ⏳ Document UC-96* and env knobs (T11). |
| `packaging/` env table | ⏳ Document knobs (T11). |
| `integration-tests/suite/benchmark_test.go` | Optional: `toolbox_wait` regression — not implemented. |

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

3. **Socket file permissions vs. non-root container user.** → Socket created
   **`0666`** on the bind-mounted node (decision #2); integrity gate is the
   per-sandbox token. Parent dir stays `0700`, sandboxd-owned; only the socket
   inode is mounted into the container.

4. **Connection-flood DoS (fd/goroutine exhaustion).** → **Accept-until-valid**
   (decision #1) with a bounded `max-invalid-attempts` cap and per-conn read
   deadline. Listener lifetime is bounded by the create's `toolboxWaitTimeout`;
   one accept goroutine per in-flight create.

5. **Slow-loris / connect-but-never-send.** → Every accepted conn gets a short
   read deadline (2s); invalid/slow connects are dropped and the listener keeps
   accepting until a valid handshake or the outer deadline.

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

`pkg/docker/ready_create_test.go` (new file, not `client_test.go`):
- create-path bind + `SB_READY_SOCKET` / `SB_READY_NONCE` env assertions;
- socket-wins race (`TestCreate_SocketPushWinsOverHealthPoll`);
- push-disabled fallback (`TestCreate_FallbackWhenPushDisabled`);
- slow-ready backoff (`TestPollToolboxHealth_SlowReadyStillSucceeds`).

`readysock_test.go` is `//go:build linux` (unix bind requires Linux hosts).

---

## Integration test updates

Registered in `integration-tests/suite/harness/usecases.go`:

```go
{ID: "UC-96",  Title: "Docker create readiness delivered via unix-socket push", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
{ID: "UC-96b", Title: "Docker socket push works for non-root container images", Requires: []Capability{CapCluster, CapDocker}, Implemented: true},
{ID: "UC-96c", Title: "Docker socket push works under gVisor runtime",         Requires: []Capability{CapCluster, CapDocker, CapGvisor}, Implemented: true},
```

`integration-tests/suite/docker_readiness_test.go` (behind `integration` build tag):

- **UC-96 / 96b / 96c:** create on `cluster-hetero`; assert `readiness;desc=socket`
  via `Client.LastCreateReadinessSource()` (per-create Server-Timing, not expvar).
- **Fallback (UC-97 equivalent):** `TestDockerReadinessFallbackOnNonCluster` on
  `local-mode` / `single-node` scenarios asserts `readiness;desc=health` (push
  gated off by `EnableCluster=false`). Plus unit test `TestCreate_FallbackWhenPushDisabled`.

**Not asserted:** `toolbox_wait ≈ 0` on push path — a correct agent still has real
init time; only the *source* matters.

**Verify on live infra:**
```bash
make integration-cluster-hetero   # UC-96, 96b, 96c
go test -tags=integration ./integration-tests/suite/ -run Readiness
```

`integration-tests/README.md`: ⏳ document UC-96* and env knobs (T11).

---

## Rollout & PR rules

- **Boot-path change** → run `/touch-create-sandbox`, read `pr-review.md`, and
  the PR description must call out the create-latency impact (improvement, with
  before/after from the Server-Timing sub-phases), the idempotency story
  (readiness is accept-until-valid + retry-safe; a retried create re-mints a
  nonce and re-listens), and the failure-path cleanup (listener `Close()`+unlink
  in deferred LIFO).
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

5. **gVisor — needs `--host-uds=open`.** `runsc` gates host UDS passthrough
   behind `--host-uds` (default `none`). The relaxation is fleet-wide (every
   runsc sandbox on the host), so it is enabled **only on cluster nodes**, by
   `scripts/cluster-init.sh` / `scripts/cluster-join.sh` (`ensure_gvisor_host_uds`)
   rather than `install.sh` — install.sh runs before the node is in a cluster
   and must not relax isolation on standalone gVisor hosts that never run the
   socket. The cluster scripts append `--host-uds=open` to the registered
   `runsc` runtimeArgs idempotently (no-op when gVisor isn't installed or the
   arg is already present), so the relaxation is scoped to cluster+gVisor.
   Without it the push path degrades to health polling (UC-97). **Pending:**
   UC-96c on live `cluster-hetero` + security sign-off.

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
| `readyListener.Accept` | gVisor blocks the connect (runsc `--host-uds` defaults to `none`) | yes (UC-96c) | grace-delayed poll wins | no (slower create only, until cluster-init/join adds `--host-uds=open`) |
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

Status as of 2026-06-30 ([PR #271](https://github.com/aerol-ai/microvm/pull/271)).

- [x] **T1** — accept-until-valid listener (`readysock.go`, `readyproto/`)
- [x] **T2** — `0666` + token/nonce (`readysock.go`, `readyclient_linux.go`)
- [x] **T3** — Create race + cleanup + nonce-keyed sweep (`client.go`, `daemon.go`)
- [x] **T4** — dial after HTTP listen (`main.go`, `readyclient_linux.go`)
- [x] **T5** — adaptive backoff + slow-ready test (`ready_create_test.go`)
- [x] **T6** — config gate + validation (`config.go`, `docker_ready_socket_test.go`)
- [x] **T7** — Server-Timing sub-phases (`handlers.go`, `create_timing.go`)
- [ ] **T8** — integration **verified on live AWS** (tests written; run `make integration-cluster-hetero`)
- [ ] **T9** — `FuzzDecode` (bounded unit tests ✅)
- [x] **T10** — expvar counters; per-create attribution via Server-Timing
- [ ] **T11** — operator docs (`integration-tests/README.md`, `packaging/`, gVisor docs)
- [x] **T12** — `readyclient_linux.go` / `readyclient_other.go`
- [x] **T13 code** — `ensure_gvisor_host_uds` in `cluster-init.sh` + `cluster-join.sh` (cluster-only gate; `install.sh` left at `--host-uds=none`)
- [ ] **T13 verify** — UC-96c green + security sign-off on `--host-uds=open`

## Propagation map (where each change actually lands)

The repo has multiple install/provision paths; this maps each change to every
place it must reach so nothing is updated in one path and missed in another.

| Change | Single source? | Reaches Terraform | Reaches Ansible | Reaches integration tests | Status |
|---|---|---|---|---|---|
| gVisor `--host-uds=open` | **Yes** — `ensure_gvisor_host_uds` in `cluster-init.sh`/`cluster-join.sh` (cluster-only) | ✅ Terraform bootstrap always runs cluster-init/join | ✅ same scripts | UC-96c on cluster-hetero | Code ✅; live verify ⏳ |
| Ready-socket knobs + `EnableCluster` gate | **config.go** | ✅ cluster bootstraps | ✅ same | non-cluster → fallback | ✅ |
| `SB_READY_SOCKET` / `SB_READY_NONCE` env | per-create in `client.go` | n/a | n/a | n/a | ✅ |
| UC-96 / 96b / 96c | `usecases.go` + `docker_readiness_test.go` | n/a | n/a | cluster-hetero | Written ✅; run ⏳ |
| Operator docs | per-file | — | — | `integration-tests/README.md` | ⏳ T11 |

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
reach `started` via the poll. **Shipped:** `TestDockerReadinessFallbackOnNonCluster`
in `docker_readiness_test.go` asserts `readiness;desc=health` on non-cluster scenarios.

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
- **VERDICT:** ENG CLEARED → **implemented in PR #271**. Remaining before merge: live UC-96c (gVisor + `--host-uds=open`), security sign-off on gVisor UDS relaxation, operator docs (T11).

**Open items (not unresolved design decisions):** T8 live run, T9 fuzz, T11 docs, T13 verify + security gate, optional benchmark assertion.
