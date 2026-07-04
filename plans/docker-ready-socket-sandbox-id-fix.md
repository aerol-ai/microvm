# Fix: Docker ready-socket push rejected on sandbox-ID mismatch

Status: **Planned** — root cause confirmed 2026-07-04 (code trace + local Docker
repro). Amends [docker-readiness-unix-socket-push.md](./docker-readiness-unix-socket-push.md)
(PR #271), whose live verification (UC-96/96b/96c/96d on `cluster-hetero`)
failed with `readiness source = "health", want socket`.

## Problem

Every Docker/gVisor create in cluster mode falls back to the health-poll path
even though the unix-socket push works mechanically end-to-end. The push
**arrives and is rejected**, so creates pay the fallback floor:
`readyHealthPollGrace` (50ms) + first probe + one 20ms backoff step ≈
**70–90ms `toolbox_wait`** instead of the ~10–30ms the socket path delivers.

### Root cause

The two sides of the handshake disagree on what the sandbox's ID is:

- **Host side** — `pkg/docker/client.go:437` creates the `ReadyListener` keyed
  to the real sandbox ID (`sb-<16 hex>`), and `readAndVerify`
  (`pkg/docker/readysock.go:209`) requires `sig.SandboxID == l.sandboxID`.
- **Guest side** — toolboxd builds its ready signal from `readSandboxID()`
  (`cmd/toolboxd/main.go:415`), which returns the **container hostname**. The
  container create request (`pkg/docker/client.go:406`) sets the container
  *name* to the sandbox ID but never sets `Hostname`, so Docker defaults the
  hostname to the first 12 hex chars of the **container ID**.

Verified empirically: `docker run --name sb-hostname-check-12345 alpine
hostname` → `5efed5c4cb2f`. So the guest pushes `SandboxID: "5efed5c4cb2f"`,
the host expects `"sb-92ebc8d009d4b12c"`, `readAndVerify` returns
`"sandbox_id mismatch"`, the connection is counted invalid
(`docker_ready_socket_invalid_attempts`), and `ReadyListener.Wait` keeps
waiting for a second push that never comes. The health-poll goroutine wins
the race after its 50ms grace → `source = "health"`.

Nonce and token verification both pass — only the ID check fails.

### Why unit tests didn't catch it

`TestCreate_SocketPushWinsOverHealthPoll`
(`pkg/docker/ready_create_test.go:200`) fakes the guest and **hardcodes the
correct ID** (`SandboxID: "sb-race"`) in the push. The fake never derives the
ID the way real toolboxd does (hostname), so the identity mismatch is
invisible offline. Only the live UC-96 suite exercises real toolboxd.

### Evidence from the live run (cluster-hetero, 2026-07-01, v0.5.22)

- v0.5.22 == `main` @ 766090d — the deployed build **does** contain #271 and
  both follow-up fixes (7e6de33, 15eed89). Staleness ruled out.
- gVisor ruled out: `scripts/install.sh:1211` configures runsc with
  `--host-uds=open`, and plain-Docker UC-96/96b failed identically to the
  gVisor UC-96c.
- All four UC-96 tests: `readiness source = "health" ok=true` — creates
  succeed, just slow. Matches silent-rejection + fallback exactly.
- Expected confirming signal on the workers:
  `docker_ready_socket_invalid_attempts` ≈ number of docker creates,
  `docker_ready_socket_hit` == 0.

## Fix design

**Make the daemon tell toolboxd its sandbox ID explicitly via env
(`SB_SANDBOX_ID`), and have toolboxd prefer it over the hostname.** The env
var is the source of truth; hostname stays as the fallback for runtimes that
don't set it (Firecracker guests get toolboxd config via vsock and don't use
the ready socket at all, so they are unaffected).

Grep confirms `SB_SANDBOX_ID` is unused anywhere in the tree today — no
collision.

### Rejected alternative: set `Hostname` in the container create request

Setting `createRequest["Hostname"] = sandboxID` would also fix the mismatch
and is nice UX (guest hostname == API identity), but:

1. `Hostname` **conflicts with `NetworkMode: host`** — dockerd rejects the
   create ("conflicting options"). `c.network` is operator-configurable, so
   this needs a mode-dependent guard, i.e. the identity fix would silently
   not apply on some deployments — reintroducing exactly the class of
   env-dependent breakage we're fixing.
2. It changes guest-visible behavior for every existing sandbox (scripts that
   read the hostname as a container-ID today).

Keep it as an optional, separately-reviewed follow-up (see "Out of scope").
The env var works identically under every network mode and runtime.

### Rejected alternative: drop the SandboxID check host-side

Nonce + token already uniquely bind a push to one specific create, so the ID
check is defense-in-depth rather than load-bearing. But weakening a
verification step to fix a latency bug is the wrong direction; keep the check
and fix the identity.

## File-by-file changes

### 1. `pkg/docker/client.go` — pass the ID into the container

At the env build (~line 387), add the sandbox ID and grow the capacity hint:

```go
envValues := make([]string, 0, len(req.Env)+4)
envValues = append(envValues,
    fmt.Sprintf("SB_TOOLBOX_PORT=%d", c.toolboxPort),
    "SB_TOOLBOX_TOKEN="+toolboxToken,
    "SB_SANDBOX_ID="+sandboxID,
)
```

Set it **unconditionally** (not just when `c.readyEnabled`): it is not a
secret, it costs nothing on the boot path, and in-sandbox code being able to
discover its own ID is independently useful (E2B exposes the equivalent).

Keep the existing "re-store the grown slice" comment/behavior at ~line 445
intact — the ready-block append still reallocates and must re-store
`createRequest["Env"]`.

Also surface rejection so this class of bug is never invisible again: after
the readiness race resolves in `waitForToolboxReady` (~line 1282), when
`res.source == "health"` and a listener existed, log a `Warn` with the
listener's invalid-attempt count and last rejection reason:

```go
c.logger.Warn("ready socket fell back to health poll",
    "sandbox_id", listener.sandboxID,
    "invalid_pushes", n, "last_reason", reason)
```

### 2. `pkg/docker/readysock.go` — expose rejection diagnostics

`readAndVerify` already returns distinct errors ("sandbox_id mismatch",
"nonce mismatch", "token mismatch"). Record them on the listener instead of
discarding:

- Add `invalidCount int` + `lastInvalidReason string` (guarded by a mutex or
  atomics) updated in the `Wait` loop where `readAndVerify` fails
  (`readysock.go:192`).
- Add accessors `InvalidAttempts() (int, string)` for the Create-side log and
  tests.

Host-side log only — the dialer still learns nothing about why its push was
dropped (unchanged security posture).

### 3. `cmd/toolboxd/main.go` — prefer the env-provided ID

```go
func readSandboxID() string {
    if id := strings.TrimSpace(os.Getenv("SB_SANDBOX_ID")); id != "" {
        return id
    }
    hostname, err := hostnameFn()
    if err != nil {
        return ""
    }
    return normalizeSandboxID(hostname)
}
```

Do **not** scrub `SB_SANDBOX_ID` in `scrubReadyEnv` — it is not a credential,
and user commands inheriting it is a feature.

Side effects of `srv.sandboxID` becoming the real ID (all improvements, none
breaking):

- `GET /` (`main.go:295`) now reports the real sandbox ID instead of a
  container-ID prefix.
- Sessions recording metadata (`main.go:128`) carries the real ID.
- `stripSandboxPrefix` (`main.go:411`): the exact-match fast path starts
  working for docker sandboxes; today it never matched and requests were
  handled by the tolerant fallback in `normalizeSandboxPath` (main.go:449–471),
  which strips any unknown first segment when the remainder is a known
  toolbox path. That fallback stays, so mixed-version behavior is unchanged.

### 4. `pkg/docker/ready_create_test.go` — derive identity like the real guest

- Change the fake-guest goroutine in `TestCreate_SocketPushWinsOverHealthPoll`
  to **extract `SB_SANDBOX_ID` from the captured create-request env** (the
  fake daemon already captures `Env` — see the pattern at
  `ready_create_test.go:91`) and push with that value instead of the
  hardcoded `"sb-race"`. If the env var is missing, push the empty string —
  which fails verification and fails the test. This makes the unit test
  structurally incapable of missing an identity-plumbing regression.
- New regression test `TestCreate_HostnameStyleIDPushFallsBack`: fake guest
  pushes a 12-hex container-ID-style `SandboxID` (the pre-fix behavior);
  assert the create still succeeds, `timing.Source == "health"`,
  `docker_ready_socket_invalid_attempts` incremented, and the listener's
  `InvalidAttempts()` reports `"sandbox_id mismatch"`.
- New assertion in an existing create test: captured create-request env
  contains `SB_SANDBOX_ID=<sandboxID>` on every create (readiness enabled or
  not).

Match the package's existing table-driven/fake-daemon style; no new harness.

### 5. `cmd/toolboxd/main_test.go` (or `readyclient_test.go`)

Table-driven cases for `readSandboxID`:

| case | SB_SANDBOX_ID | hostnameFn | want |
|---|---|---|---|
| env wins | `sb-abc` | `deadbeef1234` | `sb-abc` |
| env whitespace ignored | `"  "` | `deadbeef1234` | `deadbeef1234` |
| fallback to hostname | unset | `deadbeef1234` | `deadbeef1234` |
| both empty | unset | error | `""` |

Plus: `announceReady` sends the env-derived ID (extend the existing
`readyclient_test.go` dial test).

### 6. `plans/docker-readiness-unix-socket-push.md`

Update the status table: live verification failed → link this plan; flip to
verified after the re-run passes.

## Version-skew safety (mixed-version cluster during rollout)

| sandboxd | toolboxd | behavior |
|---|---|---|
| new | new | env set, push verified → **socket path** |
| new | old | env set but ignored; old toolboxd pushes hostname → rejected → health fallback (status quo, no worse) |
| old | new | env unset; new toolboxd falls back to hostname → rejected → health fallback (status quo) |
| old | old | status quo |

No coordination needed; the fix degrades to today's behavior in every mixed
combination. (In practice both binaries ship in one release and toolboxd is
bind-mounted from the host, so skew windows are per-node and short.)

Container **restart** path is untouched: `waitForRuntime` passes a nil
listener and health-polls, and the parked bind source (15eed89) keeps docker
start working. The ID fix changes nothing there.

## Verification & acceptance gates

Offline (must pass before PR):

1. `make test` green; `go test ./pkg/docker/... ./cmd/toolboxd/...` includes
   the new regression tests.
2. `/maintain-coverage`: `pkg/docker` and `cmd/toolboxd` stay ≥ ~85%.

Live (operator-run, costs money):

3. Re-run the readiness suite on `cluster-hetero`: **UC-96, UC-96b, UC-96c,
   UC-96d all pass** with `source = "socket"`.
4. On the docker workers: `docker_ready_socket_hit` > 0 and
   `docker_ready_socket_invalid_attempts` == 0 across the run.
5. Server-Timing `toolbox_wait` p50 for docker creates **< 50ms** (was
   ~70–90ms); no regression in `runtime_wait`.
6. Benchmark artifact (`cluster-hetero-bench.json`): docker `server_p50_ms`
   improves vs the 2026-07-01 baseline (291ms) — expect roughly −40–60ms; do
   not gate harder than that since the remaining time is create/start work
   this plan doesn't touch.

## PR checklist (pr-review.md call-outs)

- **Boot-path latency**: touches `CreateSandbox` callee (`docker.Create` env
  build + readiness race) — follow `/touch-create-sandbox`; call out that the
  change *removes* ~40ms from cluster docker creates and adds zero work
  (one env string, no I/O, no locks). First-call case unchanged.
- **Idempotency**: none of the retry/duplicate-create semantics change; the
  env var is deterministic per sandbox ID.
- **Failure-path**: unchanged — rejection still falls back to health poll;
  the only new behavior is a Warn log + counters.
- **Coverage**: new tests listed above; no new package.
- Store, TCP pool, L4, cluster FSM: untouched.

## Out of scope (explicitly deferred)

- Setting `createRequest["Hostname"] = sandboxID` for guest-hostname UX
  parity — separate decision, needs the `NetworkMode: host`/`container:`
  guard and a user-visible-change call-out.
- Deduping user-supplied `SB_*` env keys that shadow reserved ones
  (`SB_TOOLBOX_TOKEN` has the same pre-existing exposure; fix together,
  separately).
- A parked-socket accept loop for container **restarts** to give starts the
  same push path — restart latency is a different budget; revisit if start
  latency becomes a target.
- `readyproto` fuzz + operator docs remain tracked in the parent plan (T9,
  T11).
