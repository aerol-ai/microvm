# Docker warm pool — sub-100ms create for pooled images

**Status:** planned (not started) — rev 2, incorporates create-path review findings
**Prereq:** `plans/docker-ready-socket-sandbox-id-fix.md` — SHIPPED (3b5af0c, v0.5.25) and live-verified; the adopt handshake below extends that socket protocol.
**Related:** `internal/pool/wasm/` (the pattern to mirror), `internal/pool/vmm/` (daemon wiring + orphan pattern), `plans/wasm-create-latency.md` (the drain-vs-refill lesson).

## 1. Problem — measured, not estimated

Live numbers from cluster-3-mixed-docker (t3.medium × 3, v0.5.25, 2026-07-06):

| Stage | Measured |
|---|---|
| Docker engine `POST /containers/create` (unix socket, cached alpine:3.20) | 109–122ms |
| Docker engine `POST /containers/{id}/start` | 166–180ms |
| **Engine subtotal — not our code** | **276–303ms** |
| Full server-side create through sandboxd (`create;dur`, localhost, 8 samples) | 304–332ms |
| sandboxd's own overhead (raft apply ~4.5ms, store fsyncs ~1ms ea, iptables ≤10ms, readiness 0.1–3.5ms post-fix, inspects/keygen) | ~15–30ms |

The readiness-socket fix removed sandboxd's last request-path waste. What
remains is the Docker engine itself. **No change inside sandboxd gets under
100ms while `create`+`start` sit on the request path.** The only code-level
fix is to take them off it: keep containers pre-created, pre-started, with
toolboxd already booted, and *adopt* one at create time.

Target: **warm-hit server p50 ≤ 100ms on t3.medium (expected 20–50ms)**;
misses byte-identical to today (~300ms + pull if uncached).

## 2. Design overview

New package `internal/pool/dockerpool`, mirroring `internal/pool/wasm`
(targets map, ready slots, `Acquire` → hit/miss, miss kicks refill, ticker +
kick channel, `spawning` map as per-key refill single-flight — the missing
single-flight was the WASM bench's tail lesson; do not repeat it).

### Current create ordering (the constraint everything below respects)

`internal/service/service.go createSandbox`:
`admitter.Admit` (:1164) → `mounts.MountAll` (:1179) → `docker.Create`
(:1190, **pool Acquire+adopt live inside here**) → `sealRegistry` → caddy
route if public (:1264) → `store.Create` (:1281) → platform-volume
attachments. Every failure after Admit runs the rollback chain
(destroy → unmount → `releaseAdmission`). The warm-hit branch changes
nothing about this ordering — it only swaps what happens inside
`docker.Create`.

### Park lifecycle

A **parked container** is created and started ahead of demand by the refill
loop via a new `docker.Client.ParkContainer`:

- name `park-<16 hex>`, Docker label `aerol.pool=park` (the orphan-scan key)
- env: `SB_POOL_PARKED=1`, `SB_TOOLBOX_PORT`, a **park-scoped bootstrap
  token** (random, never valid for toolbox API calls), no `SB_SANDBOX_ID`
- `Entrypoint` is the host-bind-mounted toolboxd exactly as today
  (client.go:410); `Cmd` is the image's default Entrypoint+Cmd resolved at
  park time (same resolution as the cold path, client.go:402–404)
- **Parked toolboxd defers the user command.** Today toolboxd starts
  `os.Args[1:]` at boot (cmd/toolboxd/main.go:140–141). In parked mode it
  must NOT: a parked slot running the image's server/default command would
  do real work (bind ports, mutate state) with no identity. Parked mode
  boots the toolbox listener only, rejects every HTTP call except health,
  and calls `startUserCommandFn` **after the adopt ack**. Since eligibility
  (§3) already excludes custom `ContainerCommand`, the deferred command is
  always the image default — post-adopt semantics match a cold create.
- ready socket bind-mounted exactly as today (`/run/aerol/ready.sock`),
  host listener held open under `readyDir/park-<id>.sock`
- **`BlockAllEgress` applied at park time** (IP-keyed DROP at position 1 of
  DOCKER-USER, netrules/manager.go:50) — no identity, no network
- the held socket connection doubles as liveness: if it drops, the slot is
  dead — reap it, don't hand it out

### Adopt flow (the create fast path)

`docker.Client.Create` checks eligibility (§3) → `pool.Acquire(key)`:

1. `docker rename park-xxx sb-<id>` (~5ms). **A rename conflict ("name
   already in use") is a duplicate-create signal, not an error to
   propagate:** destroy the parked candidate, then re-dispatch to the
   duplicate protocol in §6 — never blind-fall-through to a cold create,
   which would hit the same conflict 300ms later.
2. `docker update` for CPU/memory if the request's shape differs from the
   park default (cgroup writes, ~ms).
3. Host sends the **adopt frame** over the held connection: real sandbox
   ID, freshly minted toolbox token, adopt nonce. toolboxd swaps identity
   atomically, starts the deferred user command, and replies with today's
   `ready` signal (ID + token + nonce echo). Same trust model as the
   shipped push: root-owned unix socket, nonce binds the exchange to this
   park socket.
4. **Network-rule replacement, in this order** (rules coexist in
   DOCKER-USER, the park DROP at position 1 wins until removed, so the
   container transitions closed→target-policy with no open window):
   a. install the request's allow/deny/block rules for the container IP;
   b. only then `ClearBlockAllEgress` the park DROP.
   Never the reverse — clearing first opens unrestricted egress for the
   gap when the request wanted restrictions.
5. Inspect for the container IP; return the `SandboxRuntime` (annotated
   with the adopted park-slot ID for the capacity transfer, §4).

Adopt total: ~15–40ms server-side. Readiness is instant — toolboxd was
already up, so `toolbox_wait ≈ 0` stays true.

**Adopt-failure rule:** a *pre-store* failure (handshake timeout, bad ack,
dead conn — anything except a duplicate signal) → destroy the parked
container **including `ClearNetworkRules` for its IP**, then fall through
to the cold create path. The pool may only ever make a create faster,
never make it fail. Duplicate signals (rename conflict, store conflict)
take the §6 protocol instead. No "un-adopt" — once renamed/handshaken, the
container is tainted and dies.

**Stale-DROP invariant:** every path that discards a parked container
(adopt failure, TTL reap, LRU eviction, liveness reap, boot purge,
shutdown drain) must clear its IP-keyed rules before/with the destroy.
Docker's bridge reuses IPs — a leaked park DROP black-holes an unrelated
future container. Regression test required (§7).

### Target policy — what gets warmed

- **Pinned targets** (`SB_DOCKER_POOL_IMAGES`, default = the host default
  image): warm at daemon start, on every worker, depth
  `SB_DOCKER_POOL_DEPTH` (default 2). These hit on the *first* create.
- **Miss-driven self-warming** (wasm `NoteModule` pattern): a pool miss
  registers the key as a refill target, so the second create of any image
  on that node hits. Bounded by:
  - `SB_DOCKER_POOL_MAX_IMAGES` (default 8) distinct targets, LRU-evicted
  - `SB_DOCKER_POOL_IDLE_TTL` (default 15m): no create for that key →
    parked slots reaped, target dropped (pinned targets never expire)
- **Capacity-gated refill:** see §4.

Cluster note: pools are per-node and independent. Warm-aware placement
(gossiping warm-image sets, preferring warm nodes) is **Phase 2** — v1
accepts ~1/N first-hit rate on self-warmed images across N workers.

## 3. Eligibility & pool key

**Pool key = resolved image identity + runtime**, not the bare tag:
`(Image, ImageDigest, ImageRegistryRef, ImageDistributionMode, Runtime)`
from `models.CreateSandboxRequest` (pkg/models/types.go:500–507, :549).
Two creates writing the same tag string can still resolve to different
rootfs (digest-pinned vs floating, aocr vs local_only) — they must not
share slots. Additionally, **tags move**: `ParkContainer` records the
local Docker image ID at park time, and `Acquire` re-validates it against
the current image ID for that reference — mismatch (image re-pulled/
retagged since park) discards the slot and counts a
`docker_pool_stale_image` metric instead of serving a stale rootfs.

Everything baked into `docker create` that we cannot change post-hoc
forces a miss:

| Field | Poolable? |
|---|---|
| image identity + `Runtime` | must match a pool key (above) |
| `CPU`, `MemoryMB` | yes — `docker update` at adopt |
| `DiskGB` ≠ park default | **miss** (storage opt is create-time) |
| `Env` non-empty | **miss in v1** (baked at create; Phase 2: adopt frame carries env, toolboxd injects into every exec/session it spawns — needs the PID-1-won't-see-it caveat documented) |
| `Mounts` / `PlatformVolumes` non-empty | **miss** (binds are create-time) |
| `OSUser` empty or `root` (normalize default) | **yes** — cold path never sets Docker `User` from OSUser; park slots run as image default (root). Non-root OSUser → **miss** |
| `ContainerCommand`, `Registry`, `GPUs` set | **miss** |
| `NetworkBlockAll` / allow/deny lists / byte limits | yes — netrules applied at adopt (§2 ordering) |
| `Name`, `Tags`, `Lifecycle`, `Failover`, custom domains | yes — store/service level, container-agnostic |

The bench (`{"image":"alpine:3.20"}`) and default agent-workload creates
are eligible; that's the traffic the 100ms goal is for. Note:
`normalizeCreateRequest` fills `OSUser="root"` before `docker.Create`, so
eligibility must treat root as the park default — rejecting any non-empty
OSUser made every create cold.

## 4. Capacity: park reservation → sandbox reservation transfer

Parked containers consume real memory/CPU, so admission must see them —
but `Admit` runs *before* `docker.Create` (service.go:1164 vs :1190), i.e.
before we know whether this create will adopt a slot. Naive "parked slots
are reservations too" double-counts during every warm hit and, at the
capacity margin, rejects a create that would have *freed* a parked slot.
Explicit semantics:

1. **Refill reserves.** Before parking, the refill loop calls
   `admitter.Admit("park:<slot-id>", slotShape)`. Refusal = no park (the
   pool never overcommits). Additionally refill keeps a **guard band**: it
   parks only while free headroom after the park ≥ one default-shaped
   sandbox, so pinned slots don't consume the last admissible request.
2. **Create admits normally.** `createSandbox` keeps its existing
   `Admit(sandboxID, req)` — unchanged, byte-identical cold path.
3. **Adopt transfers.** When `docker.Create` returns a `SandboxRuntime`
   carrying `AdoptedParkID != ""`, the service immediately calls
   `admitter.Release("park:<slot-id>")` (a new narrow
   `ReleasePark`/`Release` reuse — same ledger). Net effect: the
   double-count window is the microseconds between Admit and the release
   call, and it only ever *over*-reserves (safe direction; never
   undercounts).
4. **Margin behavior (documented, tested):** at hard capacity, `Admit` can
   reject a warm-hit-eligible create even though adoption would free a
   slot. Accepted for v1 — the guard band makes it rare, correctness is
   preserved, and the alternative (admitting against pool credit) couples
   the admitter to pool internals. Regression test pins this behavior so
   it's a choice, not an accident.
5. **Every parked-slot discard path releases its park reservation** (same
   list as the stale-DROP invariant, §2).

UC-95 density with the pool enabled is the end-to-end check: ceiling must
equal today's minus exactly the configured parked budget, and return to
today's after `SB_DOCKER_POOL_ENABLED=false` restart.

## 5. Protocol change — readyproto v2

`pkg/readyproto/readyproto.go` today: one guest→host `ready` line. Add two
frames, same newline-delimited JSON, same `MaxLineBytes` bound:

```go
EventParked = "parked" // guest→host: {event, token(bootstrap), nonce(park), agent_version}
EventAdopt  = "adopt"  // host→guest: {event, sandbox_id, token(real), nonce(adopt)}
// adopt ack = existing EventReady signal carrying the new identity
```

`Decode` stays strict per event type; the host listener
(`pkg/docker/readysock.go`) gains a parked-connection registry and a
`SendAdopt(conn, frame)` with a write deadline.

### Gating — the pool requires the socket

Today `DockerReadySocketEffective() = DockerReadySocketEnabled &&
EnableCluster` (config.go:1959–1961) — single-node hosts deliberately keep
health-poll. Adoption *depends* on the held socket, so with the current
gate the pool would silently never hit outside cluster mode. Change:

- `DockerReadySocketEffective() = DockerReadySocketEnabled &&
  (EnableCluster || DockerPoolEnabled)` — enabling the pool is the same
  "operator controls the host layout" opt-in the cluster install makes,
  which is what the gate was protecting.
- `DockerPoolEffective() = DockerPoolEnabled && DockerReadySocketEnabled`;
  daemon logs a Warn and disables the pool if the socket knob is
  explicitly off.

### Version skew (corrected: toolboxd is a host bind-mount, not an image binary)

toolboxd enters every container as a bind-mount of the **host** binary
(client.go:410 `c.toolboxMountPath`), so there is no "old toolboxd image"
case. The real skew cases:

| Case | Behavior |
|---|---|
| Parked container running the **pre-upgrade** host binary (exec'd before a sandboxd upgrade) | the boot orphan purge destroys all parked containers on daemon restart, and upgrades restart the daemon — so this only survives a binary-swap-without-restart, which the install flow doesn't do. Belt-and-braces: the `parked` hello carries `AgentVersion`; adopt refuses on mismatch → slot destroyed, cold fallback. |
| Host binary lacking parked mode (rollback to old release) with pool on | old toolboxd ignores `SB_POOL_PARKED`, starts the user command, never sends `parked` hello → spawner times out, destroys the container, **disables that target** with a Warn (don't refill-loop a broken combination). |
| Pool off / old sandboxd | `SB_POOL_PARKED` never set → toolboxd boots exactly as today. |
| Mixed cluster nodes | pools are per-node; no cross-node coupling. |

## 6. Idempotency & the duplicate-create race (pr-review non-negotiables)

Reality check on the current code: idempotency for recreate is a
**pre-check** (`CreateSandboxWithID` does `store.Get` before creating,
service.go:696–705); two concurrent duplicates can both pass it.
`store.Create` (store.go:769) checks name availability explicitly but an
ID PK conflict surfaces as a **raw SQLite error** — there is no typed
already-exists signal today, and `createSandbox` returns that error after
running the rollback chain. The plan must not pretend otherwise. Concrete
protocol:

- **Type the conflict.** `store.Create` gains detection of the sandboxes
  PK/UNIQUE violation → returns a new `models.ErrSandboxExists` (name
  conflicts keep their current 409 shape). This is a tiny, separately
  testable store change and benefits the cold path equally.
- **On `ErrSandboxExists` after an adopt** (and on adopt-time rename
  conflict, which is the same race seen earlier): destroy the adopted
  candidate (clearing its netrules + releasing its park reservation),
  release this call's admission, then `store.Get(id)` — row present →
  return it (idempotent success, matching `CreateSandboxWithID`'s
  semantics); row absent (loser of a create/destroy interleave) → return
  `ErrSandboxExists` and let the caller retry. **Never fall through to a
  cold create on a duplicate signal** — it would re-conflict 300ms later.
- **Fresh-ID path (`CreateSandbox`)**: IDs are 16 random hex; PK conflict
  is practically unreachable, but the same handling applies for free.
- **Rollback parity:** the adopt branch reuses the existing failure chain
  (destroy → unmount → release admission) so a warm create that fails
  post-adopt leaves exactly the same world as a failed cold create, plus
  the park-reservation release and netrules clear from §2/§4.
- **Boot-path call-out for the PR:** the fast path adds one pool-map
  lookup (~µs) to every docker create including misses; the miss path is
  otherwise byte-identical. First call after daemon start: pool empty →
  miss → today's behavior.

## 7. File-by-file changes

**New: `internal/pool/dockerpool/`** — `pool.go` (keys per §3, slots,
Acquire with image-ID revalidation, LRU + TTL, kickRefill), `refill.go`
(ticker + kick + §4 capacity gate + guard band), `spawner.go` (Spawner
interface; prod impl → `docker.Client.ParkContainer`), `metrics.go`
(expvars `aerolvm_docker_pool_{hits,misses,refills,orphans,stale_images,spawn_fails,target_evictions}_total`,
`aerolvm_docker_pool_parked`, `aerolvm_docker_pool_adopt_ms` — the aerolvm_
prefix is what the observability exporter publishes into /v1/metrics),
`errors.go`. Each with `_test.go` (≥85%).

**`pkg/docker/client.go`** — `ParkContainer` (park identity create+start,
records image ID, applies park DROP, returns slot handle with held conn);
`AdoptParked` (rename → update → adopt handshake → §2 rule-ordering →
inspect); `Create` gains the eligibility-check → Acquire → adopt fast path
with the §2/§6 failure dispatch. `SandboxRuntime` gains `AdoptedParkID`.
Cold-path code is untouched.

**`pkg/docker/readysock.go`** — parked-connection registry, `SendAdopt`,
liveness check on the held conn; park sockets are reaped by the boot purge
(no `ParkBindSource` survival — parked containers are cheap to rebuild).

**`pkg/readyproto/readyproto.go`** — the two frames above + table-driven
encode/decode/bounds tests.

**`cmd/toolboxd/main.go` + `readyclient_linux.go`** — parked mode: skip
`startUserCommandFn` at boot, hello, block-for-adopt, atomic identity swap
(`sandboxID`, auth token), reject non-health requests pre-adopt, start the
deferred user command, ready ack. `readyclient_other.go` stays a stub.

**`internal/store/store.go`** — typed `models.ErrSandboxExists` on
sandboxes-PK violation in `Create` (§6) + regression test in
`store_test.go`.

**`internal/service/service.go`** — release the park reservation when
`docker.Create` returns `AdoptedParkID` (§4); duplicate-signal handling
per §6. No other ordering change.

**`internal/config/config.go`** — `SB_DOCKER_POOL_ENABLED` (**default
false** in v1), `SB_DOCKER_POOL_DEPTH` (2), `SB_DOCKER_POOL_IMAGES`
(default image), `SB_DOCKER_POOL_MAX_IMAGES` (8), `SB_DOCKER_POOL_IDLE_TTL`
(15m); `DockerPoolEffective()`; widened `DockerReadySocketEffective()`
(§5 gating) — this touches the shipped readiness gate, call it out and
extend `readysock`/config tests for the single-node+pool combination.

**`pkg/daemon/daemon.go`** — wire next to the Phase-4 VMM pool block
(daemon.go ~369): construct pool, SetSpawner, RunRefill on the daemon ctx,
**boot orphan purge** (list `label=aerol.pool=park` → clear each one's
netrules → destroy; refill rebuilds in ~seconds), drain parked containers
on graceful shutdown (same clear-then-destroy).

**`pkg/capacity/`** — park-keyed reservations + the §4 transfer/release
seam and guard band. Regression tests: density ceiling, margin-rejection
behavior (§4.4), release-on-discard.

**`pkg/docker/create_timing.go` + Server-Timing** — new stage
`docker_pool;desc=hit|miss` (+ `dur` = adopt time on hits). The bench's
generic stage parser (`integration-tests/suite/harness/timing.go`) already
picks up any named stage — no harness change needed for reporting.

**Integration** — new UC (docker warm-hit): create default image twice on
a pool-enabled scenario; assert second create has `docker_pool;desc=hit`,
`readiness;desc=socket`, and `create;dur < 150` (t3.medium slack over the
100ms goal). Enable the pool in `cluster-3-mixed-docker.tfvars`/Ansible env
for `make integration-benchmark-docker`.

**Docs** — no SDK surface change (no new methods, no wire fields), so no
five-tab SDK page; operator-facing config documented on the self-hosting
configuration page + `setup/` runbook note on capacity sizing with pools.

## 8. Test matrix (beyond per-package 85%)

- pool: hit/miss, LRU eviction, TTL reap, refill single-flight, capacity
  guard band, stale-image discard.
- docker client (fake-daemon, `ready_create_test.go` style): adopt success;
  adopt handshake timeout → cold fallback with netrules cleared + park
  reservation released; rename conflict → §6 duplicate protocol; rule
  ordering (request policy present before park DROP removal).
- **stale park DROP regression:** destroy a parked container through every
  discard path, assert no `-s <ip> -j DROP` remains (netrules manager fake).
- store: `ErrSandboxExists` typing; concurrent duplicate `CreateSandboxWithID`
  (both pass pre-check, one wins, loser returns the winner's row).
- capacity: warm hit releases park reservation exactly once; margin
  rejection pinned (§4.4); density ceiling arithmetic.
- toolboxd: parked-mode table tests — deferred user command (not started
  before adopt, started exactly once after), pre-adopt API rejection,
  identity swap atomicity.
- daemon: boot purge clears rules + reservations; shutdown drain.

## 9. Rollout & acceptance gates

1. **Phase A** — land everything default-off (`SB_DOCKER_POOL_ENABLED=false`),
   full test coverage, no behavior change anywhere (including the widened
   socket gate: without the pool knob it reduces to today's expression).
2. **Phase B** — enable in cluster-3-mixed-docker; `make
   integration-benchmark-docker` gates:
   - UC-94 docker `server_p50_ms ≤ 100` (expect 20–50) with
     `docker_pool;desc=hit` on ≥ 8/10 samples
   - `docker_pool_orphan`/`stale_image` expvars = 0 across nodes
   - UC-95 density ceiling = today's − parked budget, exactly
   - existing UC-96* readiness UCs still pass with `source=socket`
3. **Phase C** — default-on after a soak on the kept cluster; update
   `agentic_docs/` request-flow notes.

## 10. Out of scope (explicit)

- Lazy-pull snapshotters (eStargz/SOCI) — containerd-level, separate track.
- Bypassing dockerd for containerd — large rewrite, uncertain payoff.
- Warm-aware placement (gossip warm-image sets) — Phase 2, needs
  `internal/cluster` care per CLAUDE.md fragility rules.
- `req.Env` injection via toolboxd exec-env — Phase 2 (semantic caveat:
  PID 1 won't see user env).
- Pull acceleration (pre-distribution on registration, pull-through
  mirror) — complementary, separate plan.
- Admitting against pool credit at the capacity margin (§4.4) — revisit
  only if the guard band proves insufficient in practice.

## 11. PR checklist

- [ ] Run `/touch-create-sandbox` before coding (boot-path change).
- [ ] Boot-path latency call-out in the PR description (miss path delta ≈ 0, first-call case).
- [ ] Idempotency call-out (§6: typed store conflict, duplicate protocol, WithID parity).
- [ ] Failure-path rollback rule documented (destroy-on-adopt-failure incl. netrules clear + park-reservation release; no un-adopt).
- [ ] Capacity call-out (§4 transfer semantics, guard band, margin behavior, density test).
- [ ] Ready-socket gate widening called out (touches shipped readiness path; single-node+pool tests).
- [ ] Version-skew matrix in the PR description (§5 table — host-binary skew, not image skew).
- [ ] `go test -coverprofile` — `internal/pool/dockerpool`, `pkg/docker`, `pkg/readyproto`, `cmd/toolboxd`, `internal/store`, `pkg/capacity` all ≥ ~85%.
- [ ] Table-driven test style matching `store_test.go` / `ready_create_test.go`.
