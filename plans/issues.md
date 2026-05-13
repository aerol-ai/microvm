# Open security issues — deferred fixes

Issues identified during the network-isolation hardening pass that were **not** fixed in the
same change set. Each entry lists the symptom, the affected code, why it was deferred, and a
proposed fix shape.

---

## 1. Boot-time race: workload runs before the egress DROP rule lands

### Symptom

A sandbox created with `network_block_all=true` can make outbound network calls during a
short window between container start and the moment the host installs the per-IP DROP rule
in the `DOCKER-USER` chain. A workload that issues its evil network call in its first few
hundred milliseconds (crypto miner, post-install hook, exfil-on-startup) gets it through.

### Affected code

- `pkg/docker/client.go:326` — `POST /containers/<id>/start` is issued first.
- `pkg/docker/client.go:331` — host then waits for the container IP via `waitForRuntime`.
- `pkg/docker/client.go:337-341` — only after that does `BlockAllEgress` install the rule.
- `cmd/toolboxd/main.go:91` — inside the container, toolboxd (PID 1) calls
  `startUserCommand` immediately, *before* it starts listening on its HTTP port at
  `main.go:105`. There is no synchronization with the host on whether the rule is in place.

### Window

Typically a few hundred ms; can stretch to seconds on a busy Docker daemon, on hosts with
slow iptables-nft writes, or when many sandboxes are being created concurrently.

### Why deferred

Closing this race requires real coordination between the host and the in-container PID 1.
Three viable shapes, each a non-trivial change:

1. **Sentinel signal from host → container.** Host writes a sentinel file (or sets a
   "rule-installed" flag readable via a control endpoint) after `BlockAllEgress` succeeds.
   toolboxd blocks at startup until it observes the sentinel, then runs the user command.
   Requires a writable shared bind mount or a host→toolbox API the workload cannot forge.
2. **Create paused, unpause after rule install.** Use Docker's `--init`-style pause / a
   create-without-start path: create the container, attach the rule against the assigned
   IP (would need to inspect IP without starting), then start. Docker's create-then-attach-IP
   ordering does not allow inspecting the IP pre-start on the bridge driver, so this needs
   investigation and may require a custom network driver.
3. **`network=none` at create, attach bridge after rule.** Create the container in
   `network=none`, then `docker network connect` the bridge *after* installing the egress
   rule against the IP that connect will assign. Cleanest model in principle, but needs
   the IP to be predictable or to install the rule reactively on the connect event.

All three are larger than a single-file fix and warrant a focused plan + tests.

### Proposed fix shape (sketch — pick one in a follow-up plan)

- **Short term (sentinel approach):**
  - Host: after `BlockAllEgress` succeeds in `Create`, write
    `/var/run/aerolvm/network-ready` inside the container via a tmpfs bind mount that the
    workload cannot write to.
  - toolboxd: at startup, before `startUserCommand`, block (with a bounded timeout, e.g.
    5s) on the sentinel's existence. If `network_block_all` was requested but the sentinel
    does not appear within the timeout, exit non-zero (fail closed).
  - Pass `SB_NETWORK_BLOCK_REQUIRED=1` into the container env so toolboxd knows when to
    enforce the wait vs. start immediately.
- **Long term:** evaluate the `network=none` + reactive-attach model. Removes the race by
  construction (no L3 connectivity exists until after the rule is in place).

### Severity

Medium-High. The control is sold as "no network." A determined adversary will hit this
window reliably; opportunistic and accidental traffic mostly will not.

### Test plan

- Integration test that creates a sandbox with `network_block_all=true` whose entrypoint
  is `sh -c 'curl -m 1 https://example.com; sleep 60'` and asserts the curl fails with a
  network error (not a 200).
- Stress variant: create N sandboxes concurrently and assert zero successful outbound
  requests across all of them in their first 500 ms.

---

## 2. Failover-recreate loses in-container runtime state

### Symptom

When the owning node dies hard and the dead-owner reconciler reassigns a sandbox to a new
owner, the new owner re-materializes the sandbox from the **replicated spec** — image, env,
command, resources, mounts, exposed ports, sealed credentials. Anything the original
container produced *after* boot is gone.

### What's lost on failover

- **Process tree** — long-running scripts, dev servers, agent processes. The new container
  boots from the image entrypoint as if it were brand new.
- **Filesystem writes outside mounts** — `apt install`, files in `/tmp`, `/home`, the
  workdir. The image's writable layer is local to the dead host.
- **In-flight sessions** — exec sessions, attached shells, established port forwards drop.
  Clients must reconnect.
- **Toolbox uploads** not yet flushed to a mount.
- **Host-local mount data** — silently gone. The mount path doesn't exist on the new owner.
  Worst case because the user may not realize until they go looking.

### What survives

- Spec (image, env, command, resources, mounts) — replicated via raft FSM.
- Sealed credentials — re-merged on recreate by the service layer.
- Sandbox ID and HTTP/TLS-SNI URLs (stable; derived from id+port+domain).
- Exposed port intents (replayed; raw TCP exposures get a new host port — public TCP URL
  changes).
- Network-backed mount data (NFS, S3FS, anything not host-local).

### Affected code

- `internal/cluster/cluster.go:55-95` — `Placement` carries Spec + SealedSecrets +
  ExposedPorts; explicitly does NOT carry runtime state.
- `internal/cluster/owner_watcher.go` — invokes `SandboxRecreator.RecreateSandbox` on the
  new owner; the recreator boots from the spec only.
- `internal/cluster/cluster.go:131-156` — `SandboxRecreator` interface; documents that the
  new owner re-runs `ExposePort` for each replicated intent but cannot recover writable-layer
  state.

### Trigger frequency

Only when the owning node goes down hard (process crash + dead-owner reconciler reassigns
after the ~30s `SB_DEAD_OWNER_GRACE` window). Graceful restarts on the same node do NOT
trigger recreate — the local store + container resume in place.

Blast radius per failover: "fraction of sandboxes owned by the dead node" × "how stateful
those sandboxes are."

### Severity by workload pattern

| Pattern | Impact |
|---|---|
| Stateless CI runner, ephemeral test sandbox | Negligible — recreate from spec is the whole job. |
| Long-running dev env with `npm install` / modified files | High — user loses all in-container work. |
| Agent with active session | Session drops mid-task; agent must reconnect. |
| Anything writing to host-local mounts | **Silent data loss** — path is empty on the new node. |

### Industry baseline

This is the same failover model as Kubernetes pods, ECS tasks, and Nomad allocations:
recreate from spec, lose runtime state. The alternatives (CRIU live migration, periodic
checkpointing) are operationally heavy and have their own failure modes.

### Decision: document, do not fix

The semantics are acceptable for v1. We expose them user-facing rather than engineer
around them. If a workload needs durable runtime state across host failure, the answer is
network-backed mounts, not in-container persistence.

### Proposed follow-ups (when revisited)

- **Cheap (do first):** user-facing docs page on failover semantics — what survives, what
  doesn't, how to design workloads that tolerate it. Add a `host_local_mount` warning at
  create time when cluster mode is on.
- **Medium:** mount-type advisory in the SDK / API: surface a warning when a sandbox in
  cluster mode uses a host-local mount.
- **Heavy (not planned):** CRIU-based checkpoint/restore, or runtime-native snapshot for
  gVisor/Kata. Deferred indefinitely; revisit only if a paying user blocks on it.

---

## What was fixed in the same pass (for context)

- `pkg/docker/client.go` — `Create` now fails closed if `BlockAllEgress` errors (was a
  warn-only fail-open).
- `internal/runtime/runtime.go` + `pkg/docker/client.go` — added
  `ApplyNetworkBlockAll(containerIP)` to the `Runtime` interface and the Docker client.
- `internal/service/service.go` — `StartSandbox` reapplies the rule after a Stop+Start
  cycle (the stop event clears it). Fail-closed on reapply error.
- `internal/service/service.go` — `Reconcile` running-sandbox branch reapplies the rule on
  every pass (idempotent at the netrules layer); heals after host iptables flush, daemon
  restart, or a missed install. Best-effort with a warn log; the next pass retries.
- `cmd/toolboxd/main.go` — `os.Unsetenv("SB_TOOLBOX_TOKEN")` immediately after the token is
  read, so user commands and `/exec`/streaming-exec children no longer inherit the token
  via `os.Environ()`.
