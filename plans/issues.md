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

## 2. Network usage poller drops bytes on the first observation

### Symptom

`pkg/docker/netstats/poller.go:167-173` (`diffAndUpdate`) treats the first sample for a
new `(sandbox, PID)` pair as a baseline-only event and emits a zero delta. The current
`/proc/<pid>/net/dev` reading is stored, the next tick's delta is computed against it,
and only that next tick contributes to the persisted counter.

For a freshly created sandbox at the default 10s poll interval, that means up to ~10s of
traffic between container start and the first poll, plus another full interval before
enforcement sees a non-zero delta. A workload that bursts hard at startup (large image
pull inside the container, an exfil-on-startup script, an aggressive `wget`) can move
tens of GB before the quota check ever fires.

### Affected code

- `pkg/docker/netstats/poller.go:163-179` — `diffAndUpdate` baseline rule.
- `pkg/docker/netstats/poller.go:41-46` — comment documenting the design intent.
- `internal/service/netstats.go:186-227` — `HandleSamples` is the only callback path,
  so any byte not surfaced here never gets metered or quota-checked.

### Why deferred

The current behaviour is intentional: it makes the poller restart-safe. After a
container restart (new PID) or a daemon restart (poller forgets baselines), `/proc`
counters reset to small numbers, and treating the first read as "delta from zero" would
spuriously credit terabytes against the quota.

A correct fix has to *distinguish* the two cases:

- **Fresh container, first observation ever:** counters start at 0 inside the new netns,
  so the first reading IS the actual usage from 0 — credit it.
- **Daemon restart, container already had traffic:** stored cumulative is non-zero,
  in-PID counters are mid-run — must baseline.

This needs persistent baselines, not just in-memory ones, and a slightly subtler diff
rule. Worth doing right rather than racing a one-line patch.

### Proposed fix shape

- Persist `(last_observed_pid, last_observed_bytes_in, last_observed_bytes_out)` on the
  sandbox row alongside the existing cumulative counters.
- On poll:
  - If the persisted PID is 0 / unset → fresh sandbox, no prior reading. Credit the
    full current reading as the delta and store the snapshot.
  - If the persisted PID matches the current PID → normal delta, store snapshot.
  - If PIDs differ → container restart, baseline only (current behaviour).
- Re-hydrate in-memory `baselines` map at `EnsureNetstatsReady` from the persisted row
  so a daemon restart doesn't lose state.
- Optional: tighten the default `NetstatsPollInterval` for the first ~minute of a
  sandbox's life (a "warm-up" sub-poller) to bound the first-observation gap. Costs
  extra `/proc` reads per new sandbox, no impact at steady state.

### Severity

Medium. Most workloads don't move tens of GB in their first 20 seconds, but billing
accuracy and abuse-prevention quotas both rely on this counter being honest. Currently
a known sub-quota leak exists at the start of every sandbox's life.

### Test plan

- Unit test for `diffAndUpdate` (or its persistent successor): asserts the
  fresh-container case produces a non-zero delta on first observation, while the
  PID-change case still baselines.
- Restart test: create a sandbox, kill the daemon, restart, observe that the first
  post-restart sample baselines (does not credit cumulative counter to zero).

---

## 3. Netstats poller scans the whole sandbox table every tick

### Symptom

`internal/service/netstats.go:159-181` (`netstatsServiceLister.NetstatsTargets`) calls
`store.List(ctx)` on every poll. `Store.List` loads every sandbox row, runs
`attachPortsBulk` (which scans all `exposed_ports`), and filters in Go. The poller only
needs `(id, container_id WHERE status='started')`.

At small scale this is invisible. As historical / running rows grow, every tick walks
more rows through the same single-writer SQLite connection that serves API traffic.

### Affected code

- `internal/service/netstats.go:159-181` — caller.
- `internal/store/store.go` — `List` is the only available query; no filtered variant.

### Why deferred

It's premature optimization until a host genuinely carries hundreds-to-thousands of
running sandboxes. The poller already runs at a low cadence (default 10s) and the work
isn't on a request-serving path. The fix is mechanical, but it adds a new store method
that needs its own tests, and shipping it with no measured pressure isn't worth the
diff cost.

### Proposed fix shape

- Add `Store.ListNetstatsTargets(ctx) ([]struct{ ID, ContainerID string }, error)` that
  runs a single `SELECT id, container_id FROM sandboxes WHERE status = ?` (no port
  attach, no full row hydration).
- Switch `netstatsServiceLister.NetstatsTargets` to call it.
- Add a regression test in `store_test.go` that verifies status filtering and that no
  port-attach side query runs (could assert via query counter or simply scope the
  fixture).

### Severity

Low until measured. Re-evaluate when single-host sandbox counts move into the hundreds.

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
