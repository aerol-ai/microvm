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
