# WASM runtime health runbook

## Symptoms

- Sandboxes stuck in `passivated` or `awaiting_runtime`
- Failover recreate succeeds for Docker but WASM stays cold
- AOCR push/pull failures in logs

## Checks

1. **Feature gate:** `SB_ENABLE_WASM=true` on worker nodes.
2. **Health:** `GET /v1/health` — `wasm` field should be `ok`.
3. **Local checkpoint:** `{SB_WASM_MODULES_DIR}/<sandbox-id>/mem.snap/config.json` exists for passivated rows.
4. **AOCR:** `wasm_registry_ref` / `wasm_registry_digest` populated on durable sandboxes after push.
5. **Capacity:** `/v1/capacity` lists `local_wasm_module_ids` when modules are cached.

## Common fixes

| Issue | Action |
|---|---|
| `awaiting_runtime` after restart with WASM disabled | Re-enable `SB_ENABLE_WASM` and start sandbox |
| Missing local mem.snap on failover | Verify snapshot push enabled + PAT; check AOCR `wasm-checkpoints` path |
| `clone generation mismatch` | Stale AOCR artifact; re-passivate source sandbox to bump generation |
| Module not on placement target | Warm module on node (create once) or disable strict inventory until cached |
| Every WASM create fails with `wasm worker: drop privileges` or `fork/exec ... operation not permitted` | Workers give up root before they run a module (`SB_WASM_WORKER_DROP_PRIVS=true`, the default) and need a new PID namespace. `sandboxd` must run as root with the rights to make one. Fix the host, or set `SB_WASM_WORKER_DROP_PRIVS=false` while you do |
| WASM sandboxes reach no address after the deny-floor file changed | A worker that cannot read the changed `SB_EGRESS_DENY_FLOOR_FILE` refuses every address until it can. Make the file readable by `SB_WASM_WORKER_UID`/`SB_WASM_WORKER_GID`, or edit it in place |
| Every WASM create fails with `wasm worker not started: wasm worker fence: ...`, `aerolvm_wasm_worker_fence_ready` is 0 | Workers that drop their privileges start only while the worker fence is in: the nftables table `inet aerolvm_wasm_workers`, which keeps the worker uid off loopback (Caddy's admin API), the node's own addresses, link-local, the cloud metadata endpoints and the egress deny floor. `sandboxd` could not install it. Check that the kernel has `nf_tables` and that `sandboxd` has `CAP_NET_ADMIN` (`nft list table inet aerolvm_wasm_workers`), then retry a create: each start tries the install again. Setting `SB_WASM_WORKER_DROP_PRIVS=false` runs workers as root instead, which is worse |
| A WASM sandbox cannot reach a name server, or the operator's upstream proxy, on `127.0.0.x`, `169.254.x` or one of the node's own addresses | The worker fence lets the worker uid reach those only on the addresses it knows: name servers in `/etc/resolv.conf` (port 53) and an upstream proxy the operator file names by address or as `localhost`. A proxy named by a hostname that resolves to loopback is not followed: name it by address. `nft list table inet aerolvm_wasm_workers` shows the exceptions. Removing the table (`nft delete table inet aerolvm_wasm_workers`) removes the fence; `sandboxd` puts it back within a minute |
| Every exposed port of every WASM sandbox times out, while `sandboxd` is healthy | Only `sandboxd` (root) opens connections to a guest's listener; the worker uid may only answer them, and the fence's `accept reply` rules need connection tracking to see that. A `notrack` rule for loopback in another table leaves those replies untracked, so the fence drops them: remove that rule |
| `this kernel has no nft fib` in the log | The kernel lacks the nftables `fib` module, so the fence lists the node's own addresses itself and refreshes the list on every sync (every 10 seconds) instead of the kernel tracking them. Load `nft_fib_inet` to go back to the kernel's view |
| `wasm sandbox keeps a root worker` in the log, `aerolvm_wasm_workers_legacy_root` above 0 | The sandbox's s3 or rclone mount was started before the upgrade, for root only. Its mount is never restarted under it, so its worker stays root. Recreate the sandbox to finish the upgrade |
| Rolling `sandboxd` back to a release from before workers dropped their privileges | Stop the dropped workers first: stop their sandboxes, or end the processes listed in `/sys/fs/cgroup/aerolvm-wasm/cgroup.procs`. An older `sandboxd` sends no file handles, so a dropped worker it takes over cannot reach the sandbox's files |

## Logs

```text
wasm sandbox passivated
wasm checkpoint pushed to AOCR
wasm checkpoint pulled from AOCR
wasm rehydrate failed
```

## Drain

Graceful shutdown calls `DrainWasmSandboxes` — ensure `SB_WASM_DRAIN_TIMEOUT` allows checkpoint completion.
