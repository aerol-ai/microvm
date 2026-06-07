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

## Logs

```text
wasm sandbox passivated
wasm checkpoint pushed to AOCR
wasm checkpoint pulled from AOCR
wasm rehydrate failed
```

## Drain

Graceful shutdown calls `DrainWasmSandboxes` — ensure `SB_WASM_DRAIN_TIMEOUT` allows checkpoint completion.
