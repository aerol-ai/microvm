# WASM runtime agent map

Quick orientation for agents working on `runtime=wasm` in AerolVM.

## Entry points

| Layer | File | Role |
|---|---|---|
| Create dispatch | `internal/service/wasm.go` | Admission, mounts, driver create, catalogue row |
| Checkpoint / rehydrate | `internal/service/wasm_checkpoint.go` | Drain, AOCR push, `rehydrateWasmIfNeeded` |
| AOCR pull | `internal/service/wasm_checkpoint_pull.go` | `ensureWasmCheckpointLocal` before rehydrate |
| Failover recreate | `internal/service/wasm_recreate.go` | Durable WASM `RecreateSandbox` path |
| Reconcile | `internal/service/wasm_reconcile.go` | Offline / `awaiting_runtime` durability policy |
| Driver | `internal/runtime/wasm/` | Cold path, checkpoint, rehydrate, toolbox host |
| Worker IPC | `pkg/wasm/worker/` | Subprocess isolation, snapshot capture |
| AOCR artifacts | `pkg/wasmmod/oras_push.go`, `oras_pull.go` | §4.8.1 mem.snap push/pull |

## Durability classes

- `ephemeral` — lost on daemon restart; reconcile marks stopped.
- `passivatable` — drain writes local `mem.snap`; rehydrate on start.
- `durable` — passivation + AOCR push; pull on failover before rehydrate.

## Config (env)

- `SB_ENABLE_WASM`, `SB_WASM_MODULES_DIR`, `SB_WASM_RUN_DIR`
- `SB_WASM_CHECKPOINT_INTERVAL`, `SB_WASM_DURABLE_PUSH_INTERVAL`
- Reuses `SB_SNAPSHOT_PUSH_ENABLED` + cluster PAT for AOCR push/pull

## Tests to run

```bash
go test ./internal/service/... -run 'Wasm|wasm'
go test ./internal/runtime/wasm/...
go test ./pkg/wasmmod/...
```
