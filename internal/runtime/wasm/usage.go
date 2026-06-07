package wasm

import (
	"expvar"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

var (
	wasmInvokeCountTotal   = expvar.NewInt("aerolvm_wasm_invoke_total")
	wasmInvokeWallMsTotal  = expvar.NewInt("aerolvm_wasm_invoke_wall_ms_total")
	wasmInvokeInstructions = expvar.NewInt("aerolvm_wasm_invoke_instructions_total")
)

func recordWasmUsage(_ string, usage wasmengine.UsageStats) {
	if usage.WallDurationMs > 0 {
		wasmInvokeWallMsTotal.Add(usage.WallDurationMs)
	}
	if usage.Instructions > 0 {
		wasmInvokeInstructions.Add(usage.Instructions)
	}
	wasmInvokeCountTotal.Add(1)
}
