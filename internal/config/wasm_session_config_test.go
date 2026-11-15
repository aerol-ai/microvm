package config

import "testing"

func TestLoadWasmSessionSettings(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WasmSessionLogBytes != 1<<20 || cfg.WasmMaxSessionsPerSandbox != 16 || cfg.WasmSessionCommandsKept != 64 || cfg.WasmSessionLogBudget != 16<<20 {
		t.Fatalf("defaults = %d %d %d %d", cfg.WasmSessionLogBytes, cfg.WasmMaxSessionsPerSandbox, cfg.WasmSessionCommandsKept, cfg.WasmSessionLogBudget)
	}

	t.Setenv("SB_WASM_SESSION_LOG_BYTES", "4096")
	t.Setenv("SB_WASM_MAX_SESSIONS_PER_SANDBOX", "2")
	t.Setenv("SB_WASM_SESSION_COMMANDS_KEPT", "5")
	t.Setenv("SB_WASM_SESSION_LOG_BUDGET_BYTES", "65536")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WasmSessionLogBytes != 4096 || cfg.WasmMaxSessionsPerSandbox != 2 || cfg.WasmSessionCommandsKept != 5 || cfg.WasmSessionLogBudget != 65536 {
		t.Fatalf("configured = %d %d %d %d", cfg.WasmSessionLogBytes, cfg.WasmMaxSessionsPerSandbox, cfg.WasmSessionCommandsKept, cfg.WasmSessionLogBudget)
	}
}
