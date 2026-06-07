package wasm

import "github.com/aerol-ai/microvm/internal/config"

// Config holds host-side WASM runtime settings. Phase 1 lands the shape;
// later phases wire engine, module cache, and warm pool knobs through here.
type Config struct {
	RunDir     string
	ModulesDir string
}

// FromDaemonConfig projects the WASM slice of daemon config into driver config.
func FromDaemonConfig(cfg config.Config) Config {
	return Config{
		RunDir:     cfg.WasmRunDir,
		ModulesDir: cfg.WasmModulesDir,
	}
}
