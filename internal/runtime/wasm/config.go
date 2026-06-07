package wasm

import (
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// Config holds host-side WASM runtime settings.
type Config struct {
	RunDir             string
	ModulesDir         string
	DefaultMemoryMB    int
	DefaultWallTimeout time.Duration
	DrainTimeout       time.Duration
}

// FromDaemonConfig projects the WASM slice of daemon config into driver config.
func FromDaemonConfig(cfg config.Config) Config {
	return Config{
		RunDir:             cfg.WasmRunDir,
		ModulesDir:         cfg.WasmModulesDir,
		DefaultMemoryMB:    cfg.WasmDefaultMemoryMB,
		DefaultWallTimeout: cfg.WasmDefaultTimeout,
		DrainTimeout:       cfg.WasmDrainTimeout,
	}
}
