package daemon

import (
	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/service"
)

func wireWasmRuntime(cfg config.Config, logger *slog.Logger, svc *service.Service) {
	driver := wasmruntime.New(wasmruntime.FromDaemonConfig(cfg), logger)
	svc.SetWasmRuntime(driver)
	logger.Info("wasm runtime enabled",
		"run_dir", cfg.WasmRunDir,
		"modules_dir", cfg.WasmModulesDir,
	)
}
