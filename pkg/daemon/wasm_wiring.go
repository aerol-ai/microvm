package daemon

import (
	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func wireWasmRuntime(cfg config.Config, logger *slog.Logger, svc *service.Service) {
	driver := wasmruntime.New(wasmruntime.FromDaemonConfig(cfg), logger)
	resolver := wasmmod.NewResolver(cfg.WasmModulesDir)
	supervisor := worker.NewSupervisor(worker.DefaultSpawner)
	driver.SetModuleResolver(resolver)
	driver.SetWorkerSupervisor(supervisor)
	svc.SetWasmRuntime(driver)
	logger.Info("wasm runtime enabled",
		"run_dir", cfg.WasmRunDir,
		"modules_dir", cfg.WasmModulesDir,
	)
}
