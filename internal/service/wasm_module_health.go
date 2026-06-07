package service

import (
	"context"
	"os"
	"time"
)

// StartWasmModuleGC launches the periodic wasm_modules catalogue janitor.
func (s *Service) StartWasmModuleGC(ctx context.Context) {
	if s == nil || !s.cfg.EnableWasm || !s.cfg.WasmModuleGCEnabled {
		return
	}
	interval := s.cfg.WasmModuleGCInterval
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				s.runWasmModuleGC(sweepCtx, time.Now())
				cancel()
			}
		}
	}()
}

func (s *Service) runWasmModuleGC(ctx context.Context, now time.Time) {
	ttl := s.cfg.WasmModuleGCTTL
	if ttl <= 0 {
		return
	}
	cutoff := now.UTC().Add(-ttl)
	records, err := s.store.ListWasmModulesOlderThan(ctx, cutoff)
	if err != nil {
		s.logger.Warn("wasm module gc list failed", "error", err)
		return
	}
	for _, rec := range records {
		referenced, err := s.store.IsWasmModuleReferenced(ctx, rec.ID, rec.ModuleRef)
		if err != nil {
			s.logger.Warn("wasm module gc reference check failed", "module_id", rec.ID, "error", err)
			continue
		}
		if referenced {
			continue
		}
		if rec.ModulePath != "" {
			_ = os.RemoveAll(rec.ModulePath)
		}
		if err := s.store.DeleteWasmModule(ctx, rec.ID); err != nil {
			s.logger.Warn("wasm module gc delete failed", "module_id", rec.ID, "error", err)
			continue
		}
		s.logger.Info("wasm module gc removed unreferenced catalogue row", "module_id", rec.ID)
	}
}
