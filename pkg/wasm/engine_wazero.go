package wasm

import (
	"context"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type wazeroEngine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	module   api.Module
}

func newWazeroEngine(ctx context.Context) (*wazeroEngine, error) {
	r := wazero.NewRuntime(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("wasi instantiate: %w", err)
	}
	return &wazeroEngine{runtime: r}, nil
}

func (e *wazeroEngine) LoadModule(ctx context.Context, path string) error {
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
	}
	if e.compiled != nil {
		_ = e.compiled.Close(ctx)
		e.compiled = nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	compiled, err := e.runtime.CompileModule(ctx, b)
	if err != nil {
		return fmt.Errorf("compile module: %w", err)
	}
	e.compiled = compiled
	return nil
}

func (e *wazeroEngine) Instantiate(ctx context.Context, caps Capabilities) error {
	if e.compiled == nil {
		return fmt.Errorf("no compiled module loaded")
	}
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
	}
	cfg := wazero.NewModuleConfig().WithArgs(caps.Args...)
	for k, v := range caps.Env {
		cfg = cfg.WithEnv(k, v)
	}
	fsCfg := wazero.NewFSConfig()
	for _, p := range caps.Preopens {
		guest := p.GuestPath
		if guest == "" {
			guest = "/"
		}
		fsCfg = fsCfg.WithDirMount(p.HostPath, guest)
	}
	if len(caps.Preopens) > 0 {
		cfg = cfg.WithFSConfig(fsCfg)
	}
	mod, err := e.runtime.InstantiateModule(ctx, e.compiled, cfg)
	if err != nil {
		return fmt.Errorf("instantiate module: %w", err)
	}
	e.module = mod
	return nil
}

func (e *wazeroEngine) StopInstance(ctx context.Context) error {
	if e.module == nil {
		return nil
	}
	err := e.module.Close(ctx)
	e.module = nil
	return err
}

func (e *wazeroEngine) InvokeExport(ctx context.Context, name string) error {
	if e.module == nil {
		return fmt.Errorf("no active instance")
	}
	fn := e.module.ExportedFunction(name)
	if fn == nil {
		return fmt.Errorf("export %q not found", name)
	}
	_, err := fn.Call(ctx)
	return err
}

func (e *wazeroEngine) Close(ctx context.Context) error {
	if e.module != nil {
		_ = e.module.Close(ctx)
		e.module = nil
	}
	if e.compiled != nil {
		_ = e.compiled.Close(ctx)
		e.compiled = nil
	}
	if e.runtime != nil {
		return e.runtime.Close(ctx)
	}
	return nil
}
