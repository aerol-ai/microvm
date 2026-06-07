package wasm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
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

func (e *wazeroEngine) Run(ctx context.Context, caps Capabilities, export string) (RunResult, error) {
	if export == "" {
		export = "_start"
	}
	var stdout, stderr bytes.Buffer
	if err := e.instantiateWithIO(ctx, caps, &stdout, &stderr); err != nil {
		return RunResult{}, err
	}
	exitCode, err := e.callExport(ctx, export)
	result := RunResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}
	if err != nil {
		var exitErr *sys.ExitError
		if errors.As(err, &exitErr) {
			return result, nil
		}
		result.Stderr = stringsTrimJoin(result.Stderr, err.Error())
		return result, err
	}
	return result, nil
}

func (e *wazeroEngine) instantiateWithIO(ctx context.Context, caps Capabilities, stdout, stderr *bytes.Buffer) error {
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
	if stdout != nil {
		cfg = cfg.WithStdout(stdout)
	}
	if stderr != nil {
		cfg = cfg.WithStderr(stderr)
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

func (e *wazeroEngine) callExport(ctx context.Context, name string) (int, error) {
	if e.module == nil {
		return 1, fmt.Errorf("no active instance")
	}
	fn := e.module.ExportedFunction(name)
	if fn == nil {
		return 1, fmt.Errorf("export %q not found", name)
	}
	_, err := fn.Call(ctx)
	return exitCodeFromInvoke(err), err
}

func exitCodeFromInvoke(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *sys.ExitError
	if errors.As(err, &exitErr) {
		return int(exitErr.ExitCode())
	}
	return 1
}

func stringsTrimJoin(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "\n" + b
	}
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
