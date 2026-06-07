package wasm

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

type sandboxExecutor struct {
	driver *Driver
	id     string
}

func (e sandboxExecutor) Exec(r *http.Request, req models.ExecRequest) (models.ExecResult, error) {
	return e.driver.execSandbox(r.Context(), e.id, req)
}

func (d *Driver) execSandbox(ctx context.Context, sandboxID string, req models.ExecRequest) (models.ExecResult, error) {
	d.mu.Lock()
	inst := d.byID[sandboxID]
	d.mu.Unlock()
	if inst == nil {
		return models.ExecResult{}, fmt.Errorf("wasm sandbox %q not found", sandboxID)
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := wasmExecArgs(req.Command, inst.baseArgs)
	env := mergeEnv(inst.baseEnv, req.Env)
	wallTimeout := time.Duration(req.TimeoutSeconds) * time.Second
	if wallTimeout <= 0 {
		wallTimeout = d.cfg.DefaultWallTimeout
	}
	caps := wasmengine.CapsFromResourceLimits(wasmengine.Capabilities{
		Env:  env,
		Args: args,
		Preopens: []wasmengine.Preopen{{
			GuestPath: "/",
			HostPath:  inst.workDir,
		}},
	}, inst.memoryMB, wallTimeout)

	client := d.newWorkerClient(inst.socketPath)
	start := time.Now()
	run, err := client.Exec(sandboxID, caps, inst.entryExport)
	durationMS := run.Usage.WallDurationMs
	if durationMS <= 0 {
		durationMS = time.Since(start).Milliseconds()
	}
	result := models.ExecResult{
		Stdout:     run.Stdout,
		Stderr:     run.Stderr,
		ExitCode:   run.ExitCode,
		DurationMS: durationMS,
	}
	if err != nil && result.Stderr == "" {
		result.Stderr = err.Error()
	}
	if err != nil && result.ExitCode == 0 {
		result.ExitCode = 1
	}
	return result, nil
}

func wasmExecArgs(command string, fallback []string) []string {
	command = strings.TrimSpace(command)
	if command == "" {
		return append([]string(nil), fallback...)
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return append([]string(nil), fallback...)
	}
	return fields
}

func mergeEnv(base, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
