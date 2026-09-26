package worker

import (
	"context"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

type successNetworkEngine struct {
	fakeNetworkAwareEngine
	runResult wasmengine.RunResult
	runErr    error
	stopErr   error
}

func (e *successNetworkEngine) Run(ctx context.Context, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	if e.runErr != nil || e.runResult.ExitCode != 0 || e.runResult.Stderr != "" {
		return e.runResult, e.runErr
	}
	return wasmengine.RunResult{Stdout: "stdout", Stderr: "stderr", ExitCode: 0}, nil
}

func (e *successNetworkEngine) StopInstance(ctx context.Context) error {
	return e.stopErr
}
