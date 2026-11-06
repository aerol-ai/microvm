package types

import (
	"encoding/json"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestStatusReasonsDecode: every server reason has an SDK constant, and a
// sandbox decodes status_reason and exit_code, keeping exit code 0 apart
// from "no exit".
func TestStatusReasonsDecode(t *testing.T) {
	t.Parallel()
	sdk := []string{
		StatusReasonUserStop, StatusReasonIdle, StatusReasonMaxAge, StatusReasonOutOfMemory,
		StatusReasonDiskLimit, StatusReasonCrashed, StatusReasonProgramExited, StatusReasonReconcile,
		StatusReasonFailover, StatusReasonRestarted,
	}
	seen := map[string]bool{}
	for _, r := range sdk {
		seen[r] = true
	}
	for _, r := range models.StatusReasons {
		if !seen[r] {
			t.Fatalf("server reason %q has no SDK constant", r)
		}
	}
	if len(sdk) != len(models.StatusReasons) {
		t.Fatalf("%d SDK constants for %d server reasons", len(sdk), len(models.StatusReasons))
	}

	var exited Sandbox
	if err := json.Unmarshal([]byte(`{"id":"sb","status":"started","status_reason":"program_exited","exit_code":0}`), &exited); err != nil {
		t.Fatal(err)
	}
	if exited.StatusReason != StatusReasonProgramExited || exited.ExitCode == nil || *exited.ExitCode != 0 {
		t.Fatalf("decoded %q %v", exited.StatusReason, exited.ExitCode)
	}
	var plain Sandbox
	if err := json.Unmarshal([]byte(`{"id":"sb","status":"started"}`), &plain); err != nil {
		t.Fatal(err)
	}
	if plain.StatusReason != "" || plain.ExitCode != nil {
		t.Fatalf("plain sandbox decoded %q %v", plain.StatusReason, plain.ExitCode)
	}
}

func TestRuntimeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "docker", got: RuntimeDocker, want: models.RuntimeDocker},
		{name: "gvisor", got: RuntimeGvisor, want: models.RuntimeGvisor},
		{name: "kata", got: RuntimeKata, want: models.RuntimeKata},
		{name: "firecracker", got: RuntimeFirecracker, want: models.RuntimeFirecracker},
		{name: "wasm", got: RuntimeWasm, want: models.RuntimeWasm},
		{name: "isolate", got: RuntimeIsolate, want: models.RuntimeIsolate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Fatalf("Runtime%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
	if RuntimeIsolate != "isolate" {
		t.Fatalf("RuntimeIsolate = %q, want %q", RuntimeIsolate, "isolate")
	}
}
