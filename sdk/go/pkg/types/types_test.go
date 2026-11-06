package types

import (
	"encoding/json"
	"testing"
	"time"

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
	// restartOnFailure is a plain lifecycle field: sent only when set.
	on, err := json.Marshal(Lifecycle{RestartOnFailure: true})
	if err != nil || string(on) != `{"restart_on_failure":true}` {
		t.Fatalf("Lifecycle{RestartOnFailure} = %s, %v", on, err)
	}
	if exit, _ := json.Marshal(Lifecycle{DestroyAfterExitFor: time.Minute}); string(exit) != `{"destroy_after_exit_for":60000000000}` {
		t.Fatalf("Lifecycle{DestroyAfterExitFor} = %s", exit)
	}
	at := time.Date(2026, 11, 6, 18, 0, 0, 0, time.UTC)
	if b, _ := json.Marshal(Lifecycle{DestroyAt: &at}); string(b) != `{"destroy_at":"2026-11-06T18:00:00Z"}` {
		t.Fatalf("Lifecycle{DestroyAt} = %s", b)
	}
	if off, _ := json.Marshal(Lifecycle{}); string(off) != `{}` {
		t.Fatalf("empty Lifecycle = %s", off)
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
