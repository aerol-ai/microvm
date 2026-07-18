package types

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

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
