package microvm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestRuntimesList(t *testing.T) {
	var gotTeam string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/runtimes" {
			t.Errorf("request = %s %s, want GET /v1/runtimes", r.Method, r.URL.Path)
		}
		gotTeam = r.Header.Get(HeaderTeam)
		_, _ = w.Write([]byte(`{"runtimes":[` +
			`{"name":"firecracker","isolation":"hardware-vm","backend":"kvm","features":{"snapshots":true,"pause":true,"moves":"memory","warm_pool":"snapshot","confidential":false},"available":true},` +
			`{"name":"wasm","isolation":"wasm","features":{"moves":"memory","warm_pool":"parked"},"limits":{"max_checkpoint_memory_mb":1024},"available":false}]}`))
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "avm_tenant", APIUrl: server.URL, Team: "payments"})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	runtimes, err := client.Runtimes().List(context.Background())
	if err != nil {
		t.Fatalf("Runtimes().List: %v", err)
	}
	if gotTeam != "payments" {
		t.Fatalf("%s = %q, want payments", HeaderTeam, gotTeam)
	}
	if len(runtimes) != 2 {
		t.Fatalf("listed %d runtimes, want 2: %+v", len(runtimes), runtimes)
	}
	fc, wasm := runtimes[0], runtimes[1]
	want := sdktypes.RuntimeFeatures{Snapshots: true, Pause: true, Moves: "memory", WarmPool: "snapshot"}
	if fc.Name != "firecracker" || fc.Backend != "kvm" || !fc.Available || fc.Features != want || fc.Limits != nil || fc.Nodes != nil {
		t.Fatalf("firecracker = %+v", fc)
	}
	if wasm.Available || wasm.Limits == nil || wasm.Limits.MaxCheckpointMemoryMB != 1024 || wasm.Backend != "" {
		t.Fatalf("wasm = %+v", wasm)
	}
}
