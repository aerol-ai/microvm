package worker

import (
	"context"
	"net/http"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestClient_ConnectionClosed_AllMethods(t *testing.T) {
	client := NewClient("/does/not/exist.sock")

	ctx := context.Background()
	sb := "sb"

	if err := client.LoadModule(sb, "path"); err == nil {
		t.Error("expected error")
	}
	if err := client.Instantiate(sb, wasmengine.Capabilities{}); err == nil {
		t.Error("expected error")
	}
	if _, err := client.Exec(sb, wasmengine.Capabilities{}, ""); err == nil {
		t.Error("expected error")
	}
	if err := client.Invoke(sb, ""); err == nil {
		t.Error("expected error")
	}
	if err := client.Checkpoint(ctx, sb, "", wasmengine.SnapshotConfig{}); err == nil {
		t.Error("expected error")
	}
	if err := client.Restore(sb, "", wasmengine.Capabilities{}); err == nil {
		t.Error("expected error")
	}
	if err := client.SetCapability(sb, wasmengine.Capabilities{}); err == nil {
		t.Error("expected error")
	}
	if _, _, err := client.NetstatsTick(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.SetNetworkBlocks(sb, true, true); err == nil {
		t.Error("expected error")
	}
	if _, err := client.InstanceLoaded(ctx, sb); err == nil {
		t.Error("expected error")
	}
	if err := client.Ping(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.StopInstance(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.TriggerPanic(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.SetListenPort(sb, 80, ""); err == nil {
		t.Error("expected error")
	}
	if _, err := client.ResolvedListenPort(sb); err == nil {
		t.Error("expected error")
	}
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	if err := client.ProxyHTTP(sb, 80, nil, req); err == nil {
		t.Error("expected error")
	}
}
