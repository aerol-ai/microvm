package wasm

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

type stubWorkerNetstatsClient struct {
	in  int64
	out int64
}

func (c *stubWorkerNetstatsClient) Ping(string) error { return nil }
func (c *stubWorkerNetstatsClient) InstanceLoaded(context.Context, string) (bool, error) {
	return true, nil
}
func (c *stubWorkerNetstatsClient) LoadModule(string, string) error {
	return nil
}
func (c *stubWorkerNetstatsClient) Instantiate(string, wasmengine.Capabilities) error {
	return nil
}
func (c *stubWorkerNetstatsClient) Invoke(string, string) error { return nil }
func (c *stubWorkerNetstatsClient) Exec(string, wasmengine.Capabilities, string) (wasmengine.RunResult, error) {
	return wasmengine.RunResult{}, nil
}
func (c *stubWorkerNetstatsClient) StopInstance(string) error { return nil }
func (c *stubWorkerNetstatsClient) Checkpoint(context.Context, string, string, wasmengine.SnapshotConfig) error {
	return nil
}
func (c *stubWorkerNetstatsClient) Restore(string, string, wasmengine.Capabilities) error {
	return nil
}
func (c *stubWorkerNetstatsClient) SetCapability(string, wasmengine.Capabilities) error {
	return nil
}
func (c *stubWorkerNetstatsClient) NetstatsTick(string) (int64, int64, error) {
	return c.in, c.out, nil
}
func (c *stubWorkerNetstatsClient) SetNetworkBlocks(string, bool, bool) error { return nil }
func (c *stubWorkerNetstatsClient) SetListenPort(string, int, string) error   { return nil }
func (c *stubWorkerNetstatsClient) ResolvedListenPort(string) (int, error)    { return 0, nil }
func (c *stubWorkerNetstatsClient) ProxyHTTP(_ string, _ int, w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusBadGateway)
	return nil
}

func TestDrainNetworkByteCountersMergesGatewayAndWorker(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.newWorkerClient = func(string) WorkerClient {
		return &stubWorkerNetstatsClient{in: 3, out: 7}
	}
	d.mu.Lock()
	d.byID["sb-merge"] = &sandboxInstance{
		sandboxID:  "sb-merge",
		socketPath: "/tmp/fake.sock",
		status:     models.SandboxStatusStarted,
	}
	d.mu.Unlock()

	ctx := context.Background()
	dial, err := d.EnsureHTTPListener(ctx, "sb-merge", 9000)
	if err != nil {
		t.Fatalf("EnsureHTTPListener: %v", err)
	}
	d.SyncAllowedPorts("sb-merge", []int{9000})
	resp, err := http.Get("http://" + dial + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	got := d.DrainNetworkByteCounters()["sb-merge"]
	if got.BytesIn < 1 {
		t.Fatalf("gateway bytes in = %d, want >= 1", got.BytesIn)
	}
	if got.BytesOut < 1 {
		t.Fatalf("gateway bytes out = %d, want >= 1", got.BytesOut)
	}
	if got.BytesIn < 3 {
		t.Fatalf("merged bytes in = %d, want >= 3 (gateway + worker)", got.BytesIn)
	}
	if got.BytesOut < 7 {
		t.Fatalf("merged bytes out = %d, want >= 7 (gateway + worker)", got.BytesOut)
	}
}
