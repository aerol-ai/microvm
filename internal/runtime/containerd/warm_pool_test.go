package containerd

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSetWarmPoolNilSafe(t *testing.T) {
	var d *Driver
	d.SetWarmPool(nil)
	d = New(Config{}, nil, nil)
	d.SetWarmPool(nil)
}

func TestWarmPoolSeamAcquire(t *testing.T) {
	p := containerdpool.New(nil)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	d := New(Config{}, nil, nil)
	d.SetWarmPool(p)
	if d.warmPool == nil {
		t.Fatal("warm pool not wired")
	}
	if d.warmPool.HasReady(key) {
		t.Fatal("unexpected ready slot")
	}
}
