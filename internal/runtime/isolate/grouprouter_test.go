package isolate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

type warmPoolHost struct {
	host GroupHost
	ok   bool
}

func (p warmPoolHost) Acquire(ctx context.Context) (GroupHost, bool) {
	if !p.ok || p.host == nil {
		return nil, false
	}
	return p.host, true
}

func TestSpawnGroupWarmPool(t *testing.T) {
	warm := newFakeGroupHost()
	d := New(Config{JailUID: 1000, JailGID: 1000, JailChrootBase: "/srv/jail"}, nil)
	d.SetWarmPool(warmPoolHost{host: warm, ok: true})
	d.SetHostSupervisor(&fakeSupervisor{}) // should not be called

	host, err := d.spawnGroup(context.Background(), "acme", 1, 128)
	if err != nil || host != warm {
		t.Fatalf("spawnGroup warm = %v err=%v", host, err)
	}
	// A blank was jailed with unlimited caps; the claiming tenant's caps are
	// applied to it, so the pool never hands out an uncapped process.
	if warm.capsHits != 1 || warm.capsCPU != 1 || warm.capsMem != 128 {
		t.Fatalf("warm host caps = hits %d cpu %v mem %d, want 1/1/128", warm.capsHits, warm.capsCPU, warm.capsMem)
	}
	// A host whose caps cannot be applied is not handed to the tenant.
	broken := newFakeGroupHost()
	broken.capsErr = errors.New("cgroup write failed")
	d.SetWarmPool(warmPoolHost{host: broken, ok: true})
	if _, err := d.spawnGroup(context.Background(), "acme", 1, 128); err == nil || !strings.Contains(err.Error(), "apply caps") {
		t.Fatalf("uncappable warm host err = %v", err)
	}
	if !broken.stopped {
		t.Fatal("uncappable warm host was not stopped")
	}
}

func TestAcquireGroupSpawnError(t *testing.T) {
	sup := &fakeSupervisor{spawnErr: errors.New("spawn failed")}
	d := newCreateDriver(t, GroupPerTenant, sup)
	_, err := d.acquireGroup(context.Background(), "acme", "sb-1", 1, 128)
	if err == nil || !strings.Contains(err.Error(), "spawn failed") {
		t.Fatalf("acquireGroup spawn err = %v", err)
	}
}

func TestAcquireGroupContextCancel(t *testing.T) {
	sup := &fakeSupervisor{block: make(chan struct{})}
	d := newCreateDriver(t, GroupPerTenant, sup)
	baseCtx := context.Background()

	// First create owns the spawn and blocks inside spawnGroup.
	go func() {
		_, _ = d.acquireGroup(baseCtx, "acme", "sb-1", 1, 128)
	}()
	// Wait until the router has registered the in-flight spawn so the second
	// acquire parks on ctx cancel instead of racing into SpawnGroup.
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.groupsMu.Lock()
		_, inflight := d.spawning["acme"]
		d.groupsMu.Unlock()
		if inflight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for in-flight spawn")
		}
		time.Sleep(5 * time.Millisecond)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := d.acquireGroup(ctx, "acme", "sb-2", 1, 128)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	err := <-done
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("acquireGroup cancel = %v", err)
	}
	close(sup.block)
}

func TestReleaseFromGroupEdgeCases(t *testing.T) {
	d := New(Config{}, nil)
	// Unknown group is a no-op.
	d.releaseFromGroup("missing", "sb-1")

	sup := &fakeSupervisor{}
	d2 := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d2.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	// Releasing unknown member on live group should not stop host.
	d2.releaseFromGroup("acme", "sb-other")
	if sup.hosts[0].stopped {
		t.Fatal("host stopped for unknown member release")
	}
}
