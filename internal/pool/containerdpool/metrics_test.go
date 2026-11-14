package containerdpool

import (
	"context"
	"expvar"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

type parkingSpawner struct{}

func (parkingSpawner) Park(_ context.Context, slotID string, key Key) (*ParkedSlot, error) {
	return &ParkedSlot{ID: slotID, ContainerID: slotID, Key: key, Handle: &fakeHandle{alive: true}}, nil
}
func (parkingSpawner) DestroyParked(context.Context, *ParkedSlot) error { return nil }

func expvarValue(t *testing.T, name string) int64 {
	t.Helper()
	v, ok := expvar.Get(name).(*expvar.Int)
	if !ok {
		t.Fatalf("expvar %s is not registered", name)
	}
	return v.Value()
}

// The containerd warm pool counts into its own aerolvm_containerd_pool_*
// series (TODOS.md: containerdpool exported none), and still into the shared
// aerolvm_docker_pool_* series the warm-pool dashboards read.
func TestContainerdPoolCountsIntoItsOwnSeries(t *testing.T) {
	names := []string{"hits_total", "misses_total", "refills_total", "orphans_total", "spawn_fails_total"}
	before := map[string]int64{}
	for _, n := range names {
		before["aerolvm_containerd_pool_"+n] = expvarValue(t, "aerolvm_containerd_pool_"+n)
		before["aerolvm_docker_pool_"+n] = expvarValue(t, "aerolvm_docker_pool_"+n)
	}

	p := New(nil)
	key := KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)

	// One miss.
	p.NoteMiss(key)
	// One orphan (a dead slot pruned) and one hit (a live slot taken).
	p.RecordLoaded(&ParkedSlot{ID: "park-dead", Key: key, Handle: &fakeHandle{alive: false}})
	p.RecordLoaded(&ParkedSlot{ID: "park-live", Key: key, Handle: &fakeHandle{alive: true}})
	if got := expvarValue(t, "aerolvm_containerd_pool_parked"); got != 2 {
		t.Fatalf("aerolvm_containerd_pool_parked = %d, want 2", got)
	}
	if _, err := p.Acquire(context.Background(), key, ""); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// One spawn failure.
	p.Metrics().RecordSpawnFail()
	// One refill, by the refill loop.
	p.PinTarget(key)
	p.SetDefaultDepth(1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx, dockerpool.RefillConfig{RefillInterval: 5 * time.Millisecond, SpawnTimeout: time.Second}, parkingSpawner{}, nil)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for expvarValue(t, "aerolvm_containerd_pool_refills_total")-before["aerolvm_containerd_pool_refills_total"] < 1 {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("refill loop never counted a refill")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	p.Close()

	want := map[string]int64{"hits_total": 1, "misses_total": 1, "refills_total": 1, "orphans_total": 1, "spawn_fails_total": 1}
	for _, n := range names {
		ctd := expvarValue(t, "aerolvm_containerd_pool_"+n) - before["aerolvm_containerd_pool_"+n]
		shared := expvarValue(t, "aerolvm_docker_pool_"+n) - before["aerolvm_docker_pool_"+n]
		if ctd != want[n] {
			t.Errorf("aerolvm_containerd_pool_%s delta = %d, want %d", n, ctd, want[n])
		}
		if shared != ctd {
			t.Errorf("aerolvm_docker_pool_%s delta = %d, want the same %d (the shared series keeps counting)", n, shared, ctd)
		}
	}
}

// A docker pool counts only into the shared series: the containerd series
// stays the containerd pool's alone.
func TestDockerPoolLeavesContainerdSeriesAlone(t *testing.T) {
	before := expvarValue(t, "aerolvm_containerd_pool_misses_total")
	p := dockerpool.New(nil)
	p.NoteMiss(KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker))
	if got := expvarValue(t, "aerolvm_containerd_pool_misses_total") - before; got != 0 {
		t.Fatalf("docker pool miss moved aerolvm_containerd_pool_misses_total by %d", got)
	}
}
