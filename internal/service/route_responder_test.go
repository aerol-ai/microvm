package service

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/routedns"
)

type fakeWatcherCluster struct {
	*cluster.Noop
	fn cluster.PlacementChangeHandler
}

func (f *fakeWatcherCluster) WatchPlacementChanges(_ context.Context, fn cluster.PlacementChangeHandler) bool {
	f.fn = fn
	return true
}

func (f *fakeWatcherCluster) PlacementOf(id string) (cluster.Placement, bool) {
	if id == "sbm" {
		return cluster.Placement{SandboxID: "sbm"}, true
	}
	return cluster.Placement{}, false
}

func TestWatchIngressRouteIndexAppliesFullViewAndDeltas(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.Domain = "d.test"
	fw := &fakeWatcherCluster{Noop: cluster.NewNoop("n", "", "")}
	svc.AttachCluster(fw)
	idx := routedns.NewIngressIndex()
	if !svc.watchIngressRouteIndex(context.Background(), idx) {
		t.Fatal("watcher not registered")
	}
	pub := func(id string) cluster.Placement {
		return cluster.Placement{SandboxID: id, OwnerNodeID: "w", OwnerDataPlaneHost: "10.0.0.1", PublicTraffic: true}
	}
	fw.fn([]cluster.Placement{pub("a"), pub("b")}, nil)
	if _, ok := idx.Lookup("a.d.test"); !ok {
		t.Fatal("full view not applied")
	}
	p := pub("c")
	fw.fn(nil, []cluster.PlacementChange{{SandboxID: "c", Placement: &p}, {SandboxID: "a", Deleted: true}, {SandboxID: "b"}})
	if _, ok := idx.Lookup("c.d.test"); !ok {
		t.Fatal("upsert delta not applied")
	}
	for _, gone := range []string{"a.d.test", "b.d.test"} {
		if _, ok := idx.Lookup(gone); ok {
			t.Fatalf("%s survived a delete (or a nil-placement change)", gone)
		}
	}
	if p, ok := svc.ingressMissLookup()(context.Background(), "sbm"); !ok || p.SandboxID != "sbm" {
		t.Fatalf("miss lookup = %+v %v", p, ok)
	}
}

func TestWatchIngressRouteIndexWithoutAWatcher(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n", "", "")) // single-node: no watcher
	if svc.watchIngressRouteIndex(context.Background(), routedns.NewIngressIndex()) {
		t.Fatal("a Noop cluster has no placement watcher")
	}
	if svc.watchIngressRouteIndex(context.Background(), nil) {
		t.Fatal("nil index accepted")
	}
	empty := &Service{cfg: config.Config{}}
	if _, ok := empty.ingressMissLookup()(context.Background(), "x"); ok {
		t.Fatal("miss lookup without a cluster resolved")
	}
}
