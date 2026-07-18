package isolate

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestGroupJoinDoesNotRaceLastMemberTeardown is the deterministic regression
// for the P1 zombie-sandbox bug: a create that has joined a group (registered
// under groupsMu in acquireGroup) but is still inside host.Load must not have
// its group torn down by a concurrent last-member Destroy. Before the router
// tracked membership itself, Destroy decided teardown from host.Unload's pinned
// count — which did not yet include the in-flight join — and Stop()'d the host
// out from under it.
func TestGroupJoinDoesNotRaceLastMemberTeardown(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()

	// sb-a spawns the group.
	if _, err := d.Create(ctx, req("acme"), "sb-a", "", nil); err != nil {
		t.Fatalf("create sb-a: %v", err)
	}
	host := sup.hosts[0]

	// Gate sb-b's Load so we can interleave Destroy(sb-a) while sb-b is a
	// registered member mid-Load.
	host.loadGate = make(chan struct{})
	host.inLoad = make(chan struct{})

	done := make(chan error, 1)
	go func() { _, err := d.Create(ctx, req("acme"), "sb-b", "", nil); done <- err }()

	<-host.inLoad // sb-b has acquired the group (members has it) and is in Load.

	// Last existing member leaves while sb-b is mid-join.
	_ = d.Destroy(ctx, &models.Sandbox{ID: "sb-a"})

	if host.isStopped() {
		t.Fatal("group host was stopped while a concurrent create was mid-join (zombie-sandbox regression)")
	}

	close(host.loadGate) // let sb-b finish loading.
	if err := <-done; err != nil {
		t.Fatalf("create sb-b: %v", err)
	}

	// The group is still live and serving sb-b.
	d.groupsMu.Lock()
	g := d.groups["acme"]
	d.groupsMu.Unlock()
	if g == nil {
		t.Fatal("group torn down despite a live member sb-b")
	}
	if sup.spawnCount() != 1 {
		t.Fatalf("spawns = %d, want 1 (single group)", sup.spawnCount())
	}

	// Destroying the real last member now tears it down.
	_ = d.Destroy(ctx, &models.Sandbox{ID: "sb-b"})
	if !host.isStopped() {
		t.Fatal("group host not stopped after its last member was destroyed")
	}
}

// TestConcurrentCreateDestroyChurn stresses the router under -race: many
// concurrent create+destroy cycles on one tenant must not race the group map,
// the member set, or the host lifecycle, and must leave no group behind.
func TestConcurrentCreateDestroyChurn(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()

	const workers = 24
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("sb-%d", i)
			if _, err := d.Create(ctx, req("acme"), id, "", nil); err != nil {
				t.Errorf("create %s: %v", id, err)
				return
			}
			_ = d.Destroy(ctx, &models.Sandbox{ID: id})
		}(i)
	}
	wg.Wait()

	d.groupsMu.Lock()
	n := len(d.groups)
	d.groupsMu.Unlock()
	if n != 0 {
		t.Fatalf("groups left after churn = %d, want 0 (leak)", n)
	}
}

func req(tenant string) models.CreateSandboxRequest {
	return models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "file:///x.js", TenantID: tenant, MemoryMB: 128}
}
