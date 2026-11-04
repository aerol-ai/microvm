package isolate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// claimingGroupHost is a fakeGroupHost whose egress claim refuses once its
// pool of `free` slots is used, like pkg/isolate.Host.ClaimEgressPolicy.
type claimingGroupHost struct {
	*fakeGroupHost
	free    int
	claimed []string
}

func (h *claimingGroupHost) ClaimEgressPolicy(id string, p EgressPolicy) error {
	if !p.BlockAll {
		if h.free == 0 {
			return pkgisolate.ErrEgressPoolExhausted
		}
		h.free--
	}
	h.claimed = append(h.claimed, id)
	return nil
}

type claimingSupervisor struct{ host *claimingGroupHost }

func (s *claimingSupervisor) SpawnGroup(context.Context, JailSpec) (GroupHost, error) {
	return s.host, nil
}

// A create in a group whose egress pool is full fails as a capacity refusal
// and unloads the bundle it pinned; before, it started a sandbox whose egress
// fell back to deny-all.
func TestCreateRefusesWhenGroupEgressPoolIsFull(t *testing.T) {
	host := &claimingGroupHost{fakeGroupHost: newFakeGroupHost(), free: 1}
	d := New(Config{GroupGranularity: GroupPerTenant, JailUID: 1000, JailGID: 1000, JailChrootBase: "/srv/jail"}, nil)
	d.SetBundleResolver(stubResolver{})
	d.SetHostSupervisor(&claimingSupervisor{host: host})
	ctx := context.Background()
	req := models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "a.js", TenantID: "acme"}

	if _, err := d.Create(ctx, req, "sb-1", "", nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := d.Create(ctx, req, "sb-2", "", nil)
	if !errors.Is(err, capacity.ErrCapacityExceeded) || !errors.Is(err, pkgisolate.ErrEgressPoolExhausted) {
		t.Fatalf("create on a full egress pool = %v, want a capacity refusal", err)
	}
	if host.LoadedCount() != 1 {
		t.Fatalf("refused create left its bundle loaded: %d loaded, want 1", host.LoadedCount())
	}
	if st, _ := d.Inspect(ctx, "sb-2"); st != nil && st.Status == models.SandboxStatusStarted {
		t.Fatalf("refused create is tracked as started: %+v", st)
	}
	// The group keeps serving its existing member.
	if host.isStopped() {
		t.Fatal("a refused claim must not stop a group that still has members")
	}

	// A block-all sandbox needs no slot, so the same full group admits it.
	blockAll := req
	blockAll.NetworkBlockAll = true
	if _, err := d.Create(ctx, blockAll, "sb-3", "", nil); err != nil {
		t.Fatalf("block-all create on a full egress pool: %v", err)
	}
}

func TestHostAdapterClaimEgressPolicy(t *testing.T) {
	runDir := t.TempDir()
	workerd := filepath.Join(runDir, "workerd")
	if err := os.WriteFile(workerd, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	host, err := pkgisolate.NewHost(pkgisolate.HostConfig{WorkerdPath: workerd, GroupKey: "acme", RunDir: filepath.Join(runDir, "g"), EgressPoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hostAdapter{Host: host}
	// Block-all claims no slot, so the adapter's conversion is exercised
	// without binding a socket (pkg/isolate covers the refusal itself).
	if err := adapter.ClaimEgressPolicy("sb-block", EgressPolicy{BlockAll: true}); err != nil {
		t.Fatalf("block-all claim: %v", err)
	}
	var _ EgressPolicyClaimer = adapter
}
