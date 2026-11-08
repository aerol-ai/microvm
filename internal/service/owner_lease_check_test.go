package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func epochPlacement(id string, epoch uint64) cluster.Placement {
	p := selfPlacement(id)
	p.OwnerEpoch = epoch
	return p
}

// With the owner cache flag on (E3b), the lease reads every local sandbox,
// not only the recreate-policy ones, and keeps each proven owner epoch. A
// row the read does not prove (another owner, another lifetime, unknown
// epoch) is not kept.
func TestOwnerLeaseRecordsEpochsForEveryLocalSandbox(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.cfg.ClusterOwnerCache = true
	svc.cfg.NodeRole = config.NodeRoleWorker
	seedLeaseRow(t, st, "sb-plain", false, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-moved", false, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-reborn", false, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-old", false, models.SandboxStatusStarted)
	moved := epochPlacement("sb-moved", 9)
	moved.OwnerNodeID = "worker-b"
	reborn := epochPlacement("sb-reborn", 10)
	reborn.IncarnationID = "inc-other-lifetime"
	lc.up(epochPlacement("sb-plain", 7), epochPlacement("sb-ha", 8), moved, reborn, epochPlacement("sb-old", 0))

	t0 := time.Unix(40_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	now := t0.Add(time.Second)
	for _, tc := range []struct {
		id    string
		epoch uint64
		want  OwnerLeaseVerdict
	}{
		{"sb-plain", 7, OwnerLeaseOwned},
		{"sb-ha", 8, OwnerLeaseOwned},
		{"sb-moved", 9, OwnerLeaseUnknown},
		{"sb-reborn", 10, OwnerLeaseUnknown},
		{"sb-old", 5, OwnerLeaseUnknown},
	} {
		if got := svc.OwnerLeaseCheck(tc.id, tc.epoch, false, now); got != tc.want {
			t.Errorf("%s at %d: got %v, want %v", tc.id, tc.epoch, got, tc.want)
		}
	}
}

// With the flag off nothing changes: the read covers only recreate-policy
// sandboxes, and the router never gets a verdict.
func TestOwnerLeaseOffKeepsTheReadSmall(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	seedLeaseRow(t, st, "sb-plain", false, models.SandboxStatusStarted)
	seedLeaseRow(t, st, "sb-ha", true, models.SandboxStatusStarted)
	lc.up(epochPlacement("sb-plain", 7), epochPlacement("sb-ha", 8))
	t0 := time.Unix(41_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got := lc.batchSizes; len(got) != 1 || got[0] != 1 {
		t.Fatalf("read batch sizes %v, want one read of the one recreate sandbox", got)
	}
	if got := svc.OwnerLeaseCheck("sb-ha", 8, false, t0); got != OwnerLeaseUnknown {
		t.Fatalf("flag off: got %v, want unknown", got)
	}
}

// The rule table the router relies on.
func TestOwnerLeaseCheckVerdicts(t *testing.T) {
	svc, _, _ := newLeaseService(t, newFreezeRuntime())
	svc.cfg.ClusterOwnerCache = true
	svc.cfg.NodeRole = config.NodeRoleWorker
	read := time.Unix(42_000, 0)
	svc.SetOwnerLeaseForTest(map[string]uint64{"sb-1": 20, "sb-fenced": 20}, read)
	svc.FenceOwnershipForTest("sb-fenced")
	lease := cluster.OwnershipLease(svc.cfg)
	for _, tc := range []struct {
		name   string
		id     string
		epoch  uint64
		hinted bool
		at     time.Time
		want   OwnerLeaseVerdict
	}{
		{"same epoch, fresh read", "sb-1", 20, false, read.Add(time.Second), OwnerLeaseOwned},
		{"same epoch, read as old as the lease", "sb-1", 20, false, read.Add(lease), OwnerLeaseOwned},
		{"same epoch, read older than the lease", "sb-1", 20, false, read.Add(lease + time.Millisecond), OwnerLeaseUnknown},
		{"cached forward, read under 2 s", "sb-1", 20, true, read.Add(1500 * time.Millisecond), OwnerLeaseOwned},
		{"cached forward, read over 2 s", "sb-1", 20, true, read.Add(2100 * time.Millisecond), OwnerLeaseUnknown},
		{"the read knows a newer epoch", "sb-1", 12, false, read.Add(time.Second), OwnerLeaseNewer},
		{"the forward knows a newer epoch", "sb-1", 25, false, read.Add(time.Second), OwnerLeaseUnknown},
		{"no entry", "sb-2", 20, false, read.Add(time.Second), OwnerLeaseUnknown},
		{"fenced", "sb-fenced", 20, false, read.Add(time.Second), OwnerLeaseUnknown},
		{"no epoch on the forward", "sb-1", 0, false, read.Add(time.Second), OwnerLeaseUnknown},
	} {
		if got := svc.OwnerLeaseCheck(tc.id, tc.epoch, tc.hinted, tc.at); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	svc.cfg.NodeRole = config.NodeRoleMixed
	if got := svc.OwnerLeaseCheck("sb-1", 20, false, read.Add(time.Second)); got != OwnerLeaseUnknown {
		t.Fatalf("server-role node: got %v, want unknown", got)
	}
	svc.cfg.NodeRole = config.NodeRoleWorker
	svc.cfg.ClusterOwnerCache = false
	if got := svc.OwnerLeaseCheck("sb-1", 20, false, read.Add(time.Second)); got != OwnerLeaseUnknown {
		t.Fatalf("flag off: got %v, want unknown", got)
	}
	var none *Service
	if got := none.OwnerLeaseCheck("sb-1", 20, false, read); got != OwnerLeaseUnknown {
		t.Fatalf("nil service: got %v, want unknown", got)
	}
}

// A failed read leaves the last reading in place, and its age then retires it.
func TestOwnerLeaseFailedReadKeepsTheOldReadingUntilItAges(t *testing.T) {
	ctx := context.Background()
	svc, st, lc := newLeaseService(t, newFreezeRuntime())
	svc.cfg.ClusterOwnerCache = true
	svc.cfg.NodeRole = config.NodeRoleWorker
	seedLeaseRow(t, st, "sb-plain", false, models.SandboxStatusStarted)
	lc.up(epochPlacement("sb-plain", 7))
	t0 := time.Unix(43_000, 0)
	svc.beginOwnershipLease(t0)
	if err := svc.confirmOwnership(ctx, t0); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	lc.down()
	if err := svc.confirmOwnership(ctx, t0.Add(5*time.Second)); err == nil {
		t.Fatal("confirm with the control plane down succeeded")
	}
	if got := svc.OwnerLeaseCheck("sb-plain", 7, false, t0.Add(6*time.Second)); got != OwnerLeaseOwned {
		t.Fatalf("within the lease: got %v, want owned", got)
	}
	if got := svc.OwnerLeaseCheck("sb-plain", 7, false, t0.Add(16*time.Second)); got != OwnerLeaseUnknown {
		t.Fatalf("past the lease: got %v, want unknown", got)
	}
}
