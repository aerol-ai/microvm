package cluster

import (
	"context"
	"errors"
	"expvar"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAdoptUnplacedRow is the rule for a local row with no placement and no
// post-delete record: place it only when that cannot bring back a deleted
// sandbox.
func TestAdoptUnplacedRow(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		createdAt  time.Time
		grace      time.Duration
		soleServer bool
		want       bool
	}{
		{"sole server places an old row (a single node turned into a cluster)", now.Add(-48 * time.Hour), time.Hour, true, true},
		{"sole server places even with grace 0", now.Add(-48 * time.Hour), 0, true, true},
		{"young row: a delete would still have its record", now.Add(-10 * time.Minute), time.Hour, false, true},
		{"row just inside grace less clock skew", now.Add(-58*time.Minute + time.Second), time.Hour, false, true},
		{"row at grace less clock skew: no longer provable", now.Add(-59 * time.Minute), time.Hour, false, false},
		{"old row: its record may have expired", now.Add(-2 * time.Hour), time.Hour, false, false},
		{"grace 0 keeps no record, so nothing is provable", now.Add(-time.Second), 0, false, false},
		{"grace shorter than the clock skew allowance", now.Add(-time.Second), 30 * time.Second, false, false},
		{"unknown creation time counts as old", time.Time{}, time.Hour, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := adoptUnplacedRow(tc.createdAt, now, tc.grace, tc.soleServer); got != tc.want {
				t.Fatalf("adoptUnplacedRow(createdAt=%s, grace=%s, sole=%v) = %v, want %v",
					now.Sub(tc.createdAt), tc.grace, tc.soleServer, got, tc.want)
			}
		})
	}
}

// TestAssertOwnershipUnplacedRowRule runs the rule through a real Raft
// server. While it is the only server it places an old row, which is how a
// single node turned into a cluster seed keeps its sandboxes. Once another
// server is in the configuration, an old row with no placement and no record
// is quarantined (not placed, no error, counted), and a young one is placed.
func TestAssertOwnershipUnplacedRowRule(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newDeletedLifecycleTestCluster(t, "leader")
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	old := time.Now().Add(-48 * time.Hour)

	if !c.soleRaftServer() {
		t.Fatal("a single bootstrapped node is the sole Raft server")
	}
	if (*Cluster)(nil).soleRaftServer() || (&Cluster{}).soleRaftServer() {
		t.Fatal("a cluster without raft is never the sole server")
	}
	if err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID: "sb-pre-cluster", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-pre-cluster"}, CreatedAt: old,
	}}); err != nil {
		t.Fatalf("AssertOwnership on the sole server: %v", err)
	}
	if _, ok := c.fsm.get("sb-pre-cluster"); !ok {
		t.Fatal("the sole server must place its old rows (single node turned into a cluster)")
	}

	if err := c.raft.raft.AddNonvoter("peer", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatalf("add peer: %v", err)
	}
	if c.soleRaftServer() {
		t.Fatal("a configuration with another server is not sole")
	}
	before := ownershipReplaySkipped(unplacedReplayUnproven)
	if err := c.AssertOwnership(ctx, []LocalSandboxState{
		{
			ID: "sb-old", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-old"}, CreatedAt: old,
			ExposedPorts: map[int]ExposedPortRoute{8080: {Protocol: "http"}}, CustomHostnames: []string{"old.example"},
		},
		{ID: "sb-young", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-young"}, CreatedAt: time.Now()},
	}); err != nil {
		t.Fatalf("a quarantined row is not an error, or the boot replay would retry forever: %v", err)
	}
	if got, ok := c.fsm.get("sb-old"); ok {
		t.Fatalf("an old row with no record was placed on a node that is not the sole server: %+v", got)
	}
	if _, ok := c.fsm.sandboxIDByCustomHostname("old.example"); ok {
		t.Fatal("a quarantined row's hostname was replayed")
	}
	if _, ok := c.fsm.get("sb-young"); !ok {
		t.Fatal("a young row with no record must still be placed")
	}
	if after := ownershipReplaySkipped(unplacedReplayUnproven); after != before+1 {
		t.Fatalf("quarantined rows counted %d, want %d", after-before, 1)
	}
}

func ownershipReplaySkipped(reason string) int64 {
	if v, ok := clusterOwnershipReplaySkipped.Get(reason).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}

// TestAssertOwnershipDeletedLifecycleReportsSentinel: the refusal reaches the
// caller as ErrPlacementDeleted and stops the port replay for that row.
func TestAssertOwnershipDeletedLifecycleReportsSentinel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newDeletedLifecycleTestCluster(t, "leader")
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	if err := c.RecordPlacement(ctx, "sb-gone", spec, PlacementSecrets{IncarnationID: "inc-gone"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeletePlacementExact(ctx, "sb-gone", c.nodeID, "inc-gone"); err != nil {
		t.Fatal(err)
	}
	err := c.AssertOwnership(ctx, []LocalSandboxState{{
		ID: "sb-gone", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-gone"}, CreatedAt: time.Now(),
		CustomHostnames: []string{"gone.example"},
	}})
	if !errors.Is(err, ErrPlacementDeleted) {
		t.Fatalf("AssertOwnership = %v, want ErrPlacementDeleted", err)
	}
	if _, ok := c.fsm.sandboxIDByCustomHostname("gone.example"); ok {
		t.Fatal("a refused row's hostname was replayed")
	}
}

// TestAgentAssertOwnershipUnplacedRows is the worker side, over the
// control-plane hop: a worker is never the sole server, so an old row with no
// placement is quarantined without a write; a refused row comes back as
// ErrPlacementDeleted and its ports are not replayed; a young row is placed.
func TestAgentAssertOwnershipUnplacedRows(t *testing.T) {
	var applied []command
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, PublicInternalPlacementPath):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && (r.URL.Path == PublicInternalApplyPath || r.URL.Path == InternalAPIPath):
			body, _ := io.ReadAll(r.Body)
			var cmd command
			if err := decodeCommandInto(body, &cmd); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			applied = append(applied, cmd)
			if cmd.Op == opPlace && cmd.SandboxID == "sb-deleted" {
				http.Error(w, "cluster: fsm apply: "+ErrPlacementDeleted.Error()+": sb-deleted", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	agent.cfg.AuditDeletedGrace = time.Hour
	spec := &models.CreateSandboxRequest{Image: "alpine"}
	ports := map[int]ExposedPortRoute{8080: {Protocol: "http"}}
	err := agent.AssertOwnership(context.Background(), []LocalSandboxState{
		{ID: "sb-old", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-old"}, CreatedAt: time.Now().Add(-2 * time.Hour), ExposedPorts: ports},
		{ID: "sb-deleted", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-deleted"}, CreatedAt: time.Now(), ExposedPorts: ports},
		{ID: "sb-young", Spec: spec, Secrets: PlacementSecrets{IncarnationID: "inc-young"}, CreatedAt: time.Now()},
	})
	if !errors.Is(err, ErrPlacementDeleted) {
		t.Fatalf("AssertOwnership = %v, want ErrPlacementDeleted", err)
	}
	var placed []string
	for _, cmd := range applied {
		if cmd.SandboxID == "sb-old" {
			t.Fatalf("a quarantined row reached the control plane: %+v", cmd)
		}
		if cmd.SandboxID == "sb-deleted" && cmd.Op != opPlace {
			t.Fatalf("a refused row's ports were replayed: %+v", cmd)
		}
		if cmd.Op == opPlace {
			placed = append(placed, cmd.SandboxID)
		}
	}
	if !slices.Equal(placed, []string{"sb-deleted", "sb-young"}) {
		t.Fatalf("opPlace sent for %v, want [sb-deleted sb-young]", placed)
	}
}
