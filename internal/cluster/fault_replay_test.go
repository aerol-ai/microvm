package cluster

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Replay determinism (invariant I5): applying the log gives the same state
// on every server, whenever it is applied. A scripted run covers every
// placement op the create, failover and delete paths use; then one server
// restarts and replays its whole log, and another restarts from a Raft
// snapshot plus the log after it. Every live server must then hold the same
// replicated state at the same log index.
//
// The comparison is semantic, not byte for byte: Persist builds the rows
// from a Go map and gob writes maps in iteration order, so two identical
// states encode differently. dumpFSM sorts the rows and compares decoded
// values, plus every placement joined with its recovery payload.
func TestClusterFaultReplayDeterminism(t *testing.T) {
	t.Skip("needs PR #1001 (C1): the FSM decides with the applying server's clock, so a replay later disagrees")
	fc := newFaultCluster(t, "rpl", 3)
	s1, s2, s3 := fc.servers[0], fc.servers[1], fc.servers[2]
	for _, s := range fc.servers {
		fc.setLease(s.id, staticCapacity(100))
	}
	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64, DiskGB: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	do := func(op func(context.Context) error) error {
		return retryLeaderChange(ctx, 50*time.Millisecond, op)
	}
	must := func(what string, op func(context.Context) error) {
		t.Helper()
		if err := do(op); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	target := func(s *faultServer) PlacementTarget {
		c := s.cluster()
		return PlacementTarget{NodeID: c.nodeID, APIURL: c.apiURL, DataPlaneHost: c.dataPlaneHost}
	}
	reserve := func(via, owner *faultServer, id, inc string, ttl time.Duration) error {
		return do(func(ctx context.Context) error {
			return via.cluster().ReserveOnTarget(ctx, id, target(owner), spec, PlacementSecrets{IncarnationID: inc}, ttl)
		})
	}
	promote := func(owner *faultServer, id, inc string) {
		must("promote "+id, func(ctx context.Context) error {
			return owner.cluster().RecordPlacement(ctx, id, nil, PlacementSecrets{IncarnationID: inc})
		})
	}
	incs := map[string]string{}
	for _, id := range []string{"a", "b", "c", "c2", "d", "e", "e2", "f"} {
		incs[id] = mustIncarnation(t)
	}

	// Full creates through a router that is not the owner.
	if err := reserve(s3, s2, "sb-rpl-a", incs["a"], time.Minute); err != nil {
		t.Fatal(err)
	}
	promote(s2, "sb-rpl-a", incs["a"])
	if err := reserve(s1, s3, "sb-rpl-b", incs["b"], time.Minute); err != nil {
		t.Fatal(err)
	}
	promote(s3, "sb-rpl-b", incs["b"])
	// An abandoned create, overwritten once it expires.
	if err := reserve(s1, s2, "sb-rpl-c", incs["c"], time.Second); err != nil {
		t.Fatal(err)
	}
	// A placement written directly, as the boot-time ownership replay does.
	must("place sb-rpl-d", func(ctx context.Context) error {
		return s1.cluster().RecordPlacement(ctx, "sb-rpl-d", spec, PlacementSecrets{IncarnationID: incs["d"]})
	})
	// The C1 hazard: a reserve the leader refuses because the first one has
	// not expired. The refused entry stays in the log; a server that applies
	// it after the expiry must refuse it too.
	if err := reserve(s3, s2, "sb-rpl-e", incs["e"], 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// (Owner s1, which nothing below orphans: an orphan of the owner would
	// drop the wrongly applied reservation again and hide the divergence.)
	if err := reserve(s3, s1, "sb-rpl-e", incs["e2"], time.Minute); !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("second owner's reserve of a live reservation = %v, want ErrReservationConflict", err)
	}
	// Failover and the false-positive recovery: reassign, orphan, claim.
	must("reassign sb-rpl-a", func(ctx context.Context) error {
		return fc.leader().cluster().ReassignPlacement(ctx, "sb-rpl-a", target(s3))
	})
	must("orphan "+s3.id, func(ctx context.Context) error { return fc.leader().cluster().orphanOwner(ctx, s3.id) })
	must("claim sb-rpl-b", func(ctx context.Context) error {
		return s3.cluster().ClaimOrphan(ctx, "sb-rpl-b", nil, PlacementSecrets{IncarnationID: incs["b"]})
	})
	// A delete leaves its post-delete record (the C2 fence reads it).
	must("delete sb-rpl-d", func(ctx context.Context) error {
		return s1.cluster().DeletePlacementExact(ctx, "sb-rpl-d", s1.id, incs["d"])
	})
	must("drain "+s1.id, func(ctx context.Context) error { return s1.cluster().SetNodeDrainState(ctx, s1.id, true) })
	must("undrain "+s1.id, func(ctx context.Context) error { return s1.cluster().SetNodeDrainState(ctx, s1.id, false) })
	// Overwrite the expired abandoned reservation from another owner.
	for p, ok := s1.cluster().PlacementOf("sb-rpl-c"); ok && p.IsReserved() && time.Now().Unix() <= p.ExpiresUnix; p, ok = s1.cluster().PlacementOf("sb-rpl-c") {
		time.Sleep(100 * time.Millisecond)
	}
	if err := reserve(s2, s3, "sb-rpl-c", incs["c2"], time.Minute); err != nil {
		t.Fatal(err)
	}

	before := fc.requireIdenticalServers("after the scripted run")

	// Replay the whole log: stop s3 long enough that it re-applies every
	// entry at a later second than the leader did, and after sb-rpl-e's
	// first reservation expired.
	fc.restartServer(s3, 2500*time.Millisecond)
	after := fc.requireIdenticalServers("after " + s3.id + " replayed its log")
	if len(after) != len(before) {
		t.Fatalf("%d live servers after the restart, %d before", len(after), len(before))
	}

	// Restore path: s2 restarts from a Raft snapshot plus the entries after
	// it, which rebuilds every derived index from snapshot rows.
	if err := s2.cluster().raft.raft.Snapshot().Error(); err != nil {
		t.Fatalf("snapshot %s: %v", s2.id, err)
	}
	if err := reserve(s3, s1, "sb-rpl-f", incs["f"], time.Minute); err != nil {
		t.Fatal(err)
	}
	promote(s1, "sb-rpl-f", incs["f"])
	fc.restartServer(s2, time.Second)
	fc.requireIdenticalServers("after " + s2.id + " restored a snapshot and replayed the rest")
	fc.requireInvariants("after both restarts")

	// The refused second reservation must not have won anywhere.
	for _, s := range fc.up() {
		if p, ok := s.cluster().PlacementOf("sb-rpl-e"); ok && strings.TrimSpace(p.IncarnationID) == incs["e2"] {
			t.Errorf("%s applied the refused reserve of sb-rpl-e: %+v", s.id, p)
		}
	}
}
