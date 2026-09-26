package cluster

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// The post-delete audit index is a bounded routing stub, never history:
// capped by the command's AuditIndexMax (oldest log index evicted first),
// pruned from the expiry ordering in O(expired), and never retained when the
// expiry is zero. These are the regression tests for "ACL not in FSM".

func placeAndDelete(t *testing.T, fsm *placementFSM, idx *uint64, sandboxID, owner string, expires, indexMax int64) {
	t.Helper()
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: sandboxID, OwnerNodeID: "node-a", OwnerRef: owner, IncarnationID: "inc-" + sandboxID})
	*idx++
	if got := fsm.Apply(&raft.Log{Index: *idx, Data: place}); got != nil {
		t.Fatalf("place %s: %v", sandboxID, got)
	}
	del, _ := encodeCommand(command{Op: opDelete, SandboxID: sandboxID, ExpectedIncarnationID: "inc-" + sandboxID, ExpiresUnix: expires, AuditIndexMax: indexMax})
	*idx++
	if got := fsm.Apply(&raft.Log{Index: *idx, Data: del}); got != nil {
		t.Fatalf("delete %s: %v", sandboxID, got)
	}
}

func retainedIDs(fsm *placementFSM) map[string]bool {
	fsm.mu.RLock()
	defer fsm.mu.RUnlock()
	out := map[string]bool{}
	for _, acl := range fsm.auditACLs {
		out[acl.SandboxID] = true
	}
	return out
}

func TestFSMAuditIndexBoundedByCommandCap(t *testing.T) {
	fsm := newPlacementFSM()
	var idx uint64
	far := time.Now().Add(time.Hour).Unix()
	for i := range 12 {
		placeAndDelete(t, fsm, &idx, fmt.Sprintf("sb-%02d", i), "tenant", far, 5)
	}
	got := retainedIDs(fsm)
	if len(got) != 5 {
		t.Fatalf("retained %d stubs, want cap 5: %v", len(got), got)
	}
	for i := range 12 {
		id := fmt.Sprintf("sb-%02d", i)
		_, ok := fsm.auditACLForSandbox(id, "", far-1)
		if i < 7 && (ok || got[id]) {
			t.Fatalf("%s should have been evicted (oldest first)", id)
		}
		if i >= 7 && (!ok || !got[id]) {
			t.Fatalf("%s should be retained", id)
		}
	}
	fsm.mu.RLock()
	if fsm.auditACLByVersion.Len() != 5 || fsm.auditACLByExpiry.Len() != 5 || len(fsm.auditACLLatest) != 5 || len(fsm.auditACLBySandbox) != 5 {
		t.Fatalf("derived indexes out of sync: ver=%d exp=%d latest=%d bysb=%d", fsm.auditACLByVersion.Len(), fsm.auditACLByExpiry.Len(), len(fsm.auditACLLatest), len(fsm.auditACLBySandbox))
	}
	fsm.mu.RUnlock()

	// A legacy command without a cap uses the compiled-in default.
	old := maxRetainedAuditACLs
	maxRetainedAuditACLs = 3
	t.Cleanup(func() { maxRetainedAuditACLs = old })
	placeAndDelete(t, fsm, &idx, "sb-legacy", "tenant", far, 0)
	if got := retainedIDs(fsm); len(got) != 3 || !got["sb-legacy"] {
		t.Fatalf("default cap not applied: %v", got)
	}
}

func TestFSMAuditIndexPruneIsExpiryOrderedAndZeroMeansNoRetention(t *testing.T) {
	fsm := newPlacementFSM()
	var idx uint64
	placeAndDelete(t, fsm, &idx, "sb-10", "t", 10, 0)
	placeAndDelete(t, fsm, &idx, "sb-30", "t", 30, 0)
	placeAndDelete(t, fsm, &idx, "sb-20", "t", 20, 0)
	// Zero expiry: the old code kept this forever; it must not be retained.
	placeAndDelete(t, fsm, &idx, "sb-never", "t", 0, 0)
	if got := retainedIDs(fsm); len(got) != 3 || got["sb-never"] {
		t.Fatalf("retained = %v, want exactly sb-10/20/30", got)
	}

	// Snapshot/restore must rebuild the orderings so prune still works.
	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	prune, _ := encodeCommand(command{Op: opPruneAuditACL, ExpiresUnix: 20})
	idx++
	if got := restored.Apply(&raft.Log{Index: idx, Data: prune}); got != nil {
		t.Fatalf("prune: %v", got)
	}
	if got := retainedIDs(restored); len(got) != 1 || !got["sb-30"] {
		t.Fatalf("after prune@20 retained = %v, want only sb-30", got)
	}
	if _, ok := restored.auditACLForSandbox("sb-20", "", 5); ok {
		t.Fatal("pruned stub still resolvable")
	}
	restored.mu.RLock()
	if _, ok := restored.auditACLLatest["sb-20"]; ok {
		t.Fatal("latest pointer not repaired after prune")
	}
	if restored.auditACLByExpiry.Len() != 1 || restored.auditACLByVersion.Len() != 1 {
		t.Fatalf("orderings not trimmed: exp=%d ver=%d", restored.auditACLByExpiry.Len(), restored.auditACLByVersion.Len())
	}
	restored.mu.RUnlock()
	// Idempotent: a second sweep at the same cutoff changes nothing.
	idx++
	if got := restored.Apply(&raft.Log{Index: idx, Data: prune}); got != nil {
		t.Fatalf("second prune: %v", got)
	}
	if got := retainedIDs(restored); len(got) != 1 {
		t.Fatalf("second prune changed state: %v", got)
	}
}

// A snapshot from before the connector split may carry an oversized map and
// "forever" expiries. Restore must bound both — and, because the cap is a
// streaming top-k by log index, the result must not depend on map order.
func TestFSMAuditIndexRestoreBoundsLegacySnapshotDeterministically(t *testing.T) {
	old := maxRetainedAuditACLs
	maxRetainedAuditACLs = 50
	t.Cleanup(func() { maxRetainedAuditACLs = old })

	legacy := make(map[string]AuditACL, 300)
	for i := 1; i <= 300; i++ {
		id := fmt.Sprintf("sb-%03d", i)
		exp := int64(1_000_000 + i)
		if i%10 == 0 {
			exp = 0 // "forever" under the old semantics
		}
		legacy[auditACLKey(id, "inc")] = AuditACL{SandboxID: id, IncarnationID: "inc", OwnerRef: "t", ExpiresUnix: exp, RetainedVersion: uint64(i)}
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(fsmSnapshotPayload{Version: 300, AuditACLs: legacy}); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()

	var first map[string]bool
	for round := range 5 {
		fsm := newPlacementFSM()
		if err := fsm.Restore(io.NopCloser(bytes.NewReader(raw))); err != nil {
			t.Fatalf("restore round %d: %v", round, err)
		}
		got := retainedIDs(fsm)
		if len(got) != 50 {
			t.Fatalf("round %d retained %d, want cap 50", round, len(got))
		}
		for id := range got {
			var n int
			fmt.Sscanf(id, "sb-%03d", &n)
			if n%10 == 0 {
				t.Fatalf("round %d retained a zero-expiry legacy stub %s", round, id)
			}
			if n <= 244 { // the 50 newest non-zero versions are 245..300 minus the six multiples of 10 in that range... compute directly below
				_ = n
			}
		}
		if first == nil {
			first = got
			continue
		}
		for id := range first {
			if !got[id] {
				t.Fatalf("restore is order-dependent: round %d lacks %s", round, id)
			}
		}
	}
	// The survivors are exactly the 50 highest log indexes among the non-zero
	// expiries (those not divisible by 10).
	var expect []string
	for i := 300; i >= 1 && len(expect) < 50; i-- {
		if i%10 != 0 {
			expect = append(expect, fmt.Sprintf("sb-%03d", i))
		}
	}
	for _, id := range expect {
		if !first[id] {
			t.Fatalf("expected survivor %s missing (got %v)", id, first)
		}
	}
}

func TestFSMAuditIndexReplaceOnIDReuseKeepsLatestPointer(t *testing.T) {
	fsm := newPlacementFSM()
	var idx uint64
	far := time.Now().Add(time.Hour).Unix()
	// Two lifecycles of the same sandbox id, different incarnations.
	for _, inc := range []string{"inc-1", "inc-2"} {
		place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-reuse", OwnerNodeID: "node-a", OwnerRef: "t", IncarnationID: inc})
		idx++
		if got := fsm.Apply(&raft.Log{Index: idx, Data: place}); got != nil {
			t.Fatal(got)
		}
		del, _ := encodeCommand(command{Op: opDelete, SandboxID: "sb-reuse", ExpectedIncarnationID: inc, ExpiresUnix: far})
		idx++
		if got := fsm.Apply(&raft.Log{Index: idx, Data: del}); got != nil {
			t.Fatal(got)
		}
	}
	acl, ok := fsm.auditACLForSandbox("sb-reuse", "", far-1)
	if !ok || acl.IncarnationID != "inc-2" {
		t.Fatalf("latest = %+v, %v; want inc-2", acl, ok)
	}
	if acl, ok := fsm.auditACLForSandbox("sb-reuse", "inc-1", far-1); !ok || acl.IncarnationID != "inc-1" {
		t.Fatalf("explicit older lifecycle = %+v, %v", acl, ok)
	}
	// Evicting the newer one under a cap of 1 repairs the pointer to the older.
	placeAndDelete(t, fsm, &idx, "sb-other", "t", far, 2)
	// cap 2 with 3 entries → evict the oldest (inc-1).
	if acl, ok := fsm.auditACLForSandbox("sb-reuse", "", far-1); !ok || acl.IncarnationID != "inc-2" {
		t.Fatalf("latest after eviction = %+v, %v", acl, ok)
	}
	if _, ok := fsm.auditACLForSandbox("sb-reuse", "inc-1", far-1); ok {
		t.Fatal("oldest lifecycle should have been evicted")
	}
}

func TestAuditACLExpiryUnixGraceSemantics(t *testing.T) {
	if auditACLExpiryUnix(0) != 0 || auditACLExpiryUnix(-time.Second) != 0 {
		t.Fatal("zero/negative grace must disable retention, not mean forever")
	}
	got := auditACLExpiryUnix(time.Hour)
	want := time.Now().UTC().Add(time.Hour).Unix()
	if got < want-2 || got > want+2 {
		t.Fatalf("grace expiry = %d, want ≈ %d", got, want)
	}
}
