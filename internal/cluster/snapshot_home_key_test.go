package cluster

import (
	"testing"

	"github.com/hashicorp/raft"
)

// Two tenants' same-named snapshots on different nodes must keep separate home
// entries, so one tenant's registration cannot redirect (hijack) the other's
// snapshot routing (#11). The index is keyed by SnapshotHomeKey(owner, name).
func TestFSMSnapshotHomeKeyIsolatesOwners(t *testing.T) {
	if SnapshotHomeKey("", "prod") != "prod" {
		t.Fatalf("operator key = %q, want bare name", SnapshotHomeKey("", "prod"))
	}
	if SnapshotHomeKey("a", "prod") == SnapshotHomeKey("b", "prod") {
		t.Fatal("two owners' keys for the same name collide")
	}

	fsm := newPlacementFSM()
	keyA := SnapshotHomeKey("tenant-a", "prod")
	keyB := SnapshotHomeKey("tenant-b", "prod")

	if got := fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, registerSnapCmd(keyA, "node-1"))}); got != nil {
		t.Fatalf("register A: %v", got)
	}
	// B registering the same user-facing name on another node must NOT overwrite A.
	if got := fsm.Apply(&raft.Log{Index: 2, Data: mustEncode(t, registerSnapCmd(keyB, "node-2"))}); got != nil {
		t.Fatalf("register B: %v", got)
	}
	if node, ok := fsm.snapshotHomeNode(keyA); !ok || node != "node-1" {
		t.Fatalf("A home = %q,%v after B registered 'prod'; want node-1,true (no hijack)", node, ok)
	}
	if node, ok := fsm.snapshotHomeNode(keyB); !ok || node != "node-2" {
		t.Fatalf("B home = %q,%v, want node-2,true", node, ok)
	}
	// Forgetting B leaves A intact.
	if got := fsm.Apply(&raft.Log{Index: 3, Data: mustEncode(t, command{Op: opForgetSnapshotNode, SnapshotName: keyB})}); got != nil {
		t.Fatalf("forget B: %v", got)
	}
	if node, ok := fsm.snapshotHomeNode(keyA); !ok || node != "node-1" {
		t.Fatalf("A home after forgetting B = %q,%v; want node-1,true", node, ok)
	}
}
