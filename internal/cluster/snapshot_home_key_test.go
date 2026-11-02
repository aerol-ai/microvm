package cluster

import (
	"strings"
	"testing"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/docker"
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

// A committed snapshot's home is also recorded under its image tag, so a create
// naming the tag can find the node that holds it. Every spelling of the tag maps
// to one key, the key never collides with a name key, and the two keys live
// side by side in the index: forgetting one leaves the other.
func TestSnapshotImageHomeKey(t *testing.T) {
	tag := docker.SnapshotImageTagForOwner("tenant-a", "prod")
	for _, tc := range []struct {
		image string
		want  string
	}{
		{image: tag, want: tag},
		{image: "docker.io/" + tag, want: tag},
		{image: strings.TrimSuffix(tag, ":latest"), want: tag},
		{image: "prod", want: ""},
		{image: "ghcr.io/" + tag, want: ""},
		{image: docker.BuiltImageNamespace + "/abc:latest", want: ""},
		{image: "", want: ""},
	} {
		if got := SnapshotImageHomeKey(tc.image); got != tc.want {
			t.Errorf("SnapshotImageHomeKey(%q) = %q, want %q", tc.image, got, tc.want)
		}
	}
	if docker.SnapshotImageTagForOwner("tenant-b", "prod") == tag {
		t.Fatal("two owners' same-named snapshots share one tag, so the tag key is not tenant-scoped")
	}

	fsm := newPlacementFSM()
	nameKey := SnapshotHomeKey("tenant-a", "prod")
	tagKey := SnapshotImageHomeKey(tag)
	if nameKey == tagKey {
		t.Fatalf("name key and tag key collide: %q", nameKey)
	}
	for i, key := range []string{nameKey, tagKey} {
		if got := fsm.Apply(&raft.Log{Index: uint64(i + 1), Data: mustEncode(t, registerSnapCmd(key, "node-1"))}); got != nil {
			t.Fatalf("register %q: %v", key, got)
		}
	}
	if got := fsm.Apply(&raft.Log{Index: 3, Data: mustEncode(t, command{Op: opForgetSnapshotNode, SnapshotName: nameKey})}); got != nil {
		t.Fatalf("forget name key: %v", got)
	}
	if node, ok := fsm.snapshotHomeNode(tagKey); !ok || node != "node-1" {
		t.Fatalf("tag key home after forgetting the name key = %q,%v, want node-1,true", node, ok)
	}
}
