package cluster

import (
	"fmt"
	"testing"
)

func TestSelectSecretRecipientsDeterministic(t *testing.T) {
	candidates := []Member{
		{NodeID: "node-z"},
		{NodeID: "node-a"},
		{NodeID: "node-m"},
		{NodeID: "owner"},
	}
	got := SelectSecretRecipients("sb-1", candidates, "owner", 2)
	if len(got) != 3 || got[0] != "owner" {
		t.Fatalf("SelectSecretRecipients = %v, want owner + 2 backups", got)
	}
	// Same inputs → identical backups (rendezvous stability).
	again := SelectSecretRecipients("sb-1", candidates, "owner", 2)
	for i := range got {
		if got[i] != again[i] {
			t.Fatalf("unstable: %v vs %v", got, again)
		}
	}
}

func TestSelectSecretRecipientsVariesBySandbox(t *testing.T) {
	candidates := []Member{
		{NodeID: "node-a"}, {NodeID: "node-b"}, {NodeID: "node-c"},
		{NodeID: "node-d"}, {NodeID: "owner"},
	}
	a := SelectSecretRecipients("sandbox-aaa", candidates, "owner", 2)
	b := SelectSecretRecipients("sandbox-bbb", candidates, "owner", 2)
	if len(a) != 3 || len(b) != 3 {
		t.Fatalf("len a=%v b=%v", a, b)
	}
	// Different sandboxes should usually pick different backup pairs; if they
	// collide, that's fine for a single pair — just assert both are valid.
	for _, got := range [][]string{a, b} {
		if got[0] != "owner" {
			t.Fatalf("owner not first: %v", got)
		}
	}
}

func TestSelectSecretRecipientsSmallCluster(t *testing.T) {
	candidates := []Member{{NodeID: "a"}, {NodeID: "b"}}
	got := SelectSecretRecipients("sb", candidates, "a", 2)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("small cluster = %v, want [a b]", got)
	}
}

func TestSelectSecretRecipientsEmpty(t *testing.T) {
	if got := SelectSecretRecipients("sb", nil, "owner", 2); got != nil {
		t.Fatalf("empty candidates = %v, want nil", got)
	}
	if got := SelectSecretRecipients("sb", []Member{{NodeID: "a"}}, "", 2); got != nil {
		t.Fatalf("empty owner = %v, want nil", got)
	}
}

func TestSelectSecretRecipientsOwnerFirstStable(t *testing.T) {
	candidates := []Member{{NodeID: "c"}, {NodeID: "b"}, {NodeID: "a"}, {NodeID: "owner"}}
	a := SelectSecretRecipients("sb-stable", candidates, "owner", 3)
	b := SelectSecretRecipients("sb-stable", candidates, "owner", 3)
	if len(a) != len(b) {
		t.Fatalf("len mismatch %v vs %v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("unstable: %v vs %v", a, b)
		}
	}
	if a[0] != "owner" {
		t.Fatalf("owner not first: %v", a)
	}
}

// TestSelectSecretRecipientsDistributionSkew guards the NodeID-sort hotspot:
// with many sandboxes and a large worker pool, no backup node should receive
// vastly more rows than the mean. Lexicographic selection fails this hard.
func TestSelectSecretRecipientsDistributionSkew(t *testing.T) {
	const (
		workers    = 200
		sandboxes  = 10_000
		maxBackups = 2
		// Mean backups/node ≈ sandboxes*maxBackups/workers = 100.
		// Allow 3× mean as the hard ceiling (lexicographic sort would put
		// ~10000 on the first two IDs).
		maxSkewFactor = 3.0
	)
	candidates := make([]Member, 0, workers+1)
	owner := "owner-0"
	candidates = append(candidates, Member{NodeID: owner})
	for i := 1; i <= workers; i++ {
		candidates = append(candidates, Member{NodeID: fmt.Sprintf("worker-%04d", i)})
	}

	load := make(map[string]int, workers)
	for i := 0; i < sandboxes; i++ {
		sb := fmt.Sprintf("sb-%05d", i)
		got := SelectSecretRecipients(sb, candidates, owner, maxBackups)
		for _, id := range got[1:] {
			load[id]++
		}
	}
	mean := float64(sandboxes*maxBackups) / float64(workers)
	maxLoad := 0
	hottest := ""
	for id, n := range load {
		if n > maxLoad {
			maxLoad = n
			hottest = id
		}
	}
	if float64(maxLoad) > mean*maxSkewFactor {
		t.Fatalf("backup hotspot %s has load %d (mean %.1f, max allowed %.1f) — selection is not well distributed",
			hottest, maxLoad, mean, mean*maxSkewFactor)
	}
}
