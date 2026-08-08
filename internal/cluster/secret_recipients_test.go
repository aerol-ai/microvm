package cluster

import (
	"testing"
)

func TestSelectSecretRecipientsDeterministic(t *testing.T) {
	candidates := []Member{
		{NodeID: "node-z"},
		{NodeID: "node-a"},
		{NodeID: "node-m"},
		{NodeID: "owner"},
	}
	got := SelectSecretRecipients(candidates, "owner", 2)
	want := []string{"owner", "node-a", "node-m"}
	if len(got) != len(want) {
		t.Fatalf("SelectSecretRecipients = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SelectSecretRecipients[%d] = %q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

func TestSelectSecretRecipientsSmallCluster(t *testing.T) {
	candidates := []Member{{NodeID: "a"}, {NodeID: "b"}}
	got := SelectSecretRecipients(candidates, "a", 2)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("small cluster = %v, want [a b]", got)
	}
}

func TestSelectSecretRecipientsEmpty(t *testing.T) {
	if got := SelectSecretRecipients(nil, "owner", 2); got != nil {
		t.Fatalf("empty candidates = %v, want nil", got)
	}
	if got := SelectSecretRecipients([]Member{{NodeID: "a"}}, "", 2); got != nil {
		t.Fatalf("empty owner = %v, want nil", got)
	}
}

func TestSelectSecretRecipientsOwnerFirstStable(t *testing.T) {
	// Same inputs twice must yield identical output (sort stability).
	candidates := []Member{{NodeID: "c"}, {NodeID: "b"}, {NodeID: "a"}, {NodeID: "owner"}}
	a := SelectSecretRecipients(candidates, "owner", 3)
	b := SelectSecretRecipients(candidates, "owner", 3)
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
