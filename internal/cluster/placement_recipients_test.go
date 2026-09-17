package cluster

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
)

// TestSelectPlacementForCreateReturnsBoundedRecipients pins the scale contract
// of the create path: the answer is a target plus a handful of recipient ids,
// never the candidate fleet. At 2,000 nodes the old shape made every create's
// control-plane response O(fleet) in bytes and allocations.
func TestSelectPlacementForCreateReturnsBoundedRecipients(t *testing.T) {
	n := NewNoop("node-self", "http://self", "")
	req := capacity.Request{CPU: 1, MemoryMB: 256, DiskGB: 1}

	target, recipients, err := n.SelectPlacementForCreate(req, "sb-1", 2)
	if err != nil {
		t.Fatalf("SelectPlacementForCreate: %v", err)
	}
	if !target.IsSelf {
		t.Fatalf("target = %+v, want self in standalone mode", target)
	}
	// Standalone has one member, so the owner is the only recipient.
	if len(recipients) != 1 || recipients[0] != "node-self" {
		t.Fatalf("recipients = %v, want [node-self]", recipients)
	}

	// A create that wants no fan-out skips selection entirely.
	if _, recipients, err := n.SelectPlacementForCreate(req, "sb-1", 0); err != nil || recipients != nil {
		t.Fatalf("no-fanout create = %v, %v; want no recipients", recipients, err)
	}
}

// TestSelectSecretRecipientsIsBoundedAndStable pins the selection itself: the
// result is owner + at most maxBackups, and it does not depend on the order
// the candidate list happened to arrive in.
func TestSelectSecretRecipientsIsBoundedAndStable(t *testing.T) {
	candidates := make([]Member, 0, 64)
	for _, id := range []string{"n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8"} {
		candidates = append(candidates, Member{NodeID: id, Alive: true})
	}
	got := SelectSecretRecipients("sb-stable", candidates, "n3", 2)
	if len(got) != 3 || got[0] != "n3" {
		t.Fatalf("recipients = %v, want owner first and 3 total", got)
	}

	reversed := make([]Member, len(candidates))
	for i, m := range candidates {
		reversed[len(candidates)-1-i] = m
	}
	if other := SelectSecretRecipients("sb-stable", reversed, "n3", 2); len(other) != len(got) {
		t.Fatalf("selection is order-sensitive: %v vs %v", got, other)
	} else {
		for i := range got {
			if got[i] != other[i] {
				t.Fatalf("selection is order-sensitive: %v vs %v", got, other)
			}
		}
	}
}
