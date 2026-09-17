package service

import (
	"testing"
)

// TestSecretOutboxPassTargetsRejoinedNode pins the rejoin narrowing. The
// backoff override exists so a returning member's obligations are retried at
// once; applying it to every row turns one member flap into a fleet-wide
// retransmit of obligations owed to peers that never left.
func TestSecretOutboxPassTargetsRejoinedNode(t *testing.T) {
	rejoin := secretOutboxPass{rejoinedNodes: map[string]struct{}{"node-b": {}}}

	if !rejoin.targetsRejoinedNode([]string{"node-a", " node-b "}) {
		t.Fatal("an obligation owed to the returning node was skipped")
	}
	if rejoin.targetsRejoinedNode([]string{"node-a", "node-c"}) {
		t.Fatal("an obligation owed only to peers that never left was retried")
	}
	if rejoin.targetsRejoinedNode(nil) {
		t.Fatal("a recipient-less row was retried on rejoin")
	}

	// A non-rejoin pass (boot, manual reconcile) still sweeps everything.
	all := secretOutboxPass{}
	if !all.targetsRejoinedNode([]string{"node-a"}) || !all.targetsRejoinedNode(nil) {
		t.Fatal("a non-rejoin pass must not filter rows")
	}
}

// TestSecretRecipientsInclude pins the same rule for the durable re-fanout
// scan, which is the expensive half: each selected row costs a peer push and
// contributes to a placement-snapshot RPC against the Raft leader.
func TestSecretRecipientsInclude(t *testing.T) {
	want := map[string]struct{}{"node-b": {}}
	if !secretRecipientsInclude([]string{"node-b"}, want) {
		t.Fatal("secret held by the returning node was skipped")
	}
	if secretRecipientsInclude([]string{"node-a", "node-c"}, want) {
		t.Fatal("secret not held by the returning node was re-fanned out")
	}
	if !secretRecipientsInclude([]string{"node-a"}, nil) {
		t.Fatal("an empty node set must select every secret (boot path)")
	}
}
