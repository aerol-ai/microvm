package auditlog

import "testing"

func TestLinkEventBuildsStableTamperEvidentChain(t *testing.T) {
	first := Event{EventID: "event-1", SandboxID: "sb-1", Result: "success"}
	LinkEvent("", &first)
	if first.PrevHash != GenesisPrevHash || first.EventHash == "" {
		t.Fatalf("first link = prev %q hash %q", first.PrevHash, first.EventHash)
	}
	if got := HashEvent(first.PrevHash, first); got != first.EventHash {
		t.Fatalf("HashEvent = %q, want %q", got, first.EventHash)
	}

	second := Event{EventID: "event-2", SandboxID: "sb-1", Result: "denied"}
	LinkEvent(first.EventHash, &second)
	if second.PrevHash != first.EventHash || second.EventHash == first.EventHash {
		t.Fatalf("second link = prev %q hash %q", second.PrevHash, second.EventHash)
	}
	tampered := second
	tampered.Result = "success"
	if got := HashEvent(tampered.PrevHash, tampered); got == second.EventHash {
		t.Fatal("tampering did not change the event hash")
	}

	// EventHash is deliberately excluded from its own digest.
	withBogusHash := second
	withBogusHash.EventHash = "bogus"
	if got := HashEvent(withBogusHash.PrevHash, withBogusHash); got != second.EventHash {
		t.Fatalf("self-hash affected digest: got %q want %q", got, second.EventHash)
	}
	LinkEvent("ignored", nil)
}

// Adding owner_ref must not change the hash of records that never carried it
// (omitempty), while a record that does carry it is bound to it.
func TestOwnerRefIsOmittedWhenEmptyAndBoundWhenSet(t *testing.T) {
	base := Event{EventID: "ae-1", SandboxID: "sb-1", Result: "success"}
	without := HashEvent(GenesisPrevHash, base)
	withEmpty := base
	withEmpty.OwnerRef = ""
	if HashEvent(GenesisPrevHash, withEmpty) != without {
		t.Fatal("empty owner_ref changed the hash of a legacy record")
	}
	withOwner := base
	withOwner.OwnerRef = "acct-1"
	if HashEvent(GenesisPrevHash, withOwner) == without {
		t.Fatal("owner_ref is not covered by the hash")
	}
}
