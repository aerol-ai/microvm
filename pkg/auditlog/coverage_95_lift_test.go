package auditlog

import (
	"strings"
	"testing"
	"time"
)

func TestEnsureEventIDGuardsAndActorFallback(t *testing.T) {
	EnsureEventID(nil)

	already := Event{EventID: "ae-existing", NodeID: "node-a"}
	EnsureEventID(&already)
	if already.EventID != "ae-existing" {
		t.Fatalf("replaced existing id: %q", already.EventID)
	}

	viaActor := Event{Actor: "actor-node"}
	EnsureEventID(&viaActor)
	if viaActor.EventID == "" || !strings.HasPrefix(viaActor.EventID, "ae-") {
		t.Fatalf("actor fallback id = %q", viaActor.EventID)
	}

	emptyNode := Event{}
	EnsureEventID(&emptyNode)
	if emptyNode.EventID == "" {
		t.Fatal("empty node/actor produced no event id")
	}
}

func TestMintCapabilityDefaultExpiryAndParseGuards(t *testing.T) {
	cap, err := MintEgressCapability("key", "sb-1", "inc-1", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseAndVerifyEgressCapability("key", cap, time.Time{}); err != nil {
		t.Fatalf("zero now should use wall clock: %v", err)
	}
	if _, _, err := ParseAndVerifyEgressCapability("", cap, time.Now().UTC()); err == nil {
		t.Fatal("expected missing capability error")
	}
	if _, _, err := ParseAndVerifyEgressCapability("key", "too|few|parts", time.Now().UTC()); err == nil {
		t.Fatal("expected malformed capability")
	}
	if _, _, err := ParseAndVerifyEgressCapability("key", "sb|inc|notanint|mac", time.Now().UTC()); err == nil {
		t.Fatal("expected malformed expiry")
	}
	expired, err := MintEgressCapability("key", "sb-1", "inc-1", time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseAndVerifyEgressCapability("key", expired, time.Now().UTC()); err == nil {
		t.Fatal("expected expired capability")
	}
}
