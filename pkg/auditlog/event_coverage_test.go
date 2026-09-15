package auditlog

import (
	"strings"
	"testing"
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
