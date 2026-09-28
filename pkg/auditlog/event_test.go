package auditlog

import "testing"

func TestNewEventIDUniqueAndEnsureStable(t *testing.T) {
	seen := make(map[string]struct{}, 10_000)
	for i := 0; i < 10_000; i++ {
		id := NewEventID("node-a")
		if id == "" {
			t.Fatal("empty event id")
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate event id %q", id)
		}
		seen[id] = struct{}{}
	}

	ev := Event{NodeID: "node-a"}
	EnsureEventID(&ev)
	first := ev.EventID
	EnsureEventID(&ev)
	if ev.EventID != first {
		t.Fatalf("EnsureEventID replaced %q with %q", first, ev.EventID)
	}
}
