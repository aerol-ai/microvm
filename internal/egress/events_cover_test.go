package egress

import "testing"

// TestEventHubRequeueNothing: a delivery that failed before taking anything
// requeues nothing and counts no drops; TakeAllForTest drains the rest.
func TestEventHubRequeueNothing(t *testing.T) {
	h := NewEventHub(2)
	h.Publish(Event{Reason: "a"})
	h.requeue(nil)
	if h.Len() != 1 || h.Dropped() != 0 {
		t.Fatalf("len=%d dropped=%d", h.Len(), h.Dropped())
	}
	if got := h.TakeAllForTest(); len(got) != 1 || got[0].Reason != "a" || h.Len() != 0 {
		t.Fatalf("drained %+v, left %d", got, h.Len())
	}
}
