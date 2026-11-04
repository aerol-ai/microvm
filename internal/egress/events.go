package egress

import (
	"sync"
	"sync/atomic"
)

// DefaultAuditBuffer is the gateway-side event ring size
// (SB_EGRESS_AUDIT_BUFFER).
const DefaultAuditBuffer = 10000

// EventHub buffers gateway events (audit decisions, heartbeats) for sandboxd,
// which writes them into the hash-chained audit log (spec review 1, P1-14).
// The gateway is its own process, so events cross the UDS: while sandboxd is
// away they queue in a bounded ring (drop-oldest, counted) and drain on
// reconnect.
type EventHub struct {
	mu      sync.Mutex
	buf     []Event
	max     int
	notify  chan struct{}
	dropped atomic.Uint64
}

// NewEventHub returns a hub holding at most max events (DefaultAuditBuffer if
// max <= 0).
func NewEventHub(max int) *EventHub {
	if max <= 0 {
		max = DefaultAuditBuffer
	}
	return &EventHub{max: max, notify: make(chan struct{}, 1)}
}

// Publish queues an event, dropping the oldest when full.
func (h *EventHub) Publish(e Event) {
	h.mu.Lock()
	if len(h.buf) >= h.max {
		h.buf = h.buf[1:]
		h.dropped.Add(1)
	}
	h.buf = append(h.buf, e)
	h.mu.Unlock()
	select {
	case h.notify <- struct{}{}:
	default:
	}
}

// Dropped is aerolvm_egress_audit_dropped_total on the gateway side.
func (h *EventHub) Dropped() uint64 { return h.dropped.Load() }

// Len returns the queued event count.
func (h *EventHub) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.buf)
}

// take removes and returns up to n queued events.
func (h *EventHub) take(n int) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > len(h.buf) {
		n = len(h.buf)
	}
	out := append([]Event(nil), h.buf[:n]...)
	h.buf = h.buf[n:]
	return out
}

// requeue puts events back at the front after a failed delivery, keeping the
// ring bound.
func (h *EventHub) requeue(events []Event) {
	if len(events) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	merged := append(append([]Event(nil), events...), h.buf...)
	if over := len(merged) - h.max; over > 0 {
		merged = merged[over:]
		h.dropped.Add(uint64(over))
	}
	h.buf = merged
}

// TakeAllForTest drains the hub (tests in other packages).
func (h *EventHub) TakeAllForTest() []Event { return h.take(h.Len()) }
