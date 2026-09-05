package auditlog

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Event is the shared JSONL/wire representation for secret-open and egress
// audit records. Keeping the daemon, peer transport, and WASM worker on this
// single shape prevents fields that affect pagination from drifting.
type Event struct {
	Time          time.Time `json:"time"`
	Actor         string    `json:"actor,omitempty"`
	SandboxID     string    `json:"sandbox_id,omitempty"`
	Ref           string    `json:"ref,omitempty"`
	Result        string    `json:"result"`
	Reason        string    `json:"reason,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	EventID       string    `json:"event_id,omitempty"`
	NodeID        string    `json:"node_id,omitempty"`
	Kind          string    `json:"kind,omitempty"`
	Destination   string    `json:"destination,omitempty"`
	Network       string    `json:"network,omitempty"`
	BytesIn       int64     `json:"bytes_in,omitempty"`
	BytesOut      int64     `json:"bytes_out,omitempty"`
	// IncarnationID scopes the event to a placement incarnation so post-delete
	// ACL and recreate history do not cross tenant ownership boundaries.
	IncarnationID string `json:"incarnation_id,omitempty"`
	// Dropped is set on gap markers to record how many events were coalesced
	// into this single overflow marker (lossy buffer evidence).
	Dropped int64 `json:"dropped,omitempty"`
	// PrevHash / EventHash form the local append-only hash chain used for
	// tamper detection once heads are witnessed off-node (E2b).
	PrevHash  string `json:"prev_hash,omitempty"`
	EventHash string `json:"event_hash,omitempty"`
	// WitnessedThrough is set on retention_checkpoint records to record the
	// last externally witnessed head that prune dropped (optional MVP field).
	WitnessedThrough string `json:"witnessed_through,omitempty"`
}

var fallbackSequence atomic.Uint64

// NewEventID returns a fleet-unique audit event identifier. The normal path is
// 128 bits from crypto/rand. The fallback includes node, wall clock, process,
// and a process-local sequence so audit emission remains available even if the
// host entropy source fails.
func NewEventID(nodeID string) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return "ae-" + hex.EncodeToString(raw[:])
	}
	nodeID = strings.TrimSpace(nodeID)
	return fmt.Sprintf("ae-fallback-%s-%d-%d-%d", nodeID, time.Now().UnixNano(), os.Getpid(), fallbackSequence.Add(1))
}

// EnsureEventID assigns an ID exactly once.
func EnsureEventID(ev *Event) {
	if ev == nil || strings.TrimSpace(ev.EventID) != "" {
		return
	}
	nodeID := strings.TrimSpace(ev.NodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(ev.Actor)
	}
	ev.EventID = NewEventID(nodeID)
}
