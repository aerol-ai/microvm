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
	// OwnerRef is the tenant account the sandbox belonged to when the event
	// was recorded. It makes an exported record self-describing downstream
	// and lets a node authorize a post-delete read from the evidence itself,
	// without consulting Raft. Empty for operator-owned sandboxes. Being
	// omitempty, records written before the field existed hash identically.
	OwnerRef string `json:"owner_ref,omitempty"`
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
	// Caller is who caused the record (plans/identity-and-access.md §5.8).
	// It stays LAST and omitempty: the hash covers json.Marshal of this
	// struct in field order, so moving it, or writing it without omitempty,
	// would change the hash of every record written before it existed. A nil
	// pointer is omitted, so those records re-marshal byte for byte and
	// still verify. A binary that predates the field drops it on decode and
	// computes a different hash, which is why writers gate it on every
	// cluster member advertising support (internal/cluster's audit caller
	// gate) and why rolling back below the release that writes it fails
	// strict boot verification.
	Caller *Caller `json:"caller,omitempty"`
	// Request describes the API call behind a kind "api" record (§5.9).
	// Same rules as Caller, for the same reason: appended after it, a nil
	// pointer omitted so every record written before it existed re-marshals
	// byte for byte, never reordered, and written only behind the same
	// cluster gate.
	Request *Request `json:"request,omitempty"`
	// IdentityConfig is set only on an identity_config record: what an
	// identity-file change did to who can sign in and with which role
	// (plans/identity-and-access.md §5.5, CEO review D20). Appended after
	// Request and omitempty for the same reason Caller is: every older record
	// re-marshals byte for byte. Its record kind is behind the same cluster
	// write gate as Caller.
	IdentityConfig *IdentityConfig `json:"identity_config,omitempty"`
}

// KindIdentityConfig is the record a node writes when the identity file it
// enforces changes, at reload or at boot (D20).
const KindIdentityConfig = "identity_config"

// IdentityConfig is an identity-file change as evidence. The file cannot say
// who edited it; the hashes point at the exact file versions, and the
// operator's own config history (git, Ansible) names the author. The lists
// hold canonical one-line forms, never secrets: issuers ("name url
// audiences=…"), bindings ("okta group=platform-admins -> admin/*") and
// deny-list subjects ("okta:00u1ab"). Field order is part of the hash:
// append only.
type IdentityConfig struct {
	// OldHash is empty for the first file this node ever recorded.
	OldHash string `json:"old_hash,omitempty"`
	NewHash string `json:"new_hash"`
	// BindingsAdded and BindingsRemoved diff the binding lists as sets.
	// Bindings are first-match, so a pure reorder changes who gets which
	// role without adding or removing a line: Reordered says so.
	BindingsAdded   []string `json:"bindings_added,omitempty"`
	BindingsRemoved []string `json:"bindings_removed,omitempty"`
	Reordered       bool     `json:"reordered,omitempty"`
	DenyAdded       []string `json:"deny_added,omitempty"`
	DenyRemoved     []string `json:"deny_removed,omitempty"`
	IssuersAdded    []string `json:"issuers_added,omitempty"`
	IssuersRemoved  []string `json:"issuers_removed,omitempty"`
	// Omitted counts diff lines left out to keep the record far below the
	// audit line cap (MaxLineBytes); the hashes still identify both files.
	Omitted int `json:"omitted,omitempty"`
}

// Caller names who made the request behind a record, or which daemon
// subsystem acted when no request did. Kind and ID are the principal
// (controlplane.Principal: "operator", "node:n3", "tok_…", "oidc:…",
// "controlplane:…", "system:reconcile"); Name is the display name when it
// adds something to ID (an email, a token name); Team is the team a
// team-bound credential acted for; Via is the edge node that forwarded the
// request to the node that wrote the record, taken from the verified mTLS
// peer, never from a header. Field order is part of the hash: append only.
type Caller struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Team string `json:"team,omitempty"`
	Via  string `json:"via,omitempty"`
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
