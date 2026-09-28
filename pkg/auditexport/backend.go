// Package auditexport ships already-redacted, hash-chained audit records
// off-node through pluggable backends. The split is deliberately the one
// kube-apiserver uses: the consensus store (Raft here, etcd there) holds only
// live state, a bounded local buffer absorbs bursts, and log/webhook-style
// backends carry history asynchronously. Nothing in this package runs on a
// sandbox request path; the service's cursor-tailer calls Export from one
// goroutine after it has released the audit file lock.
package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Batch is one export unit. Events are complete JSONL records exactly as they
// sit in secrets.jsonl (event_hash/prev_hash included), so a receiver can
// re-verify the chain. BatchID is deterministic over (node, offset, events)
// and doubles as the idempotency key: delivery is at-least-once and a re-send
// after a crash carries the same id.
type Batch struct {
	NodeID    string
	BatchID   string
	Offset    string
	Events    []json.RawMessage
	ShippedAt time.Time
}

// Backend is the connector contract. Export must be safe to call again with
// the same Batch (idempotent receivers dedupe on BatchID or event_id).
// Healthy reports the last observed outcome; it must not perform network I/O
// of its own, so a health check can never add a second failure mode.
type Backend interface {
	Name() string
	Export(ctx context.Context, batch Batch) error
	Healthy(ctx context.Context) error
}

// Factory builds a Backend from validated configuration.
type Factory func(cfg Config) (Backend, error)

var (
	// ErrTemporary marks a failure the tailer should retry with backoff
	// (network, 429, 5xx). Anything else is retried too — the local buffer is
	// never dropped — but is counted as a permanent failure for alerting.
	ErrTemporary = errors.New("audit export: temporary failure")
	// ErrNotImplemented is returned for a registered seam with no
	// implementation wired (the bus backend without a publisher).
	ErrNotImplemented = errors.New("audit export: backend not implemented")
	// ErrUnknownBackend is returned by Open for a name nothing registered.
	ErrUnknownBackend = errors.New("audit export: unknown backend")
	// ErrOnNodeBackend is returned when enterprise mode selects a backend
	// that never leaves the node (noop / stdout / file). See IsOffNodeBackend.
	ErrOnNodeBackend = errors.New("audit export: enterprise mode requires an off-node backend (webhook, s3, bus) or a wired controlplane.AuditExporter")
)

var registry = struct {
	mu        sync.RWMutex
	factories map[string]Factory
}{factories: map[string]Factory{}}

// Register adds a backend factory under name. Duplicate registration is a
// programming error and panics at init so it cannot be masked at runtime.
func Register(name string, f Factory) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || f == nil {
		panic("auditexport: Register requires a name and a factory")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, dup := registry.factories[name]; dup {
		panic(fmt.Sprintf("auditexport: backend %q registered twice", name))
	}
	registry.factories[name] = f
}

// Names lists registered backends, sorted, for error messages and docs.
func Names() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]string, 0, len(registry.factories))
	for name := range registry.factories {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Open validates cfg and builds the named backend.
func Open(cfg Config) (Backend, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	registry.mu.RLock()
	f, ok := registry.factories[cfg.Backend]
	registry.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q (registered: %s)", ErrUnknownBackend, cfg.Backend, strings.Join(Names(), ", "))
	}
	return f(cfg)
}

// IsNoop reports whether b discards everything, so callers can decide whether
// an enterprise "must export" requirement is satisfied.
func IsNoop(b Backend) bool {
	if b == nil {
		return true
	}
	_, ok := b.(*noopBackend)
	return ok
}

// Temporary wraps err as retry-with-backoff.
func Temporary(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrTemporary, err)
}

// IsTemporary reports whether err was marked retryable.
func IsTemporary(err error) bool { return errors.Is(err, ErrTemporary) }

// EncodeNDJSON renders a batch as newline-delimited JSON, the wire form every
// backend shares (webhook body, file line set, S3 object).
func EncodeNDJSON(batch Batch) []byte {
	size := 0
	for _, raw := range batch.Events {
		size += len(raw) + 1
	}
	out := make([]byte, 0, size)
	for _, raw := range batch.Events {
		out = append(out, raw...)
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			out = append(out, '\n')
		}
	}
	return out
}
