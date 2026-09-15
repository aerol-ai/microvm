package auditexport

import (
	"expvar"
	"fmt"
	"sync"
	"time"
)

// Metrics are keyed by backend name so one dashboard row per connector reads
// naturally; expvar maps stand in for labels.
var (
	exportBatchesTotal  = expvar.NewMap("aerolvm_audit_export_batches_total")
	exportEventsTotal   = expvar.NewMap("aerolvm_audit_export_events_total")
	exportFailuresTotal = expvar.NewMap("aerolvm_audit_export_failures_total")
	exportBackendHealth = expvar.NewMap("aerolvm_audit_export_backend_healthy")
	exportLastSuccess   = expvar.NewMap("aerolvm_audit_export_last_success_unix")
)

// health is the observed-outcome tracker every network backend embeds.
// Healthy never probes; it reports the last Export result.
type health struct {
	name    string
	mu      sync.Mutex
	lastErr error
	streak  int
	lastOK  time.Time
}

func newHealth(name string) *health {
	h := &health{name: name}
	exportBackendHealth.Set(name, new(expvar.Int))
	h.markOK(0)
	return h
}

func (h *health) markOK(events int) {
	h.mu.Lock()
	h.lastErr, h.streak, h.lastOK = nil, 0, time.Now().UTC()
	h.mu.Unlock()
	if events > 0 {
		exportBatchesTotal.Add(h.name, 1)
		exportEventsTotal.Add(h.name, int64(events))
	}
	if v, ok := exportBackendHealth.Get(h.name).(*expvar.Int); ok {
		v.Set(1)
	}
	if events > 0 {
		last := new(expvar.Int)
		last.Set(h.lastOK.Unix())
		exportLastSuccess.Set(h.name, last)
	}
}

func (h *health) markErr(err error) error {
	h.mu.Lock()
	h.lastErr = err
	h.streak++
	h.mu.Unlock()
	exportFailuresTotal.Add(h.name, 1)
	if v, ok := exportBackendHealth.Get(h.name).(*expvar.Int); ok {
		v.Set(0)
	}
	return err
}

// Healthy returns the last error while a failure streak is open.
func (h *health) Healthy() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastErr == nil {
		return nil
	}
	return fmt.Errorf("%s: %d consecutive export failures, last: %w", h.name, h.streak, h.lastErr)
}
