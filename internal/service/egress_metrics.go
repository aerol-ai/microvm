package service

import (
	"expvar"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
)

// Exported egress metrics (plans/egress-domain-filtering.md P1-12, P1-15).
//
// Counters are owned by sandboxd and only ever go up. The gateway reports
// cumulative totals that reset when it restarts, so each heartbeat adds the
// delta since the previous one (a total below the last one is a restart and
// counts in full). Rate queries and alerts then survive gateway restarts,
// and the WASM and isolate mediators can add their denials to the same
// series later without fighting a reset.
//
// Gauges read the node's wired Service at scrape time.
var (
	egressDeniedTotal       = expvar.NewMap("aerolvm_egress_denied_total")
	egressDNSQueriesTotal   = expvar.NewInt("aerolvm_egress_dns_queries_total")
	egressAuditDroppedTotal = expvar.NewInt("aerolvm_egress_audit_dropped_total")
	egressAttachFailedTotal = expvar.NewInt("aerolvm_egress_attach_failed_total")
	egressLayoutLostTotal   = expvar.NewInt("aerolvm_egress_layout_lost_total")

	// activeEgressStats is the Service the gauges read: the one whose
	// gateway was wired last (one per daemon; tests wire many).
	activeEgressStats atomic.Pointer[egressCounters]
)

func init() {
	gauge := func(name string, fn func(*egressCounters) float64) {
		expvar.Publish(name, expvar.Func(func() any {
			c := activeEgressStats.Load()
			if c == nil {
				return 0
			}
			return fn(c)
		}))
	}
	gauge("aerolvm_egress_gateway_up", func(c *egressCounters) float64 {
		if c.gatewayUp.Load() {
			return 1
		}
		return 0
	})
	gauge("aerolvm_egress_gateway_sync_age_seconds", func(c *egressCounters) float64 { return ageSeconds(c.lastSync.Load()) })
	gauge("aerolvm_egress_gateway_heartbeat_age_seconds", func(c *egressCounters) float64 { return ageSeconds(c.lastHeartbeat.Load()) })
	gauge("aerolvm_egress_fqdn_sandboxes", func(c *egressCounters) float64 { return float64(c.fqdnSandboxes.Load()) })
	gauge("aerolvm_egress_held_sandboxes", func(c *egressCounters) float64 { return float64(c.held.Load()) })
	gauge("aerolvm_egress_proxy_connections", func(c *egressCounters) float64 { return float64(c.proxyConns.Load()) })
	gauge("aerolvm_egress_proxy_connections_cap", func(c *egressCounters) float64 { return float64(c.proxyConnCap.Load()) })
}

// ageSeconds is the time since a unix-nanos stamp, or -1 for "never" so a
// node that has not synced yet can't read as freshly synced.
func ageSeconds(unixNanos int64) float64 {
	if unixNanos == 0 {
		return -1
	}
	return time.Since(time.Unix(0, unixNanos)).Seconds()
}

// gatewayTotals remembers the last cumulative values a heartbeat reported,
// and which gateway process reported them.
type gatewayTotals struct {
	mu           sync.Mutex
	start        time.Time
	denied       map[string]uint64
	dnsQueries   uint64
	auditDropped uint64
}

// delta returns how much a cumulative counter grew. A smaller value is a
// restart the start stamp missed (an older gateway sends none): count it all.
func delta(now, prev uint64) uint64 {
	if now < prev {
		return now
	}
	return now - prev
}

// observeHeartbeat folds one heartbeat's cumulative totals into the exported
// counters.
func (c *egressCounters) observeHeartbeat(ev egress.Event) {
	c.totals.mu.Lock()
	defer c.totals.mu.Unlock()
	t := &c.totals
	if !ev.GatewayStart.Equal(t.start) {
		// A new gateway process: its totals started from zero.
		t.start, t.denied, t.dnsQueries, t.auditDropped = ev.GatewayStart, nil, 0, 0
	}
	if d := delta(ev.DNSQueries, t.dnsQueries); d > 0 {
		egressDNSQueriesTotal.Add(int64(d))
	}
	t.dnsQueries = ev.DNSQueries
	if d := delta(ev.AuditDropped, t.auditDropped); d > 0 {
		egressAuditDroppedTotal.Add(int64(d))
	}
	t.auditDropped = ev.AuditDropped
	c.auditDropped.Store(ev.AuditDropped)
	next := make(map[string]uint64, len(ev.Denied))
	for reason, n := range ev.Denied {
		if d := delta(n, t.denied[reason]); d > 0 {
			egressDeniedTotal.Add(reason, int64(d))
			c.denied.addN(reason, d)
		}
		next[reason] = n
	}
	t.denied = next
}

func (c *egressCounters) recordAttachFailed() {
	c.attachFailed.Add(1)
	egressAttachFailedTotal.Add(1)
}

func (c *egressCounters) recordLayoutLost() {
	c.layoutLost.Add(1)
	egressLayoutLostTotal.Add(1)
}

// EgressDenialObserver is the callback for denials decided inside sandboxd
// rather than by the gateway (the isolate egress proxy; P1-7, H5): it adds
// to aerolvm_egress_denied_total and writes the denial to the audit log
// when attribution is on. It never blocks the request path: the audit
// write is handed to a goroutine like the success observer's.
func (s *Service) EgressDenialObserver() func(sandboxID, destination, reason string) {
	return func(sandboxID, destination, reason string) {
		egressDeniedTotal.Add(reason, 1)
		if s != nil && s.cfg.EgressAttributionEnabled {
			go s.emitEgressDecision(sandboxID, "tcp", destination, false, reason)
		}
	}
}
