package service

import (
	"expvar"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
)

func expvarFloat(t *testing.T, name string) float64 {
	t.Helper()
	v := expvar.Get(name)
	if v == nil {
		t.Fatalf("%s not published", name)
	}
	f, err := strconv.ParseFloat(v.String(), 64)
	if err != nil {
		t.Fatalf("%s = %q: %v", name, v.String(), err)
	}
	return f
}

func deniedTotal(reason string) int64 {
	if v, ok := egressDeniedTotal.Get(reason).(*expvar.Int); ok {
		return v.Value()
	}
	return 0
}

// TestObserveHeartbeatDeltas: the exported counters only go up. Steady
// heartbeats add their growth, a new gateway process (new start stamp)
// counts its totals in full, and a total that shrinks without a stamp
// change (an older gateway) is treated the same way.
func TestObserveHeartbeatDeltas(t *testing.T) {
	var c egressCounters
	start := time.Unix(1000, 0)
	dns0, drop0 := egressDNSQueriesTotal.Value(), egressAuditDroppedTotal.Value()
	sni0, ip0 := deniedTotal("sni_not_allowed"), deniedTotal("ip_not_allowed")

	c.observeHeartbeat(egress.Event{GatewayStart: start, DNSQueries: 10, AuditDropped: 2, Denied: map[string]uint64{"sni_not_allowed": 3}})
	c.observeHeartbeat(egress.Event{GatewayStart: start, DNSQueries: 15, AuditDropped: 2, Denied: map[string]uint64{"sni_not_allowed": 5, "ip_not_allowed": 1}})
	if got := egressDNSQueriesTotal.Value() - dns0; got != 15 {
		t.Fatalf("dns delta = %d, want 15", got)
	}
	if got := deniedTotal("sni_not_allowed") - sni0; got != 5 {
		t.Fatalf("sni denials = %d, want 5", got)
	}
	// Gateway restart: smaller totals under a new stamp all count.
	c.observeHeartbeat(egress.Event{GatewayStart: start.Add(time.Hour), DNSQueries: 4, AuditDropped: 1, Denied: map[string]uint64{"sni_not_allowed": 2}})
	if got := egressDNSQueriesTotal.Value() - dns0; got != 19 {
		t.Fatalf("dns after restart = %d, want 19", got)
	}
	if got := deniedTotal("sni_not_allowed") - sni0; got != 7 {
		t.Fatalf("sni after restart = %d, want 7", got)
	}
	if got := egressAuditDroppedTotal.Value() - drop0; got != 3 {
		t.Fatalf("audit dropped = %d, want 3", got)
	}
	// Same stamp, smaller value: count it whole rather than going negative.
	c.observeHeartbeat(egress.Event{GatewayStart: start.Add(time.Hour), DNSQueries: 1})
	if got := egressDNSQueriesTotal.Value() - dns0; got != 20 {
		t.Fatalf("dns after shrink = %d, want 20", got)
	}
	if got := deniedTotal("ip_not_allowed") - ip0; got != 1 {
		t.Fatalf("ip denials = %d, want 1", got)
	}
	if c.denied.snapshot()["sni_not_allowed"] != 7 || c.auditDropped.Load() != 0 {
		t.Fatalf("per-service view = %v dropped=%d", c.denied.snapshot(), c.auditDropped.Load())
	}
}

// TestEgressGauges: the gauges read the wired Service, report -1 for "never
// synced", and flip with gateway reachability (EF-46).
func TestEgressGauges(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	if expvarFloat(t, "aerolvm_egress_gateway_up") != 0 {
		t.Fatal("down before the bootstrap")
	}
	if expvarFloat(t, "aerolvm_egress_gateway_sync_age_seconds") != -1 {
		t.Fatal("never synced must read -1")
	}
	svc.handleEgressEvent(t.Context(), egress.Event{Kind: "heartbeat", FQDNSandboxes: 3, ProxyConns: 9, ProxyConnCap: 16384})
	if expvarFloat(t, "aerolvm_egress_gateway_up") != 1 || expvarFloat(t, "aerolvm_egress_fqdn_sandboxes") != 3 ||
		expvarFloat(t, "aerolvm_egress_proxy_connections") != 9 || expvarFloat(t, "aerolvm_egress_proxy_connections_cap") != 16384 {
		t.Fatal("heartbeat must drive the gauges")
	}
	if age := expvarFloat(t, "aerolvm_egress_gateway_heartbeat_age_seconds"); age < 0 || age > 5 {
		t.Fatalf("heartbeat age = %v", age)
	}
	svc.egressStats.held.Store(2)
	if expvarFloat(t, "aerolvm_egress_held_sandboxes") != 2 {
		t.Fatal("held gauge")
	}
	svc.egressStats.gatewayUp.Store(false)
	if expvarFloat(t, "aerolvm_egress_gateway_up") != 0 {
		t.Fatal("gateway down must read 0")
	}
	before := egressAttachFailedTotal.Value()
	svc.egressStats.recordAttachFailed()
	if egressAttachFailedTotal.Value() != before+1 {
		t.Fatal("attach failures exported")
	}
	activeEgressStats.Store(nil)
	if expvarFloat(t, "aerolvm_egress_gateway_up") != 0 {
		t.Fatal("no wired service reads 0")
	}
}

// TestEgressDenialObserver (P1-7, H5): denials decided in sandboxd (the
// isolate proxy) count in the shared series and reach the audit log when
// attribution is on.
func TestEgressDenialObserver(t *testing.T) {
	before := deniedTotal("host_not_allowed")
	var nilSvc *Service
	nilSvc.EgressDenialObserver()("sb", "evil.example:443", "host_not_allowed")
	svc, _, _ := newEgressHarness(t)
	svc.cfg.EgressAttributionEnabled = true
	svc.EgressDenialObserver()("sb", "evil.example:443", "host_not_allowed")
	if got := deniedTotal("host_not_allowed") - before; got != 2 {
		t.Fatalf("denials counted = %d, want 2", got)
	}
}
