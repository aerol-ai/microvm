package routedns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/testport"
)

func TestOwnerTableMutations(t *testing.T) {
	tb := NewOwnerTable()
	tb.Set("", OwnerTarget{Port: 1}) // ignored
	tb.SetState(" ", TargetWake)     // ignored
	tb.Set("A.x.", OwnerTarget{IP: net.ParseIP("10.0.0.1"), Port: 80})
	tb.Set("a-1.x", OwnerTarget{IP: net.ParseIP("10.0.0.1"), Port: 1})
	tb.Set("b.x", OwnerTarget{IP: net.ParseIP("10.0.0.2"), Port: 80})
	if tb.Len() != 3 {
		t.Fatalf("len = %d, want 3 (empty hosts ignored, case/dot normalized)", tb.Len())
	}
	tb.SetState("a.x", TargetInFlux)
	if got, _ := tb.Lookup("a.x"); got.State != TargetInFlux || got.Port != 80 {
		t.Fatalf("SetState must keep the upstream: %+v", got)
	}
	tb.DeleteFunc(func(h string) bool { return strings.HasPrefix(h, "a") })
	if tb.Len() != 1 {
		t.Fatalf("DeleteFunc left %d, want 1", tb.Len())
	}
	tb.Delete("B.X.")
	if _, ok := tb.Lookup("b.x"); ok || tb.Len() != 0 {
		t.Fatal("Delete did not remove b.x")
	}
}

func TestIngressIndexHosts(t *testing.T) {
	x := NewIngressIndex()
	x.Replace([]cluster.Placement{{SandboxID: "sb", OwnerDataPlaneHost: "10.0.0.1", PublicTraffic: true, OwnerNodeID: "w"}}, "")
	if x.Len() != 0 {
		t.Fatal("an empty domain must index nothing")
	}
	x.Replace([]cluster.Placement{
		{SandboxID: "", OwnerNodeID: "w"}, // ignored
		{SandboxID: "sb", OwnerNodeID: "w", OwnerDataPlaneHost: "10.0.0.1", PublicTraffic: true,
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{443: {Protocol: "tls"}, 22: {Protocol: "tcp"}}},
		{SandboxID: "rsv", OwnerNodeID: "w", OwnerDataPlaneHost: "10.0.0.1", PublicTraffic: true, State: cluster.PlacementStateReserved},
		{SandboxID: "nohost", OwnerNodeID: "w", PublicTraffic: true},
	}, "d.test")
	if e, ok := x.Lookup("sb-443.d.test"); !ok || !e.Routable {
		t.Fatalf("tls port route missing: %+v", e)
	}
	if _, ok := x.Lookup("sb-22.d.test"); ok {
		t.Fatal("raw tcp port must not be an SNI host")
	}
	if e, _ := x.Lookup("rsv.d.test"); e.Routable {
		t.Fatal("a reserved placement must not be routable")
	}
	if e, _ := x.Lookup("nohost.d.test"); e.Routable {
		t.Fatal("a placement without a data-plane host must not be routable")
	}
	x.Upsert(cluster.Placement{SandboxID: "new", OwnerNodeID: "w", OwnerDataPlaneHost: "10.0.0.2", PublicTraffic: true}, "d.test")
	if _, ok := x.Lookup("new.d.test"); !ok {
		t.Fatal("Upsert did not add")
	}
	if _, ok := x.Lookup("sb.d.test"); !ok {
		t.Fatal("Upsert dropped an existing host")
	}
}

func TestItoa(t *testing.T) {
	for n, want := range map[int]string{0: "0", 7: "7", 8080: "8080", -3: "-3"} {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q", n, got)
		}
	}
}

func TestResponderMalformedAndNilTables(t *testing.T) {
	r := &Responder{Domain: testDomain}
	addr, _ := startResponder(t, r)
	m := new(dns.Msg)
	m.Question = []dns.Question{{Name: "a.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, {Name: "b.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	in, _, err := new(dns.Client).Exchange(m, addr)
	if err != nil || in.Rcode != dns.RcodeFormatError {
		t.Fatalf("two questions: rcode=%v err=%v, want FORMERR", in, err)
	}
	// Nil tables answer NXDOMAIN (fall back / close), never panic.
	if got := query(t, addr, "sb.sandbox.test", dns.TypeA); got.Rcode != dns.RcodeNameError {
		t.Fatalf("nil owner table: %s", dns.RcodeToString[got.Rcode])
	}
	if got := query(t, addr, "sb.sandbox.test."+IngressZone, dns.TypeA); got.Rcode != dns.RcodeNameError {
		t.Fatalf("nil ingress index without LocalIP: %s", dns.RcodeToString[got.Rcode])
	}
	// The only zone the responder ever claims is the ingress zone.
	if soa := r.soa().(*dns.SOA); soa.Hdr.Name != IngressZone+"." {
		t.Fatalf("SOA zone = %s", soa.Hdr.Name)
	}
}

func TestResponderListenAndServeFailsOnBusyAddr(t *testing.T) {
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	r := newTestResponder()
	if err := r.ListenAndServe(context.Background(), busy.LocalAddr().String()); err == nil {
		t.Fatal("ListenAndServe on a busy address returned nil")
	}
}

func TestIngressIndexIncrementalUpdates(t *testing.T) {
	x := NewIngressIndex()
	a := cluster.Placement{SandboxID: "a", OwnerNodeID: "w", OwnerDataPlaneHost: "10.0.0.1", PublicTraffic: true,
		ExposedPorts: map[int]string{8080: "http"}, CustomHostnames: []string{"one.customer.com", "two.customer.com"}}
	x.Upsert(a, "d.test")
	if x.Len() != 4 {
		t.Fatalf("hosts after upsert = %d, want root + port + 2 custom", x.Len())
	}
	// The placement drops a custom domain and unexposes the port.
	a.CustomHostnames = []string{"one.customer.com"}
	a.ExposedPorts = nil
	x.Upsert(a, "d.test")
	if _, ok := x.Lookup("two.customer.com"); ok {
		t.Fatal("a removed custom domain survived the upsert")
	}
	if _, ok := x.Lookup("a-8080.d.test"); ok {
		t.Fatal("an unexposed port survived the upsert")
	}
	// A custom domain moves to another sandbox; removing the old one must
	// not remove the moved host.
	b := cluster.Placement{SandboxID: "b", OwnerNodeID: "w2", OwnerDataPlaneHost: "10.0.0.2", PublicTraffic: true,
		CustomHostnames: []string{"one.customer.com"}}
	x.Upsert(b, "d.test")
	x.Remove("a")
	if e, ok := x.Lookup("one.customer.com"); !ok || e.SandboxID != "b" {
		t.Fatalf("moved custom domain = %+v ok=%v, want owned by b", e, ok)
	}
	if _, ok := x.Lookup("a.d.test"); ok {
		t.Fatal("Remove left a's root host")
	}
	x.Remove("never-existed")
}

// A failed bind must not leak the other socket, or a retry can never
// succeed ("address already in use" on our own leaked TCP listener).
func TestResponderListenAndServeReleasesPortsOnFailureAndCancel(t *testing.T) {
	// The test frees this port and binds it again several times. A ":0"
	// pick comes from the ephemeral range, where any other socket can take
	// it in between; on a busy machine the old pick often found the UDP
	// side taken and skipped the test. testport's port sits below that
	// range and goes to no other test.
	addr := testport.UDPAddr(t)
	held, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("hold udp %s: %v", addr, err)
	}
	r := newTestResponder()
	if err := r.ListenAndServe(context.Background(), addr); err == nil {
		t.Fatal("ListenAndServe with the UDP port held returned nil")
	}
	if ln, err := net.Listen("tcp", addr); err != nil {
		t.Fatalf("TCP port leaked after a failed UDP bind: %v", err)
	} else {
		_ = ln.Close()
	}
	_ = held.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ListenAndServe(ctx, addr) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("responder never served")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("cancel: %v", err)
	}
	for _, network := range []string{"tcp", "udp"} {
		var err error
		if network == "tcp" {
			var ln net.Listener
			if ln, err = net.Listen("tcp", addr); err == nil {
				_ = ln.Close()
			}
		} else {
			var pc net.PacketConn
			if pc, err = net.ListenPacket("udp", addr); err == nil {
				_ = pc.Close()
			}
		}
		if err != nil {
			t.Fatalf("%s port not released after cancel: %v", network, err)
		}
	}
}

// When one server fails, serve returns its error, and only after the other
// server has returned too, so the UDP port is free. serve has already read
// the failed server's error, so it must wait for one more: waiting for two
// would hang here.
func TestServeReturnsAServerErrorAndReleasesTheOtherPort(t *testing.T) {
	addr := testport.UDPAddr(t)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	// A closed listener makes the TCP server's first Accept fail, while the
	// UDP server runs normally.
	_ = ln.Close()
	done := make(chan error, 1)
	go func() { done <- newTestResponder().serve(context.Background(), pc, ln) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve returned nil after the TCP server failed")
		}
	case <-time.After(5 * time.Second):
		_ = pc.Close()
		t.Fatal("serve did not return after the TCP server failed")
	}
	again, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("udp port not released after a server failed: %v", err)
	}
	_ = again.Close()
}
