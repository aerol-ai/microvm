package routedns

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/cluster"
)

const testDomain = "sandbox.test"

// startResponder serves r on a random loopback UDP port and returns its
// address plus a log of every name it was asked.
func startResponder(t *testing.T, r *Responder) (string, func() []string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var asked []string
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		mu.Lock()
		for _, q := range m.Question {
			asked = append(asked, q.Name)
		}
		mu.Unlock()
		r.ServeDNS(w, m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	in, _, err := new(dns.Client).Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange %s: %v", name, err)
	}
	return in
}

func aOf(m *dns.Msg) string {
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
		if c, ok := rr.(*dns.CNAME); ok {
			return "CNAME " + c.Target
		}
	}
	return ""
}

func newTestResponder() *Responder {
	return &Responder{
		Domain: testDomain, SelfNodeID: "self", LocalIP: net.ParseIP("127.0.0.2"), ToolboxPort: 2280,
		Owner: NewOwnerTable(), Ingress: NewIngressIndex(),
	}
}

func TestResponderOwnerAnswers(t *testing.T) {
	r := newTestResponder()
	r.Owner.Set("sb1.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.5"), Port: 2280})
	r.Owner.Set("sb1-8080.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.5"), Port: 8080})
	r.Owner.Set("sb1-9090.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.5"), Port: 7000})   // port mismatch
	r.Owner.Set("wasm-8080.sandbox.test", OwnerTarget{IP: net.ParseIP("127.0.0.1"), Port: 8080}) // loopback upstream
	r.Owner.SetState("sb2-8080.sandbox.test", TargetWake)
	r.Owner.Set("sb3.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.7"), Port: 2280, State: TargetInFlux})
	addr, _ := startResponder(t, r)

	tests := []struct {
		name      string
		host      string
		wantA     string
		wantRcode int
	}{
		{"root host", "sb1.sandbox.test", "10.0.0.5", dns.RcodeSuccess},
		{"port host", "sb1-8080.sandbox.test", "10.0.0.5", dns.RcodeSuccess},
		{"port Caddy would derive differs: fall back", "sb1-9090.sandbox.test", "", dns.RcodeNameError},
		{"loopback upstream (wasm/isolate): fall back", "wasm-8080.sandbox.test", "", dns.RcodeNameError},
		{"serverless stopped: fall back to wake", "sb2-8080.sandbox.test", "", dns.RcodeNameError},
		{"in flux: fall back to the 503", "sb3.sandbox.test", "", dns.RcodeNameError},
		{"unknown", "nope.sandbox.test", "", dns.RcodeNameError},
		{"case and trailing dot", "SB1.Sandbox.Test.", "10.0.0.5", dns.RcodeSuccess},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := query(t, addr, tc.host, dns.TypeA)
			if in.Rcode != tc.wantRcode || aOf(in) != tc.wantA {
				t.Fatalf("rcode=%s A=%q, want %s %q", dns.RcodeToString[in.Rcode], aOf(in), dns.RcodeToString[tc.wantRcode], tc.wantA)
			}
			if !in.Authoritative || in.RecursionAvailable {
				t.Fatalf("answer must be authoritative and non-recursive: aa=%v ra=%v", in.Authoritative, in.RecursionAvailable)
			}
			if tc.wantA == "" && (len(in.Ns) == 0 || in.Ns[0].(*dns.SOA).Minttl != answerTTL) {
				t.Fatalf("negative answer needs an SOA with minttl=%d so resolvers don't cache it long: %v", answerTTL, in.Ns)
			}
		})
	}
	if in := query(t, addr, "sb1.sandbox.test", dns.TypeAAAA); in.Rcode != dns.RcodeSuccess || len(in.Answer) != 0 {
		t.Fatalf("AAAA for an IPv4 target should be NODATA, got rcode=%s answers=%v", dns.RcodeToString[in.Rcode], in.Answer)
	}
}

func TestResponderIngressAnswers(t *testing.T) {
	r := newTestResponder()
	r.Ingress.Replace([]cluster.Placement{
		{SandboxID: "sbA", OwnerNodeID: "w1", OwnerDataPlaneHost: "10.1.0.1", PublicTraffic: true,
			ExposedPorts: map[int]string{8080: "http", 5432: "tcp"}, CustomHostnames: []string{"app.customer.com"}},
		{SandboxID: "sbSelf", OwnerNodeID: "self", OwnerDataPlaneHost: "10.1.0.9", PublicTraffic: true},
		{SandboxID: "sbDNS", OwnerNodeID: "w2", OwnerDataPlaneHost: "w2.internal.example", PublicTraffic: true},
		{SandboxID: "sbOrphan", OwnerNodeID: "", OwnerDataPlaneHost: "10.1.0.3", PublicTraffic: true,
			CustomHostnames: []string{"orphan.customer.com"}},
		{SandboxID: "sbPrivate", OwnerNodeID: "w1", OwnerDataPlaneHost: "10.1.0.1", PublicTraffic: false},
	}, testDomain)
	addr, _ := startResponder(t, r)

	tests := []struct {
		name      string
		sni       string
		want      string
		wantRcode int
	}{
		{"root host to owner", "sbA.sandbox.test", "10.1.0.1", dns.RcodeSuccess},
		{"http port host to owner", "sbA-8080.sandbox.test", "10.1.0.1", dns.RcodeSuccess},
		{"custom domain to owner (owner terminates)", "app.customer.com", "10.1.0.1", dns.RcodeSuccess},
		{"owner is self: local listener", "sbSelf.sandbox.test", "127.0.0.2", dns.RcodeSuccess},
		{"owner host is a DNS name: CNAME", "sbDNS.sandbox.test", "CNAME w2.internal.example.", dns.RcodeSuccess},
		{"orphaned platform host: local 503 (1A)", "sbOrphan.sandbox.test", "127.0.0.2", dns.RcodeSuccess},
		{"orphaned custom host: close, no ACME on ingress (T5)", "orphan.customer.com", "", dns.RcodeNameError},
		{"private: local router answers 404", "sbPrivate.sandbox.test", "127.0.0.2", dns.RcodeSuccess},
		{"tcp port is not an SNI route", "sbA-5432.sandbox.test", "127.0.0.2", dns.RcodeSuccess},
		{"unknown platform host: local router", "ghost.sandbox.test", "127.0.0.2", dns.RcodeSuccess},
		{"unknown custom host: close", "evil.example.org", "", dns.RcodeNameError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := query(t, addr, tc.sni+"."+IngressZone, dns.TypeA)
			if in.Rcode != tc.wantRcode || aOf(in) != tc.want {
				t.Fatalf("rcode=%s answer=%q, want %s %q", dns.RcodeToString[in.Rcode], aOf(in), dns.RcodeToString[tc.wantRcode], tc.want)
			}
		})
	}
}

// A brand-new sandbox the index hasn't seen: one control-plane read per
// host no matter how many connections arrive, and a miss is remembered.
func TestResponderOnMissSingleFlightAndNegativeCache(t *testing.T) {
	r := newTestResponder()
	var calls atomic.Int32
	gate := make(chan struct{})
	r.Miss = func(_ context.Context, id string) (cluster.Placement, bool) {
		calls.Add(1)
		<-gate
		if id == "sbnew" { // hosts are case-insensitive; real IDs are lowercase
			return cluster.Placement{SandboxID: "sbnew", OwnerNodeID: "w9", OwnerDataPlaneHost: "10.9.9.9", PublicTraffic: true,
				ExposedPorts: map[int]string{3000: "http"}}, true
		}
		return cluster.Placement{}, false
	}
	var wg sync.WaitGroup
	results := make([]IngressEntry, 20)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = r.lookupIngress("sbnew-3000.sandbox.test")
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	for i, e := range results {
		if e.OwnerHost != "10.9.9.9" {
			t.Fatalf("result %d = %+v, want the looked-up owner", i, e)
		}
	}
	// "sbnew-3000" is tried first (not found), then "sbnew": 2 reads, not 40.
	if n := calls.Load(); n > 2 {
		t.Fatalf("on-miss reads = %d for 20 concurrent connections, want at most 2 (single-flight)", n)
	}
	if _, ok := r.Ingress.Lookup("sbnew.sandbox.test"); !ok {
		t.Fatal("on-miss result was not cached into the index")
	}

	// Negative cache: an unknown host is read once per TTL.
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	r.NegativeTTL = 2 * time.Second
	before := calls.Load()
	for i := 0; i < 5; i++ {
		if _, ok := r.lookupIngress("ghost.sandbox.test"); ok {
			t.Fatal("unknown host resolved")
		}
	}
	if got := calls.Load() - before; got != 1 {
		t.Fatalf("reads for a repeated unknown host = %d, want 1 (negative cache)", got)
	}
	now = now.Add(3 * time.Second)
	r.lookupIngress("ghost.sandbox.test")
	if got := calls.Load() - before; got != 2 {
		t.Fatalf("after the negative TTL, reads = %d, want 2", got)
	}
	// Custom hosts never trigger an on-miss read (no ID in them).
	before = calls.Load()
	r.lookupIngress("some.customer.com")
	if calls.Load() != before {
		t.Fatal("a custom host triggered an on-miss read")
	}
}

// The spike worried that a Caddy-style resolver leaks sandbox hostnames to
// public DNS on NXDOMAIN. It resolves the way Caddy's dynamic upstream does
// (pure Go, every dial overridden to the responder) and checks every dial
// went to the responder. With a fully-qualified name (trailing dot) there is
// no search-domain expansion either.
func TestCaddyStyleResolverNeverLeavesTheResponder(t *testing.T) {
	r := newTestResponder()
	r.Owner.Set("sb1.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.5"), Port: 2280})
	addr, asked := startResponder(t, r)
	var dials []string
	var mu sync.Mutex
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, address)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr) // like Caddy's resolver option
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ips, err := res.LookupIPAddr(ctx, "sb1.sandbox.test."); err != nil || len(ips) != 1 || ips[0].IP.String() != "10.0.0.5" {
		t.Fatalf("hit: ips=%v err=%v", ips, err)
	}
	if _, err := res.LookupIPAddr(ctx, "missing.sandbox.test."); err == nil {
		t.Fatal("miss resolved")
	}
	for _, name := range asked() {
		if name != "sb1.sandbox.test." && name != "missing.sandbox.test." {
			t.Fatalf("responder saw an unexpected name %q (search-domain expansion)", name)
		}
	}
	// Every dial went to our responder: Go passes the resolv.conf server as
	// the "address", but the override ignores it, so nothing leaves.
	mu.Lock()
	defer mu.Unlock()
	if len(dials) == 0 {
		t.Fatal("resolver never dialed")
	}
}

func TestDerivedPort(t *testing.T) {
	for host, want := range map[string]int{
		"sb1.sandbox.test":        2280,
		"sb1-8080.sandbox.test":   8080,
		"sb-4af25-3000.x.y":       3000,
		"app.customer.com":        2280,
		"sb-1234567890.sandbox.t": 1234567890, // matches the map regex; responder then refuses (mismatch)
	} {
		if got := DerivedPort(host, 2280); got != want {
			t.Errorf("DerivedPort(%q) = %d, want %d", host, got, want)
		}
	}
}

func TestResponderListenAndServe(t *testing.T) {
	r := newTestResponder()
	r.Owner.Set("sb1.sandbox.test", OwnerTarget{IP: net.ParseIP("10.0.0.5"), Port: 2280})
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.ListenAndServe(ctx, addr) }()
	var in *dns.Msg
	for i := 0; i < 50; i++ {
		m := new(dns.Msg)
		m.SetQuestion("sb1.sandbox.test.", dns.TypeA)
		if got, _, err := new(dns.Client).Exchange(m, addr); err == nil {
			in = got
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if in == nil || aOf(in) != "10.0.0.5" {
		t.Fatalf("ListenAndServe did not answer: %v", in)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not stop on cancel")
	}
}
