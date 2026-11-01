package harness

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// Three TEST-NET-1 addresses standing in for the API domain's A records.
const (
	ipA = "192.0.2.1"
	ipB = "192.0.2.2"
	ipC = "192.0.2.3"
)

// markedDown reads the pool's view of one address.
func markedDown(p *lbPool, ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.down[poolKey(netip.MustParseAddr(ip))]
}

// fixedLookup answers every lookup with addrs, in order.
func fixedLookup(addrs ...string) func(context.Context, string, string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return func(context.Context, string, string) ([]netip.Addr, error) { return out, nil }
}

// recordingDial records every address it is asked for and connects only to
// the ones in ok, over an in-memory pipe.
type recordingDial struct {
	mu     sync.Mutex
	dialed []string
	ok     map[string]bool
}

func (d *recordingDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	host, _, _ := net.SplitHostPort(addr)
	d.dialed = append(d.dialed, host)
	if !d.ok[host] {
		return nil, fmt.Errorf("dial %s: connection refused", addr)
	}
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

// The dialer is the whole model: a health-checked load balancer never sends a
// request to a node whose daemon is down, and when every node is down it has
// nothing better to do than try them all, so the case fails on the request
// (loudly) rather than on a dialer that refuses to dial.
func TestLBPoolDialsTheAddressesThatAreUpInOrder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		down       []string
		reachable  []string
		wantDialed []string
		wantErr    bool
	}{
		{name: "nothing down: the first address", reachable: []string{ipA, ipB, ipC}, wantDialed: []string{ipA}},
		{name: "first down: skipped", down: []string{ipA}, reachable: []string{ipA, ipB, ipC}, wantDialed: []string{ipB}},
		{name: "two down: the third", down: []string{ipA, ipB}, reachable: []string{ipA, ipB, ipC}, wantDialed: []string{ipC}},
		{name: "an up address that refuses falls through to the next", down: []string{ipA}, reachable: []string{ipC}, wantDialed: []string{ipB, ipC}},
		{name: "a down address is never the fallback while one is up", down: []string{ipA}, reachable: []string{ipA}, wantDialed: []string{ipB, ipC}, wantErr: true},
		{name: "every address down: all of them, in order", down: []string{ipA, ipB, ipC}, reachable: []string{ipC}, wantDialed: []string{ipA, ipB, ipC}},
		{name: "every address down and refusing: an error naming each", down: []string{ipA, ipB, ipC}, wantDialed: []string{ipA, ipB, ipC}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &recordingDial{ok: map[string]bool{}}
			for _, ip := range tc.reachable {
				d.ok[ip] = true
			}
			p := newLBPool(fixedLookup(ipA, ipB, ipC), d.dial)
			for _, ip := range tc.down {
				p.setDown(ip, true)
			}
			conn, err := p.DialContext(context.Background(), "tcp", "api.itest.invalid:443")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if conn != nil {
				_ = conn.Close()
			}
			if strings.Join(d.dialed, ",") != strings.Join(tc.wantDialed, ",") {
				t.Fatalf("dialed %v, want %v", d.dialed, tc.wantDialed)
			}
			if tc.wantErr && len(tc.wantDialed) > 1 {
				for _, ip := range tc.wantDialed {
					if !strings.Contains(err.Error(), ip) {
						t.Fatalf("the error does not say %s was tried: %v", ip, err)
					}
				}
			}
		})
	}
}

// MarkNodeUp is the restore half: a node that came back must be dialled
// again, or every later case runs against a smaller pool than the fleet.
func TestLBPoolMarkUpRestoresAnAddress(t *testing.T) {
	d := &recordingDial{ok: map[string]bool{ipA: true, ipB: true}}
	p := newLBPool(fixedLookup(ipA, ipB), d.dial)
	p.setDown(ipA, true)
	p.setDown(ipA, false)
	conn, err := p.DialContext(context.Background(), "tcp", "api.itest.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(d.dialed) != 1 || d.dialed[0] != ipA {
		t.Fatalf("dialed %v after marking %s up again, want it first", d.dialed, ipA)
	}
}

// Terraform hands out the address as a plain string; whitespace or the
// IPv4-mapped form must not make a marked node look like a different one,
// and a node with no public address (not in DNS) must be a no-op.
func TestLBPoolNormalisesTheAddressItMarks(t *testing.T) {
	p := newLBPool(fixedLookup(ipA), (&recordingDial{}).dial)
	p.setDown(" "+ipA+"\n", true)
	if !markedDown(p, ipA) {
		t.Fatal("an address with surrounding whitespace was not marked")
	}
	p.setDown("::ffff:"+ipA, false)
	if markedDown(p, ipA) {
		t.Fatal("the IPv4-mapped form did not name the same node")
	}
	for _, junk := range []string{"", "node3", "300.1.1.1"} {
		p.setDown(junk, true)
	}
	p.mu.Lock()
	n := len(p.down)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("an empty or unparsable address marked %d entries", n)
	}
}

// A case that dials one node by address means that node, so an IP literal is
// never looked up and is still dialled when it is the one marked down.
func TestLBPoolDialsAnIPLiteralDirectly(t *testing.T) {
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("an IP literal was sent to the resolver")
		return nil, nil
	}
	d := &recordingDial{ok: map[string]bool{ipB: true}}
	p := newLBPool(lookup, d.dial)
	p.setDown(ipB, true)
	conn, err := p.DialContext(context.Background(), "tcp", ipB+":443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(d.dialed) != 1 || d.dialed[0] != ipB {
		t.Fatalf("dialed %v, want only %s", d.dialed, ipB)
	}
}

func TestLBPoolResolveAsksForTheDialedFamily(t *testing.T) {
	for network, want := range map[string]string{"tcp": "ip", "tcp4": "ip4", "tcp6": "ip6"} {
		var got string
		lookup := func(_ context.Context, family, _ string) ([]netip.Addr, error) {
			got = family
			return []netip.Addr{netip.MustParseAddr(ipA)}, nil
		}
		p := newLBPool(lookup, (&recordingDial{ok: map[string]bool{ipA: true}}).dial)
		conn, err := p.DialContext(context.Background(), network, "api.itest.invalid:443")
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		_ = conn.Close()
		if got != want {
			t.Fatalf("%s looked up %q, want %q", network, got, want)
		}
	}
}

func TestLBPoolSurfacesLookupFailures(t *testing.T) {
	boom := errors.New("no such host")
	failing := newLBPool(func(context.Context, string, string) ([]netip.Addr, error) { return nil, boom }, (&recordingDial{}).dial)
	if _, err := failing.DialContext(context.Background(), "tcp", "api.itest.invalid:443"); !errors.Is(err, boom) {
		t.Fatalf("lookup error = %v, want %v", err, boom)
	}
	empty := newLBPool(fixedLookup(), (&recordingDial{}).dial)
	if _, err := empty.DialContext(context.Background(), "tcp", "api.itest.invalid:443"); err == nil {
		t.Fatal("a lookup with no addresses dialled nothing and reported no error")
	}
	if _, err := empty.DialContext(context.Background(), "tcp", "no-port"); err == nil {
		t.Fatal("an address without a port was accepted")
	}
}

// node is one fake ingress: an HTTP server that says which node answered and
// reports every connection it saw close.
type node struct {
	name   string
	srv    *httptest.Server
	closed chan struct{}
	// hold blocks a request for /hold until it is closed.
	hold chan struct{}
	got  chan struct{}
}

func newNode(t *testing.T, name string) *node {
	t.Helper()
	n := &node{name: name, closed: make(chan struct{}, 64), got: make(chan struct{}, 64), hold: make(chan struct{})}
	t.Cleanup(func() { close(n.hold) })
	n.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.got <- struct{}{}
		if r.URL.Path == "/hold" {
			select {
			case <-n.hold:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, n.name)
	}))
	n.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			n.closed <- struct{}{}
		}
	}
	n.srv.Start()
	t.Cleanup(n.srv.Close)
	return n
}

// twoNodePool is the API domain with two A records, ipA and ipB, whose
// connections land on two local servers.
func twoNodePool(t *testing.T) (*lbPool, *node, *node) {
	t.Helper()
	a, b := newNode(t, "node-a"), newNode(t, "node-b")
	backends := map[string]string{ipA: a.srv.Listener.Addr().String(), ipB: b.srv.Listener.Addr().String()}
	var d net.Dialer
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		return d.DialContext(ctx, network, backends[host])
	}
	return newLBPool(fixedLookup(ipA, ipB), dial), a, b
}

// get fetches path from the fake API domain and returns which node answered
// and whether the request rode an existing connection.
func get(t *testing.T, c *http.Client, path string) (string, bool) {
	t.Helper()
	var reused bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.itest.invalid"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), reused
}

func awaitClosed(t *testing.T, n *node, why string) {
	t.Helper()
	select {
	case <-n.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: %s never saw its connection close", why, n.name)
	}
}

// The live failure, end to end: a keep-alive client pinned to the node whose
// daemon a case stopped. Before, every later request rode that connection to
// the dead node's Caddy. Marking the node down must close the connection and
// move the client to a node that is up, and marking it up must let it back.
func TestMarkNodeDownMovesAKeepAliveClientOffTheNode(t *testing.T) {
	p, a, b := twoNodePool(t)
	c := &http.Client{Transport: p.newTransport(nil), Timeout: 10 * time.Second}

	if got, _ := get(t, c, "/"); got != a.name {
		t.Fatalf("first request answered by %s, want %s (the first A record)", got, a.name)
	}
	if got, reused := get(t, c, "/"); got != a.name || !reused {
		t.Fatalf("second request: %s reused=%v; the premise is a client pinned to one node by keep-alive", got, reused)
	}

	p.setDown(ipA, true)
	awaitClosed(t, a, "marking node-a down")
	if got, reused := get(t, c, "/"); got != b.name || reused {
		t.Fatalf("after marking node-a down: answered by %s (reused=%v), want %s on a new connection", got, reused, b.name)
	}

	p.setDown(ipA, false)
	p.setDown(ipB, true)
	awaitClosed(t, b, "marking node-b down")
	if got, _ := get(t, c, "/"); got != a.name {
		t.Fatalf("after marking node-a up and node-b down: answered by %s, want %s", got, a.name)
	}
}

// Closing only idle connections is not enough. A connection that is mid-
// request when the node is marked down goes back to the idle pool once its
// response lands and is then reused for every later request: the same 502
// loop. So a busy connection to the node is closed too, and the request on
// it fails at once instead of riding a dead node.
func TestMarkNodeDownClosesABusyConnectionToTheNode(t *testing.T) {
	p, a, b := twoNodePool(t)
	c := &http.Client{Transport: p.newTransport(nil), Timeout: 10 * time.Second}

	errc := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "http://api.itest.invalid/hold", nil)
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errc <- err
	}()
	select {
	case <-a.got:
	case <-time.After(5 * time.Second):
		t.Fatal("the held request never reached node-a")
	}

	p.setDown(ipA, true)
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the request in flight to the node marked down completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request in flight to the node marked down was left hanging")
	}
	if got, _ := get(t, c, "/"); got != b.name {
		t.Fatalf("after the busy connection was cut: answered by %s, want %s", got, b.name)
	}
}

// Every transport the pool built is cleared, not only the one in hand: the
// SDK client, APIClient and the raw helpers share one, and a case that needed
// its own pool settings (NewTransport) must not keep a stale connection
// either. Idle connections to nodes that are up are dropped too; the next
// request simply opens a new one.
func TestMarkNodeDownClosesIdleConnectionsOnEveryTransport(t *testing.T) {
	p, _, b := twoNodePool(t)
	p.setDown(ipA, true) // both transports start on node-b
	shared := &http.Client{Transport: p.newTransport(nil)}
	own := &http.Client{Transport: p.newTransport(func(tr *http.Transport) { tr.MaxIdleConnsPerHost = 8 })}
	for _, c := range []*http.Client{shared, own} {
		if got, _ := get(t, c, "/"); got != b.name {
			t.Fatalf("answered by %s, want %s", got, b.name)
		}
	}

	p.setDown(ipC, true) // any mark-down clears idle connections everywhere
	awaitClosed(t, b, "first transport")
	awaitClosed(t, b, "second transport")
	for i, c := range []*http.Client{shared, own} {
		if _, reused := get(t, c, "/"); reused {
			t.Fatalf("transport %d reused a connection that marking a node down should have closed", i)
		}
	}
}

// configure may tune a transport but never replace the pool's dialer; a
// transport that bypassed it would quietly ignore every mark.
func TestNewTransportKeepsThePoolDialer(t *testing.T) {
	p, _, b := twoNodePool(t)
	p.setDown(ipA, true)
	tr := p.newTransport(func(tr *http.Transport) {
		tr.DialContext = (&net.Dialer{}).DialContext
	})
	if got, _ := get(t, &http.Client{Transport: tr}, "/"); got != b.name {
		t.Fatalf("answered by %s: the configure hook replaced the pool's dialer", got)
	}
}

// The pool remembers connections only while they are open; a long run must
// not accumulate every connection it ever made.
func TestLBPoolForgetsClosedConnections(t *testing.T) {
	p, _, _ := twoNodePool(t)
	tr := p.newTransport(nil)
	c := &http.Client{Transport: tr}
	get(t, c, "/")
	tr.CloseIdleConnections()
	p.mu.Lock()
	n := len(p.conns)
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d closed connections are still tracked", n)
	}
}

// The exported surface is wired to the one shared pool the clients use.
func TestSharedClientsUseTheAPIPool(t *testing.T) {
	if SharedTransport().DialContext == nil || HTTPClient(time.Second).Transport != SharedTransport() || apiHTTPClient.Transport != SharedTransport() {
		t.Fatal("the shared clients are not on the shared transport")
	}
	if NewAPIClient("http://x", "b").HTTP.Transport != SharedTransport() {
		t.Fatal("APIClient does not use the shared transport")
	}
	if NewTransport(nil) == SharedTransport() {
		t.Fatal("NewTransport returned the shared transport instead of its own pool")
	}
	const ip = "198.51.100.200"
	MarkNodeDown(ip)
	if !markedDown(apiPool, ip) {
		t.Fatal("MarkNodeDown did not reach the shared pool")
	}
	MarkNodeUp(ip)
	if markedDown(apiPool, ip) {
		t.Fatal("MarkNodeUp did not reach the shared pool")
	}
}

// bootFake is an SSH fake for the helpers that take a daemon down. A target
// listed in refuse answers is-active "failed" (a boot gate holding) until a
// restore removes the override; every other target, and every target after
// its restore, answers "active".
type bootFake struct {
	mu       sync.Mutex
	refuse   map[string]bool
	restored map[string]bool
	scripts  []string
}

func installBootFake(t *testing.T, refuse ...string) *bootFake {
	t.Helper()
	f := &bootFake{refuse: map[string]bool{}, restored: map[string]bool{}}
	for _, target := range refuse {
		f.refuse[target] = true
	}
	prev, prevWindow := sshRunner, unitStableWindow
	unitStableWindow = 10 * time.Millisecond
	sshRunner = func(_ *testing.T, target, script string) (string, error) {
		if strings.Contains(script, "aerol-ssh-ok") {
			return "aerol-ssh-ok\n", nil
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.scripts = append(f.scripts, script)
		switch {
		case strings.Contains(script, "rm -f "+itestEnvDropIn):
			f.restored[target] = true
		case strings.Contains(script, "is-active"):
			if f.refuse[target] && !f.restored[target] {
				return "failed\n", nil
			}
			return "active\n", nil
		case strings.Contains(script, "NRestarts"):
			return "0\n", nil
		}
		return "", nil
	}
	resetSSHReachability()
	t.Cleanup(func() {
		sshRunner, unitStableWindow = prev, prevWindow
		resetSSHReachability()
	})
	return f
}

// rejoinProbe stands in for the suite's NodeRejoinCheck. It records whether
// each node was still out of the API pool when it was asked, and fails the
// first fail calls.
type rejoinProbe struct {
	mu        sync.Mutex
	fail      int
	calls     int
	downAtAsk []bool
}

func installRejoinProbe(t *testing.T, fail int) *rejoinProbe {
	t.Helper()
	r := &rejoinProbe{fail: fail}
	prev := NodeRejoinCheck
	NodeRejoinCheck = func(_ *testing.T, node IntegrationNode) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls++
		r.downAtAsk = append(r.downAtAsk, markedDown(apiPool, node.PublicIP))
		if r.calls <= r.fail {
			return errors.New("not in the member list yet")
		}
		return nil
	}
	t.Cleanup(func() { NodeRejoinCheck = prev })
	return r
}

// clearMark makes sure a test leaves the shared pool as it found it.
func clearMark(t *testing.T, ip string) {
	t.Helper()
	MarkNodeUp(ip)
	t.Cleanup(func() { MarkNodeUp(ip) })
}

// KillNodeDaemon is the helper the live failure ran through: the victim
// must leave the API pool once its daemon is stopped, and come back only
// after the restart AND the rejoin check, so a restore that is still
// rejoining sends no request to a node that cannot answer it.
func TestKillNodeDaemonTakesTheNodeOutOfThePoolUntilItRejoins(t *testing.T) {
	fake := installBootFake(t)
	probe := installRejoinProbe(t, 0)
	node := IntegrationNode{Name: "node2", PublicIP: "203.0.113.20"}
	clearMark(t, node.PublicIP)

	restore := KillNodeDaemon(t, node)
	if !fake.ran("systemctl stop sandboxd") {
		t.Fatal("the daemon was never stopped")
	}
	if !markedDown(apiPool, node.PublicIP) {
		t.Fatal("the stopped node is still in the API pool: every poll that lands on its Caddy reads 502 for the whole outage")
	}

	restore()
	if !fake.ran("systemctl start sandboxd") {
		t.Fatal("the restore never started the daemon")
	}
	if len(probe.downAtAsk) != 1 || !probe.downAtAsk[0] {
		t.Fatalf("the node was back in the pool before the rejoin check ran (down at ask: %v)", probe.downAtAsk)
	}
	if markedDown(apiPool, node.PublicIP) {
		t.Fatal("the node rejoined but was never put back in the API pool")
	}
}

// A refused boot is the expected outcome of a boot-gate case, and the node
// stays down for all of fn: fn's own API requests must not land on it. After
// the restore brings it back and it rejoins, it is in the pool again.
func TestWithNodeEnvKeepsARefusedNodeOutOfThePoolDuringFn(t *testing.T) {
	node := IntegrationNode{Name: "node3", PublicIP: "203.0.113.30"}
	target, _ := SSHTarget(node)
	installBootFake(t, target)
	probe := installRejoinProbe(t, 0)
	clearMark(t, node.PublicIP)

	WithNodeEnv(t, node, map[string]string{"SB_X": "refused"}, func(res NodeBootResult) {
		if res.Started {
			t.Fatal("the fake boot gate did not hold")
		}
		if !markedDown(apiPool, node.PublicIP) {
			t.Fatal("a node whose boot was refused is in the API pool while fn runs")
		}
	})
	if markedDown(apiPool, node.PublicIP) {
		t.Fatal("the restored node was never put back in the API pool")
	}
	if probe.calls != 1 || !probe.downAtAsk[0] {
		t.Fatalf("rejoin checks %d (down at ask %v): the node must rejoin before it is back in the pool", probe.calls, probe.downAtAsk)
	}
}

// A node that started under the override but has not rejoined is not usable
// yet, so it is not in the pool while fn runs; once it is up and rejoined it
// is.
func TestWithNodeEnvPoolFollowsTheRejoinCheck(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures int
		wantDown bool
	}{
		{name: "started and rejoined: in the pool", failures: 0, wantDown: false},
		{name: "started but not rejoined: out of the pool", failures: 1, wantDown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installBootFake(t)
			installRejoinProbe(t, tc.failures)
			node := IntegrationNode{Name: "node4", PublicIP: "203.0.113.40"}
			clearMark(t, node.PublicIP)

			WithNodeEnv(t, node, map[string]string{"SB_X": "1"}, func(res NodeBootResult) {
				if !res.Started {
					t.Fatal("the node did not start")
				}
				if got := markedDown(apiPool, node.PublicIP); got != tc.wantDown {
					t.Fatalf("marked down during fn = %v, want %v", got, tc.wantDown)
				}
			})
			if markedDown(apiPool, node.PublicIP) {
				t.Fatal("the node was left out of the pool after a restore that rejoined")
			}
		})
	}
}

// WithClusterEnv restarts the fleet back to back, so a node is back in the
// pool as soon as its unit holds active; one whose boot was refused stays out
// while fn runs. After the restore every node is back.
func TestWithClusterEnvKeepsOnlyRefusedNodesOutOfThePool(t *testing.T) {
	seed := IntegrationNode{Name: "seed", Seed: true, PublicIP: "203.0.113.50"}
	joiner := IntegrationNode{Name: "joiner", PublicIP: "203.0.113.51"}
	joinerTarget, _ := SSHTarget(joiner)
	installBootFake(t, joinerTarget)
	installRejoinProbe(t, 0)
	clearMark(t, seed.PublicIP)
	clearMark(t, joiner.PublicIP)

	WithClusterEnv(t, &IntegrationTargets{Nodes: []IntegrationNode{joiner, seed}}, map[string]string{"SB_X": "1"}, func(res map[string]NodeBootResult) {
		if !res["seed"].Started || res["joiner"].Started {
			t.Fatalf("boot outcomes %+v, want the seed up and the joiner refused", res)
		}
		if markedDown(apiPool, seed.PublicIP) {
			t.Fatal("the seed started but is out of the API pool during fn")
		}
		if !markedDown(apiPool, joiner.PublicIP) {
			t.Fatal("the refused joiner is in the API pool during fn")
		}
	})
	for _, n := range []IntegrationNode{seed, joiner} {
		if markedDown(apiPool, n.PublicIP) {
			t.Fatalf("%s was left out of the API pool after the restore", n.Name)
		}
	}
}

func (f *bootFake) ran(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.scripts {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
