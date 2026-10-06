package egress

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startServer serves a gateway on a short temp socket path (macOS caps
// sun_path at 104 bytes).
func startServer(t *testing.T, hooks ServerHooks, peer PeerCheck) (*Client, *Gateway, *MemBackend, *EventHub) {
	t.Helper()
	g, be, _ := newTestGateway(t)
	dir, err := os.MkdirTemp("", "eg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "gw.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	hub := NewEventHub(4)
	srv := NewServer(g, hooks, peer, hub, nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close(); srv.Close() })
	c := NewClient(path)
	t.Cleanup(c.Close)
	return c, g, be, hub
}

func TestClientServerRoundTrip(t *testing.T) {
	changed := 0
	bridges := []Bridge(nil)
	hooks := ServerHooks{
		SetBridges: func(b []Bridge) error { bridges = b; return nil },
		Probe:      func(p ProbeRequest) (ProbeResult, error) { return ProbeResult{DNSSeen: p.Begin}, nil },
		Listeners:  func() []string { return []string{"10.88.0.1:53054"} },
		Learned:    func(id string) (json.RawMessage, error) { return json.RawMessage(`{"mode":"learn"}`), nil },
		Changed:    func() { changed++ },
	}
	c, g, be, _ := startServer(t, hooks, nil)
	ctx := context.Background()
	if err := c.Attach(ctx, allowSpec("sb", ipA, "pypi.org", "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	if c.Version() != ProtocolVersion {
		t.Fatalf("negotiated %d", c.Version())
	}
	if !be.Has(SetFQDNSrc, Elem{Src: ipA}) {
		t.Fatal("attach did not reach the gateway")
	}
	if err := c.Update(ctx, allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBlocked(ctx, "sb", BlockHold, true); err != nil {
		t.Fatal(err)
	}
	if !g.IsBlocked("sb") {
		t.Fatal("set_blocked did not reach the gateway")
	}
	if err := c.SetBlocked(ctx, "ghost", BlockHold, true); !errors.Is(err, ErrNotAttached) {
		t.Fatalf("unknown sandbox err = %v, want ErrNotAttached", err)
	}
	if err := c.Attach(ctx, Spec{ID: "bad", IP: ipB, DenyOut: []string{"evil.com"}}); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid spec err = %v, want a plain validation error", err)
	}
	st, err := c.Ready(ctx)
	if err != nil || !st.Layout || len(st.Listeners) != 1 {
		t.Fatalf("Ready = %+v, %v", st, err)
	}
	if err := c.SetBridges(ctx, []Bridge{{Name: "aerolvm0", GatewayIP: netip.MustParseAddr("10.88.0.1")}}); err != nil || len(bridges) != 1 {
		t.Fatalf("SetBridges: %v %v", err, bridges)
	}
	if r, err := c.Probe(ctx, ProbeRequest{Begin: true}); err != nil || !r.DNSSeen {
		t.Fatalf("Probe = %+v, %v", r, err)
	}
	if raw, err := c.Learned(ctx, "sb"); err != nil || !strings.Contains(string(raw), "learn") {
		t.Fatalf("Learned = %s, %v", raw, err)
	}
	if err := c.Sync(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if be.Has(SetFQDNSrc, Elem{Src: ipA}) {
		t.Fatal("empty sync must clear the sets")
	}
	if err := c.Detach(ctx, "sb", ipA); err != nil {
		t.Fatal(err)
	}
	if changed < 4 {
		t.Fatalf("Changed hook fired %d times", changed)
	}
}

func TestServerWithoutHooks(t *testing.T) {
	c, _, be, _ := startServer(t, ServerHooks{}, nil)
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"bridges": func() error { return c.SetBridges(ctx, nil) },
		"probe":   func() error { _, err := c.Probe(ctx, ProbeRequest{}); return err },
		"learned": func() error { _, err := c.Learned(ctx, "x"); return err },
	} {
		if err := call(); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s err = %v, want ErrUnavailable", name, err)
		}
	}
	be.DropLayout()
	st, err := c.Ready(ctx)
	if err != nil || st.Layout || st.Error == "" {
		t.Fatalf("Ready with lost layout = %+v, %v", st, err)
	}
}

func TestPeerCheckRejects(t *testing.T) {
	c, _, _, _ := startServer(t, ServerHooks{}, func(net.Conn) error { return errors.New("not sandboxd") })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Attach(ctx, allowSpec("sb", ipA)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("rejected peer err = %v, want ErrUnavailable", err)
	}
}

func TestVersionNegotiation(t *testing.T) {
	cases := []struct {
		offered []int
		want    int
		ok      bool
	}{
		{[]int{ProtocolVersion}, ProtocolVersion, true},
		{[]int{ProtocolVersion + 1, ProtocolVersion}, ProtocolVersion, true},
		{[]int{ProtocolVersion - 1}, ProtocolVersion - 1, ProtocolVersion-1 > 0},
		{[]int{ProtocolVersion + 2}, 0, false},
		{nil, 0, false},
	}
	for _, tc := range cases {
		got, ok := negotiate(tc.offered)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("negotiate(%v) = %d,%v want %d,%v", tc.offered, got, ok, tc.want, tc.ok)
		}
	}
}

// TestVersionMismatchOverWire: a server that refuses the hello maps to
// ErrVersionMismatch on the client (EF-63: gap of two → 503 upstream).
func TestVersionMismatchOverWire(t *testing.T) {
	dir, _ := os.MkdirTemp("", "eg")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "v.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var req request
		_ = newFrameReader(c).read(&req)
		_ = writeFrame(c, response{ID: req.ID, Code: codeVersion, Error: "speaks 9"})
	}()
	err = NewClient(path).Attach(context.Background(), allowSpec("sb", ipA))
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("err = %v, want ErrVersionMismatch", err)
	}
}

func TestServerRejectsMissingHello(t *testing.T) {
	_, g, _, _ := startServer(t, ServerHooks{}, nil)
	_ = g
	dir, _ := os.MkdirTemp("", "eg")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "h.sock")
	ln, _ := net.Listen("unix", path)
	defer ln.Close()
	srv := NewServer(g, ServerHooks{}, nil, nil, nil)
	go func() { _ = srv.Serve(ln) }()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = writeFrame(conn, request{ID: 1, Op: opAttach})
	var resp response
	if err := newFrameReader(conn).read(&resp); err != nil || resp.Code != codeVersion {
		t.Fatalf("resp = %+v, %v", resp, err)
	}
}

func TestEventStream(t *testing.T) {
	c, _, _, hub := startServer(t, ServerHooks{}, nil)
	hub.Publish(Event{Kind: "audit", SandboxID: "sb", Result: "denied", Reason: "sni_not_allowed"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := c.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-ch:
		if e.Reason != "sni_not_allowed" {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued event not drained on subscribe")
	}
	hub.Publish(Event{Kind: "heartbeat", LayoutOK: true})
	select {
	case e := <-ch:
		if e.Kind != "heartbeat" {
			t.Fatalf("event = %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live event not delivered")
	}
	cancel()
	for range ch {
	}
}

func TestEventHubBound(t *testing.T) {
	h := NewEventHub(2)
	for i := 0; i < 5; i++ {
		h.Publish(Event{Reason: string(rune('a' + i))})
	}
	if h.Len() != 2 || h.Dropped() != 3 {
		t.Fatalf("len=%d dropped=%d", h.Len(), h.Dropped())
	}
	got := h.take(10)
	if got[0].Reason != "d" || got[1].Reason != "e" {
		t.Fatalf("kept %+v, want the newest two", got)
	}
	h.Publish(Event{Reason: "f"})
	h.requeue(got)
	if h.Len() != 2 || h.Dropped() != 4 {
		t.Fatalf("requeue must keep the bound: len=%d dropped=%d", h.Len(), h.Dropped())
	}
	if NewEventHub(0).max != DefaultAuditBuffer {
		t.Fatal("default buffer size")
	}
}

func TestNoopFailsClosed(t *testing.T) {
	ctx := context.Background()
	var n Noop
	for name, err := range map[string]error{
		"attach":  n.Attach(ctx, Spec{}),
		"update":  n.Update(ctx, Spec{}),
		"sync":    n.Sync(ctx, nil),
		"bridges": n.SetBridges(ctx, nil),
	} {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Noop.%s = %v, want ErrUnavailable", name, err)
		}
	}
	if _, err := n.Ready(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Noop.Ready must fail")
	}
	if _, err := n.Probe(ctx, ProbeRequest{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Noop.Probe must fail")
	}
	if _, err := n.Learned(ctx, "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("Noop.Learned must fail")
	}
	if n.Detach(ctx, "x", ipA) != nil || n.SetBlocked(ctx, "x", BlockAll, true) != nil {
		t.Fatal("Noop removals must succeed")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "snapshot.json")
	if _, ok, err := LoadSnapshot(path); ok || err != nil {
		t.Fatalf("missing snapshot = %v, %v", ok, err)
	}
	spec := allowSpec("sb", ipA, "pypi.org")
	spec.Secrets = map[string]string{"GITHUB_TOKEN": "ghp_real"}
	in := Snapshot{Specs: []Spec{spec}, Bridges: []Bridge{{Name: "docker0", GatewayIP: netip.MustParseAddr("172.17.0.1")}}}
	if err := SaveSnapshot(path, in); err != nil {
		t.Fatal(err)
	}
	out, ok, err := LoadSnapshot(path)
	if err != nil || !ok || len(out.Specs) != 1 || out.Bridges[0].Name != "docker0" {
		t.Fatalf("load = %+v, %v, %v", out, ok, err)
	}
	// Injected credentials never reach the disk (P3-2), and the caller's
	// spec keeps them.
	if raw, _ := os.ReadFile(path); strings.Contains(string(raw), "ghp_real") || out.Specs[0].Secrets != nil {
		t.Fatal("a secret reached the snapshot")
	}
	if in.Specs[0].Secrets["GITHUB_TOKEN"] != "ghp_real" {
		t.Fatal("SaveSnapshot must not modify the caller's specs")
	}
	if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSnapshot(path); err == nil {
		t.Fatal("corrupt snapshot must error")
	}
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadSnapshot(path); err == nil {
		t.Fatal("unknown snapshot version must error")
	}
}
