package gatewayd

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
)

var lo = netip.MustParseAddr("127.0.0.1")

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

type running struct {
	d      *Daemon
	be     *egress.MemBackend
	client *egress.Client
	cfg    Config
	cancel context.CancelFunc
	done   chan error
}

func startDaemon(t *testing.T, stateDir string, be *egress.MemBackend) *running {
	t.Helper()
	sockDir, _ := os.MkdirTemp("", "egd")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	cfg := Config{
		SocketPath: filepath.Join(sockDir, "gw.sock"), StateDir: stateDir,
		DNSPort: freePort(t), ProxyPort: freePort(t), DNSQPS: 1000,
		DNSUpstreams:      []string{"127.0.0.1:1"},
		HeartbeatInterval: time.Hour, FlowReadInterval: time.Hour, SnapshotDebounce: 10 * time.Millisecond,
		AuditBuffer: 100, LearnMax: 64,
	}
	d, err := New(cfg, Deps{Backend: be, OriginalDst: func(c net.Conn) (netip.AddrPort, error) {
		return netip.AddrPortFrom(netip.MustParseAddr("93.184.216.34"), 443), nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := socketListener(cfg.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{d: d, be: be, client: egress.NewClient(cfg.SocketPath), cfg: cfg, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- d.Serve(ctx, ln) }()
	t.Cleanup(func() { r.stop(t) })
	return r
}

func (r *running) stop(t *testing.T) {
	if r.cancel == nil {
		return
	}
	r.cancel()
	r.cancel = nil
	r.client.Close()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func dnsQuery(t *testing.T, port uint16, name string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("dns %s: %v", name, err)
	}
	return resp
}

func TestDaemonEndToEnd(t *testing.T) {
	r := startDaemon(t, t.TempDir(), egress.NewMemBackend())
	ctx := context.Background()
	if err := r.client.SetBridges(ctx, []egress.Bridge{{Name: "lo", GatewayIP: lo}}); err != nil {
		t.Fatal(err)
	}
	st, err := r.client.Ready(ctx)
	if err != nil || !st.Layout || len(st.Listeners) != 3 {
		t.Fatalf("Ready = %+v, %v", st, err)
	}
	if err := r.client.Attach(ctx, egress.Spec{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	evCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	events, err := r.client.Subscribe(evCtx)
	if err != nil {
		t.Fatal(err)
	}
	if resp := dnsQuery(t, r.cfg.DNSPort, "evil.example"); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode %d, want NXDOMAIN", resp.Rcode)
	}
	select {
	case ev := <-events:
		if ev.Kind != "audit" || ev.Result != "denied" || ev.Reason != "dns_not_allowed" || ev.SandboxID != "sb" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("denial never reached the event stream")
	}
	if got := r.d.DeniedCounts()["dns_not_allowed"]; got != 1 {
		t.Fatalf("denied counter = %d", got)
	}
	// Proxy denial on the bound proxy listener: an unlisted SNI.
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.cfg.ProxyPort))))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("not tls"))
	buf := make([]byte, 8)
	_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
	n, _ := c.Read(buf)
	_ = c.Close()
	if n == 0 || buf[0] != 0x15 {
		t.Fatalf("proxy must alert, got %x", buf[:n])
	}
}

func TestDaemonProbe(t *testing.T) {
	r := startDaemon(t, t.TempDir(), egress.NewMemBackend())
	ctx := context.Background()
	if err := r.client.SetBridges(ctx, []egress.Bridge{{Name: "lo", GatewayIP: lo}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Probe(ctx, egress.ProbeRequest{Bridge: "lo", Source: lo, Begin: true}); err != nil {
		t.Fatal(err)
	}
	if !r.be.Has(egress.SetFQDNSrc, egress.Elem{Src: lo}) {
		t.Fatal("probe source must be redirected for the window")
	}
	dnsQuery(t, r.cfg.DNSPort, "aerolvm-probe.invalid")
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(r.cfg.ProxyPort))))
	if err == nil {
		_ = c.Close()
	}
	res, err := r.client.Probe(ctx, egress.ProbeRequest{Bridge: "lo", Source: lo, Wait: time.Second})
	if err != nil || !res.DNSSeen || !res.ProxySeen {
		t.Fatalf("probe = %+v, %v", res, err)
	}
	if r.be.Has(egress.SetFQDNSrc, egress.Elem{Src: lo}) {
		t.Fatal("probe source must be detached after the window")
	}
	if _, err := r.client.Probe(ctx, egress.ProbeRequest{Source: netip.MustParseAddr("fd00::1"), Begin: true}); err == nil {
		t.Fatal("IPv6 probe source must be refused")
	}
	// A probe nobody answers times out with nothing seen.
	if _, err := r.client.Probe(ctx, egress.ProbeRequest{Source: netip.MustParseAddr("169.254.250.1"), Begin: true}); err != nil {
		t.Fatal(err)
	}
	res, err = r.client.Probe(ctx, egress.ProbeRequest{Source: netip.MustParseAddr("169.254.250.1"), Wait: 50 * time.Millisecond})
	if err != nil || res.DNSSeen || res.ProxySeen {
		t.Fatalf("silent probe = %+v, %v", res, err)
	}
}

// TestDaemonRestartRestoresSnapshot covers D13 + S5: the restarted gateway
// rebinds its bridges from the snapshot and holds every sandbox
// restart-blocked (in memory only) until sandboxd's Sync.
func TestDaemonRestartRestoresSnapshot(t *testing.T) {
	state := t.TempDir()
	be := egress.NewMemBackend()
	r := startDaemon(t, state, be)
	ctx := context.Background()
	if err := r.client.SetBridges(ctx, []egress.Bridge{{Name: "lo", GatewayIP: lo}}); err != nil {
		t.Fatal(err)
	}
	if err := r.client.Attach(ctx, egress.Spec{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	r.stop(t)
	if _, ok, err := egress.LoadSnapshot(filepath.Join(state, "snapshot.json")); !ok || err != nil {
		t.Fatalf("snapshot not written: %v %v", ok, err)
	}
	r2 := startDaemon(t, state, be)
	if !r2.d.Gateway().IsBlocked("sb") {
		t.Fatal("restored sandbox must be restart-blocked until Sync")
	}
	if be.Has(egress.SetBlockedSrc, egress.Elem{Src: lo}) {
		t.Fatal("restart block must not reach the kernel")
	}
	if st, err := r2.client.Ready(ctx); err != nil || len(st.Listeners) != 3 {
		t.Fatalf("listeners not rebound from the snapshot: %+v %v", st, err)
	}
	if err := r2.client.Sync(ctx, []egress.Spec{{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}}); err != nil {
		t.Fatal(err)
	}
	if r2.d.Gateway().IsBlocked("sb") {
		t.Fatal("Sync must lift the restart block")
	}
}

// TestDaemonTableLossRebuild covers CEO D17: a deleted table is rebuilt in
// one batch with the in-memory state re-applied, and the heartbeat reports it.
func TestDaemonTableLossRebuild(t *testing.T) {
	be := egress.NewMemBackend()
	r := startDaemon(t, t.TempDir(), be)
	ctx := context.Background()
	if err := r.client.Attach(ctx, egress.Spec{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	be.DropLayout()
	r.d.heartbeat()
	if !be.Has(egress.SetFQDNSrc, egress.Elem{Src: lo}) {
		t.Fatal("rebuild must re-apply the attached sandboxes")
	}
	var hb egress.Event
	for _, e := range r.d.Events().TakeAllForTest() {
		if e.Kind == "heartbeat" {
			hb = e
		}
	}
	if hb.LayoutOK || !hb.LayoutLostSeen || hb.FQDNSandboxes != 1 {
		t.Fatalf("heartbeat = %+v", hb)
	}
	// Totals for sandboxd's monotonic counters ride every heartbeat, tagged
	// with this process's start so a restart is unambiguous (P1-12).
	if hb.GatewayStart.IsZero() || hb.Denied == nil {
		t.Fatalf("heartbeat must carry totals and the gateway start: %+v", hb)
	}
	r.d.AckLayoutLost()
	r.d.heartbeat()
	for _, e := range r.d.Events().TakeAllForTest() {
		if e.Kind == "heartbeat" && (!e.LayoutOK || e.LayoutLostSeen) {
			t.Fatalf("after ack: %+v", e)
		}
	}
}

func TestDaemonFlowReads(t *testing.T) {
	be := egress.NewMemBackend()
	r := startDaemon(t, t.TempDir(), be)
	ctx := context.Background()
	if err := r.client.Attach(ctx, egress.Spec{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	learnIP := netip.MustParseAddr("127.0.0.2")
	if err := r.d.Gateway().Attach(egress.Spec{ID: "ln", IP: learnIP, Learn: true}); err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr("203.0.113.7")
	_ = be.Apply([]egress.Op{
		{Set: egress.SetRejectedFlows, Elems: []egress.Elem{{Src: lo, Dst: dst, Port: 9000}}},
		{Set: egress.SetLearnFlows, Elems: []egress.Elem{{Src: learnIP, Dst: dst, Port: 5432}}},
	})
	r.d.readFlows()
	r.d.readFlows() // a second read must not duplicate the audit event
	var rejects int
	for _, e := range r.d.Events().TakeAllForTest() {
		if e.Reason == "firewall_reject" && e.Destination == "203.0.113.7:9000" {
			rejects++
		}
	}
	if rejects != 1 {
		t.Fatalf("firewall_reject events = %d, want 1", rejects)
	}
	raw, err := r.client.Learned(ctx, "ln")
	if err != nil || len(raw) == 0 {
		t.Fatalf("learned = %s, %v", raw, err)
	}
	r.d.saveNow()
	if _, err := os.Stat(filepath.Join(r.cfg.StateDir, "learn", "ln.json")); err != nil {
		t.Fatalf("per-sandbox recording file (S9): %v", err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("SB_EGRESS_DNS_PORT", "5353")
	t.Setenv("SB_EGRESS_PROXY_PORT", "15081")
	t.Setenv("SB_EGRESS_DNS_UPSTREAMS", "10.0.0.2, 10.0.0.3:5353")
	t.Setenv("SB_EGRESS_DNS_QPS", "12.5")
	t.Setenv("SB_EGRESS_LEARNED_MAX", "7")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNSPort != 5353 || cfg.ProxyPort != 15081 || cfg.DNSQPS != 12.5 || cfg.LearnedMax != 7 {
		t.Fatalf("cfg = %+v", cfg)
	}
	if len(cfg.DNSUpstreams) != 2 || cfg.DNSUpstreams[0] != "10.0.0.2:53" || cfg.DNSUpstreams[1] != "10.0.0.3:5353" {
		t.Fatalf("upstreams = %v", cfg.DNSUpstreams)
	}
	if cfg.Traces.Enabled || cfg.Traces.ServiceName != "aerolvm-egress-gateway" {
		t.Fatalf("traces default off: %+v", cfg.Traces)
	}
	// sandboxd's tracing env turns the gateway's on too, endpoint alone
	// included, so one env file traces both processes (P1-15).
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://otel:4318")
	t.Setenv("SB_OTEL_TRACES_SAMPLE_RATIO", "0.5")
	if cfg, err = FromEnv(); err != nil || !cfg.Traces.Enabled || cfg.Traces.Endpoint != "http://otel:4318" || cfg.Traces.SampleRatio != 0.5 {
		t.Fatalf("traces = %+v err=%v", cfg.Traces, err)
	}
	t.Setenv("SB_OTEL_TRACES_ENABLED", "false")
	if cfg, _ = FromEnv(); cfg.Traces.Enabled {
		t.Fatal("an explicit false wins over the endpoint")
	}
	for name, val := range map[string]string{
		"SB_EGRESS_DNS_PORT":          "nope",
		"SB_EGRESS_PROXY_PORT":        "0",
		"SB_EGRESS_DNS_QPS":           "-1",
		"SB_EGRESS_LEARNED_MAX":       "x",
		"SB_OTEL_TRACES_ENABLED":      "maybe",
		"SB_OTEL_TRACES_SAMPLE_RATIO": "2",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, val)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("%s=%s: want error", name, val)
			}
		})
	}
	t.Setenv("SB_EGRESS_PROXY_PORT", "5353")
	if _, err := FromEnv(); err == nil {
		t.Fatal("equal ports must be refused")
	}
}

func TestSocketListenerAndGuard(t *testing.T) {
	if _, err := socketListener(""); err == nil {
		t.Fatal("no path and no activation must error")
	}
	dir, _ := os.MkdirTemp("", "egs")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sub", "gw.sock")
	ln, err := socketListener(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, %v (want 0600, CEO D22)", st.Mode().Perm(), err)
	}
	if g, err := guardFromOperatorFile(""); err != nil || g.Zone != nil {
		t.Fatal("no operator file = zero guard")
	}
	if _, err := guardFromOperatorFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("a missing operator file must fail the gateway start")
	}
	op := filepath.Join(dir, "op.yaml")
	_ = os.WriteFile(op, []byte("version: 1\ndeny_cidrs: [10.99.0.0/16]\n"), 0o600)
	if g, err := guardFromOperatorFile(op); err != nil || len(g.DenyFloor) != 1 {
		t.Fatalf("operator guard = %+v, %v", g, err)
	}
	if safeName("a/b.c") != "a_b_c" {
		t.Fatal("safeName")
	}
}

// TestLogDecisionFields (P1-15): every gateway decision logs sandbox_id,
// reason, rule and mode at debug, and costs nothing when debug is off.
func TestLogDecisionFields(t *testing.T) {
	var buf strings.Builder
	d := &Daemon{log: slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	d.logDecision("proxy", "sb-1", false, "evil.example:443", "sni_not_allowed", "", egress.ModeAllowlist)
	for _, want := range []string{`"sandbox_id":"sb-1"`, `"reason":"sni_not_allowed"`, `"rule":""`, `"mode":"allowlist"`, `"path":"proxy"`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("log %s missing %s", buf.String(), want)
		}
	}
	buf.Reset()
	d.log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	d.logDecision("dns", "sb-1", false, "evil.example", "host_not_allowed", "", egress.ModeAllowlist)
	if buf.Len() != 0 {
		t.Fatal("decisions must not log above debug")
	}
}
