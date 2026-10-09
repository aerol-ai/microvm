package gatewayd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// newIdleDaemon builds a gateway that is never served: no background loop
// runs, so a test drives heartbeat, readFlows and saveNow one call at a time
// and may swap package seams without racing a loop.
func newIdleDaemon(t *testing.T, stateDir string, be egress.Backend) *Daemon {
	t.Helper()
	d, err := New(Config{
		StateDir: stateDir, DNSPort: 53054, ProxyPort: 15080,
		DNSUpstreams: []string{"127.0.0.1:1"}, AuditBuffer: 100, LearnMax: 64,
		HeartbeatInterval: time.Hour, FlowReadInterval: time.Hour, SnapshotDebounce: time.Hour,
	}, Deps{Backend: be}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func heartbeatEvent(t *testing.T, d *Daemon) egress.Event {
	t.Helper()
	for _, e := range d.Events().TakeAllForTest() {
		if e.Kind == "heartbeat" {
			return e
		}
	}
	t.Fatal("no heartbeat published")
	return egress.Event{}
}

// TestRestoreSnapshotEdges: a snapshot spec that no longer compiles keeps the
// whole snapshot out (the gateway waits for Sync), and bridges that can't be
// bound don't stop the specs from coming back restart-blocked.
func TestRestoreSnapshotEdges(t *testing.T) {
	for _, tc := range []struct {
		name     string
		snap     egress.Snapshot
		restored bool
	}{
		{"spec does not compile", egress.Snapshot{Specs: []egress.Spec{{IP: lo, AllowOut: []string{"pypi.org"}}}}, false},
		{"bridge does not bind", egress.Snapshot{
			Specs:   []egress.Spec{{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}},
			Bridges: []egress.Bridge{{Name: "v6", GatewayIP: netip.MustParseAddr("fd00::1")}},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			if err := egress.SaveSnapshot(filepath.Join(state, "snapshot.json"), tc.snap); err != nil {
				t.Fatal(err)
			}
			d := newIdleDaemon(t, state, egress.NewMemBackend())
			if got := len(d.Gateway().Specs()) == 1; got != tc.restored {
				t.Fatalf("specs = %+v, want restored=%v", d.Gateway().Specs(), tc.restored)
			}
			if tc.restored && !d.Gateway().IsBlocked("sb") {
				t.Fatal("a restored sandbox must stay restart-blocked until Sync")
			}
			if addrs := d.lns.Addrs(); len(addrs) != 0 {
				t.Fatalf("listeners = %v", addrs)
			}
		})
	}
}

// TestSetOperatorFloorWriteFails: a kernel that refuses the deny floor still
// leaves the new operator file in force for the DNS filter and the proxy.
func TestSetOperatorFloorWriteFails(t *testing.T) {
	be := egress.NewMemBackend()
	d := newIdleDaemon(t, t.TempDir(), be)
	op, err := operator.Parse([]byte("version: 1\ndeny_cidrs: [10.50.0.0/16]\n"))
	if err != nil {
		t.Fatal(err)
	}
	be.FailApply = errors.New("nft transaction refused")
	d.SetOperator(op)
	if d.OperatorHash() != op.Hash() {
		t.Fatal("the operator file must be applied even when the floor write fails")
	}
	if be.Len(egress.SetDenyFloor) != 0 {
		t.Fatal("a refused write must not reach the set")
	}
}

type failingListener struct {
	closed chan struct{}
	once   sync.Once
}

var errAccept = errors.New("accept: too many open files")

func (l *failingListener) Accept() (net.Conn, error) { return nil, errAccept }
func (l *failingListener) Addr() net.Addr            { return &net.UnixAddr{Name: "gw.sock", Net: "unix"} }
func (l *failingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// TestServeReturnsServerError: a UDS server that stops on its own ends Serve
// with its error, without waiting for the daemon's context.
func TestServeReturnsServerError(t *testing.T) {
	d := newIdleDaemon(t, t.TempDir(), egress.NewMemBackend())
	ln := &failingListener{closed: make(chan struct{})}
	// ctx stays live: a failed server must end Serve on its own, so the
	// process exits and is restarted rather than idling with nothing served.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Serve(ctx, ln) }()
	select {
	case err := <-done:
		if !errors.Is(err, errAccept) {
			t.Fatalf("Serve = %v, want the accept error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestProbeSeesDNSOverTCP (T41): a probe query that arrives over TCP counts
// as DNS seen, like one over UDP.
func TestProbeSeesDNSOverTCP(t *testing.T) {
	r := startDaemon(t, t.TempDir(), egress.NewMemBackend())
	ctx := context.Background()
	if err := r.client.SetBridges(ctx, []egress.Bridge{{Name: "lo", GatewayIP: lo}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Probe(ctx, egress.ProbeRequest{Bridge: "lo", Source: lo, Begin: true}); err != nil {
		t.Fatal(err)
	}
	r.d.noteProbe(net.IP{127, 0, 0}, false) // not an address: ignored
	m := new(dns.Msg)
	m.SetQuestion("aerolvm-probe.invalid.", dns.TypeA)
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	if _, _, err := c.Exchange(m, net.JoinHostPort(lo.String(), strconv.Itoa(int(r.cfg.DNSPort)))); err != nil {
		t.Fatal(err)
	}
	res, err := r.client.Probe(ctx, egress.ProbeRequest{Bridge: "lo", Source: lo, Wait: 50 * time.Millisecond})
	if err != nil || !res.DNSSeen || res.ProxySeen {
		t.Fatalf("probe = %+v, %v", res, err)
	}
}

// TestUnreadableRecordingStartsOver: a recording file that doesn't parse is
// not served and doesn't block new learning.
func TestUnreadableRecordingStartsOver(t *testing.T) {
	state := t.TempDir()
	d := newIdleDaemon(t, state, egress.NewMemBackend())
	if err := os.MkdirAll(filepath.Join(state, "learn"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "learn", "sb.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := d.learned("sb")
	if err != nil {
		t.Fatal(err)
	}
	var l egresspolicy.Learned
	if err := json.Unmarshal(raw, &l); err != nil || len(l.Entries) != 0 {
		t.Fatalf("learned = %s, %v", raw, err)
	}
	d.recorder("sb").ObserveHost("pypi.org", 443)
	if l := d.recorder("sb").Snapshot(); len(l.Entries) != 1 {
		t.Fatalf("entries = %+v", l.Entries)
	}
}

// TestRetainLearnedDiskEdges (review finding 13): no recordings directory is
// nothing to collect; a directory that can't be read or an orphan that can't
// be removed is reported, so sandboxd retries.
func TestRetainLearnedDiskEdges(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, learn string)
		wantErr bool
	}{
		{"no recordings", func(*testing.T, string) {}, false},
		{"recordings path is a file", func(t *testing.T, learn string) {
			if err := os.WriteFile(learn, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"orphan can't be removed", func(t *testing.T, learn string) {
			if os.Geteuid() == 0 {
				t.Skip("root removes from a read-only directory")
			}
			if err := os.MkdirAll(learn, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(learn, "orphan.json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(learn, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(learn, 0o700) })
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			d := newIdleDaemon(t, state, egress.NewMemBackend())
			tc.setup(t, filepath.Join(state, "learn"))
			if err := d.retainLearned([]string{"keep"}); (err != nil) != tc.wantErr {
				t.Fatalf("retainLearned = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// TestHeartbeatKernelWriteFailures (CEO D17): a rebuild, re-apply or retried
// block the kernel refuses is reported and retried by later heartbeats, never
// fatal to the gateway.
func TestHeartbeatKernelWriteFailures(t *testing.T) {
	refused := errors.New("nft transaction refused")
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, d *Daemon, be *egress.MemBackend)
		lost  bool
	}{
		{"rebuild refused", func(t *testing.T, d *Daemon, be *egress.MemBackend) {
			// Node-wide subnets make the rebuild rewrite the floor.
			if err := d.gw.SetNodeWide(egress.NodeWide{Subnets: []netip.Prefix{netip.MustParsePrefix("10.88.0.0/16")}}); err != nil {
				t.Fatal(err)
			}
			be.DropLayout()
		}, true},
		{"re-apply refused", func(t *testing.T, d *Daemon, be *egress.MemBackend) {
			if err := d.gw.Attach(egress.Spec{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}); err != nil {
				t.Fatal(err)
			}
			be.DropLayout()
		}, true},
		{"block retry refused", func(t *testing.T, d *Daemon, _ *egress.MemBackend) {
			// A restored block the kernel doesn't hold yet is a dirty write.
			if err := d.gw.Restore([]egress.Spec{{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}, Blocked: egress.BlockAll}}); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be := egress.NewMemBackend()
			d := newIdleDaemon(t, t.TempDir(), be)
			tc.setup(t, d, be)
			be.FailApply = refused
			d.heartbeat()
			if hb := heartbeatEvent(t, d); hb.LayoutOK == tc.lost || hb.LayoutLostSeen != tc.lost {
				t.Fatalf("heartbeat = %+v, want lost=%v", hb, tc.lost)
			}
			if tc.lost {
				return
			}
			if be.Has(egress.SetBlockedSrc, egress.Elem{Src: lo}) {
				t.Fatal("a refused block write must not reach the set")
			}
			be.FailApply = nil
			d.heartbeat()
			if !be.Has(egress.SetBlockedSrc, egress.Elem{Src: lo}) {
				t.Fatal("the next heartbeat must re-drive the block")
			}
		})
	}
}

// TestReadFlowsSkipsStrangers (C9, F3): flows from sources the gateway
// doesn't hold, or from a sandbox that isn't learning, produce no audit
// event and no recording; dedupe entries age out.
func TestReadFlowsSkipsStrangers(t *testing.T) {
	be := egress.NewMemBackend()
	d := newIdleDaemon(t, t.TempDir(), be)
	if err := d.gw.Attach(egress.Spec{ID: "sb", IP: lo, AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	stranger := netip.MustParseAddr("127.0.0.9")
	dst := netip.MustParseAddr("203.0.113.7")
	if err := be.Apply([]egress.Op{
		{Set: egress.SetRejectedFlows, Elems: []egress.Elem{{Src: stranger, Dst: dst, Port: 9000}}},
		{Set: egress.SetLearnFlows, Elems: []egress.Elem{{Src: stranger, Dst: dst, Port: 5432}, {Src: lo, Dst: dst, Port: 5432}}},
	}); err != nil {
		t.Fatal(err)
	}
	stale := egress.Elem{Src: lo, Dst: dst, Port: 1}
	d.statsMu.Lock()
	d.seenRejected[stale] = time.Now().Add(-10 * time.Minute)
	d.statsMu.Unlock()
	d.readFlows()
	for _, e := range d.Events().TakeAllForTest() {
		if e.Kind == "audit" {
			t.Fatalf("unexpected audit event %+v", e)
		}
	}
	if n := d.DeniedCounts()["firewall_reject"]; n != 0 {
		t.Fatalf("firewall_reject = %d", n)
	}
	d.statsMu.Lock()
	_, kept := d.seenRejected[stale]
	d.statsMu.Unlock()
	if kept {
		t.Fatal("a dedupe entry older than its window must be dropped")
	}
	d.learnMu.Lock()
	n := len(d.learn)
	d.learnMu.Unlock()
	if n != 0 {
		t.Fatalf("recordings = %d, want none", n)
	}
}

// TestSaveNowUnwritableState: snapshot and recording writes that fail are
// logged, and the recording stays unsaved so the next save tries again.
func TestSaveNowUnwritableState(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newIdleDaemon(t, filepath.Join(file, "state"), egress.NewMemBackend())
	d.recorder("ln").ObserveHost("pypi.org", 443)
	d.saveNow()
	d.saveMu.Lock()
	_, saved := d.savedLearn["ln"]
	d.saveMu.Unlock()
	if saved {
		t.Fatal("a recording that wasn't written must not be marked saved")
	}
}

// TestSaveNowForgetDuringWrite: a forget that lands while a recording is
// being written wins; the file doesn't outlive the save.
func TestSaveNowForgetDuringWrite(t *testing.T) {
	orig := createTemp
	t.Cleanup(func() { createTemp = orig })
	state := t.TempDir()
	d := newIdleDaemon(t, state, egress.NewMemBackend())
	d.recorder("gone").ObserveHost("pypi.org", 443)
	createTemp = func(dir, pattern string) (*os.File, error) {
		if err := d.forgetLearned("gone"); err != nil {
			t.Error(err)
		}
		return orig(dir, pattern)
	}
	d.saveNow()
	if _, err := os.Stat(filepath.Join(state, "learn", "gone.json")); !os.IsNotExist(err) {
		t.Fatalf("a forgotten recording must not stay on disk: %v", err)
	}
	d.saveMu.Lock()
	_, saved := d.savedLearn["gone"]
	d.saveMu.Unlock()
	if saved {
		t.Fatal("a forgotten recording's saved version must go with it")
	}
}

// TestWriteFileAtomicFailures: a write that fails at any step leaves neither
// the target nor a temp file behind.
func TestWriteFileAtomicFailures(t *testing.T) {
	orig := createTemp
	t.Cleanup(func() { createTemp = orig })
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"directory not writable", func(t *testing.T, dir string) {
			if os.Geteuid() == 0 {
				t.Skip("root writes into a read-only directory")
			}
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		}},
		{"write fails", func(t *testing.T, _ string) {
			createTemp = func(dir, pattern string) (*os.File, error) {
				f, err := orig(dir, pattern)
				if err != nil {
					return nil, err
				}
				_ = f.Close()
				return os.Open(f.Name()) // read-only
			}
		}},
		{"sync fails", func(t *testing.T, _ string) {
			// A pipe takes the write but can't be synced.
			createTemp = func(string, string) (*os.File, error) {
				r, w, err := os.Pipe()
				if err != nil {
					return nil, err
				}
				t.Cleanup(func() { _ = r.Close() })
				return w, nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			createTemp = orig
			dir := t.TempDir()
			tc.setup(t, dir)
			path := filepath.Join(dir, "rec.json")
			if err := writeFileAtomic(path, []byte(`{"entries":[]}`)); err == nil {
				t.Fatal("want an error")
			}
			createTemp = orig
			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				t.Errorf("left behind: %s", e.Name())
			}
		})
	}
}

// TestIdentifierAsksSandboxd (review finding 16): with a procid socket the
// proxy's identifier asks sandboxd about the sandbox; without one there is no
// identifier and per-binary flows are refused.
func TestIdentifierAsksSandboxd(t *testing.T) {
	if identifier("") != nil {
		t.Fatal("no socket must mean no identifier")
	}
	dir, err := os.MkdirTemp("", "egp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "procid.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	asked := make(chan string, 1)
	srv := &procid.Server{Authorize: func(id string) (int, []string, error) {
		asked <- id
		return 0, nil, errors.New("sandbox gone")
	}}
	go func() { _ = srv.Serve(ln) }()
	_, err = identifier(sock)("sb-7", 4242, netip.MustParseAddrPort("10.0.0.2:40000"),
		netip.MustParseAddrPort("203.0.113.7:443"), []string{"/usr/bin/curl"})
	if err == nil || !strings.Contains(err.Error(), "sandbox gone") {
		t.Fatalf("identify = %v, want sandboxd's refusal", err)
	}
	if got := <-asked; got != "sb-7" {
		t.Fatalf("sandboxd asked about %q", got)
	}
}
