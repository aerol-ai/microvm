package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/internal/service"
)

type fakeRoutingService struct {
	startErr, commitErr, rollbackErr error
	calls                            []string
	gotOwnerReasserted               bool
	gotOpts                          service.IngressRoutingOptions
}

func (f *fakeRoutingService) StartIngressProxyRouting(_ context.Context, opts service.IngressRoutingOptions) (*service.IngressRouting, error) {
	f.calls = append(f.calls, "start")
	f.gotOpts = opts
	if f.startErr != nil {
		return nil, f.startErr
	}
	return &service.IngressRouting{Owner: routedns.NewOwnerTable(), SelfNodeID: "n1", ClusterMode: true}, nil
}

func (f *fakeRoutingService) CommitIngressProxyRouting(_ context.Context, _ *service.IngressRouting, owner bool) error {
	f.calls = append(f.calls, "commit")
	f.gotOwnerReasserted = owner
	return f.commitErr
}

func (f *fakeRoutingService) RollbackIngressProxyRouting(context.Context, service.HostPortForwarder) error {
	f.calls = append(f.calls, "rollback")
	return f.rollbackErr
}

type nopForwarder struct{}

func (nopForwarder) Ensure(int, hostport.Target) error       { return nil }
func (nopForwarder) Remove(int) error                        { return nil }
func (nopForwarder) PruneUnasserted() error                  { return nil }
func (nopForwarder) Reconcile(map[int]hostport.Target) error { return nil }

// The rollout matrix (review 6A / T7). Inputs:
//   - the flag this boot;
//   - the marker (did the last boot engage?);
//   - the node role;
//   - start/commit/rollback failures.
//
// Checked: exactly which steps run, whether the router is mounted, and
// what the marker says afterwards (so the next boot does the right thing).
func TestIngressRoutingBootMatrix(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name        string
		flag        bool
		marker      string // "", "true", "false"
		role        string
		svc         fakeRoutingService
		wantCalls   string
		wantEngaged bool
		wantMarker  string
	}{
		{name: "off, never on", flag: false, marker: "", wantCalls: "", wantMarker: ""},
		{name: "off, was off", flag: false, marker: "false", wantCalls: "", wantMarker: "false"},
		{name: "off, was on: rollback", flag: false, marker: "true", wantCalls: "rollback", wantMarker: "false"},
		{name: "off, was on, rollback fails: retry next boot", flag: false, marker: "true", svc: fakeRoutingService{rollbackErr: boom}, wantCalls: "rollback", wantMarker: "true"},
		{name: "on: engage + commit", flag: true, wantCalls: "start,commit", wantEngaged: true, wantMarker: "true"},
		{name: "on, was on: re-engage", flag: true, marker: "true", wantCalls: "start,commit", wantEngaged: true, wantMarker: "true"},
		{name: "on, refused: stay on caddy", flag: true, svc: fakeRoutingService{startErr: boom}, wantCalls: "start", wantMarker: ""},
		// Live finding: a refusal left the previous boot's static routes in
		// Caddy with no responder behind them. It must roll back.
		{name: "on, refused after a flag-on boot: roll back", flag: true, marker: "true", svc: fakeRoutingService{startErr: boom}, wantCalls: "start,rollback", wantMarker: "false"},
		{name: "on, refused after a flag-on boot, rollback fails: retry next boot", flag: true, marker: "true", svc: fakeRoutingService{startErr: boom, rollbackErr: boom}, wantCalls: "start,rollback", wantMarker: "true"},
		{name: "on, commit fails: roll back", flag: true, svc: fakeRoutingService{commitErr: boom}, wantCalls: "start,commit,rollback", wantMarker: "false"},
		{name: "on, commit and rollback fail: retry next boot", flag: true, svc: fakeRoutingService{commitErr: boom, rollbackErr: boom}, wantCalls: "start,commit,rollback", wantMarker: "true"},
		{name: "on, pure server: nothing to route", flag: true, role: "server", wantCalls: "", wantMarker: ""},
		{name: "on, ingress-only", flag: true, role: "ingress", wantCalls: "start,commit", wantEngaged: true, wantMarker: "true"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.Config{
				DBPath: filepath.Join(dir, "sandboxd.db"), IngressProxyRouting: tc.flag, NodeRole: tc.role,
				RouteDNSAddr: "127.0.0.1:53053", InternalIngressAddr: "127.0.0.1:21213", ToolboxPort: 2280, HostPortRedirectPort: 21215,
			}
			marker := ingressRoutingMarkerPath(cfg)
			if tc.marker != "" {
				if err := os.WriteFile(marker, []byte(tc.marker+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			svc := tc.svc
			b := startIngressRouting(context.Background(), cfg, &svc, nopForwarder{}, logger)
			if b.engaged() {
				if hr := b.hostRoutes(); hr == nil || hr.Owner == nil || hr.SelfNodeID != "n1" || !hr.ClusterMode {
					t.Fatalf("host routes = %+v", hr)
				}
			}
			b.commit(context.Background(), &svc, true)
			if got := strings.Join(svc.calls, ","); got != tc.wantCalls {
				t.Fatalf("calls = %q, want %q", got, tc.wantCalls)
			}
			if b.engaged() != tc.wantEngaged {
				t.Fatalf("engaged = %v, want %v", b.engaged(), tc.wantEngaged)
			}
			if !tc.wantEngaged && b.hostRoutes() != nil {
				t.Fatal("router mounted while not engaged")
			}
			raw, _ := os.ReadFile(marker)
			if got := strings.TrimSpace(string(raw)); got != tc.wantMarker {
				t.Fatalf("marker = %q, want %q", got, tc.wantMarker)
			}
			if strings.HasPrefix(tc.wantCalls, "start") {
				o := svc.gotOpts
				if o.Static.RouteDNSAddr != cfg.RouteDNSAddr || o.Static.RouterAddr != cfg.InternalIngressAddr ||
					o.Static.LocalIP != "127.0.0.1" || o.RedirectAddr != ":21215" || o.Forwarder == nil {
					t.Fatalf("start options = %+v", o)
				}
			}
			if strings.Contains(tc.wantCalls, "commit") && !svc.gotOwnerReasserted {
				t.Fatal("ownerReasserted not passed through")
			}
		})
	}
}

// Live finding: bootstrap restarts sandboxd back to back, so a process can
// be refused because it is being stopped. That must not roll back the
// previous boot's routing.
func TestIngressRoutingRefusedWhileShuttingDownDoesNotRollBack(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "sandboxd.db"), IngressProxyRouting: true, HostPortRedirectPort: 21215}
	marker := ingressRoutingMarkerPath(cfg)
	if err := os.WriteFile(marker, []byte("true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc := &fakeRoutingService{startErr: context.Canceled}
	b := startIngressRouting(ctx, cfg, svc, nopForwarder{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := strings.Join(svc.calls, ","); got != "start" || b.engaged() {
		t.Fatalf("calls = %q engaged=%v, want start only", got, b.engaged())
	}
	if raw, _ := os.ReadFile(marker); strings.TrimSpace(string(raw)) != "true" {
		t.Fatalf("marker = %q, want it kept", raw)
	}
}

func TestIngressRoutingMarkerWriteFailureIsLoggedNotFatal(t *testing.T) {
	cfg := config.Config{DBPath: "/nonexistent-dir/for/sure/sandboxd.db", IngressProxyRouting: true}
	svc := &fakeRoutingService{}
	b := startIngressRouting(context.Background(), cfg, svc, nopForwarder{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !b.engaged() {
		t.Fatal("a marker write failure must not block engaging")
	}
	var nilBoot *ingressRoutingBoot
	if nilBoot.engaged() || nilBoot.hostRoutes() != nil {
		t.Fatal("nil boot")
	}
	nilBoot.commit(context.Background(), svc, true)
}

func TestNewHostPortForwarderIsNeverATypedNil(t *testing.T) {
	fwd := newHostPortForwarder(slog.New(slog.NewTextHandler(io.Discard, nil)))
	// On a host without iptables (macOS CI, containers) it's a true nil
	// interface; with iptables it's a forwarder. Never a typed nil.
	if fwd != nil {
		if f, ok := fwd.(*hostport.Forwarder); ok && f == nil {
			t.Fatal("typed nil forwarder")
		}
	}
}

// levelRecorder keeps every record at or above Debug, so a test can assert
// what a boot said and at which level.
type levelRecorder struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (r *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *levelRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	r.recs = append(r.recs, rec)
	r.mu.Unlock()
	return nil
}
func (r *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *levelRecorder) WithGroup(string) slog.Handler      { return r }

func (r *levelRecorder) at(min slog.Level) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.recs {
		if rec.Level >= min {
			out = append(out, rec.Level.String()+" "+rec.Message)
		}
	}
	return out
}

// The flag defaults on (plans/cluster-phase-2.md §4.3), so a node without a
// Caddy domain (local mode, IP mode, Caddy off) must not pay for it: config
// clears the flag, no engage is attempted, iptables is not probed, and
// nothing above Debug is logged. Before the flip such a node logged an
// ERROR refusal on every boot.
func TestIngressRoutingNotApplicableWithoutADomainIsQuiet(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"IP mode", map[string]string{"SB_DOMAIN": "", "SB_PUBLIC_HOST": "203.0.113.10"}},
		{"IP mode, flag set on", map[string]string{"SB_DOMAIN": "", "SB_PUBLIC_HOST": "203.0.113.10", "SB_INGRESS_PROXY_ROUTING": "true"}},
		{"Caddy off", map[string]string{"SB_DOMAIN": "sandbox.example.com", "SB_ENABLE_CADDY": "false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_DB_PATH", filepath.Join(t.TempDir(), "state.db"))
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.IngressProxyRouting {
				t.Fatal("config left the flag on for a node without a Caddy domain")
			}
			rec := &levelRecorder{}
			logger := slog.New(rec)
			if fwd := hostPortForwarderFor(cfg, logger); fwd != nil {
				t.Fatal("the host-port forwarder was built (iptables probed) on a node the flag does not apply to")
			}
			svc := &fakeRoutingService{}
			b := startIngressRouting(context.Background(), cfg, svc, nil, logger)
			b.commit(context.Background(), svc, true)
			if len(svc.calls) != 0 || b.engaged() {
				t.Fatalf("calls = %v engaged = %v, want nothing attempted", svc.calls, b.engaged())
			}
			if loud := rec.at(slog.LevelInfo); len(loud) != 0 {
				t.Fatalf("logged above Debug: %v", loud)
			}
			if dbg := rec.at(slog.LevelDebug); len(dbg) != 1 || !strings.Contains(dbg[0], "not applicable") {
				t.Fatalf("debug records = %v, want the one not-applicable line", dbg)
			}
		})
	}
}

// The contrast: a node WITH a domain that lacks a prerequisite still
// refuses loudly, because there the operator is missing something real.
func TestIngressRoutingRefusalWithADomainIsLoud(t *testing.T) {
	cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), IngressProxyRouting: true,
		EnableCaddy: true, Domain: "sandbox.example.com", HostPortRedirectPort: 21215}
	rec := &levelRecorder{}
	svc := &fakeRoutingService{startErr: errors.New("ingress proxy routing needs kernel host-port forwarding (iptables), unavailable on this host")}
	b := startIngressRouting(context.Background(), cfg, svc, nil, slog.New(rec))
	if b.engaged() || strings.Join(svc.calls, ",") != "start" {
		t.Fatalf("calls = %v engaged = %v, want one refused start", svc.calls, b.engaged())
	}
	errs := rec.at(slog.LevelError)
	if len(errs) != 1 || !strings.Contains(errs[0], "ingress proxy routing refused") {
		t.Fatalf("error records = %v, want the refusal", errs)
	}
}

// A previous flag-on boot leaves the marker, and the rollback needs the
// forwarder to remove its kernel rules even though the flag is now off.
func TestHostPortForwarderForBuildsItForARollback(t *testing.T) {
	cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}
	if err := os.WriteFile(ingressRoutingMarkerPath(cfg), []byte("false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := &levelRecorder{}
	if fwd := hostPortForwarderFor(cfg, slog.New(rec)); fwd != nil || len(rec.at(slog.LevelDebug)) != 0 {
		t.Fatalf("marker false: forwarder %v, logs %v; want neither", fwd, rec.at(slog.LevelDebug))
	}
	if err := os.WriteFile(ingressRoutingMarkerPath(cfg), []byte("true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Built (or, without iptables, a warning that it could not be): either
	// way it was attempted.
	fwd := hostPortForwarderFor(cfg, slog.New(rec))
	if fwd == nil && len(rec.at(slog.LevelWarn)) == 0 {
		t.Fatal("marker true: the forwarder was neither built nor attempted")
	}
}
