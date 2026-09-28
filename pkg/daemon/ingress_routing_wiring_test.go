package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
