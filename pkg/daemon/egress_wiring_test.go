package daemon

import (
	"context"
	"expvar"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

func TestFirstHost(t *testing.T) {
	if gw, ok := firstHost("10.88.0.0/16"); !ok || gw.String() != "10.88.0.1" {
		t.Fatalf("firstHost = %s %v", gw, ok)
	}
	for _, bad := range []string{"nope", "fd00::/8"} {
		if _, ok := firstHost(bad); ok {
			t.Fatalf("%s must not yield a gateway", bad)
		}
	}
}

// TestWireEgressGatewaySkips: off, privileged or non-worker nodes never wire
// the gateway client (nil service is never touched on those paths).
func TestWireEgressGatewaySkips(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, cfg := range []config.Config{
		{EgressFQDNEnabled: false},
		{EgressFQDNEnabled: true, ContainerPrivileged: true},
	} {
		wireEgressGateway(context.Background(), cfg, nil, nil, log)
	}
}

// TestWireEgressOperator: unset is a no-op; a file is loaded for every
// runtime, and an invalid one refuses creates until fixed.
func TestWireEgressOperator(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	wireEgressOperator(context.Background(), config.Config{}, nil, log)

	svc := service.New(config.Config{}, log, nil, nil, nil, nil, nil, nil, nil)
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	if err := os.WriteFile(path, []byte("version: 1\ndefault_policy: {mode: sometimes}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wireEgressOperator(ctx, config.Config{EgressOperatorFile: path}, svc, log)
	if v := expvar.Get("aerolvm_egress_operator_config_load_failures_total"); v == nil || v.String() != "1" {
		t.Fatalf("the invalid boot load must be wired and counted, got %v", v)
	}
}

// TestWireEgressOperatorIsolateGuard: the isolate guard follows the file.
func TestWireEgressOperatorIsolateGuard(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, log, nil, nil, nil, nil, nil, nil, nil)
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	// A public range: strict isolate would otherwise allow it.
	if err := os.WriteFile(path, []byte("version: 1\ndeny_cidrs: [203.0.113.0/24]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(func() { pkgisolate.SetEgressDialGuard(egresspolicy.DialGuard{}) })
	wireEgressOperator(ctx, config.Config{EgressOperatorFile: path}, svc, log)
	g := pkgisolate.EgressDialGuard()
	if err := g.Check(nil, egresspolicy.DialTarget{Addr: netip.MustParseAddrPort("203.0.113.9:443")}); err == nil || !g.Strict {
		t.Fatalf("isolate must refuse the operator floor and stay strict: %v", err)
	}
}
