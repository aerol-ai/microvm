package gatewayd

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/dnsfilter"
	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/internal/egress/proxy"
)

func TestDaemonDecisionAndOperatorEdges(t *testing.T) {
	r := startDaemon(t, t.TempDir(), egress.NewMemBackend())
	r.d.log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))

	r.d.onDNS(dnsfilter.Decision{SandboxID: probePrefix + "x"})
	r.d.onDNS(dnsfilter.Decision{
		SandboxID: "sb", Mode: egress.ModeLearn, Allowed: true, Name: "a.example",
		Answers: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
	})
	r.d.onDNS(dnsfilter.Decision{SandboxID: "sb", Allowed: false, Reason: "denied", Name: "b.example", Mode: egress.ModeAllowlist})
	r.d.onDNS(dnsfilter.Decision{SandboxID: "sb", Allowed: true})

	r.d.onProxy(proxy.Decision{SandboxID: probePrefix + "y"})
	r.d.onProxy(proxy.Decision{SandboxID: "sb", Host: "b.example", Port: 443, Allowed: false, Reason: "denied", Mode: egress.ModeAllowlist})
	r.d.onProxy(proxy.Decision{SandboxID: "sb", Host: "c.example", Port: 443, Allowed: true, Mode: egress.ModeLearn})
	r.d.logDecision("dns", "sb", false, "b.example", "denied", "", egress.ModeAllowlist)

	if err := os.WriteFile(r.d.snapshotPath(), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.d.restore(); err == nil {
		t.Fatal("a corrupt snapshot must not restore")
	}

	opPath := filepath.Join(t.TempDir(), "op.yaml")
	if err := os.WriteFile(opPath, []byte("version: 1\nupstream_proxy:\n  url: http://proxy.example:3128\n  auth_file: /no/such/auth\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	op, err := operator.Load(opPath)
	if err != nil {
		t.Fatal(err)
	}
	r.d.SetOperator(op)
}
