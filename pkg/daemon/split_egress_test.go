package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/service"
)

// memEgressHelper is the helper's gateway calls in memory.
type memEgressHelper struct {
	calls    []string
	resp     map[rootdpb.BridgeProbeOp]*rootdpb.BridgeProbeResponse
	err      error
	matched  []string
	notFound bool
}

func (m *memEgressHelper) BridgeProbe(_ context.Context, op rootdpb.BridgeProbeOp, slot uint32) (*rootdpb.BridgeProbeResponse, error) {
	m.calls = append(m.calls, fmt.Sprintf("%v %d", op, slot))
	if m.err != nil {
		return nil, m.err
	}
	if r := m.resp[op]; r != nil {
		return r, nil
	}
	return &rootdpb.BridgeProbeResponse{}, nil
}

func (m *memEgressHelper) MatchProcess(_ context.Context, pid uint32, local, remote string, paths []string) ([]string, bool, error) {
	m.calls = append(m.calls, fmt.Sprintf("match %d %s %s %v", pid, local, remote, paths))
	return m.matched, m.notFound, m.err
}

// fakeProber is the gateway's side of the self-test.
type fakeProber struct{ seen bool }

func (p *fakeProber) Probe(_ context.Context, r egress.ProbeRequest) (egress.ProbeResult, error) {
	return egress.ProbeResult{DNSSeen: p.seen, ProxySeen: p.seen}, nil
}

// TestHelperProbeNet (M1 PR 5b): the self-test runs as in single mode,
// each probe step one helper call; the helper's answers become the same
// errors the self-test reads.
func TestHelperProbeNet(t *testing.T) {
	ctx := context.Background()
	b := egress.Bridge{Name: "aerolvm0", GatewayIP: netip.MustParseAddr("10.88.0.1"), Subnet: netip.MustParsePrefix("10.88.0.0/16")}
	m := &memEgressHelper{}
	pn := helperProbeNet{h: m}
	if err := egress.SelfTest(ctx, &fakeProber{seen: true}, pn, b, 0); err != nil {
		t.Fatal(err)
	}
	want := []string{"BRIDGE_PROBE_OP_SETUP 0", "BRIDGE_PROBE_OP_SEND 0", "BRIDGE_PROBE_OP_CLOSE 0"}
	if !slices.Equal(m.calls, want) {
		t.Fatalf("calls %q", m.calls)
	}
	if err := egress.SelfTest(ctx, &fakeProber{}, pn, b, 1); !errors.Is(err, egress.ErrSelfTest) {
		t.Fatalf("no flow seen = %v", err)
	}
	m.resp = map[rootdpb.BridgeProbeOp]*rootdpb.BridgeProbeResponse{rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP: {BridgeAbsent: true}}
	if err := egress.SelfTest(ctx, &fakeProber{seen: true}, pn, b, 0); !errors.Is(err, egress.ErrBridgeAbsent) {
		t.Fatalf("absent = %v", err)
	}
	m.resp[rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP] = &rootdpb.BridgeProbeResponse{NotReady: "IPv6 on the bridge"}
	if err := egress.SelfTest(ctx, &fakeProber{seen: true}, pn, b, 0); !errors.Is(err, egress.ErrSelfTest) {
		t.Fatalf("not ready = %v", err)
	}
	m.resp = map[rootdpb.BridgeProbeOp]*rootdpb.BridgeProbeResponse{rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND: {SendError: "tcp: refused"}}
	env, err := pn.Setup(ctx, b, netip.Addr{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Send(ctx); err == nil || err.Error() != "tcp: refused" {
		t.Fatalf("send = %v", err)
	}
	m.err = errors.New("helper down")
	if err := env.Send(ctx); err == nil {
		t.Fatal("a failed call sent")
	}
	if err := env.Close(); err == nil {
		t.Fatal("a failed close closed")
	}
	if _, err := pn.Setup(ctx, b, netip.Addr{}, 0); err == nil {
		t.Fatal("a failed set-up set up")
	}
	if _, err := pn.Setup(ctx, b, netip.Addr{}, -1); err == nil {
		t.Fatal("a negative slot passed")
	}
}

// TestHelperMatch: the lookups' answers through the helper.
func TestHelperMatch(t *testing.T) {
	m := &memEgressHelper{matched: []string{"/usr/bin/curl"}}
	match := helperMatch(m)
	l, r := netip.MustParseAddrPort("10.88.0.5:40000"), netip.MustParseAddrPort("1.2.3.4:443")
	got, err := match(100, l, r, []string{"/usr/bin/curl", "/bin/sh"})
	if err != nil || !slices.Equal(got, []string{"/usr/bin/curl"}) || m.calls[0] != "match 100 10.88.0.5:40000 1.2.3.4:443 [/usr/bin/curl /bin/sh]" {
		t.Fatalf("= %v %v %q", got, err, m.calls)
	}
	m.notFound = true
	if _, err := match(100, l, r, []string{"/a"}); !errors.Is(err, procid.ErrNotFound) {
		t.Fatalf("not found = %v", err)
	}
	m.err = errors.New("refused")
	if _, err := match(100, l, r, []string{"/a"}); err == nil {
		t.Fatal("an error matched")
	}
	if _, err := match(0, l, r, []string{"/a"}); err == nil {
		t.Fatal("process 0 was asked about")
	}
}

// TestStartEgressProcidSplit: in split mode the lookup socket is open to
// every local user (sandboxd may not give it to the gateway's group), and
// the peer check still answers the gateway's uid alone.
func TestStartEgressProcidSplit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir, err := os.MkdirTemp("", "egs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "egress-procid.sock")
	svc := service.New(config.Config{}, testLogger(), openTestStore(t), nil, nil, nil, nil, nil, nil)
	// A gid this process may not chown to: in split mode it is never used.
	cfg := config.Config{EgressProcidSocket: sock, EgressGatewayUser: fmt.Sprintf("%d:%d", os.Getuid()+1, 1)}
	if err := startEgressProcid(ctx, cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil)), &memEgressHelper{}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode = %v, %v", st.Mode(), err)
	}
	// This process is not the gateway's uid: no answer.
	if _, err := (procid.Client{Path: sock}).Match("sb", netip.MustParseAddrPort("10.0.0.2:1"), netip.MustParseAddrPort("1.1.1.1:443"), []string{"/a"}); err == nil {
		t.Fatal("a peer other than the gateway was answered")
	}
}
