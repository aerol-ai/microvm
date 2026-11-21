package rootd

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// fakeHostPorts is a HostPortHost in memory: the node's forwards by host
// port, the node's own addresses, and every call.
type fakeHostPorts struct {
	mu      sync.Mutex
	fwd     map[int]hostport.Target
	local   []netip.Addr
	calls   []string
	failSet error
	failRec error
	failLoc error
}

func newFakeHostPorts() *fakeHostPorts {
	return &fakeHostPorts{fwd: map[int]hostport.Target{}, local: []netip.Addr{netip.MustParseAddr("10.0.0.10")}}
}

func (f *fakeHostPorts) Set(hp int, t *hostport.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("set %d %v", hp, t != nil))
	if f.failSet != nil {
		return f.failSet
	}
	if t == nil {
		delete(f.fwd, hp)
	} else {
		f.fwd[hp] = *t
	}
	return nil
}

func (f *fakeHostPorts) Reconcile(desired map[int]hostport.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("reconcile %d", len(desired)))
	if f.failRec != nil {
		return f.failRec
	}
	f.fwd = map[int]hostport.Target{}
	for hp, t := range desired {
		f.fwd[hp] = t
	}
	return nil
}

func (f *fakeHostPorts) IsLocal(a netip.Addr) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failLoc != nil {
		return false, f.failLoc
	}
	return slices.Contains(f.local, a), nil
}

func (f *fakeHostPorts) forwards() map[int]hostport.Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[int]hostport.Target{}
	for k, v := range f.fwd {
		out[k] = v
	}
	return out
}

func hostPortRig(t *testing.T) (*rig, rootdpb.RootHelperClient, *fakeNet, *fakeHostPorts) {
	t.Helper()
	fn, fh := newFakeNet(), newFakeHostPorts()
	r := newRig(t, func(_ *Config, o *Options) { o.Network, o.HostPorts = fn, fh })
	return r, rootdpb.NewRootHelperClient(r.conn), fn, fh
}

func sandboxFwd(hp uint32, addr string, port uint32) *rootdpb.HostPortForward {
	return &rootdpb.HostPortForward{HostPort: hp, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_SANDBOX, Address: addr, Port: port}
}

func peerFwd(hp uint32, addr string, port uint32) *rootdpb.HostPortForward {
	return &rootdpb.HostPortForward{HostPort: hp, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_PEER, Address: addr, Port: port}
}

func redirectFwd(hp uint32, port uint32) *rootdpb.HostPortForward {
	return &rootdpb.HostPortForward{HostPort: hp, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_REDIRECT, Port: port}
}

func setReq(f *rootdpb.HostPortForward) *rootdpb.HostPortRequest {
	return &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_SET, Forwards: []*rootdpb.HostPortForward{f}}
}

// TestHostPortForwards: each kind of target, as single mode's writer
// makes it, goes to the kernel as that writer's hostport.Target; a remove
// clears one port, whatever forwarded it; a reconcile makes the set exact.
func TestHostPortForwards(t *testing.T) {
	_, c, _, fh := hostPortRig(t)
	ctx := callCtx(t)
	sb, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	ip := sb.GetContainerIp()
	for _, f := range []*rootdpb.HostPortForward{
		sandboxFwd(22000, ip, 5432),
		peerFwd(22001, "10.0.1.7", 22001),
		redirectFwd(22002, 21215),
	} {
		if _, err := c.HostPort(ctx, setReq(f)); err != nil {
			t.Fatalf("%v: %v", f, err)
		}
	}
	want := map[int]hostport.Target{
		22000: {Kind: hostport.DNAT, Addr: netip.MustParseAddrPort(ip + ":5432")},
		22001: {Kind: hostport.DNAT, Addr: netip.MustParseAddrPort("10.0.1.7:22001"), Masquerade: true},
		22002: {Kind: hostport.Redirect, RedirectPort: 21215},
	}
	if got := fh.forwards(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("forwards %v, want %v", got, want)
	}
	if _, err := c.HostPort(ctx, &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_REMOVE, HostPort: 22001}); err != nil {
		t.Fatal(err)
	}
	if _, ok := fh.forwards()[22001]; ok {
		t.Fatal("removed port still forwarded")
	}
	// A reconcile: exact, and a sandbox target whose lease is gone is
	// skipped and named.
	resp, err := c.HostPort(ctx, &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE, Forwards: []*rootdpb.HostPortForward{
		sandboxFwd(22000, ip, 5432), sandboxFwd(22003, "10.88.0.77", 80), redirectFwd(22004, 21215),
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := fh.forwards()
	if !slices.Equal(resp.GetSkipped(), []uint32{22003}) || len(got) != 2 || got[22004].Kind != hostport.Redirect {
		t.Fatalf("reconcile: skipped %v, forwards %v", resp.GetSkipped(), got)
	}
	// None: no forwarding (the agent's rollback).
	if _, err := c.HostPort(ctx, &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE}); err != nil || len(fh.forwards()) != 0 {
		t.Fatalf("empty reconcile: %v, %v", err, fh.forwards())
	}
}

// TestHostPortRefusals: the helper never takes a port outside the node's
// host-port range, never hands one to an address that is not a leased
// sandbox's, to this node's own addresses or to another port of its own,
// and a refused reconcile writes nothing.
func TestHostPortRefusals(t *testing.T) {
	r, c, _, fh := hostPortRig(t)
	ctx := callCtx(t)
	sb, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	ip := sb.GetContainerIp()
	for _, bad := range []struct {
		name   string
		f      *rootdpb.HostPortForward
		code   codes.Code
		reason rootpolicy.Rule
	}{
		{"the node's SSH port", sandboxFwd(22, ip, 22), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"the kubelet's port", sandboxFwd(10250, ip, 80), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"the redirect listener's own port", redirectFwd(21215, 21215), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"the bridge's address (the node's)", sandboxFwd(22000, "10.88.0.1", 22), codes.InvalidArgument, rootpolicy.RuleAddress},
		{"a sandbox address nobody holds", sandboxFwd(22000, "10.88.0.77", 80), codes.PermissionDenied, rootpolicy.RuleLease},
		{"an address of another range", sandboxFwd(22000, "172.17.0.2", 80), codes.InvalidArgument, rootpolicy.RuleAddress},
		{"a sandbox, as a peer", peerFwd(22000, ip, 22000), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"this node's own address, as a peer", peerFwd(22000, "10.0.0.10", 22000), codes.PermissionDenied, rootpolicy.RuleHostPort},
		{"loopback, as a peer", peerFwd(22000, "127.0.0.1", 22000), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"the metadata endpoint, as a peer", peerFwd(22000, "169.254.169.254", 22000), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"a peer's own services", peerFwd(22000, "10.0.1.7", 22), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"a redirect to another port", redirectFwd(22000, 22), codes.InvalidArgument, rootpolicy.RuleHostPort},
		{"a redirect with an address", &rootdpb.HostPortForward{HostPort: 22000, Kind: rootdpb.HostPortKind_HOST_PORT_KIND_REDIRECT, Address: "10.0.1.7", Port: 21215}, codes.InvalidArgument, rootpolicy.RuleHostPort},
	} {
		_, err := c.HostPort(ctx, setReq(bad.f))
		wantRefusal(t, r, err, bad.code, string(bad.reason))
		// The same forward in a reconcile refuses the whole list; the
		// unleased sandbox is the one exception (skipped).
		if bad.reason == rootpolicy.RuleLease {
			continue
		}
		_, err = c.HostPort(ctx, &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE,
			Forwards: []*rootdpb.HostPortForward{redirectFwd(22999, 21215), bad.f}})
		wantRefusal(t, r, err, bad.code, string(bad.reason))
	}
	for _, bad := range []*rootdpb.HostPortRequest{
		{},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_SET},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_SET, Forwards: []*rootdpb.HostPortForward{redirectFwd(22000, 21215), redirectFwd(22001, 21215)}},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_SET, Forwards: []*rootdpb.HostPortForward{redirectFwd(22000, 21215)}, HostPort: 22000},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_SET, Forwards: []*rootdpb.HostPortForward{{HostPort: 22000}}},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_REMOVE, HostPort: 22000, Forwards: []*rootdpb.HostPortForward{redirectFwd(22000, 21215)}},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_REMOVE, HostPort: 80},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE, HostPort: 22000},
		{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE, Forwards: []*rootdpb.HostPortForward{redirectFwd(22000, 21215), redirectFwd(22000, 21215)}},
	} {
		if _, err := c.HostPort(ctx, bad); codeOf(err) != codes.InvalidArgument {
			t.Errorf("%v = %v, want InvalidArgument", bad, err)
		}
	}
	// More forwards than the range has ports.
	var many []*rootdpb.HostPortForward
	for p := range uint32(1002) {
		many = append(many, redirectFwd(22000+p%1001, 21215))
	}
	_, err = c.HostPort(ctx, &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE, Forwards: many})
	wantRefusal(t, r, err, codes.InvalidArgument, string(rootpolicy.RuleHostPort))
	if len(fh.forwards()) != 0 || slices.ContainsFunc(fh.calls, func(c string) bool { return c != "" }) {
		t.Fatalf("a refused call wrote: %v %v", fh.forwards(), fh.calls)
	}
}

// TestHostPortFailures: the kernel's failures are the helper's (Internal),
// a forwarder that cannot open is FailedPrecondition, and a helper with
// no network serves no host-port call.
func TestHostPortFailures(t *testing.T) {
	_, c, fn, fh := hostPortRig(t)
	ctx := callCtx(t)
	sb, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	fh.failSet = errors.New("xtables lock")
	_, err = c.HostPort(ctx, setReq(redirectFwd(22000, 21215)))
	wantCode(t, err, codes.Internal)
	_, err = c.HostPort(ctx, &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_REMOVE, HostPort: 22000})
	wantCode(t, err, codes.Internal)
	fh.failRec = errors.New("xtables lock")
	_, err = c.HostPort(ctx, &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE})
	wantCode(t, err, codes.Internal)
	fh.failLoc = errors.New("netlink")
	_, err = c.HostPort(ctx, setReq(peerFwd(22000, "10.0.1.7", 22000)))
	wantCode(t, err, codes.Internal)
	fn.fail["lease"] = errors.New("lease folder")
	_, err = c.HostPort(ctx, setReq(sandboxFwd(22000, sb.GetContainerIp(), 80)))
	wantCode(t, err, codes.Internal)

	// The kernel's forwarder cannot open: FailedPrecondition, tried again
	// on the next call.
	opens := 0
	h := &hostPortCalls{net: newNetwork(testConfig(t), newFakeNet(), &keyedLocks{}), bounds: rootpolicy.HostPortBounds{RangeStart: 22000, RangeEnd: 23000, RedirectPort: 21215},
		locks: &keyedLocks{}, open: func() (HostPortHost, error) {
			if opens++; opens == 1 {
				return nil, errors.New("no iptables")
			}
			return newFakeHostPorts(), nil
		}}
	_, err = h.hostPort(ctx, setReq(redirectFwd(22000, 21215)))
	var fe *fileError
	if !errors.As(err, &fe) || fe.code != codes.FailedPrecondition {
		t.Fatalf("first open = %v", err)
	}
	if _, err := h.hostPort(ctx, setReq(redirectFwd(22000, 21215))); err != nil {
		t.Fatalf("second open = %v", err)
	}
	// Settings that are no range: FailedPrecondition.
	h.bounds = rootpolicy.HostPortBounds{}
	if _, err := h.hostPort(ctx, setReq(redirectFwd(22000, 21215))); !errors.As(err, &fe) || fe.code != codes.FailedPrecondition {
		t.Fatalf("no range = %v", err)
	}

	// No network configuration: not served.
	r2 := newRig(t, nil)
	_, err = rootdpb.NewRootHelperClient(r2.conn).HostPort(ctx, setReq(redirectFwd(22000, 21215)))
	wantCode(t, err, codes.Unimplemented)
}
