package rootclient

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// kernelPorts is the node's host-port rules as the kernel keeps them: it
// outlives any helper process (rootd.HostPortHost in memory).
type kernelPorts struct {
	mu    sync.Mutex
	fwd   map[int]hostport.Target
	local []netip.Addr
	fail  error
}

func newKernelPorts() *kernelPorts {
	return &kernelPorts{fwd: map[int]hostport.Target{}, local: []netip.Addr{netip.MustParseAddr("10.0.0.10")}}
}

func (k *kernelPorts) Set(hp int, t *hostport.Target) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return k.fail
	}
	if t == nil {
		delete(k.fwd, hp)
	} else {
		k.fwd[hp] = *t
	}
	return nil
}

func (k *kernelPorts) Reconcile(desired map[int]hostport.Target) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail != nil {
		return k.fail
	}
	k.fwd = maps.Clone(desired)
	return nil
}

func (k *kernelPorts) IsLocal(a netip.Addr) (bool, error) { return slices.Contains(k.local, a), nil }

func (k *kernelPorts) state() map[int]hostport.Target {
	k.mu.Lock()
	defer k.mu.Unlock()
	return maps.Clone(k.fwd)
}

// hostPortHelper is the helper's real server over k and a network in
// memory, at sock.
func hostPortHelper(t *testing.T, sock string, net *memNet, k *kernelPorts) *rootd.Server {
	return realHelper(t, sock, func(o *rootd.Options) { o.Network, o.HostPorts = net, k })
}

func redirect(port int) hostport.Target {
	return hostport.Target{Kind: hostport.Redirect, RedirectPort: port}
}
func dnatTo(ap string, masq bool) hostport.Target {
	return hostport.Target{Kind: hostport.DNAT, Addr: netip.MustParseAddrPort(ap), Masquerade: masq}
}

// TestHostPortForwarderKeepsTheForwardersContract is the regression test
// for raw-TCP host-port forwarding in privilege mode split (a fragile
// area, like the host-port pool): through the agent's forwarder, the
// helper's real server and its rules, every step leaves the node's rules
// as single mode's in-process hostport.Forwarder leaves them, across an
// agent restart and a helper restart.
func TestHostPortForwarderKeepsTheForwardersContract(t *testing.T) {
	sock := sockPath(t)
	net, k := newMemNet(), newKernelPorts()
	srv := hostPortHelper(t, sock, net, k)
	c := newClient(t, sock)
	ip, err := func() (string, error) { _, ip, err := c.RealizeNetns(ctxT(t), "sb-1"); return ip, err }()
	if err != nil {
		t.Fatal(err)
	}
	f := NewHostPortForwarder(c, nil)
	owner := dnatTo(ip+":5432", false)
	peer := dnatTo("10.0.1.7:22001", true)
	for _, tc := range []struct {
		name string
		do   func() error
		want map[int]hostport.Target
	}{
		{"owner: the host port goes to the sandbox", func() error { return f.Ensure(22000, owner) }, map[int]hostport.Target{22000: owner}},
		{"the same again is a no-op", func() error { return f.Ensure(22000, owner) }, map[int]hostport.Target{22000: owner}},
		{"a stop: the port goes to sandboxd's wake listener", func() error { return f.Ensure(22000, redirect(21215)) }, map[int]hostport.Target{22000: redirect(21215)}},
		{"a wake: back to the sandbox", func() error { return f.Ensure(22000, owner) }, map[int]hostport.Target{22000: owner}},
		{"ingress: the hop to the owner node", func() error { return f.Ensure(22001, peer) }, map[int]hostport.Target{22000: owner, 22001: peer}},
		{"unexpose", func() error { return f.Remove(22001) }, map[int]hostport.Target{22000: owner}},
		{"unexpose again is a no-op", func() error { return f.Remove(22001) }, map[int]hostport.Target{22000: owner}},
	} {
		if err := tc.do(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := k.state(); !maps.Equal(got, tc.want) {
			t.Fatalf("%s: the node forwards %v, want %v", tc.name, got, tc.want)
		}
	}

	// An agent restart: the kernel keeps an exposure that went while
	// sandboxd was down (22002). The boot re-assert replays 22000, and the
	// prune removes only what was not re-asserted.
	if err := k.Set(22002, &owner); err != nil {
		t.Fatal(err)
	}
	f = NewHostPortForwarder(newClient(t, sock), nil)
	if err := f.Ensure(22000, owner); err != nil {
		t.Fatal(err)
	}
	if err := f.PruneUnasserted(); err != nil {
		t.Fatal(err)
	}
	if got := k.state(); !maps.Equal(got, map[int]hostport.Target{22000: owner}) {
		t.Fatalf("after the prune: %v", got)
	}

	// A helper restart: the new helper knows nothing in memory; the kernel
	// still has the rules, and a remove and a reconcile still act on them.
	srv.Shutdown(context.Background())
	hostPortHelper(t, sock, net, k)
	if err := f.Ensure(22003, redirect(21215)); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove(22000); err != nil {
		t.Fatal(err)
	}
	if got := k.state(); !maps.Equal(got, map[int]hostport.Target{22003: redirect(21215)}) {
		t.Fatalf("after a helper restart: %v", got)
	}

	// The routing rollback: no forwarding at all.
	if err := f.Reconcile(nil); err != nil || len(k.state()) != 0 {
		t.Fatalf("rollback: %v, %v", err, k.state())
	}
}

// TestHostPortForwarderNeverPrunesAConcurrentEnsure: a prune takes the
// asserted set and writes it under the forwarder's one lock, so an Ensure
// racing it is either in the set or written after it, never removed.
func TestHostPortForwarderNeverPrunesAConcurrentEnsure(t *testing.T) {
	sock := sockPath(t)
	k := newKernelPorts()
	hostPortHelper(t, sock, newMemNet(), k)
	f := NewHostPortForwarder(newClient(t, sock), nil)
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f.Ensure(22100+i, redirect(21215)); err != nil {
				t.Error(err)
			}
		}()
		if i%8 == 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := f.PruneUnasserted(); err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if got := k.state(); len(got) != 40 {
		t.Fatalf("the node forwards %d ports, want all 40 ensured", len(got))
	}
}

// TestHostPortForwarderRefusals: what the helper refuses comes back as the
// agent's refusal, and the node's rules do not change; a reconcile names
// what it left out, and only that.
func TestHostPortForwarderRefusals(t *testing.T) {
	sock := sockPath(t)
	net, k := newMemNet(), newKernelPorts()
	hostPortHelper(t, sock, net, k)
	c := newClient(t, sock)
	var skipped []int
	f := NewHostPortForwarder(c, func(p []int) { skipped = append(skipped, p...) })
	for _, bad := range []struct {
		hp int
		t  hostport.Target
	}{
		{22, redirect(21215)},                    // the node's SSH port
		{22000, dnatTo("10.88.0.77:80", false)},  // no slot holds it
		{22000, dnatTo("10.0.0.10:22000", true)}, // the node's own address
		{22000, dnatTo("10.88.0.1:22", false)},   // the bridge
		{22000, redirect(6443)},                  // not sandboxd's listener
		{22000, dnatTo("169.254.169.254:80", true)},
	} {
		err := f.Ensure(bad.hp, bad.t)
		var refused *RefusedError
		if !errors.As(err, &refused) {
			t.Errorf("%d -> %+v = %v, want a refusal", bad.hp, bad.t, err)
		}
	}
	for _, bad := range []hostport.Target{{}, {Kind: hostport.DNAT}} {
		if err := f.Ensure(22000, bad); err == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	if err := f.Ensure(0, redirect(21215)); err == nil || f.Remove(70000) == nil {
		t.Fatal("an invalid host port passed")
	}
	if len(k.state()) != 0 {
		t.Fatalf("a refused call wrote %v", k.state())
	}
	// A sandbox that went while the agent made its list.
	if err := f.Reconcile(map[int]hostport.Target{22000: redirect(21215), 22001: dnatTo("10.88.0.77:80", false)}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(skipped, []int{22001}) || len(k.state()) != 1 {
		t.Fatalf("skipped %v, forwards %v", skipped, k.state())
	}
	// The prune then asserts only what is forwarded.
	if err := f.PruneUnasserted(); err != nil || len(k.state()) != 1 {
		t.Fatalf("prune after a skip: %v %v", err, k.state())
	}
	// A kernel failure is the helper's, and asserts nothing.
	k.fail = errors.New("xtables lock")
	if err := f.Ensure(22005, redirect(21215)); err == nil {
		t.Fatal("a kernel failure was hidden")
	}
	if err := f.PruneUnasserted(); err == nil {
		t.Fatal("a kernel failure was hidden")
	}
	k.fail = nil
	if err := f.PruneUnasserted(); err != nil || k.state()[22005] != (hostport.Target{}) {
		t.Fatalf("a failed Ensure was asserted: %v %v", err, k.state())
	}
}

// TestHostPortForwarderNeedsItsFeature: against a helper that does not
// serve host ports (one release back), every call is refused unsent.
func TestHostPortForwarderNeedsItsFeature(t *testing.T) {
	sock := sockPath(t)
	h := &countingHelper{features: []string{rootdpb.FeatureEnsureHost}}
	serveCounting(t, sock, h)
	f := NewHostPortForwarder(newClient(t, sock), nil)
	for name, err := range map[string]error{
		"ensure":    f.Ensure(22000, redirect(21215)),
		"remove":    f.Remove(22000),
		"reconcile": f.Reconcile(nil),
		"prune":     f.PruneUnasserted(),
	} {
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s = %v, want ErrUnsupported", name, err)
		}
	}
	if seen := h.seen(); len(seen) != 0 {
		t.Fatalf("calls the helper does not serve were sent: %v", seen)
	}
}
