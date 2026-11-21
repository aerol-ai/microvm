package rootd

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// fakeNet is a NetworkHost in memory: namespaces by path, each with what
// Inspect reports. It records every call, and a test can make a step fail
// or hold it.
type fakeNet struct {
	mu     sync.Mutex
	ns     map[string]NetnsState
	calls  []string
	next   int
	fail   map[string]error
	ipFor  map[string]string // Realize answers this address for a name
	hold   chan struct{}     // Realize waits on it when set
	active atomic.Int32      // Realize/Remove calls running now
	peak   atomic.Int32
}

func newFakeNet() *fakeNet {
	return &fakeNet{ns: map[string]NetnsState{}, fail: map[string]error{}, ipFor: map[string]string{}}
}

func (f *fakeNet) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeNet) failing(step string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[step]
}

func (f *fakeNet) set(path string, st NetnsState) {
	f.mu.Lock()
	f.ns[path] = st
	f.mu.Unlock()
}

func (f *fakeNet) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeNet) Subnet() netip.Prefix { return netip.MustParsePrefix("10.88.0.0/16") }

func (f *fakeNet) EnsureHost() error {
	f.record("ensure")
	return f.failing("ensure")
}

func (f *fakeNet) Inspect(path string) (NetnsState, error) {
	if err := f.failing("inspect"); err != nil {
		return NetnsState{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ns[path], nil
}

func (f *fakeNet) enter() func() {
	n := f.active.Add(1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	return func() { f.active.Add(-1) }
}

func (f *fakeNet) Realize(_ context.Context, name, path string) (string, error) {
	defer f.enter()()
	f.record("realize " + name)
	if f.hold != nil {
		<-f.hold
	}
	if err := f.failing("realize"); err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.ipFor[name]
	if !ok {
		f.next++
		ip = fmt.Sprintf("10.88.0.%d", f.next+1)
	}
	f.ns[path] = NetnsState{Exists: true, IPv4: []string{ip}}
	return ip, nil
}

func (f *fakeNet) Remove(_ context.Context, name, path, ip string) error {
	defer f.enter()()
	f.record("remove " + name + " " + ip)
	if err := f.failing("remove"); err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.ns, path)
	f.mu.Unlock()
	return nil
}

func (f *fakeNet) DisableIPv6(path string) error {
	f.record("ipv6 " + path)
	return f.failing("ipv6")
}

func netRig(t *testing.T, fn *fakeNet) (*rig, rootdpb.RootHelperClient) {
	t.Helper()
	r := newRig(t, func(_ *Config, o *Options) { o.Network = fn })
	return r, rootdpb.NewRootHelperClient(r.conn)
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("err %v, want %v", err, code)
	}
}

// wantRefusal: refused with code and reason, and the refusal recorded.
func wantRefusal(t *testing.T, r *rig, err error, code codes.Code, reason string) {
	t.Helper()
	wantCode(t, err, code)
	if got, ok := rootdpb.RefusalReason(err); !ok || got != reason {
		t.Fatalf("refusal reason %q (%v), want %q", got, ok, reason)
	}
	refs := r.refused()
	if len(refs) == 0 || refs[len(refs)-1].Reason != reason {
		t.Fatalf("refusals %+v, want one with %q", refs, reason)
	}
}

func TestEnsureHostNetwork(t *testing.T) {
	fn := newFakeNet()
	_, c := netRig(t, fn)
	resp, err := c.EnsureHostNetwork(callCtx(t), &rootdpb.EnsureHostNetworkRequest{})
	if err != nil || resp.GetSubnet() != "10.88.0.0/16" {
		t.Fatalf("EnsureHostNetwork = %v, %v", resp, err)
	}
	fn.fail["ensure"] = errors.New("sysctl read-only")
	_, err = c.EnsureHostNetwork(callCtx(t), &rootdpb.EnsureHostNetworkRequest{})
	wantCode(t, err, codes.Internal)
}

// TestRealizeNetns: a fresh namespace is built at the helper's own path,
// and every later call for it, a retry whose answer was lost included,
// gets the same answer without a second build.
func TestRealizeNetns(t *testing.T) {
	fn := newFakeNet()
	r, c := netRig(t, fn)
	path := r.cfg.Policy.NetnsDir + "/sb-1"
	first, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
	if err != nil || first.GetNetnsPath() != path || first.GetContainerIp() != "10.88.0.2" {
		t.Fatalf("RealizeNetns = %v, %v", first, err)
	}
	for i := 0; i < 3; i++ {
		again, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
		if err != nil || again.GetContainerIp() != first.GetContainerIp() || again.GetNetnsPath() != path {
			t.Fatalf("repeat %d = %v, %v", i, again, err)
		}
	}
	if got := fn.recorded(); !slices.Equal(got, []string{"realize sb-1"}) {
		t.Fatalf("calls %v: a repeat built again", got)
	}
}

// TestRealizeNetnsHalfMade: a namespace with no sandbox address (a build
// cut short, or one whose address is outside the range) is removed whole,
// CNI DEL included, and built again.
func TestRealizeNetnsHalfMade(t *testing.T) {
	for _, st := range []NetnsState{{Exists: true}, {Exists: true, IPv4: []string{"10.88.0.1"}}, {Exists: true, IPv4: []string{"192.168.4.4"}}} {
		fn := newFakeNet()
		r, c := netRig(t, fn)
		fn.set(r.cfg.Policy.NetnsDir+"/sb-1", st)
		resp, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
		if err != nil || resp.GetContainerIp() != "10.88.0.2" {
			t.Fatalf("%+v: RealizeNetns = %v, %v", st, resp, err)
		}
		if got := fn.recorded(); !slices.Equal(got, []string{"remove sb-1 ", "realize sb-1"}) {
			t.Fatalf("%+v: calls %v", st, got)
		}
	}
}

func TestRealizeNetnsFails(t *testing.T) {
	t.Run("the half-made one cannot be cleared", func(t *testing.T) {
		fn := newFakeNet()
		r, c := netRig(t, fn)
		fn.set(r.cfg.Policy.NetnsDir+"/sb-1", NetnsState{Exists: true})
		fn.fail["remove"] = errors.New("busy")
		_, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
		wantCode(t, err, codes.Internal)
		if got := fn.recorded(); slices.Contains(got, "realize sb-1") {
			t.Fatalf("built over a namespace it could not clear: %v", got)
		}
	})
	t.Run("the build fails", func(t *testing.T) {
		fn := newFakeNet()
		_, c := netRig(t, fn)
		fn.fail["realize"] = errors.New("cni add: exit status 1")
		_, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
		wantCode(t, err, codes.Internal)
	})
	t.Run("the kernel cannot be read", func(t *testing.T) {
		fn := newFakeNet()
		_, c := netRig(t, fn)
		fn.fail["inspect"] = errors.New("netlink: permission denied")
		_, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
		wantCode(t, err, codes.Internal)
	})
	t.Run("CNI hands out an address outside the range: undone, never answered", func(t *testing.T) {
		fn := newFakeNet()
		r, c := netRig(t, fn)
		fn.ipFor["sb-1"] = "172.17.0.5"
		_, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
		wantCode(t, err, codes.Internal)
		if got := fn.recorded(); !slices.Equal(got, []string{"realize sb-1", "remove sb-1 "}) {
			t.Fatalf("calls %v", got)
		}
		if refs := r.refused(); len(refs) != 0 {
			t.Fatalf("CNI's own answer counted as the agent's refusal: %+v", refs)
		}
	})
}

// TestNetworkCallsRefuse is the broken-agent suite for the network calls
// (plans/security-gaps-m1-m4.md §3.6): every request that names something
// other than a sandbox's namespace, or an address other than a sandbox's,
// is refused before the kernel is touched, and recorded.
func TestNetworkCallsRefuse(t *testing.T) {
	bad := []string{"", "..", ".", "../../etc", "sb/../../proc/1/ns", "/run/netns/sb-1", "sb-1/x", "sb-1\x00", "sb 1", "sb.1", strings.Repeat("a", 129)}
	calls := map[string]func(c rootdpb.RootHelperClient, name string) error{
		"RealizeNetns": func(c rootdpb.RootHelperClient, name string) error {
			_, err := c.RealizeNetns(context.Background(), &rootdpb.RealizeNetnsRequest{NetnsName: name})
			return err
		},
		"RemoveNetns": func(c rootdpb.RootHelperClient, name string) error {
			_, err := c.RemoveNetns(context.Background(), &rootdpb.RemoveNetnsRequest{NetnsName: name})
			return err
		},
		"DisableNetnsIPv6": func(c rootdpb.RootHelperClient, name string) error {
			_, err := c.DisableNetnsIPv6(context.Background(), &rootdpb.DisableNetnsIPv6Request{NetnsName: name})
			return err
		},
		"NetnsAddrs": func(c rootdpb.RootHelperClient, name string) error {
			_, err := c.NetnsAddrs(context.Background(), &rootdpb.NetnsAddrsRequest{NetnsName: name})
			return err
		},
	}
	for call, do := range calls {
		t.Run(call, func(t *testing.T) {
			fn := newFakeNet()
			r, c := netRig(t, fn)
			for _, name := range bad {
				wantRefusal(t, r, do(c, name), codes.InvalidArgument, string(rootpolicy.RuleNetns))
			}
			if got := fn.recorded(); len(got) != 0 {
				t.Fatalf("a refused name reached the kernel: %v", got)
			}
		})
	}

	t.Run("an address that is not a sandbox's", func(t *testing.T) {
		fn := newFakeNet()
		r, c := netRig(t, fn)
		for _, ip := range []string{"10.88.0.1", "10.88.0.0", "10.88.255.255", "10.0.0.5", "127.0.0.1", "169.254.169.254", "fd00::1", "10.88.0.2/32", "x"} {
			_, err := c.RemoveNetns(callCtx(t), &rootdpb.RemoveNetnsRequest{NetnsName: "sb-1", ContainerIp: ip})
			wantRefusal(t, r, err, codes.InvalidArgument, string(rootpolicy.RuleAddress))
		}
		if got := fn.recorded(); len(got) != 0 {
			t.Fatalf("a refused address reached the kernel: %v", got)
		}
	})

	// A namespace in the netns folder that is not a sandbox's (another
	// program's, on a VM where /run/netns is shared): no call touches it,
	// reads included.
	t.Run("a namespace that is not a sandbox's", func(t *testing.T) {
		fn := newFakeNet()
		r, c := netRig(t, fn)
		fn.set(r.cfg.Policy.NetnsDir+"/cni-0b6f5c1e", NetnsState{Exists: true, Foreign: "link eth0", IPv4: []string{"10.244.1.7"}})
		for call, do := range calls {
			err := do(c, "cni-0b6f5c1e")
			wantRefusal(t, r, err, codes.PermissionDenied, ReasonNotSandboxNetns)
			if s := status.Convert(err).Message(); strings.Contains(s, "10.244") {
				t.Fatalf("%s leaked its address: %s", call, s)
			}
		}
		if got := fn.recorded(); len(got) != 0 {
			t.Fatalf("a foreign namespace was touched: %v", got)
		}
	})

	// Another sandbox's namespace, by name: the helper keeps no state, so
	// whose it is stays the agent's bookkeeping. A broken agent can reach
	// its own sandboxes already (R9); what the helper guarantees is that
	// the call touches only a sandbox namespace and sandbox addresses.
	t.Run("another sandbox's namespace stays the agent's bookkeeping", func(t *testing.T) {
		fn := newFakeNet()
		_, c := netRig(t, fn)
		other, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-other"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.RemoveNetns(callCtx(t), &rootdpb.RemoveNetnsRequest{NetnsName: "sb-other", ContainerIp: other.GetContainerIp()}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRemoveNetns(t *testing.T) {
	fn := newFakeNet()
	r, c := netRig(t, fn)
	resp, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "aerol-netns-0"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.RemoveNetns(callCtx(t), &rootdpb.RemoveNetnsRequest{NetnsName: "aerol-netns-0", ContainerIp: resp.GetContainerIp()}); err != nil {
			t.Fatalf("remove %d: %v", i, err)
		}
	}
	want := []string{"realize aerol-netns-0", "remove aerol-netns-0 10.88.0.2", "remove aerol-netns-0 10.88.0.2"}
	if got := fn.recorded(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
	if st, _ := fn.Inspect(r.cfg.Policy.NetnsDir + "/aerol-netns-0"); st.Exists {
		t.Fatal("the namespace is still there")
	}
	fn.fail["remove"] = errors.New("cni del: plugin gone")
	_, err = c.RemoveNetns(callCtx(t), &rootdpb.RemoveNetnsRequest{NetnsName: "aerol-netns-0"})
	wantCode(t, err, codes.Internal)
	fn.fail["remove"] = nil
	fn.fail["inspect"] = errors.New("netlink")
	_, err = c.RemoveNetns(callCtx(t), &rootdpb.RemoveNetnsRequest{NetnsName: "aerol-netns-0"})
	wantCode(t, err, codes.Internal)
}

func TestDisableNetnsIPv6(t *testing.T) {
	fn := newFakeNet()
	r, c := netRig(t, fn)
	_, err := c.DisableNetnsIPv6(callCtx(t), &rootdpb.DisableNetnsIPv6Request{NetnsName: "sb-1"})
	wantCode(t, err, codes.NotFound)
	if refs := r.refused(); len(refs) != 0 {
		t.Fatalf("a missing namespace counted as a refusal: %+v", refs)
	}
	path := r.cfg.Policy.NetnsDir + "/sb-1"
	fn.set(path, NetnsState{Exists: true, IPv4: []string{"10.88.0.9"}})
	if _, err := c.DisableNetnsIPv6(callCtx(t), &rootdpb.DisableNetnsIPv6Request{NetnsName: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	if got := fn.recorded(); !slices.Equal(got, []string{"ipv6 " + path}) {
		t.Fatalf("calls %v", got)
	}
	fn.fail["ipv6"] = errors.New("read-only")
	_, err = c.DisableNetnsIPv6(callCtx(t), &rootdpb.DisableNetnsIPv6Request{NetnsName: "sb-1"})
	wantCode(t, err, codes.Internal)
	fn.fail["inspect"] = errors.New("netlink")
	_, err = c.DisableNetnsIPv6(callCtx(t), &rootdpb.DisableNetnsIPv6Request{NetnsName: "sb-1"})
	wantCode(t, err, codes.Internal)
}

func TestNetnsAddrs(t *testing.T) {
	fn := newFakeNet()
	r, c := netRig(t, fn)
	resp, err := c.NetnsAddrs(callCtx(t), &rootdpb.NetnsAddrsRequest{NetnsName: "sb-1"})
	if err != nil || resp.GetExists() || len(resp.GetIpv4()) != 0 {
		t.Fatalf("a missing namespace = %v, %v", resp, err)
	}
	fn.set(r.cfg.Policy.NetnsDir+"/sb-1", NetnsState{Exists: true, IPv4: []string{"10.88.0.9", "10.88.3.3"}})
	resp, err = c.NetnsAddrs(callCtx(t), &rootdpb.NetnsAddrsRequest{NetnsName: "sb-1"})
	if err != nil || !resp.GetExists() || !slices.Equal(resp.GetIpv4(), []string{"10.88.0.9", "10.88.3.3"}) {
		t.Fatalf("NetnsAddrs = %v, %v", resp, err)
	}
	fn.fail["inspect"] = errors.New("netlink")
	_, err = c.NetnsAddrs(callCtx(t), &rootdpb.NetnsAddrsRequest{NetnsName: "sb-1"})
	wantCode(t, err, codes.Internal)
}

// TestNetworkOpensLazily: the helper's own network is opened on the first
// network call, not at start, so a node whose CNI layout is missing or
// unsafe still serves the other calls; each network call is refused with
// the reason until a later one opens it.
func TestNetworkOpensLazily(t *testing.T) {
	fn := newFakeNet()
	var opens atomic.Int32
	real := openNetworkFn
	t.Cleanup(func() { openNetworkFn = real })
	openNetworkFn = func(Config) (NetworkHost, error) {
		if opens.Add(1) == 1 {
			return nil, errors.New("CNI plugin folder /opt/cni/bin: belongs to uid 1000")
		}
		return fn, nil
	}
	r := newRig(t, func(c *Config, _ *Options) {
		c.Network = NetworkConfig{PluginDir: "/opt/cni/bin", ConfPath: "/etc/cni/net.d/aerolvm.conflist"}
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	_, err := c.NetnsAddrs(callCtx(t), &rootdpb.NetnsAddrsRequest{NetnsName: "sb-1"})
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "belongs to uid 1000") {
		t.Fatalf("the reason is lost: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.NetnsAddrs(context.Background(), &rootdpb.NetnsAddrsRequest{NetnsName: "sb-1"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := opens.Load(); n != 2 {
		t.Fatalf("opened %d times, want 2: one failure, then once for all", n)
	}
	// The real opener with no configuration (and off Linux, at all).
	if _, err := real(Config{}); err == nil {
		t.Fatal("openNetwork with no configuration")
	}
}

func TestNoNetworkConfiguration(t *testing.T) {
	r := newRig(t, nil)
	c := rootdpb.NewRootHelperClient(r.conn)
	for _, err := range []error{
		func() error {
			_, err := c.EnsureHostNetwork(callCtx(t), &rootdpb.EnsureHostNetworkRequest{})
			return err
		}(),
		func() error {
			_, err := c.RealizeNetns(callCtx(t), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
			return err
		}(),
		func() error {
			_, err := c.RemoveNetns(callCtx(t), &rootdpb.RemoveNetnsRequest{NetnsName: "sb-1"})
			return err
		}(),
		func() error {
			_, err := c.DisableNetnsIPv6(callCtx(t), &rootdpb.DisableNetnsIPv6Request{NetnsName: "sb-1"})
			return err
		}(),
		func() error {
			_, err := c.NetnsAddrs(callCtx(t), &rootdpb.NetnsAddrsRequest{NetnsName: "sb-1"})
			return err
		}(),
	} {
		wantCode(t, err, codes.Unimplemented)
	}
	if refs := r.refused(); len(refs) != 0 {
		t.Fatalf("a call this helper lacks counted as a refusal: %+v", refs)
	}
}

// TestCallsForOneSandboxRunInOrder (eng review D11): calls naming one
// namespace run one at a time, so a Remove never interleaves with a
// Realize of it; calls for different namespaces run together.
func TestCallsForOneSandboxRunInOrder(t *testing.T) {
	t.Run("one namespace", func(t *testing.T) {
		fn := newFakeNet()
		fn.hold = make(chan struct{})
		_, c := netRig(t, fn)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = c.RealizeNetns(context.Background(), &rootdpb.RealizeNetnsRequest{NetnsName: "sb-1"})
				_, _ = c.RemoveNetns(context.Background(), &rootdpb.RemoveNetnsRequest{NetnsName: "sb-1"})
			}()
		}
		time.Sleep(50 * time.Millisecond)
		close(fn.hold)
		wg.Wait()
		if p := fn.peak.Load(); p != 1 {
			t.Fatalf("%d calls for one namespace ran at once", p)
		}
	})
	t.Run("different namespaces", func(t *testing.T) {
		fn := newFakeNet()
		fn.hold = make(chan struct{})
		_, c := netRig(t, fn)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = c.RealizeNetns(context.Background(), &rootdpb.RealizeNetnsRequest{NetnsName: fmt.Sprintf("sb-%d", i)})
			}()
		}
		deadline := time.Now().Add(5 * time.Second)
		for fn.active.Load() < 8 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		close(fn.hold)
		wg.Wait()
		if p := fn.peak.Load(); p != 8 {
			t.Fatalf("only %d of 8 namespaces were built at once", p)
		}
	})
}

func TestKeyedLocks(t *testing.T) {
	var k keyedLocks
	a := k.lock("a")
	b := k.lock("b")
	if k.held() != 2 {
		t.Fatalf("held %d", k.held())
	}
	got := make(chan struct{})
	go func() {
		defer k.lock("a")()
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a second holder of a got in")
	case <-time.After(20 * time.Millisecond):
	}
	a()
	<-got
	b()
	if k.held() != 0 {
		t.Fatalf("entries left: %d", k.held())
	}
	var none *keyedLocks
	none.lock("x")()
}
