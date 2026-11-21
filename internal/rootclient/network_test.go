package rootclient

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// memNet is a rootd.NetworkHost in memory, for the agent's side of the
// network calls against the helper's real server.
type memNet struct {
	mu   sync.Mutex
	ns   map[string]rootd.NetnsState
	next int
	// work stands in for the kernel and CNI time of a build, the same on
	// both sides of the benchmark: a wait, as for the CNI plugins sandboxd
	// or the helper runs as child processes.
	work time.Duration
}

func newMemNet() *memNet { return &memNet{ns: map[string]rootd.NetnsState{}} }

func (m *memNet) Subnet() netip.Prefix { return netip.MustParsePrefix("10.88.0.0/16") }
func (m *memNet) EnsureHost() error    { return nil }
func (m *memNet) Inspect(path string) (rootd.NetnsState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ns[path], nil
}

func (m *memNet) Realize(_ context.Context, _, path string) (string, error) {
	if m.work > 0 {
		time.Sleep(m.work)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	ip := fmt.Sprintf("10.88.%d.%d", m.next/250, m.next%250+2)
	m.ns[path] = rootd.NetnsState{Exists: true, IPv4: []string{ip}}
	return ip, nil
}

func (m *memNet) Remove(_ context.Context, _, path, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ns, path)
	return nil
}

func (m *memNet) DisableIPv6(string) error { return nil }

// netCalls is every network call, with the feature each needs.
var netCalls = []struct {
	feature string
	call    func(ctx context.Context, c *Client) error
}{
	{rootdpb.FeatureEnsureHostNetwork, func(ctx context.Context, c *Client) error { _, err := c.EnsureHostNetwork(ctx); return err }},
	{rootdpb.FeatureRealizeNetns, func(ctx context.Context, c *Client) error { _, _, err := c.RealizeNetns(ctx, "sb-1"); return err }},
	{rootdpb.FeatureRemoveNetns, func(ctx context.Context, c *Client) error { return c.RemoveNetns(ctx, "sb-1", "") }},
	{rootdpb.FeatureDisableNetnsIPv6, func(ctx context.Context, c *Client) error { return c.DisableNetnsIPv6(ctx, "sb-1") }},
	{rootdpb.FeatureNetnsAddrs, func(ctx context.Context, c *Client) error { _, _, err := c.NetnsAddrs(ctx, "sb-1"); return err }},
}

// TestNetworkCallsWithTheRealHelper: each call against the helper's own
// server, from the subnet at boot to a namespace's teardown.
func TestNetworkCallsWithTheRealHelper(t *testing.T) {
	sock := sockPath(t)
	mn := newMemNet()
	realHelper(t, sock, func(o *rootd.Options) { o.Network = mn })
	c := newClient(t, sock)
	ctx := ctxT(t)
	subnet, err := c.EnsureHostNetwork(ctx)
	if err != nil || subnet != "10.88.0.0/16" {
		t.Fatalf("EnsureHostNetwork = %q, %v", subnet, err)
	}
	path, ip, err := c.RealizeNetns(ctx, "aerol-netns-0")
	if err != nil || path != "/run/netns/aerol-netns-0" || ip == "" {
		t.Fatalf("RealizeNetns = %q %q %v", path, ip, err)
	}
	exists, addrs, err := c.NetnsAddrs(ctx, "aerol-netns-0")
	if err != nil || !exists || !slices.Equal(addrs, []string{ip}) {
		t.Fatalf("NetnsAddrs = %v %v %v", exists, addrs, err)
	}
	if err := c.DisableNetnsIPv6(ctx, "aerol-netns-0"); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveNetns(ctx, "aerol-netns-0", ip); err != nil {
		t.Fatal(err)
	}
	if exists, _, err := c.NetnsAddrs(ctx, "aerol-netns-0"); err != nil || exists {
		t.Fatalf("after remove: exists %v, %v", exists, err)
	}
	// A refused name is a refusal, recorded, never a helper that is down.
	_, _, err = c.RealizeNetns(ctx, "../../proc/1/ns/net")
	if status.Code(err) != codes.InvalidArgument || !errors.Is(err, ErrRefused) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("a hostile name = %v, want ErrRefused", err)
	}
}

// TestNetworkCallsNeedTheirFeature: against a helper one release back,
// which lists none of them, each is refused before it is sent (D5).
func TestNetworkCallsNeedTheirFeature(t *testing.T) {
	sock := sockPath(t)
	h := &countingHelper{features: []string{rootdpb.FeatureEnsureHostFiles}}
	serveCounting(t, sock, h)
	c := newClient(t, sock)
	for _, nc := range netCalls {
		err := nc.call(ctxT(t), c)
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Feature != nc.feature {
			t.Fatalf("%s = %v, want an UnsupportedError naming it", nc.feature, err)
		}
	}
	if seen := h.seen(); len(seen) != 0 {
		t.Fatalf("calls the helper does not serve were sent: %v", seen)
	}
}

// TestNetworkCallsHelperDown: a helper that is gone fails each call with
// ErrUnavailable (503), within the client's timeout, never a hang.
func TestNetworkCallsHelperDown(t *testing.T) {
	c := newClient(t, sockPath(t))
	for _, nc := range netCalls {
		start := time.Now()
		if err := nc.call(context.Background(), c); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s = %v, want ErrUnavailable", nc.feature, err)
		}
		if d := time.Since(start); d > 3*c.timeout {
			t.Fatalf("%s waited %v; the timeout is %v", nc.feature, d, c.timeout)
		}
	}
}

// createCalls are the helper calls a cold create makes in privilege mode
// split: the namespace build (a warm-queue miss). The address it answers
// is the one the driver reports, with no read after the task starts
// (containerd sandboxAddress), and a warm hit makes none.
func createCalls(ctx context.Context, c *Client, name string) error {
	_, _, err := c.RealizeNetns(ctx, name)
	return err
}

// inProcess is today's path for the same work, single mode: the steps
// run in sandboxd itself, with no socket between, and the driver reads the
// address back after the task starts.
func inProcess(m *memNet, name string) error {
	path := "/run/netns/" + name
	if _, err := m.Realize(context.Background(), name, path); err != nil {
		return err
	}
	_, err := m.Inspect(path)
	return err
}

func percentile(d []time.Duration, p float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(float64(len(d)-1)*p)]
}

// burst runs n creates at once and returns each one's time, from the
// moment all n were let go to its own end: a create that waited for a CPU
// or a lock waited as a real burst's would.
func burst(n int, one func(i int) error) ([]time.Duration, error) {
	out := make([]time.Duration, n)
	errs := make([]error, n)
	var wg, ready sync.WaitGroup
	start := make(chan struct{})
	var t0 time.Time
	for i := range n {
		wg.Add(1)
		ready.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			errs[i] = one(i)
			out[i] = time.Since(t0)
		}()
	}
	ready.Wait()
	t0 = time.Now()
	close(start)
	wg.Wait()
	return out, errors.Join(errs...)
}

// BenchmarkCreate100 is the 100-parallel-create benchmark (plan §3.7, eng
// review D11): 100 cold creates at once, each making its helper call
// (RealizeNetns) through the real client and the helper's real server,
// against the same 100 creates doing the same work in process, as single
// mode does. The work itself is a fixed stand-in (work), so the gap
// between the two is the socket, the handshake latch, the per-sandbox
// lock and the helper's checks. It reports p50 and p99 of each, and of
// the first create after the helper starts (the handshake included).
//
//	go test -run '^$' -bench Create100 -benchtime 20x ./internal/rootclient/
func BenchmarkCreate100(b *testing.B) {
	const n = 100
	// About what a namespace build with CNI ADD takes on a node; the
	// Linux kernel benchmark in internal/rootd does the real build.
	work := 20 * time.Millisecond
	var split, single, first []time.Duration
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		sock := sockPath(b)
		mn := &memNet{ns: map[string]rootd.NetnsState{}, work: work}
		srv := realHelper(b, sock, func(o *rootd.Options) { o.Network = mn })
		c := New(Config{Socket: sock, Timeout: 5 * time.Second, HelperUID: uint32(os.Getuid())})
		b.StartTimer()
		t0 := time.Now()
		if err := createCalls(context.Background(), c, fmt.Sprintf("first-%d", i)); err != nil {
			b.Fatal(err)
		}
		first = append(first, time.Since(t0))
		d, err := burst(n, func(j int) error { return createCalls(context.Background(), c, fmt.Sprintf("sb-%d-%d", i, j)) })
		if err != nil {
			b.Fatal(err)
		}
		split = append(split, d...)
		b.StopTimer()
		local := &memNet{ns: map[string]rootd.NetnsState{}, work: work}
		d, err = burst(n, func(j int) error { return inProcess(local, fmt.Sprintf("sb-%d-%d", i, j)) })
		if err != nil {
			b.Fatal(err)
		}
		single = append(single, d...)
		_ = c.Close()
		srv.Shutdown(context.Background())
		b.StartTimer()
	}
	b.ReportMetric(float64(percentile(split, 0.5).Microseconds()), "split-p50-us")
	b.ReportMetric(float64(percentile(split, 0.99).Microseconds()), "split-p99-us")
	b.ReportMetric(float64(percentile(single, 0.5).Microseconds()), "single-p50-us")
	b.ReportMetric(float64(percentile(single, 0.99).Microseconds()), "single-p99-us")
	b.ReportMetric(float64(percentile(first, 0.5).Microseconds()), "first-p50-us")
}

// BenchmarkCreateCalls is one cold create's helper call with nothing else
// running (plan §3.7 boot-path numbers): RealizeNetns through the real
// client and server, the stand-in work set to none, so ns/op is the cost
// the split adds to a cold create. A warm hit makes no call;
// BenchmarkAddrsCall is the read a start or an inspect makes.
func BenchmarkCreateCalls(b *testing.B) {
	sock := sockPath(b)
	realHelper(b, sock, func(o *rootd.Options) { o.Network = newMemNet() })
	c := New(Config{Socket: sock, Timeout: 5 * time.Second, HelperUID: uint32(os.Getuid())})
	b.Cleanup(func() { _ = c.Close() })
	if err := c.Ensure(context.Background()); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := createCalls(context.Background(), c, fmt.Sprintf("sb-%d", i)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAddrsCall is the address read a start or an inspect makes.
func BenchmarkAddrsCall(b *testing.B) {
	sock := sockPath(b)
	realHelper(b, sock, func(o *rootd.Options) { o.Network = newMemNet() })
	c := New(Config{Socket: sock, Timeout: 5 * time.Second, HelperUID: uint32(os.Getuid())})
	b.Cleanup(func() { _ = c.Close() })
	if _, _, err := c.RealizeNetns(context.Background(), "sb-1"); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.NetnsAddrs(context.Background(), "sb-1"); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCreate100 runs the benchmark's burst once as a test, so `go test`
// keeps it working, and checks every create got its own address.
func TestCreate100(t *testing.T) {
	sock := sockPath(t)
	mn := newMemNet()
	realHelper(t, sock, func(o *rootd.Options) { o.Network = mn })
	c := newClient(t, sock)
	c.timeout = 5 * time.Second
	if _, err := burst(100, func(j int) error { return createCalls(context.Background(), c, fmt.Sprintf("sb-%d", j)) }); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for j := range 100 {
		_, addrs, err := c.NetnsAddrs(ctxT(t), fmt.Sprintf("sb-%d", j))
		if err != nil || len(addrs) != 1 || seen[addrs[0]] {
			t.Fatalf("sb-%d: %v %v", j, addrs, err)
		}
		seen[addrs[0]] = true
	}
}
