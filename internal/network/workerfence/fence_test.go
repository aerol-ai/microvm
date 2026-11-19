package workerfence

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBlocked(t *testing.T) {
	got := Blocked()
	for _, want := range []string{"127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "fd00:ec2::23/128", "168.63.129.16/32", "100.100.100.200/32"} {
		if !slices.Contains(got, netip.MustParsePrefix(want)) {
			t.Errorf("Blocked() lacks %s: %v", want, got)
		}
	}
	// A metadata endpoint inside a blocked range is not listed twice.
	if slices.Contains(got, netip.MustParsePrefix("169.254.169.254/32")) {
		t.Errorf("169.254.169.254 listed beside 169.254.0.0/16: %v", got)
	}
}

func TestPlan(t *testing.T) {
	if _, err := Plan(Spec{}); err == nil {
		t.Fatal("a plan for uid 0")
	}
	pfx := netip.MustParsePrefix
	rules, err := Plan(Spec{UID: 61000, Allow: []Allow{
		{Proto: "tcp", Prefix: pfx("127.0.0.1/32"), PortLo: 4100, PortHi: 4100, Why: "audit ingest"},
		{Proto: "tcp", Prefix: pfx("127.0.0.1/32"), PortLo: 4100, PortHi: 4100, Why: "audit ingest"}, // twice
		{Proto: "udp", Prefix: pfx("127.0.0.53/32"), PortLo: 53, PortHi: 53, Why: "name server"},
		{Proto: "tcp", Prefix: pfx("127.0.97.1/32"), PortLo: 32768, PortHi: 60999, Why: "guest listeners"},
		{Proto: "udp", Prefix: pfx("10.0.0.2/32"), PortLo: 53, PortHi: 53, Why: "outside the fence"},
		{Proto: "icmp", Prefix: pfx("127.0.0.1/32"), PortLo: 1, PortHi: 1},
		{Proto: "tcp", Prefix: pfx("127.0.0.1/32"), PortLo: 0, PortHi: 0},
		{Proto: "tcp", Prefix: pfx("127.0.0.1/32"), PortLo: 9, PortHi: 8},
		{Proto: "tcp"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var accepts, drops []string
	for _, r := range rules {
		if r.UID != 61000 {
			t.Fatalf("rule without the uid: %+v", r)
		}
		if r.Accept {
			if len(drops) > 0 {
				t.Fatalf("an exception after a drop: %s", Key(rules))
			}
			accepts = append(accepts, r.Comment())
		} else {
			drops = append(drops, r.Comment())
		}
	}
	want := []string{
		"uid 61000 accept tcp 127.0.0.1/32 port 4100 (audit ingest)",
		"uid 61000 accept tcp 127.0.97.1/32 ports 32768-60999 (guest listeners)",
		"uid 61000 accept udp 127.0.0.53/32 port 53 (name server)",
	}
	if !slices.Equal(accepts, want) {
		t.Fatalf("exceptions = %q, want %q", accepts, want)
	}
	if len(drops) != len(Blocked()) || drops[0] != "uid 61000 drop 127.0.0.0/8" {
		t.Fatalf("drops = %q", drops)
	}
	if strings.Contains(Key(rules), "10.0.0.2") {
		t.Fatal("an exception outside the fence made it into the chain")
	}
}

// fakeBackend counts what the fence asks of it.
type fakeBackend struct {
	mu       sync.Mutex
	applies  int
	checks   int
	applyErr error
	checkErr error
	inKernel bool
	last     []Rule
	gate     chan struct{}
}

func (f *fakeBackend) Apply(rules []Rule) error {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	if f.applyErr != nil {
		return f.applyErr
	}
	f.last, f.inKernel = rules, true
	return nil
}

func (f *fakeBackend) Check(rules []Rule) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	return f.inKernel && Key(f.last) == Key(rules), f.checkErr
}

func (f *fakeBackend) Remove() error { f.inKernel = false; return nil }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Ensure is the EnsureLayer4Ready latch: one install for concurrent
// callers, an atomic load once it is in, and a failure retried by the next
// caller.
func TestFenceEnsureLatch(t *testing.T) {
	be := &fakeBackend{gate: make(chan struct{})}
	f := New(be, func() (Spec, error) { return Spec{UID: 61000}, nil }, quiet())
	var wg sync.WaitGroup
	var failed atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.Ensure() != nil {
				failed.Add(1)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(be.gate)
	wg.Wait()
	if be.applies != 1 || failed.Load() != 0 || !f.Ready() || ready.Value() != 1 {
		t.Fatalf("applies=%d failed=%d ready=%v", be.applies, failed.Load(), f.Ready())
	}
	if err := f.Ensure(); err != nil || be.applies != 1 {
		t.Fatalf("a latched Ensure installed again: %v, %d", err, be.applies)
	}

	// A failed install leaves the latch open: the gate refuses, and the
	// next caller tries again.
	be2 := &fakeBackend{applyErr: errors.New("netlink: operation not permitted")}
	f2 := New(be2, func() (Spec, error) { return Spec{UID: 61000}, nil }, quiet())
	if err := f2.Ensure(); err == nil || f2.Ready() || ready.Value() != 0 {
		t.Fatalf("failed install = %v, ready=%v", err, f2.Ready())
	}
	_ = f2.Ensure()
	if be2.applies != 2 {
		t.Fatalf("a failed install was not retried: %d", be2.applies)
	}
	be2.applyErr = nil
	if err := f2.Ensure(); err != nil || !f2.Ready() {
		t.Fatalf("recovered install = %v", err)
	}
	// A plan that cannot be made is a failure too.
	f3 := New(be, func() (Spec, error) { return Spec{}, nil }, nil)
	if err := f3.Ensure(); err == nil || f3.Ready() {
		t.Fatal("a fence with no worker uid counted as installed")
	}
}

// Sync applies a changed plan, and on the reassert puts back a table
// something took away.
func TestFenceSync(t *testing.T) {
	be := &fakeBackend{}
	port := uint16(4100)
	f := New(be, func() (Spec, error) {
		return Spec{UID: 61000, Allow: []Allow{{Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: port, PortHi: port}}}, nil
	}, quiet())
	clock := time.Unix(1000, 0)
	f.now = func() time.Time { return clock }
	if err := f.Ensure(); err != nil {
		t.Fatal(err)
	}
	// Nothing changed and the reassert is not due: nothing is asked.
	if err := f.Sync(); err != nil || be.applies != 1 || be.checks != 0 {
		t.Fatalf("idle sync: %v applies=%d checks=%d", err, be.applies, be.checks)
	}
	// A new ingest port: installed at once.
	port = 4200
	if err := f.Sync(); err != nil || be.applies != 2 || !strings.Contains(Key(be.last), "port 4200") {
		t.Fatalf("changed plan: %v applies=%d", err, be.applies)
	}
	// Someone flushed the ruleset: the reassert puts it back.
	_ = be.Remove()
	clock = clock.Add(ReassertInterval)
	if err := f.Sync(); err != nil || be.checks != 1 || be.applies != 3 || !be.inKernel {
		t.Fatalf("repair: %v checks=%d applies=%d", err, be.checks, be.applies)
	}
	// A check that fails closes the gate until a sync gets it back.
	be.checkErr = errors.New("netlink busy")
	clock = clock.Add(ReassertInterval)
	if err := f.Sync(); err == nil || f.Ready() {
		t.Fatal("a failed check left the gate open")
	}
	be.checkErr = nil
	if err := f.Sync(); err != nil || !f.Ready() {
		t.Fatalf("after the failed check: %v", err)
	}
}

func TestFenceRun(t *testing.T) {
	be := &fakeBackend{}
	f := New(be, func() (Spec, error) { return Spec{UID: 61000}, nil }, quiet())
	ctx, cancel := contextWithCancel()
	done := make(chan struct{})
	go func() { f.Run(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !f.Ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if !f.Ready() {
		t.Fatal("Run did not install the fence")
	}
	ctx2, cancel2 := contextWithCancel()
	cancel2()
	f.Run(ctx2, 0) // a stopped context returns at once
}

func TestRuleComment(t *testing.T) {
	for _, tc := range []struct {
		r    Rule
		want string
	}{
		{Rule{UID: 7, Prefix: netip.MustParsePrefix("fe80::/10")}, "uid 7 drop fe80::/10"},
		{Rule{UID: 7, Accept: true, Proto: "udp", Prefix: netip.MustParsePrefix("::1/128"), PortLo: 53, PortHi: 53}, "uid 7 accept udp ::1/128 port 53"},
		{Rule{UID: 7, Accept: true, Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.97.1/32"), PortLo: 1, PortHi: 9, Why: "w"}, "uid 7 accept tcp 127.0.97.1/32 ports 1-9 (w)"},
	} {
		if got := tc.r.Comment(); got != tc.want {
			t.Errorf("Comment() = %q, want %q", got, tc.want)
		}
	}
}

func TestNameservers(t *testing.T) {
	got := Nameservers([]byte("# generated\nnameserver 127.0.0.53\nnameserver   10.0.0.2 \nnameserver fe80::1%eth0\nnameserver ::ffff:169.254.169.253\nnameserver bogus\nsearch ec2.internal\nnameserver\n"))
	want := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("169.254.169.253")}
	if !slices.Equal(got, want) {
		t.Fatalf("Nameservers = %v, want %v", got, want)
	}
}

func TestPortRange(t *testing.T) {
	if lo, hi, err := PortRange([]byte("32768\t60999\n")); err != nil || lo != 32768 || hi != 60999 {
		t.Fatalf("PortRange = %d %d %v", lo, hi, err)
	}
	for _, bad := range []string{"", "1", "0 10", "10 9", "x 10", "1 70000"} {
		if _, _, err := PortRange([]byte(bad)); err == nil {
			t.Errorf("PortRange(%q) accepted", bad)
		}
	}
}

func TestHostAddrs(t *testing.T) {
	if got := HostAddrs("LocalHost"); len(got) != 2 || !got[0].IsLoopback() || !got[1].IsLoopback() {
		t.Fatalf("localhost = %v", got)
	}
	if got := HostAddrs("[::1]"); len(got) != 1 || got[0] != netip.IPv6Loopback() {
		t.Fatalf("[::1] = %v", got)
	}
	if got := HostAddrs(" 127.0.0.1 "); len(got) != 1 || got[0].String() != "127.0.0.1" {
		t.Fatalf("127.0.0.1 = %v", got)
	}
	if HostAddrs("proxy.internal") != nil {
		t.Fatal("a name the fence cannot follow gave addresses")
	}
}

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
