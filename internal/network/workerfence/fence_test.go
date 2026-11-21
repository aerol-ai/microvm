package workerfence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestBlocked(t *testing.T) {
	got := Blocked()
	for _, want := range []string{"127.0.0.0/8", "::1/128", "0.0.0.0/8", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8", "255.255.255.255/32",
		"fd00:ec2::254/128", "fd00:ec2::23/128", "168.63.129.16/32", "100.100.100.200/32"} {
		if !slices.Contains(got, netip.MustParsePrefix(want)) {
			t.Errorf("Blocked() lacks %s: %v", want, got)
		}
	}
	// A metadata endpoint inside a blocked range is not listed twice.
	if slices.Contains(got, netip.MustParsePrefix("169.254.169.254/32")) {
		t.Errorf("169.254.169.254 listed beside 169.254.0.0/16: %v", got)
	}
}

func TestWithPrefixes(t *testing.T) {
	pfx := netip.MustParsePrefix
	got := withPrefixes([]netip.Prefix{pfx("10.0.0.0/8")}, []netip.Prefix{
		pfx("10.1.0.0/16"),    // inside one already there
		pfx("192.168.1.7/24"), // host bits: masked
		pfx("0.0.0.0/0"),      // never a floor
		{},                    // invalid
		pfx("192.168.1.0/24"), // the same once masked
		pfx("fd00::/8"),
	})
	want := []netip.Prefix{pfx("10.0.0.0/8"), pfx("192.168.1.0/24"), pfx("fd00::/8")}
	if !slices.Equal(got, want) {
		t.Fatalf("withPrefixes = %v, want %v", got, want)
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
		{Proto: "udp", Prefix: pfx("::ffff:10.0.0.2/128"), PortLo: 53, PortHi: 53, Why: "name server"}, // mapped: unmapped
		{Proto: "tcp", Prefix: pfx("127.0.0.0/8"), PortLo: 1, PortHi: 65535, Why: "a range"},
		{Proto: "icmp", Prefix: pfx("127.0.0.1/32"), PortLo: 1, PortHi: 1},
		{Proto: "tcp", Prefix: pfx("127.0.0.1/32"), PortLo: 0, PortHi: 0},
		{Proto: "tcp", Prefix: pfx("127.0.0.1/32"), PortLo: 9, PortHi: 8},
		{Proto: "tcp"},
	}, Floor: []netip.Prefix{pfx("10.96.0.1/32"), pfx("169.254.20.10/32"), pfx("0.0.0.0/0")}, NodePorts: []uint16{443, 80, 443, 0}})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(rules))
	for i, r := range rules {
		if r.UID != 61000 {
			t.Fatalf("rule without the uid: %+v", r)
		}
		got[i] = r.Comment()
	}
	want := []string{
		"uid 61000 accept reply 127.0.97.1 -> 127.0.0.0/8",
		"uid 61000 accept tcp 127.0.0.1/32 nat port 4100 (audit ingest)",
		"uid 61000 accept tcp 127.0.0.1/32 port 4100 (audit ingest)",
		"uid 61000 accept udp 10.0.0.2/32 nat port 53 (name server)",
		"uid 61000 accept udp 10.0.0.2/32 port 53 (name server)",
		"uid 61000 accept udp 127.0.0.53/32 nat port 53 (name server)",
		"uid 61000 accept udp 127.0.0.53/32 port 53 (name server)",
	}
	for _, p := range Blocked() {
		want = append(want, "uid 61000 drop "+p.String())
	}
	want = append(want, "uid 61000 drop 10.96.0.1/32",
		"uid 61000 accept local tcp port 80 (node port)",
		"uid 61000 accept local tcp port 443 (node port)",
		"uid 61000 drop local",
		"uid 61000 drop broadcast")
	if !slices.Equal(got, want) {
		t.Fatalf("plan =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range rules {
		if r.Kind != KindReply && r.Accepts() && r.Prefix.Contains(netip.MustParseAddr(GuestListenHost)) {
			t.Fatalf("%s: workers must not open connections to guest listeners", r.Comment())
		}
	}
	for _, r := range rules {
		if r.Accepts() != strings.Contains(r.Comment(), "accept") {
			t.Errorf("%s: Accepts() = %v", r.Comment(), r.Accepts())
		}
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
	// A refusal that is not a missing expression does not fall back.
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
		{Rule{UID: 7, Kind: KindReply, From: netip.MustParseAddr("127.0.97.1"), Prefix: netip.MustParsePrefix("127.0.0.0/8")}, "uid 7 accept reply 127.0.97.1 -> 127.0.0.0/8"},
		{Rule{UID: 7, Kind: KindAllow, Proto: "udp", Prefix: netip.MustParsePrefix("::1/128"), PortLo: 53, PortHi: 53}, "uid 7 accept udp ::1/128 port 53"},
		{Rule{UID: 7, Kind: KindAllow, Proto: "tcp", Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: 1, PortHi: 9, Why: "w"}, "uid 7 accept tcp 127.0.0.1/32 ports 1-9 (w)"},
		{Rule{UID: 7, Kind: KindAllowNAT, Proto: "udp", Prefix: netip.MustParsePrefix("127.0.0.11/32"), PortLo: 53, PortHi: 53, Why: "dns"}, "uid 7 accept udp 127.0.0.11/32 nat port 53 (dns)"},
		{Rule{UID: 7, Kind: KindBroadcastDrop}, "uid 7 drop broadcast"},
		{Rule{UID: 7, Kind: KindLocalPort, PortLo: 443, PortHi: 443}, "uid 7 accept local tcp port 443"},
		{Rule{UID: 7, Kind: KindLocalDrop}, "uid 7 drop local"},
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

// Without nft fib, the node's addresses are listed: the same node ports
// open on each, then a drop per address, per IPv4 subnet network address
// and per IPv4 subnet broadcast, after the floor.
func TestPlanNoFib(t *testing.T) {
	pfx := netip.MustParsePrefix
	rules, err := Plan(Spec{UID: 7, NodePorts: []uint16{443}, NoFib: true, Local: []netip.Prefix{
		pfx("10.0.0.5/24"), pfx("::ffff:10.0.0.5/120"), pfx("127.0.0.1/8"), pfx("fe80::1/64"), pfx("2001:db8::5/64"), pfx("192.168.9.9/32"), {},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key := Key(rules)
	tail := "uid 7 accept tcp 10.0.0.5/32 port 443 (node port); uid 7 accept tcp 192.168.9.9/32 port 443 (node port); uid 7 accept tcp 2001:db8::5/128 port 443 (node port); " +
		"uid 7 drop 10.0.0.5/32 (node address); uid 7 drop 192.168.9.9/32 (node address); uid 7 drop 2001:db8::5/128 (node address); " +
		"uid 7 drop 10.0.0.0/32 (node network address); uid 7 drop 10.0.0.255/32 (node broadcast)"
	if !strings.HasSuffix(key, tail) || usesFib(rules) {
		t.Fatalf("plan = %s", key)
	}
	if fib, _ := Plan(Spec{UID: 7}); !usesFib(fib) {
		t.Fatal("a plan with fib does not use it")
	}
	for _, tc := range []struct {
		p       string
		network string
		bcast   string
	}{
		{"172.17.0.2/16", "172.17.0.0", "172.17.255.255"},
		{"10.1.2.3/30", "10.1.2.0", "10.1.2.3"},
		{"10.1.2.3/31", "", ""},
		{"2001:db8::1/64", "", ""},
		{"0.0.0.0/0", "", ""},
	} {
		n, b, ok := broadcastOf(pfx(tc.p))
		if (tc.bcast == "") == ok || ok && (n.String() != tc.network || b.String() != tc.bcast) {
			t.Errorf("broadcastOf(%s) = %v %v %v, want %q %q", tc.p, n, b, ok, tc.network, tc.bcast)
		}
	}
}

// fibless refuses any install that needs nft fib, as a kernel without the
// module does (the kernel answers ENOENT for an expression it lacks).
type fibless struct {
	fakeBackend
	fibOK bool
}

func (f *fibless) Apply(rules []Rule) error {
	if usesFib(rules) && !f.fibOK {
		f.mu.Lock()
		f.applies++
		f.mu.Unlock()
		return fmt.Errorf("install: conn.Receive: netlink receive: %w", syscall.ENOENT)
	}
	return f.fakeBackend.Apply(rules)
}

// On a kernel without nft fib the fence still goes in, listing the node's
// addresses; each sync tries fib again (a refused batch changes nothing)
// and re-installs the listed plan only when an address changed; once fib
// works, the fence uses it. A failure that is not a missing expression
// keeps its own error and never falls back.
func TestFenceFallsBackWithoutFib(t *testing.T) {
	be := &fibless{}
	local := []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")}
	f := New(be, func() (Spec, error) { return Spec{UID: 61000, NodePorts: []uint16{443}, Local: local}, nil }, quiet())
	clock := time.Unix(1000, 0)
	f.now = func() time.Time { return clock }
	if err := f.Ensure(); err != nil || !f.Ready() || !f.noFib {
		t.Fatalf("fallback: %v ready=%v noFib=%v", err, f.Ready(), f.noFib)
	}
	if k := Key(be.last); !strings.Contains(k, "drop 10.0.0.5/32 (node address)") || !strings.Contains(k, "drop 10.0.0.0/32 (node network address)") || !strings.Contains(k, "drop 10.0.0.255/32 (node broadcast)") || usesFib(be.last) {
		t.Fatalf("installed = %s", k)
	}
	// Nothing changed: fib is tried again; the listed plan is not
	// re-installed.
	applies := be.applies
	if err := f.Sync(); err != nil || be.applies != applies+1 {
		t.Fatalf("idle sync: %v applies %d->%d", err, applies, be.applies)
	}
	// A new address is picked up by the next sync.
	local = append(local, netip.MustParsePrefix("10.0.0.6/24"))
	if err := f.Sync(); err != nil || !strings.Contains(Key(be.last), "10.0.0.6/32 (node address)") {
		t.Fatalf("new address: %v", err)
	}
	// The listed plan is checked on the reassert schedule and put back.
	_ = be.Remove()
	clock = clock.Add(ReassertInterval)
	if err := f.Sync(); err != nil || !be.inKernel {
		t.Fatalf("repair without fib: %v", err)
	}
	// A failed check closes the gate.
	be.checkErr = errors.New("netlink busy")
	clock = clock.Add(ReassertInterval)
	if err := f.Sync(); err == nil || f.Ready() {
		t.Fatal("a failed check left the gate open")
	}
	be.checkErr = nil
	// The kernel gained fib: the fence uses it from the next sync on.
	be.fibOK = true
	if err := f.Sync(); err != nil || f.noFib || !usesFib(be.last) {
		t.Fatalf("fib back: %v noFib=%v", err, f.noFib)
	}

	bad := &fakeBackend{applyErr: errors.New("netlink: operation not permitted")}
	f2 := New(bad, func() (Spec, error) { return Spec{UID: 61000}, nil }, quiet())
	if err := f2.Ensure(); err == nil || !strings.Contains(err.Error(), "operation not permitted") || f2.noFib || bad.applies != 1 {
		t.Fatalf("not fib: %v noFib=%v applies=%d", err, f2.noFib, bad.applies)
	}
	// fib missing, and the listed plan refused too: the first error stands.
	worse := &fibless{fakeBackend: fakeBackend{applyErr: errors.New("busy")}}
	f3 := New(worse, func() (Spec, error) { return Spec{UID: 61000}, nil }, quiet())
	if err := f3.Ensure(); err == nil || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("both refused: %v", err)
	}
}
