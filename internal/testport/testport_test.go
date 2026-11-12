package testport

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestReserveStaysBelowTheEphemeralRangeAndNeverRepeats(t *testing.T) {
	low, high, ok := testPortRange()
	if !ok {
		t.Skipf("ephemeral range starts at %d: no room below it", high)
	}
	if start, found := ephemeralPortStart(); found && high > start {
		t.Fatalf("picking range [%d, %d) reaches the ephemeral start %d", low, high, start)
	}
	seen := map[int]bool{}
	// More than one block, so taking a second block is covered too.
	for range 3 * testPortBlock {
		port := Reserve(t, true)
		if port < low || port >= high {
			if blocksUsedUp() {
				t.Skip("this process used up every block (a long -count run); the fallback has its own test")
			}
			t.Fatalf("port %d outside [%d, %d)", port, low, high)
		}
		if seen[port] {
			t.Fatalf("port %d handed out twice", port)
		}
		seen[port] = true
		if !loopbackPortFree(port, true) {
			t.Fatalf("port %d was handed out but is in use", port)
		}
	}
}

func TestReserveSkipsAPortSomethingHolds(t *testing.T) {
	if _, _, ok := testPortRange(); !ok {
		t.Skip("no room below the ephemeral range")
	}
	// The ports right after the last one handed out come next: hold some
	// of them, as an unrelated program might.
	last := Reserve(t, false)
	held := map[int]bool{}
	for port := last + 1; port <= last+8; port++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = l.Close() })
		held[port] = true
	}
	for range 20 {
		if port := Reserve(t, false); held[port] {
			t.Fatalf("port %d is held by a listener but was handed out", port)
		}
	}
}

func TestReserveFallsBackWhenNoBlockIsLeft(t *testing.T) {
	low, high, ok := testPortRange()
	if !ok {
		t.Skip("no room below the ephemeral range")
	}
	// Use up every block as far as this process can tell, then put the
	// real state back for the other tests.
	testPorts.mu.Lock()
	saved := struct {
		claimed   map[int]bool
		next, end int
		exhausted bool
	}{testPorts.claimed, testPorts.next, testPorts.end, testPorts.exhausted}
	all := map[int]bool{}
	for first := low; first+testPortBlock <= high; first += testPortBlock {
		all[first] = true
	}
	testPorts.claimed, testPorts.next, testPorts.end = all, 0, 0
	testPorts.mu.Unlock()
	t.Cleanup(func() {
		testPorts.mu.Lock()
		testPorts.claimed, testPorts.next, testPorts.end, testPorts.exhausted = saved.claimed, saved.next, saved.end, saved.exhausted
		testPorts.mu.Unlock()
	})
	seen := map[int]bool{}
	for range 5 {
		port := Reserve(t, true)
		if port >= low && port < high {
			t.Fatalf("port %d came from a block although none was left", port)
		}
		if seen[port] || !loopbackPortFree(port, true) {
			t.Fatalf("fallback port %d repeated or in use", port)
		}
		seen[port] = true
	}
	if !testPorts.exhausted {
		t.Fatal("the picker did not record that the blocks ran out")
	}
}

func TestClaimPortBlockSkipsABlockAnotherProcessHolds(t *testing.T) {
	dir := t.TempDir()
	low, high := 40000, 40000+4*testPortBlock
	// A second open file description of the same lock file conflicts with
	// this one exactly as another process's would.
	other, ok := lockPortBlock(dir, low+testPortBlock)
	if !ok {
		t.Fatal("could not take block 1")
	}
	defer other.Close()
	first, lock, ok := claimPortBlock(dir, low, high, 1, nil)
	if !ok || first != low+2*testPortBlock {
		t.Fatalf("claim from block 1 = %d %v, want block 2 (%d)", first, ok, low+2*testPortBlock)
	}
	defer lock.Close()
	// Every block held: the claim says so.
	var locks []*os.File
	for _, b := range []int{0, 3} {
		f, ok := lockPortBlock(dir, low+b*testPortBlock)
		if !ok {
			t.Fatalf("could not take block %d", b)
		}
		locks = append(locks, f)
	}
	if _, _, ok := claimPortBlock(dir, low, high, 0, nil); ok {
		t.Fatal("claimed a block while all four were held")
	}
	for _, f := range locks {
		_ = f.Close()
	}
	// A lock dies with its file: block 0 is free again.
	if first, f, ok := claimPortBlock(dir, low, high, 0, nil); !ok || first != low {
		t.Fatalf("after release, claim = %d %v, want %d", first, ok, low)
	} else {
		_ = f.Close()
	}
}

func TestClaimPortBlockNeverTakesOneOfItsOwnBlocksTwice(t *testing.T) {
	low, high := 40000, 40000+3*testPortBlock
	claimed := map[int]bool{}
	for range 3 {
		// No lock dir: only the skip set keeps the blocks apart.
		first, _, ok := claimPortBlock("", low, high, 0, claimed)
		if !ok || claimed[first] {
			t.Fatalf("claim = %d %v, already claimed %v", first, ok, claimed)
		}
		claimed[first] = true
	}
	if _, _, ok := claimPortBlock("", low, high, 0, claimed); ok {
		t.Fatal("claimed a fourth block out of three")
	}
}

// Two test processes at once never get the same port: the child is this
// test binary again, reserving ports while this process holds its own.
func TestReserveTwoProcessesNeverShareAPort(t *testing.T) {
	if os.Getenv("AEROLVM_TEST_PORT_CHILD") == "1" {
		// Start where the parent holds a block: without the lock the
		// child would hand out the parent's ports.
		start, _ := strconv.Atoi(os.Getenv("AEROLVM_TEST_PORT_START"))
		testPortStart = func(int) int { return start }
		var out []string
		for range 2 * testPortBlock {
			out = append(out, strconv.Itoa(Reserve(t, false)))
		}
		fmt.Println("PORTS " + strings.Join(out, ","))
		return
	}
	if _, _, ok := testPortRange(); !ok || testPorts.lockDir == "" || blocksUsedUp() {
		t.Skip("no room below the ephemeral range, no lock directory, or every block used up")
	}
	mine := map[int]bool{}
	var last int
	for range 2 * testPortBlock {
		last = Reserve(t, false)
		mine[last] = true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReserveTwoProcessesNeverShareAPort$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AEROLVM_TEST_PORT_CHILD=1",
		"AEROLVM_TEST_PORT_START="+strconv.Itoa((last-testPorts.low)/testPortBlock))
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, raw)
	}
	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "PORTS ") {
			line = strings.TrimPrefix(l, "PORTS ")
		}
	}
	if line == "" {
		t.Fatalf("child printed no ports:\n%s", raw)
	}
	for _, p := range strings.Split(line, ",") {
		port, _ := strconv.Atoi(p)
		if mine[port] {
			t.Fatalf("port %d handed to both processes", port)
		}
	}
}

func TestAddrAndUDPAddrAreReservedLoopbackPorts(t *testing.T) {
	for name, get := range map[string]func(testing.TB) string{"Addr": Addr, "UDPAddr": UDPAddr} {
		addr := get(t)
		host, p, err := net.SplitHostPort(addr)
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("%s = %q, want 127.0.0.1:<port>", name, addr)
		}
		port, _ := strconv.Atoi(p)
		if !loopbackPortFree(port, name == "UDPAddr") {
			t.Fatalf("%s handed out %s, which is in use", name, addr)
		}
	}
}

func TestParsePortRangeStart(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
		ok   bool
	}{
		{raw: "32768\t60999\n", want: 32768, ok: true},
		{raw: "1024 65535", want: 1024, ok: true},
		{raw: "", ok: false},
		{raw: "x 60999", ok: false},
	} {
		if got, ok := parsePortRangeStart(tc.raw); got != tc.want || ok != tc.ok {
			t.Errorf("parsePortRangeStart(%q) = %d %v, want %d %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPickingRangeEndsAtALowEphemeralStart(t *testing.T) {
	for _, tc := range []struct {
		start    int
		known    bool
		wantHigh int
	}{
		{start: 32768, known: true, wantHigh: testPortHigh}, // Linux default
		{start: 0, known: false, wantHigh: testPortHigh},    // macOS: not read
		{start: 25000, known: true, wantHigh: 25000},        // a host tuned lower
	} {
		if low, high := pickingRange(tc.start, tc.known); low != testPortLow || high != tc.wantHigh {
			t.Errorf("pickingRange(%d, %v) = [%d, %d), want [%d, %d)", tc.start, tc.known, low, high, testPortLow, tc.wantHigh)
		}
	}
}

func TestPortRangeStartFrom(t *testing.T) {
	path := t.TempDir() + "/ip_local_port_range"
	if err := os.WriteFile(path, []byte("32768\t60999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, ok := portRangeStartFrom("linux", path); n != 32768 || !ok {
		t.Fatalf("linux = %d %v, want 32768 true", n, ok)
	}
	if _, ok := portRangeStartFrom("darwin", path); ok {
		t.Fatal("read a Linux-only file on darwin")
	}
	if _, ok := portRangeStartFrom("linux", path+".missing"); ok {
		t.Fatal("a missing file gave a start")
	}
}

func TestLockDirUnderSkipsABaseItCannotUse(t *testing.T) {
	notADir := t.TempDir() + "/file"
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	good := t.TempDir()
	if dir := lockDirUnder(notADir, good); !strings.HasPrefix(dir, good+"/") {
		t.Fatalf("lockDirUnder = %q, want a dir under %s", dir, good)
	}
	if dir := lockDirUnder(notADir); dir != "" {
		t.Fatalf("lockDirUnder with no usable base = %q, want \"\"", dir)
	}
}

func TestLockPortBlockWithoutTheDirectory(t *testing.T) {
	if f, ok := lockPortBlock(t.TempDir()+"/gone", 40000); ok {
		_ = f.Close()
		t.Fatal("took a block in a directory that does not exist")
	}
}

// memberlist binds TCP and UDP on one port, so a port is free for it only
// when both are.
func TestLoopbackPortFreeNeedsUDPToo(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	if !loopbackPortFree(port, false) {
		t.Skipf("port %d is also taken for TCP", port)
	}
	if loopbackPortFree(port, true) {
		t.Fatalf("port %d is held for UDP but reported free for TCP and UDP", port)
	}
}
