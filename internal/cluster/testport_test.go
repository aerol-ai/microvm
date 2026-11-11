package cluster

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// Cluster tests start raft, gossip and HTTP listeners on ports they pick
// first and bind later, because a restarted node must come back on the port
// it had. A port picked with ":0" comes from the kernel's ephemeral range:
// the range it also hands to every other ":0" listener and to the local end
// of every outgoing connection, and this process dials raft, memberlist and
// HTTP peers all the time. Between the pick and the bind another socket can
// take the port ("bind: address already in use" in
// TestClusterFaultLeaderChangeDuringConcurrentReserves, CI run 43082200368).
//
// So the tests pick below the ephemeral range, where the kernel never gives
// out a port on its own. That range has no kernel bookkeeping between
// processes, and two test runs on one laptop (two sessions, or -p) would
// pick the same ports. So each process owns whole blocks of the range: it
// takes a block by holding an exclusive flock on that block's lock file,
// hands out the block's ports in order (never one twice) and takes another
// block when one runs out. The kernel drops the locks when the process
// exits, so a crashed run leaves no block taken. CI also runs each test
// part in its own network namespace.
const (
	testPortLow = 20000
	// testPortHigh stays below Linux's default ephemeral start (32768) and
	// macOS's (49152).
	testPortHigh   = 32000
	testPortBlock  = 128
	testPortLockNS = "aerolvm-cluster-test-ports"
)

// testPortStart picks the block index a claim starts from. A test points a
// second process at a block the first one holds.
var testPortStart = func(blocks int) int { return rand.IntN(blocks) }

var testPorts struct {
	mu       sync.Mutex
	resolved bool
	low      int
	high     int
	lockDir  string
	// held keeps every claimed block's lock file open: closing it would
	// free the block while its ports may still be bound (a node that
	// restarts on its port).
	held []*os.File
	// claimed is every block this process took, so it never takes one
	// twice (the lock alone covers that only when there is a lock dir).
	claimed   map[int]bool
	next, end int // the current block's next port and its end
	fallback  map[int]bool
}

// testPortRange is [low, high): the picking range, cut short if this
// machine's ephemeral range starts lower than usual. ok is false when too
// little room is left below it.
func testPortRange() (low, high int, ok bool) {
	if !testPorts.resolved {
		testPorts.low, testPorts.high = testPortLow, testPortHigh
		if start, found := ephemeralPortStart(); found && start < testPorts.high {
			testPorts.high = start
		}
		testPorts.lockDir = testPortLockDir()
		testPorts.resolved = true
	}
	return testPorts.low, testPorts.high, testPorts.high-testPorts.low >= 8*testPortBlock
}

// testPortLockDir is one directory for every test process of this user on
// the machine. It is under /tmp, not os.TempDir: two sessions can have
// different TMPDIRs and would then not see each other's locks.
func testPortLockDir() string {
	for _, base := range []string{"/tmp", os.TempDir()} {
		dir := filepath.Join(base, fmt.Sprintf("%s-%d", testPortLockNS, os.Getuid()))
		if err := os.MkdirAll(dir, 0o700); err == nil {
			return dir
		}
	}
	return ""
}

// ephemeralPortStart reads where Linux starts handing out ephemeral ports.
func ephemeralPortStart() (int, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(fields[0])
	return n, err == nil
}

// lockPortBlock takes the block starting at first if no other process holds
// it. The returned file keeps the lock; the kernel releases it when the
// file is closed or the process exits.
func lockPortBlock(dir string, first int) (*os.File, bool) {
	f, err := os.OpenFile(filepath.Join(dir, strconv.Itoa(first)+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, false
	}
	return f, true
}

// claimPortBlock takes the first free block at or after block index start
// (wrapping), skipping the blocks in skip, and returns its first port. ok
// is false when every block is taken.
func claimPortBlock(dir string, low, high, start int, skip map[int]bool) (first int, lock *os.File, ok bool) {
	blocks := (high - low) / testPortBlock
	for i := range blocks {
		first := low + ((start+i)%blocks)*testPortBlock
		if skip[first] {
			continue
		}
		if dir == "" {
			return first, nil, true
		}
		if f, ok := lockPortBlock(dir, first); ok {
			return first, f, true
		}
	}
	return 0, nil, false
}

// reserveTestPort returns a loopback port nothing is bound to, and with udp
// also free for UDP (memberlist binds both on one port). No other call in
// this process, and no other test process using it, gets the same port.
func reserveTestPort(t testing.TB, udp bool) int {
	t.Helper()
	testPorts.mu.Lock()
	defer testPorts.mu.Unlock()
	low, high, ok := testPortRange()
	if !ok {
		return ephemeralTestPort(t, udp)
	}
	if testPorts.claimed == nil {
		testPorts.claimed = map[int]bool{}
	}
	for {
		for testPorts.next < testPorts.end {
			port := testPorts.next
			testPorts.next++
			// Something outside the tests may sit on a port of the block.
			if loopbackPortFree(port, udp) {
				return port
			}
		}
		first, lock, ok := claimPortBlock(testPorts.lockDir, low, high, testPortStart((high-low)/testPortBlock), testPorts.claimed)
		if !ok {
			t.Fatalf("every block of loopback ports in [%d, %d) is used up or held by another test process", low, high)
		}
		if lock != nil {
			testPorts.held = append(testPorts.held, lock)
		}
		testPorts.claimed[first] = true
		testPorts.next, testPorts.end = first, first+testPortBlock
	}
}

// ephemeralTestPort is the old pick, for a machine whose ephemeral range
// leaves no room below it. Caller holds testPorts.mu.
func ephemeralTestPort(t testing.TB, udp bool) int {
	t.Helper()
	if testPorts.fallback == nil {
		testPorts.fallback = map[int]bool{}
	}
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		if testPorts.fallback[port] || (udp && !loopbackPortFree(port, true)) {
			continue
		}
		testPorts.fallback[port] = true
		return port
	}
	t.Fatal("no free loopback port")
	return 0
}

func loopbackPortFree(port int, udp bool) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = l.Close()
	if !udp {
		return true
	}
	u, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = u.Close()
	return true
}

func TestReserveTestPortStaysBelowTheEphemeralRangeAndNeverRepeats(t *testing.T) {
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
		port := reserveTestPort(t, true)
		if port < low || port >= high {
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

func TestReserveTestPortSkipsAPortSomethingHolds(t *testing.T) {
	if _, _, ok := testPortRange(); !ok {
		t.Skip("no room below the ephemeral range")
	}
	// The ports right after the last one handed out come next: hold some
	// of them, as an unrelated program might.
	last := reserveTestPort(t, false)
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
		if port := reserveTestPort(t, false); held[port] {
			t.Fatalf("port %d is held by a listener but was handed out", port)
		}
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
func TestReserveTestPortTwoProcessesNeverShareAPort(t *testing.T) {
	if os.Getenv("AEROLVM_TEST_PORT_CHILD") == "1" {
		// Start where the parent holds a block: without the lock the
		// child would hand out the parent's ports.
		start, _ := strconv.Atoi(os.Getenv("AEROLVM_TEST_PORT_START"))
		testPortStart = func(int) int { return start }
		var out []string
		for range 2 * testPortBlock {
			out = append(out, strconv.Itoa(reserveTestPort(t, false)))
		}
		fmt.Println("PORTS " + strings.Join(out, ","))
		return
	}
	if _, _, ok := testPortRange(); !ok || testPorts.lockDir == "" {
		t.Skip("no room below the ephemeral range, or no lock directory")
	}
	mine := map[int]bool{}
	var last int
	for range 2 * testPortBlock {
		last = reserveTestPort(t, false)
		mine[last] = true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReserveTestPortTwoProcessesNeverShareAPort$", "-test.count=1")
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
