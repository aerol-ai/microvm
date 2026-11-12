// Package testport hands tests loopback ports that no other test, in this
// process or in another test process on the machine, is given too. Use it
// when a test picks a port and binds it later (a server that restarts on
// its port), or needs a port where nothing listens (a "connection refused"
// check). A test that keeps its own ":0" listener open needs none of this.
package testport

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// Tests start listeners on ports they pick first and bind later: a
// restarted cluster node must come back on the port it had, and a config
// takes an address before the server that binds it starts. A port picked
// with ":0" comes from the kernel's ephemeral range: the range it also hands
// to every other ":0" listener and to the local end of every outgoing
// connection. Between the pick and the bind another socket can take the
// port ("bind: address already in use" in
// TestClusterFaultLeaderChangeDuringConcurrentReserves, CI run 43082200368).
// A port a test wants closed has the same problem the other way round:
// something else can bind it, and the "connection refused" the test expects
// becomes a connection.
//
// So the tests pick below the ephemeral range, where the kernel never gives
// out a port on its own. That range has no kernel bookkeeping between
// processes, and two test runs on one laptop (two sessions, or -p) would
// pick the same ports. So each process owns whole blocks of the range: it
// takes a block by holding an exclusive flock on that block's lock file,
// hands out the block's ports in order (never one twice) and takes another
// block when one runs out. The kernel drops the locks when the process
// exits, so a crashed run leaves no block taken. Every package's tests share
// the blocks (one lock directory), so "go test ./..." running packages in
// parallel cannot hand two of them one port. CI also runs each test part in
// its own network namespace.
const (
	testPortLow = 20000
	// testPortHigh stays below Linux's default ephemeral start (32768) and
	// macOS's (49152).
	testPortHigh   = 32000
	testPortBlock  = 128
	testPortLockNS = "aerolvm-test-ports"
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
	// exhausted is set once no block is left (a long -count run, or
	// several big runs at once): from then on the old pick serves.
	exhausted bool
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
	return parsePortRangeStart(string(raw))
}

// parsePortRangeStart reads the first number of ip_local_port_range
// ("32768\t60999\n").
func parsePortRangeStart(raw string) (int, bool) {
	fields := strings.Fields(raw)
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

// Reserve returns a loopback port nothing is bound to, and with udp also
// free for UDP (memberlist binds both on one port). No other call in this
// process, and no other test process using this package, gets the same
// port. It stays reserved until the process exits, so a test may bind it,
// close it and bind it again.
func Reserve(t testing.TB, udp bool) int {
	t.Helper()
	testPorts.mu.Lock()
	defer testPorts.mu.Unlock()
	low, high, ok := testPortRange()
	if !ok || testPorts.exhausted {
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
			// A process never gives a block back (its ports may be bound
			// again by a restarted node), so a whole-package -count=11 or
			// several big runs at once can use up all of them. The old pick
			// is racy, but a rare flake beats a run that cannot go on.
			testPorts.exhausted = true
			t.Logf("every block of loopback ports in [%d, %d) is used up or held by another test process; picking ephemeral ports from here on", low, high)
			return ephemeralTestPort(t, udp)
		}
		if lock != nil {
			testPorts.held = append(testPorts.held, lock)
		}
		testPorts.claimed[first] = true
		testPorts.next, testPorts.end = first, first+testPortBlock
	}
}

// Addr is Reserve's TCP port as "127.0.0.1:<port>".
func Addr(t testing.TB) string {
	t.Helper()
	return fmt.Sprintf("127.0.0.1:%d", Reserve(t, false))
}

// UDPAddr is Reserve's port, free for TCP and UDP, as "127.0.0.1:<port>".
func UDPAddr(t testing.TB) string {
	t.Helper()
	return fmt.Sprintf("127.0.0.1:%d", Reserve(t, true))
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

func blocksUsedUp() bool {
	testPorts.mu.Lock()
	defer testPorts.mu.Unlock()
	return testPorts.exhausted
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
