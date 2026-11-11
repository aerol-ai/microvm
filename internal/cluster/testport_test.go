package cluster

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
// out a port on its own, and one process never hands out a port twice. CI
// runs each test part in its own network namespace, so nothing else picks
// there; on a laptop the random start keeps two test processes apart.
const (
	testPortLow = 20000
	// testPortHigh stays below Linux's default ephemeral start (32768) and
	// macOS's (49152).
	testPortHigh = 32000
)

var testPorts struct {
	mu       sync.Mutex
	used     map[int]bool
	low      int
	high     int
	resolved bool
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
		testPorts.resolved = true
	}
	return testPorts.low, testPorts.high, testPorts.high-testPorts.low >= 1000
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

// reserveTestPort returns a loopback port nothing is bound to, and with udp
// also free for UDP (memberlist binds both on one port). The port is never
// returned again by this process.
func reserveTestPort(t testing.TB, udp bool) int {
	t.Helper()
	testPorts.mu.Lock()
	defer testPorts.mu.Unlock()
	if testPorts.used == nil {
		testPorts.used = map[int]bool{}
	}
	low, high, ok := testPortRange()
	if !ok {
		return ephemeralTestPort(t, udp)
	}
	span := high - low
	start := rand.IntN(span)
	for i := range span {
		port := low + (start+i)%span
		if testPorts.used[port] || !loopbackPortFree(port, udp) {
			continue
		}
		testPorts.used[port] = true
		return port
	}
	t.Fatalf("no free loopback port in [%d, %d)", low, high)
	return 0
}

// ephemeralTestPort is the old pick, for a machine whose ephemeral range
// leaves no room below it. Caller holds testPorts.mu.
func ephemeralTestPort(t testing.TB, udp bool) int {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		if testPorts.used[port] || (udp && !loopbackPortFree(port, true)) {
			continue
		}
		testPorts.used[port] = true
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
	for range 200 {
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
	low, high, ok := testPortRange()
	if !ok {
		t.Skip("no room below the ephemeral range")
	}
	// Hold every port of a small window, then check none of them comes
	// back while it is held.
	held := map[int]bool{}
	for port := low; port < high && len(held) < 20; port++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = l.Close() })
		held[port] = true
	}
	for range 200 {
		if port := reserveTestPort(t, false); held[port] {
			t.Fatalf("port %d is held by a listener but was handed out", port)
		}
	}
}
