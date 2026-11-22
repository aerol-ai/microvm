//go:build linux

package worker

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Root tests for the worker fence and the worker's syscall filter, from the
// third review: run as root in a privileged container, the worker confined
// as Confine confines it (CI's advisory root step runs them).

const fenceR3Env = "AEROL_WASM_FENCE_R3_CHILD"

// natTestAddr is a loopback address with a NAT rule in front of it in
// TestWorkerFenceNATByOriginalTuple, and the fence's one exception (udp
// port 53) in installFence.
const natTestAddr = "127.0.0.77"

// TestFenceR3Child is the confined half of the tests below.
func TestFenceR3Child(t *testing.T) {
	mode := os.Getenv(fenceR3Env)
	if mode == "" {
		t.Skip("child half of the fence's root tests")
	}
	if err := confineFromEnv(); err != nil {
		fmt.Println("confine:", err)
		os.Exit(4)
	}
	switch mode {
	case "squat":
		// A port on 127.0.0.1, as a node service (sandboxd's API, Caddy's
		// admin API) would use it while that service restarts.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("listen:", err)
			os.Exit(5)
		}
		go echoServe(ln)
		fmt.Println("PORT", ln.Addr().String())
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "sock":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Println("R socket", err)
			os.Exit(0)
		}
		fmt.Println("R so-linger", errText(unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 3600})))
		fmt.Println("R so-reuseaddr", errText(unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)))
		_ = unix.Close(fd)
		_, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
		fmt.Println("R socketpair-dgram", errText(err))
		_, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		fmt.Println("R socketpair-stream", errText(err))
	case "udp":
		for _, kv := range strings.Split(os.Getenv(fenceR3Env+"_TARGETS"), ",") {
			name, addr, _ := strings.Cut(kv, "=")
			fmt.Println("R", name, udpEcho(addr))
		}
	case "bcast":
		port, _ := strconv.Atoi(os.Getenv(fenceR3Env + "_PORT"))
		for _, kv := range strings.Split(os.Getenv(fenceR3Env+"_TARGETS"), ",") {
			name, ip, _ := strings.Cut(kv, "=")
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
			if err != nil {
				fmt.Println("R", name, err)
				continue
			}
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			sa := &unix.SockaddrInet4{Port: port}
			copy(sa.Addr[:], net.ParseIP(ip).To4())
			fmt.Println("R", name, errText(unix.Sendto(fd, []byte(name), 0, sa)))
			_ = unix.Close(fd)
		}
	}
	os.Exit(0)
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func udpEcho(addr string) string {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err.Error()
	}
	b := make([]byte, 4)
	if _, err := c.Read(b); err != nil {
		return err.Error()
	}
	return "ok"
}

// childResults runs a confined child to its end and returns its "R k v"
// lines.
func childResults(t *testing.T, env ...string) map[string]string {
	t.Helper()
	raw, err := confinedChild(t, "TestFenceR3Child", env...).Output()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, raw)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "R "); ok {
			k, v, _ := strings.Cut(rest, " ")
			got[k] = v
		}
	}
	t.Logf("child:\n%s", raw)
	return got
}

// A worker that listens on another loopback address than the guest listen
// host cannot answer root's clients there: the fence lets the worker uid
// reply only from the guest listen host. Otherwise a worker that took
// 127.0.0.1:<port> while a node service restarted would get that
// service's traffic and answer it.
func TestWorkerCannotAnswerOnOtherLoopback(t *testing.T) {
	installFence(t)
	cmd := confinedChild(t, "TestFenceR3Child", fenceR3Env+"=squat")
	stdin, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
	addr := ""
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if a, ok := strings.CutPrefix(sc.Text(), "PORT "); ok {
			addr = a
			break
		}
	}
	if addr == "" {
		t.Fatal("the confined listener gave no address")
	}
	if got := echo(addr, ""); !strings.Contains(got, "timeout") {
		t.Fatalf("root client of a worker on %s: %q, want a timeout", addr, got)
	}
}

// The worker's filter refuses SO_LINGER (a worker could otherwise make the
// last close of a socket, if it fell to sandboxd, wait for its unsent
// data) and socketpair (a datagram pair reaches the node's abstract Unix
// sockets); other socket options still work.
func TestWorkerSeccompRefusesLingerAndSocketpair(t *testing.T) {
	installFence(t)
	got := childResults(t, fenceR3Env+"=sock")
	for k, want := range map[string]string{
		"so-linger":         "operation not permitted",
		"so-reuseaddr":      "ok",
		"socketpair-dgram":  "operation not permitted",
		"socketpair-stream": "operation not permitted",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

// Nothing the worker uid sends to the node's broadcast addresses gets
// out: a subnet broadcast loops back to the node's own UDP services.
func TestWorkerFenceDropsSubnetBroadcast(t *testing.T) {
	installFence(t)
	var bcast, node string
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				ip, m := ipn.IP.To4(), ipn.Mask
				if len(m) == 16 {
					m = m[12:]
				}
				b := make(net.IP, 4)
				for i := range 4 {
					b[i] = ip[i] | ^m[i]
				}
				bcast, node = b.String(), ip.String()
			}
		}
		if bcast != "" {
			break
		}
	}
	if bcast == "" {
		t.Skip("no interface with a broadcast address")
	}
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	got := childResults(t, fenceR3Env+"=bcast", fenceR3Env+"_PORT="+port,
		fenceR3Env+"_TARGETS=node-ip="+node+",subnet-broadcast="+bcast+",limited-broadcast=255.255.255.255")
	for _, k := range []string{"node-ip", "subnet-broadcast", "limited-broadcast"} {
		if got[k] != "operation not permitted" {
			t.Errorf("send to %s = %q, want refused", k, got[k])
		}
	}
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	if n, from, err := pc.ReadFrom(b); err == nil {
		t.Fatalf("a root UDP service on 0.0.0.0 got %q from %v", b[:n], from)
	}
}

// natRule DNATs udp to natTestAddr:from onto natTestAddr:to, as Docker's
// embedded DNS redirects its name server's port.
func natRule(c *nftables.Conn, tbl *nftables.Table, ch *nftables.Chain, from, to uint16) {
	addr := net.ParseIP(natTestAddr).To4()
	c.AddRule(&nftables.Rule{Table: tbl, Chain: ch, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(from)},
		&expr.Immediate{Register: 1, Data: addr},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(to)},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2, Specified: true},
	}})
}

// The NAT'd exception matches the connection's original destination: a
// name server behind a port redirect still answers the worker, and a NAT
// rule that lands other traffic on an allowed address opens nothing.
func TestWorkerFenceNATByOriginalTuple(t *testing.T) {
	installFence(t)
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "aerolvm_test_nat"})
	ch := c.AddChain(&nftables.Chain{Name: "out", Table: tbl, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest})
	natRule(c, tbl, ch, 53, 5353)   // the allowed name server port
	natRule(c, tbl, ch, 9999, 5353) // another port onto the same service
	if err := c.Flush(); err != nil {
		t.Skipf("no nftables NAT here: %v", err)
	}
	t.Cleanup(func() { c.DelTable(tbl); _ = c.Flush() })
	pc, err := net.ListenPacket("udp4", natTestAddr+":5353")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], from)
		}
	}()
	got := childResults(t, fenceR3Env+"=udp", fenceR3Env+"_TARGETS=allowed="+natTestAddr+":53,other-port="+natTestAddr+":9999,direct="+natTestAddr+":5353")
	if got["allowed"] != "ok" {
		t.Errorf("the name server behind its redirect: %q, want an answer", got["allowed"])
	}
	for _, k := range []string{"other-port", "direct"} {
		if got[k] == "ok" {
			t.Errorf("%s reached the service the redirect lands on", k)
		}
	}
}

// The fence table lists cleanly with the nft tool operators use to look at
// it (the runbook says to): every rule, the NAT'd exception included, is
// one nft can print.
func TestFenceTableListsWithNft(t *testing.T) {
	installFence(t)
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("no nft tool here")
	}
	out, err := exec.Command(nft, "list", "table", "inet", "aerolvm_wasm_workers").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list table: %v\n%s", err, out)
	}
	for _, want := range []string{"ct direction reply ip saddr 127.0.97.1", "ct original ip daddr " + natTestAddr, "ct original proto-dst 53"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("nft listing lacks %q:\n%s", want, out)
		}
	}
}
