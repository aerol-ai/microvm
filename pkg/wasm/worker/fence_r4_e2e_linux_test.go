//go:build linux

package worker

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/network/workerfence"
)

// Root tests from the fourth review: run as root in a privileged container,
// with the real fence, and workers confined as Confine confines them (CI's
// advisory root step runs them).

const fenceR4Env = "AEROL_WASM_FENCE_R4_CHILD"

// TestFenceR4Child is the confined half of the tests below.
func TestFenceR4Child(t *testing.T) {
	mode := os.Getenv(fenceR4Env)
	if mode == "" {
		t.Skip("child half of the fourth review's root tests")
	}
	switch mode {
	case "sockets":
		if err := confineFromEnv(); err != nil {
			fmt.Println("confine:", err)
			os.Exit(4)
		}
		try := func(name string, domain, typ, proto int) {
			fd, err := unix.Socket(domain, typ, proto)
			if err == nil {
				_ = unix.Close(fd)
			}
			fmt.Println("R", name, errText(err))
		}
		try("tcp", unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		try("tcp-proto", unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
		try("tcp6", unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		try("udp", unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		try("udp6-proto", unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		try("route", unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
		try("sctp", unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
		try("sctp6", unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
		try("sctp-seqpacket", unix.AF_INET, unix.SOCK_SEQPACKET, 0)
		try("mptcp", unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_MPTCP)
		try("ping", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
		try("raw", unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		try("udplite", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDPLITE)
		// Go asks for MPTCP first for a listener, and takes plain TCP on
		// the refusal.
		ln, err := net.Listen("tcp", workerfence.GuestListenHost+":0")
		fmt.Println("R go-listen", errText(err))
		if err == nil {
			f, _ := ln.(*net.TCPListener).File()
			proto, perr := unix.GetsockoptInt(int(f.Fd()), unix.SOL_SOCKET, unix.SO_PROTOCOL)
			fmt.Println("R go-listen-protocol", proto, errText(perr))
		}
	case "listeners":
		// A hostile worker: its control socket bound before the drop (as
		// runWorker binds it), and an SCTP listener on each port of
		// _SCTP made before the drop too, as one made by any way past the
		// filter would be; after it, a TCP listener bound to a device on
		// each port of _DEV. It answers guest_listener <i> with the i-th.
		ul, err := net.Listen("unix", os.Getenv(fenceR4Env+"_SOCK"))
		if err != nil {
			fmt.Println("unix listen:", err)
			os.Exit(5)
		}
		var lns []*os.File
		listen := func(name string, fd int, err error, port int, before func(int) error) {
			if err == nil && before != nil {
				err = before(fd)
			}
			if err == nil {
				err = unix.Bind(fd, inet4Addr(workerfence.GuestListenHost, port))
			}
			if err == nil {
				err = unix.Listen(fd, 16)
			}
			fmt.Println("R", name+"-"+strconv.Itoa(port), errText(err))
			if err == nil {
				lns = append(lns, os.NewFile(uintptr(fd), name))
			}
		}
		for _, p := range strings.Split(os.Getenv(fenceR4Env+"_SCTP"), ",") {
			port, _ := strconv.Atoi(p)
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP)
			listen("sctp", fd, err, port, nil)
		}
		if err := confineFromEnv(); err != nil {
			fmt.Println("confine:", err)
			os.Exit(4)
		}
		for _, p := range strings.Split(os.Getenv(fenceR4Env+"_DEV"), ",") {
			port, _ := strconv.Atoi(p)
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
			listen("dev", fd, err, port, func(fd int) error {
				return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, os.Getenv(fenceR4Env+"_IFACE"))
			})
		}
		fmt.Println("R ready")
		go func() {
			for {
				c, err := ul.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					env, files, err := readFrameFiles(c)
					closeFiles(files)
					if err != nil || env.Type != MsgGuestListener {
						return
					}
					var p guestListenerPayload
					_ = decodePayload(env.Payload, &p)
					if p.GuestPort < 1 || p.GuestPort > len(lns) {
						return
					}
					body, _ := encodePayload(guestListenerResult{Host: workerfence.GuestListenHost})
					_ = writeFrameFiles(c, Envelope{Type: MsgOK, Payload: body, FDPaths: []string{guestListenerFDName}}, []*os.File{lns[p.GuestPort-1]})
					_, _ = io.Copy(io.Discard, c)
				}(c)
			}
		}()
		_, _ = io.Copy(io.Discard, os.Stdin)
	}
	os.Exit(0)
}

func inet4Addr(ip string, port int) *unix.SockaddrInet4 {
	sa := &unix.SockaddrInet4{Port: port}
	copy(sa.Addr[:], net.ParseIP(ip).To4())
	return sa
}

// Review round 4, F1: the worker's filter keeps socket to the family, type
// and protocol triples a worker uses: TCP, UDP and route netlink. SCTP (by
// protocol or by SOCK_SEQPACKET), MPTCP, ping, raw and UDP-Lite sockets
// fail with EAFNOSUPPORT, whatever flags ride on the type; Go's own TCP
// listener still works, as plain TCP.
func TestWorkerSeccompRefusesOtherSocketTypes(t *testing.T) {
	installFence(t)
	raw, err := confinedChild(t, "TestFenceR4Child", fenceR4Env+"=sockets").Output()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, raw)
	}
	t.Logf("child:\n%s", raw)
	got := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "R "); ok {
			k, v, _ := strings.Cut(rest, " ")
			got[k] = v
		}
	}
	const refused = "address family not supported by protocol"
	for k, want := range map[string]string{
		"tcp": "ok", "tcp-proto": "ok", "tcp6": "ok", "udp": "ok", "udp6-proto": "ok", "route": "ok",
		"sctp": refused, "sctp6": refused, "sctp-seqpacket": refused, "mptcp": refused, "ping": refused, "raw": refused, "udplite": refused,
		"go-listen": "ok", "go-listen-protocol": strconv.Itoa(unix.IPPROTO_TCP) + " ok",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

// Review round 4, F1 and F2, end to end: a confined worker answers
// guest_listener with an SCTP listener on the port of a root service on
// every address and on another tenant's guest port, and with a TCP
// listener bound to another device on the port of a root service bound to
// loopback. sandboxd refuses every one, and none of the services, nor the
// other tenant, gets a request.
func TestGuestListenerRefusesSCTPAndDeviceBoundE2E(t *testing.T) {
	installFence(t)
	root, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	rootHits := countingService(t, root)
	rootPort := root.Addr().(*net.TCPAddr).Port

	devFile, devPort := rawListener(t, unix.AF_INET, unix.SOCK_STREAM, 0, "0.0.0.0", 0, func(fd int) error {
		return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
	})
	devLn, err := net.FileListener(devFile)
	if err != nil {
		t.Fatal(err)
	}
	devHits := countingService(t, devLn)

	// Tenant B: a confined worker's guest listener.
	vcmd := confinedChild(t, "TestFenceProbeChild", fenceProbeEnv+"=listen")
	vin, _ := vcmd.StdinPipe()
	vout, _ := vcmd.StdoutPipe()
	if err := vcmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vin.Close(); _ = vcmd.Wait() })
	victim := ""
	for sc := bufio.NewScanner(vout); sc.Scan(); {
		if a, ok := strings.CutPrefix(sc.Text(), "PORT "); ok {
			victim = a
			break
		}
	}
	_, vp, _ := net.SplitHostPort(victim)
	victimPort, _ := strconv.Atoi(vp)
	if victimPort == 0 || echo(victim, "") != "ok" {
		t.Fatalf("tenant B's listener %q is not up", victim)
	}

	sock := filepath.Join(t.TempDir(), "a.sock")
	iface := ""
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			iface = i.Name
			break
		}
	}
	cmd := confinedChild(t, "TestFenceR4Child", fenceR4Env+"=listeners", fenceR4Env+"_SOCK="+sock,
		fenceR4Env+"_SCTP="+strconv.Itoa(rootPort)+","+strconv.Itoa(victimPort), fenceR4Env+"_DEV="+strconv.Itoa(devPort), fenceR4Env+"_IFACE="+iface)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Wait() })
	made := 0
	for sc := bufio.NewScanner(out); sc.Scan(); {
		line := sc.Text()
		t.Logf("worker: %s", line)
		if strings.HasPrefix(line, "R ") && strings.HasSuffix(line, " ok") {
			made++
		}
		if line == "R ready" {
			break
		}
	}
	if made == 0 {
		t.Skip("the kernel made none of the hostile listeners (no SCTP, no SO_BINDTODEVICE)")
	}
	ports := []int{rootPort, victimPort, devPort}
	for i := 1; i <= made; i++ {
		rec := httptest.NewRecorder()
		err := NewClient(sock).ProxyHTTPDialed("sb-A", i, workerfence.GuestListenHost, ports, new(atomic.Int64), new(atomic.Int64), rec, httptest.NewRequest(http.MethodGet, "http://gateway/internal/secret", nil))
		t.Logf("listener %d: err %v, %d %q", i, err, rec.Code, rec.Body.String())
		if err == nil {
			t.Errorf("listener %d was taken: %d %q", i, rec.Code, rec.Body.String())
		}
	}
	if rootHits.Load() != 0 || devHits.Load() != 0 {
		t.Fatalf("root services served %d and %d requests", rootHits.Load(), devHits.Load())
	}
}

// FUSE stand-in for a mount whose server the tenant runs. Taken from the
// fourth review's proof of concept: a one-file file system whose FLUSH
// never gets an answer (a stalled remote).
func fuseLE(b []byte, vals ...any) []byte {
	for _, v := range vals {
		switch x := v.(type) {
		case uint16:
			b = binary.LittleEndian.AppendUint16(b, x)
		case uint32:
			b = binary.LittleEndian.AppendUint32(b, x)
		case uint64:
			b = binary.LittleEndian.AppendUint64(b, x)
		}
	}
	return b
}

func fuseAttrOut(ino uint64, mode uint32) []byte {
	b := fuseLE(nil, ino, uint64(5), uint64(1), uint64(0), uint64(0), uint64(0))
	return fuseLE(b, uint32(0), uint32(0), uint32(0), mode, uint32(1), uint32(0), uint32(0), uint32(0), uint32(4096), uint32(0))
}

// stalledFuse mounts the stand-in at dir. It returns how many FLUSH requests
// wait, and an abort that ends every waiting request.
func stalledFuse(t *testing.T, dir string) (*atomic.Int64, func()) {
	t.Helper()
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no /dev/fuse: %v", err)
	}
	opts := fmt.Sprintf("fd=%d,rootmode=40000,user_id=0,group_id=0,allow_other", fd)
	if err := unix.Mount("aerolfuse", dir, "fuse", unix.MS_NOSUID|unix.MS_NODEV, opts); err != nil {
		_ = unix.Close(fd)
		t.Skipf("mount fuse: %v", err)
	}
	var flushes atomic.Int64
	reply := func(unique uint64, errno int32, payload []byte) {
		out := fuseLE(nil, uint32(16+len(payload)), uint32(errno), unique)
		_, _ = unix.Write(fd, append(out, payload...))
	}
	go func() {
		runtime.LockOSThread()
		buf := make([]byte, 1<<20+4096)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				if err == unix.EINTR || err == unix.EAGAIN {
					continue
				}
				return
			}
			if n < 40 {
				continue
			}
			op := binary.LittleEndian.Uint32(buf[4:])
			unique := binary.LittleEndian.Uint64(buf[8:])
			node := binary.LittleEndian.Uint64(buf[16:])
			switch op {
			case 26: // INIT
				reply(unique, 0, fuseLE(nil, uint32(7), uint32(22), uint32(0), uint32(0), uint16(16), uint16(12), uint32(65536)))
			case 3: // GETATTR
				mode := uint32(0o100644)
				if node == 1 {
					mode = 0o40755
				}
				reply(unique, 0, append(fuseLE(nil, uint64(1), uint32(0), uint32(0)), fuseAttrOut(node, mode)...))
			case 1: // LOOKUP
				if strings.TrimRight(string(buf[40:n]), "\x00") != "f" {
					reply(unique, -int32(unix.ENOENT), nil)
					continue
				}
				reply(unique, 0, append(fuseLE(nil, uint64(2), uint64(0), uint64(1), uint64(1), uint32(0), uint32(0)), fuseAttrOut(2, 0o100644)...))
			case 14: // OPEN
				reply(unique, 0, fuseLE(nil, uint64(7), uint32(0), uint32(0)))
			case 25: // FLUSH: never answered
				flushes.Add(1)
			case 18, 29: // RELEASE, RELEASEDIR
				reply(unique, 0, nil)
			case 2, 42, 36: // FORGET, BATCH_FORGET, INTERRUPT: no reply
			default:
				reply(unique, -int32(unix.ENOSYS), nil)
			}
		}
	}()
	aborted := false
	abort := func() {
		if aborted {
			return
		}
		aborted = true
		_ = unix.Unmount(dir, unix.MNT_DETACH)
		_ = unix.Close(fd) // aborts the connection: every waiting request ends
	}
	t.Cleanup(abort)
	return &flushes, abort
}

func osThreads() int {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Threads:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// Review round 4, F4, end to end: a worker answers guest_listener with a
// file on a FUSE mount whose server never answers FLUSH. sandboxd closing
// it on the request's thread would wait for good, one thread per request,
// and each stuck request would keep its in-flight slot. Every call returns
// at once, sandboxd's thread count stays flat, and the worker is
// quarantined.
func TestFuseFileFromWorkerHoldsNoSandboxdThread(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount FUSE")
	}
	mnt := t.TempDir()
	flushes, abort := stalledFuse(t, mnt)
	file, err := os.Open(filepath.Join(mnt, "f"))
	if err != nil {
		t.Fatalf("open the file on the FUSE mount: %v", err)
	}
	defer file.Close()
	sock := filepath.Join(t.TempDir(), "w.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if env, files, err := readFrameFiles(c); err != nil || env.Type != MsgGuestListener {
					return
				} else {
					closeFiles(files)
				}
				body, _ := encodePayload(guestListenerResult{Host: workerfence.GuestListenHost, Port: 1})
				_ = writeFrameFiles(c, Envelope{Type: MsgOK, Payload: body, FDPaths: []string{guestListenerFDName}}, []*os.File{file})
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	before := osThreads()
	const n = 30
	done := make(chan error, n)
	for range n {
		go func() {
			done <- NewClient(sock).ProxyHTTPDialed("sb", 8080, workerfence.GuestListenHost, []int{1}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}
	returned, quarantine := 0, 0
	deadline := time.After(10 * time.Second)
wait:
	for returned < n {
		select {
		case err := <-done:
			returned++
			if err != nil && strings.Contains(err.Error(), "quarantined") {
				quarantine++
			}
		case <-deadline:
			break wait
		}
	}
	after := osThreads()
	t.Logf("%d/%d calls returned (%d refused as quarantined); FLUSH waiting at the stalled server: %d; threads %d -> %d", returned, n, quarantine, flushes.Load(), before, after)
	abort()
	if returned != n {
		t.Fatalf("%d of %d calls never returned", n-returned, n)
	}
	// A thread held per call would add one per call (n). The race
	// detector's runtime starts more threads of its own on a busy machine
	// (11 -> 28 seen with every call returned), so it gets more room, still
	// short of n.
	slack := 8
	if raceEnabled {
		slack = 24
	}
	if after > before+slack {
		t.Fatalf("threads went from %d to %d", before, after)
	}
	err = NewClient(sock).ProxyHTTPDialed("sb", 8080, workerfence.GuestListenHost, []int{1}, new(atomic.Int64), new(atomic.Int64), httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("the worker that sent the file was not quarantined: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // the aborted FLUSH lets the reaper go on
}

// Review round 4, F5: a datagram from the worker uid to a subnet's network
// address must not reach the node's UDP services on 0.0.0.0. Kernels that
// still put "broadcast <network>" in the local table (5.10 does) deliver
// it like one to the broadcast address; with nft fib the fence drops every
// broadcast destination, and without it the listed plan drops the network
// address too.
func TestWorkerFenceDropsSubnetNetworkAddress(t *testing.T) {
	_, rules := installFence(t)
	var netAddr string
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				if ones, _ := ipn.Mask.Size(); ones > 0 && ones <= 30 {
					netAddr = ipn.IP.Mask(ipn.Mask).String()
				}
			}
		}
		if netAddr != "" {
			break
		}
	}
	if netAddr == "" {
		t.Skip("no interface with an IPv4 subnet of /30 or wider")
	}
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	got := childResults(t, fenceR3Env+"=bcast", fenceR3Env+"_PORT="+port, fenceR3Env+"_TARGETS=network-address="+netAddr)
	listed := false
	for _, r := range rules {
		listed = listed || r.Why == "node network address"
	}
	if listed && got["network-address"] != "operation not permitted" {
		t.Errorf("send to the network address %s = %q, want refused", netAddr, got["network-address"])
	}
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	if n, from, err := pc.ReadFrom(b); err == nil {
		t.Fatalf("a root UDP service on 0.0.0.0 got %q from %v", b[:n], from)
	}
}
