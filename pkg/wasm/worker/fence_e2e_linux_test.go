//go:build linux

package worker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/network/workerfence"
	"github.com/aerol-ai/microvm/internal/wasmtestguest"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// These run as root with nf_tables, in a host or privileged container that
// allows new PID namespaces (CI's advisory root step): the worker fence in
// the kernel, and workers confined exactly as Confine confines them.

const fenceProbeEnv = "AEROL_WASM_FENCE_PROBE"

func echoServe(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
	}
}

// echo dials addr (from src when it is set), sends "ping" and reports
// "ok" when it comes back.
func echo(addr, src string) string {
	d := net.Dialer{Timeout: time.Second}
	if src != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err.Error()
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return "no reply: " + err.Error()
	}
	return "ok"
}

// TestFenceProbeChild is the confined half of TestWorkerFenceGuestListeners.
// "listen": a worker with a guest listener on the guest listen address,
// alive until stdin closes. "probe": a worker that tries to reach what it
// must not.
func TestFenceProbeChild(t *testing.T) {
	mode := os.Getenv(fenceProbeEnv)
	if mode == "" {
		t.Skip("child half of TestWorkerFenceGuestListeners")
	}
	if err := confineFromEnv(); err != nil {
		fmt.Println("confine:", err)
		os.Exit(4)
	}
	if mode == "listen" {
		ln, err := net.Listen("tcp", workerfence.GuestListenHost+":0")
		if err != nil {
			fmt.Println("listen:", err)
			os.Exit(5)
		}
		go echoServe(ln)
		fmt.Println("PORT", ln.Addr().String())
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	// Its own guest listener: even that is root's to connect to.
	if own, err := net.Listen("tcp", workerfence.GuestListenHost+":0"); err == nil {
		go echoServe(own)
		fmt.Println("R own-listener", echo(own.Addr().String(), ""))
	}
	for _, kv := range strings.Split(os.Getenv(fenceProbeEnv+"_TARGETS"), ",") {
		name, addr, _ := strings.Cut(kv, "=")
		fmt.Println("R", name, echo(addr, ""))
		fmt.Println("R", name+"-from-guest-host", echo(addr, workerfence.GuestListenHost))
	}
	family := func(domain, typ, proto int) string {
		fd, err := unix.Socket(domain, typ, proto)
		if err != nil {
			return err.Error()
		}
		_ = unix.Close(fd)
		return "ok"
	}
	fmt.Println("R af-alg", family(unix.AF_ALG, unix.SOCK_SEQPACKET, 0))
	fmt.Println("R af-vsock", family(unix.AF_VSOCK, unix.SOCK_STREAM, 0))
	fmt.Println("R af-packet", family(unix.AF_PACKET, unix.SOCK_RAW, 0))
	fmt.Println("R af-unix", family(unix.AF_UNIX, unix.SOCK_STREAM, 0))
	fmt.Println("R af-netlink-netfilter", family(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER))
	fmt.Println("R af-netlink-route", family(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE))
	fmt.Println("R af-inet6", family(unix.AF_INET6, unix.SOCK_STREAM, 0))
	if _, err := net.InterfaceAddrs(); err != nil {
		fmt.Println("R node-addrs", err)
	} else {
		fmt.Println("R node-addrs ok")
	}
	if ab := os.Getenv(fenceProbeEnv + "_ABSTRACT"); ab != "" {
		c, err := net.DialTimeout("unix", "@"+ab, time.Second)
		if err != nil {
			fmt.Println("R abstract-unix", err)
		} else {
			_ = c.Close()
			fmt.Println("R abstract-unix ok")
		}
	}
	os.Exit(0)
}

// installFence puts the fence in for the test's worker uid as sandboxd
// does (workerfence.Fence: with nft fib, or with the node's addresses on a
// kernel without it) and returns its backend and the rules that went in.
func installFence(t *testing.T) (workerfence.Backend, []workerfence.Rule) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the worker drops from root, and the fence is an nftables table")
	}
	if !canMakePIDNamespace() {
		t.Skip("needs a host (or privileged container) that allows new PID namespaces, as sandboxd's does")
	}
	rec := &recordingBackend{Backend: workerfence.NewBackend()}
	fence := workerfence.New(rec, func() (workerfence.Spec, error) {
		var local []netip.Prefix
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					ones, _ := n.Mask.Size()
					if ip = ip.Unmap(); ip.Is4() && ones > 32 {
						ones -= 96
					}
					local = append(local, netip.PrefixFrom(ip, ones))
				}
			}
		}
		// One exception, as the audit ingest and a name server are, so its
		// rules (the NAT'd one reads the conntrack original tuple) go into
		// the real kernel too.
		return workerfence.Spec{UID: e2eWorkerUID, Local: local, Allow: []workerfence.Allow{
			{Proto: "udp", Prefix: netip.MustParsePrefix(natTestAddr + "/32"), PortLo: 53, PortHi: 53, Why: "name server"},
		}}, nil
	}, nil)
	if err := fence.Ensure(); err != nil {
		t.Fatalf("install the fence (needs nf_tables and CAP_NET_ADMIN, as sandboxd has): %v", err)
	}
	t.Cleanup(func() { _ = rec.Remove() })
	return rec.Backend, rec.last
}

// recordingBackend keeps the rules that went in.
type recordingBackend struct {
	workerfence.Backend
	last []workerfence.Rule
}

func (r *recordingBackend) Apply(rules []workerfence.Rule) error {
	err := r.Backend.Apply(rules)
	if err == nil {
		r.last = rules
	}
	return err
}

// confinedChild starts the test binary as a confined worker would start.
func confinedChild(t *testing.T, run string, env ...string) *exec.Cmd {
	t.Helper()
	spawn := Confine(func(context.Context, string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^"+run+"$")
		cmd.Env = append(os.Environ(), env...)
		cmd.Stderr = os.Stderr
		return cmd, nil
	}, Confinement{UID: e2eWorkerUID, GID: e2eWorkerUID})
	cmd, err := spawn(context.Background(), filepath.Join(t.TempDir(), "w.sock"))
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

// TestWorkerFenceGuestListeners checks the rule that only root opens
// connections to guest listeners. Root (sandboxd's readiness check and its
// proxy) reaches a confined worker's listener on the guest listen address.
// A confined worker reaches none: not another worker's listener, not its
// own, not a root service on 0.0.0.0 through that address, nor any of the
// node's own addresses, whatever source address it binds. It also cannot
// make a socket of a family it has no use for, nor reach an abstract Unix
// socket of the node.
func TestWorkerFenceGuestListeners(t *testing.T) {
	installFence(t)

	victim := confinedChild(t, "TestFenceProbeChild", fenceProbeEnv+"=listen")
	stdin, _ := victim.StdinPipe()
	out, _ := victim.StdoutPipe()
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = victim.Wait() })
	sc := bufio.NewScanner(out)
	victimAddr := ""
	for sc.Scan() {
		if a, ok := strings.CutPrefix(sc.Text(), "PORT "); ok {
			victimAddr = a
			break
		}
		t.Logf("victim: %s", sc.Text())
	}
	if victimAddr == "" {
		t.Fatal("the confined listener gave no address")
	}
	// Root, from its default source (127.0.0.1), as waitGuestListenReady
	// and the proxy dial.
	if got := echo(victimAddr, ""); got != "ok" {
		t.Fatalf("root to a confined worker's listener: %s", got)
	}

	serve := func(addr string) string {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go echoServe(ln)
		return ln.Addr().String()
	}
	admin := serve("127.0.0.1:0")
	wild := serve("0.0.0.0:0") // a root service on every address, on an ephemeral port
	_, wildPort, _ := net.SplitHostPort(wild)
	targets := []string{
		"other-worker-listener=" + victimAddr,
		"admin=" + admin,
		"wild-via-guest-host=" + net.JoinHostPort(workerfence.GuestListenHost, wildPort),
	}
	if ip := nodeIPv4(); ip != "" {
		targets = append(targets, "wild-via-node-ip="+net.JoinHostPort(ip, wildPort))
	} else {
		t.Log("no non-loopback IPv4 address: the node-address case is not checked")
	}
	abName := "aerolvm-fence-test-" + strconv.Itoa(os.Getpid())
	if abl, err := net.Listen("unix", "@"+abName); err == nil {
		t.Cleanup(func() { _ = abl.Close() })
		go func() {
			for {
				c, err := abl.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	probe := confinedChild(t, "TestFenceProbeChild", fenceProbeEnv+"=probe",
		fenceProbeEnv+"_TARGETS="+strings.Join(targets, ","), fenceProbeEnv+"_ABSTRACT="+abName)
	raw, err := probe.Output()
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, raw)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "R "); ok {
			k, v, _ := strings.Cut(rest, " ")
			got[k] = v
		}
	}
	t.Logf("probe:\n%s", raw)
	for _, k := range []string{"own-listener", "other-worker-listener", "other-worker-listener-from-guest-host", "admin", "admin-from-guest-host",
		"wild-via-guest-host", "wild-via-guest-host-from-guest-host", "wild-via-node-ip", "wild-via-node-ip-from-guest-host"} {
		v, ok := got[k]
		if !ok && strings.HasPrefix(k, "wild-via-node-ip") {
			continue
		}
		if !strings.Contains(v, "timeout") {
			t.Errorf("confined worker reached %s: %q", k, v)
		}
	}
	for _, k := range []string{"af-alg", "af-vsock", "af-packet", "af-unix", "af-netlink-netfilter", "abstract-unix"} {
		if !strings.Contains(got[k], "address family not supported") {
			t.Errorf("%s = %q, want EAFNOSUPPORT", k, got[k])
		}
	}
	for _, k := range []string{"af-netlink-route", "af-inet6", "node-addrs"} {
		if got[k] != "ok" {
			t.Errorf("%s = %q, want ok", k, got[k])
		}
	}
}

// nodeIPv4 is a non-loopback IPv4 address of this host.
func nodeIPv4() string {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return ipn.IP.String()
			}
		}
	}
	return ""
}

// TestConfinedWorkerProxiesHTTP runs the exposed-port path end to end with
// the fence in: a confined worker serves a real HTTP guest on the guest
// listen address, root checks it is ready, and a request reaches it through
// a connection sandboxd opens; the worker will not dial the guest itself.
func TestConfinedWorkerProxiesHTTP(t *testing.T) {
	installFence(t)
	guest := wasmtestguest.Path(t, wasmtestguest.HTTP)
	private := filepath.Join(t.TempDir(), "private")
	modules, work, sockets := filepath.Join(private, "modules"), filepath.Join(private, "run", "sb-http"), filepath.Join(private, "sockets")
	for _, d := range []string{modules, work, sockets} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(work, e2eWorkerUID, e2eWorkerUID); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(modules, "http.wasm")
	raw, err := os.ReadFile(guest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	withGrantPolicy(t, GrantPolicy{Roots: []string{private}, Worker: Confinement{UID: e2eWorkerUID, GID: e2eWorkerUID}})
	_, client := startConfinedWorker(t, filepath.Join(sockets, "w.sock"), false, "")
	const sb = "sb-e2e"
	if _, err := client.LoadModule(sb, module, 64); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := client.Instantiate(sb, wasmengine.Capabilities{
		MemoryMB:       64,
		WASIListenPort: wasmengine.WASIListenPortDisabled,
		Args:           []string{"aerolhttp", "multiport"},
		Preopens:       []wasmengine.Preopen{{GuestPath: "/work", HostPath: work}},
	}); err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	report, err := client.SetListenPorts(sb, []int{8080}, workerfence.GuestListenHost)
	if err != nil || report.Primary <= 0 {
		t.Fatalf("listeners = %+v, %v", report, err)
	}
	go func() { _ = client.Invoke(sb, "_start") }()
	addr := net.JoinHostPort(workerfence.GuestListenHost, strconv.Itoa(report.Primary))
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			ready = true
			break
		}
	}
	if !ready {
		t.Fatalf("root never reached the confined guest's listener %s", addr)
	}
	ports := []int{report.Primary}
	for _, p := range report.Ports {
		ports = append(ports, p)
	}
	var body string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		rec := httptest.NewRecorder()
		err := client.ProxyHTTPDialed(sb, 8080, workerfence.GuestListenHost, ports, new(atomic.Int64), new(atomic.Int64), rec, httptest.NewRequest(http.MethodGet, "http://gateway/port", nil))
		if err == nil && rec.Code == http.StatusOK {
			body = rec.Body.String()
			break
		}
		body = fmt.Sprintf("%v %d %q", err, rec.Code, rec.Body.String())
	}
	if body != "8080" {
		t.Fatalf("proxied request = %s", body)
	}
	// The plain proxy_http asks the worker to dial: a confined one refuses.
	err = client.ProxyHTTP(sb, 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://gateway/port", nil))
	if err == nil || !strings.Contains(err.Error(), "opens no connection to it") {
		t.Fatalf("plain proxy_http on a confined worker = %v", err)
	}
}
