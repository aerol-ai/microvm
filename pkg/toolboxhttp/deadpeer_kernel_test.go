//go:build linux && kerneltest

package toolboxhttp

// Dead-peer behaviour on a real kernel, as root:
//
//	sudo go test -tags kerneltest ./pkg/toolboxhttp/ -run 'TestKernelDeadPeer' -v
//
// A "sandbox" is an HTTP server in a network namespace behind a veth on a
// bridge, the way a CNI sandbox sits on cni0. Deleting its veth is what the
// node sees when a gVisor sandbox or a Firecracker VM is killed: nothing is
// left to send a FIN or a reset, the bridge route stays, and the address goes
// silent (ARP is never answered). Through the shipped Transport:
//
//   - a request waiting on a response from such a sandbox fails within the
//     dead-peer bound (keepalive, TCP_USER_TIMEOUT);
//   - a request still sending to one fails within the bound
//     (TCP_USER_TIMEOUT; keepalive does not run while data is unacknowledged);
//   - a live sandbox that answers only after 130s, with nothing on the wire
//     until then, is answered: keepalive probes are acknowledged by its kernel.
//
// TestKernelDeadPeerBaseline (AEROL_KERNEL_BASELINE=1) runs the first case
// with the dialer this package used before the bound, Go's default
// keepalive, for the before number.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	kBridge   = "tbdpbr0"
	kHostCIDR = "10.251.77.1/24"
	kPort     = 2280
	// kHelperEnv makes the test binary the sandbox's HTTP server.
	kHelperEnv = "AEROL_TOOLBOXHTTP_KERNEL_HELPER"
)

func krun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

var bridgeOnce sync.Once

// kernelBridge creates the shared bridge once per test binary.
func kernelBridge(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (network namespaces, veths, a bridge)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2")
	}
	bridgeOnce.Do(func() {
		_ = exec.Command("ip", "link", "del", kBridge).Run()
		krun(t, "ip", "link", "add", kBridge, "type", "bridge")
		krun(t, "ip", "addr", "add", kHostCIDR, "dev", kBridge)
		krun(t, "ip", "link", "set", kBridge, "up")
	})
}

// kernelSandbox is one sandbox: a namespace, its veth on the bridge, and an
// HTTP server inside it. It returns the server's address and the host-side
// veth whose deletion kills the sandbox's network.
func kernelSandbox(t *testing.T, n int) (addr, hostVeth string) {
	t.Helper()
	kernelBridge(t)
	ns := fmt.Sprintf("tbdp-sb%d", n)
	hostVeth = fmt.Sprintf("tbdpv%dh", n)
	nsVeth := fmt.Sprintf("tbdpv%dn", n)
	ip := fmt.Sprintf("10.251.77.%d", 10+n)
	_ = exec.Command("ip", "netns", "del", ns).Run()
	_ = exec.Command("ip", "link", "del", hostVeth).Run()
	krun(t, "ip", "netns", "add", ns)
	krun(t, "ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth)
	krun(t, "ip", "link", "set", nsVeth, "netns", ns)
	krun(t, "ip", "link", "set", hostVeth, "master", kBridge)
	krun(t, "ip", "link", "set", hostVeth, "up")
	krun(t, "ip", "netns", "exec", ns, "ip", "addr", "add", ip+"/24", "dev", nsVeth)
	krun(t, "ip", "netns", "exec", ns, "ip", "link", "set", nsVeth, "up")
	krun(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	addr = fmt.Sprintf("%s:%d", ip, kPort)

	srv := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestKernelDeadPeerHelper$", "-test.timeout=30m")
	srv.Env = append(os.Environ(), kHelperEnv+"="+addr)
	srv.Stdout, srv.Stderr = os.Stderr, os.Stderr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.Process.Kill()
		_ = srv.Wait()
		_ = exec.Command("ip", "link", "del", hostVeth).Run()
		_ = exec.Command("ip", "netns", "del", ns).Run()
	})
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sandbox's server at %s never listened: %v", addr, err)
		}
	}
	return addr, hostVeth
}

// TestKernelDeadPeerHelper is the sandbox's server when run by kernelSandbox.
func TestKernelDeadPeerHelper(t *testing.T) {
	addr := os.Getenv(kHelperEnv)
	if addr == "" {
		t.Skip("helper process only")
	}
	mux := http.NewServeMux()
	// /hang never answers: an exec whose command is still running.
	mux.HandleFunc("/hang", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	// /slow answers after ?for=, with nothing on the wire until then.
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		d, _ := time.ParseDuration(r.URL.Query().Get("for"))
		select {
		case <-time.After(d):
			_, _ = io.WriteString(w, "done")
		case <-r.Context().Done():
		}
	})
	// /upload reads the body to its end: an upload or terminal input.
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		_, _ = fmt.Fprintf(w, "%d", n)
	})
	_ = http.ListenAndServe(addr, mux)
}

// cutAfter deletes hostVeth after d and returns when it did.
func cutAfter(t *testing.T, hostVeth string, d time.Duration) <-chan time.Time {
	t.Helper()
	cut := make(chan time.Time, 1)
	go func() {
		time.Sleep(d)
		if out, err := exec.Command("ip", "link", "del", hostVeth).CombinedOutput(); err != nil {
			t.Errorf("delete %s: %v %s", hostVeth, err, out)
		}
		cut <- time.Now()
	}()
	return cut
}

// failsWithin asserts the request ended in an error between lo and hi after
// the sandbox's network was cut.
func failsWithin(t *testing.T, err error, cut <-chan time.Time, lo, hi time.Duration) {
	t.Helper()
	ended := time.Now()
	cutAt := <-cut
	after := ended.Sub(cutAt)
	t.Logf("request ended %v after the cut: %v", after.Round(100*time.Millisecond), err)
	if err == nil {
		t.Fatal("a request to a sandbox whose network vanished succeeded")
	}
	if after < lo || after > hi {
		t.Fatalf("the request ended %v after the cut, want between %v and %v", after.Round(100*time.Millisecond), lo, hi)
	}
}

func TestKernelDeadPeer(t *testing.T) {
	bound := DeadPeerTimeout()
	if bound <= 0 {
		t.Fatal("the dead-peer bound is off")
	}
	// The kernel checks its timers at probe granularity; allow one interval
	// and a little scheduling on top of the bound.
	slack := bound/6 + 2*time.Second
	client := Client(0)

	t.Run("waiting on a response", func(t *testing.T) {
		t.Parallel()
		addr, veth := kernelSandbox(t, 1)
		cut := cutAfter(t, veth, 2*time.Second)
		resp, err := client.Get("http://" + addr + "/hang")
		if err == nil {
			resp.Body.Close()
		}
		// Nothing ends the request before the first probe goes unanswered.
		failsWithin(t, err, cut, bound/3, bound+slack)
	})

	t.Run("still sending", func(t *testing.T) {
		t.Parallel()
		addr, veth := kernelSandbox(t, 2)
		pr, pw := io.Pipe()
		go func() {
			chunk := make([]byte, 4096)
			for {
				if _, err := pw.Write(chunk); err != nil {
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()
		cut := cutAfter(t, veth, 2*time.Second)
		resp, err := client.Post("http://"+addr+"/upload", "application/octet-stream", pr)
		_ = pr.CloseWithError(io.ErrClosedPipe)
		if err == nil {
			resp.Body.Close()
		}
		// Unacknowledged data retransmits until TCP_USER_TIMEOUT, counted
		// from the first unacknowledged segment, about the cut.
		failsWithin(t, err, cut, bound/3, bound+slack)
	})

	t.Run("slow live sandbox", func(t *testing.T) {
		t.Parallel()
		addr, _ := kernelSandbox(t, 3)
		const answerAfter = 130 * time.Second
		start := time.Now()
		resp, err := client.Get("http://" + addr + "/slow?for=" + answerAfter.String())
		if err != nil {
			t.Fatalf("a live sandbox that answers after %v was cut off after %v: %v", answerAfter, time.Since(start).Round(time.Second), err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		took := time.Since(start)
		t.Logf("answered %q after %v", body, took.Round(100*time.Millisecond))
		if string(body) != "done" || took < answerAfter {
			t.Fatalf("answer %q after %v", body, took)
		}
	})
}

// TestKernelDeadPeerBaseline is the before number: the same dead sandbox
// through Go's default keepalive (idle 30s, then 9 probes 15s apart).
func TestKernelDeadPeerBaseline(t *testing.T) {
	if os.Getenv("AEROL_KERNEL_BASELINE") == "" {
		t.Skip("set AEROL_KERNEL_BASELINE=1 for the before number (about 3 minutes)")
	}
	addr, veth := kernelSandbox(t, 4)
	tr := Transport.Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialerFor(0).DialContext(ctx, network, addr)
	}
	cut := cutAfter(t, veth, 2*time.Second)
	resp, err := (&http.Client{Transport: tr}).Get("http://" + addr + "/hang")
	if err == nil {
		resp.Body.Close()
	}
	failsWithin(t, err, cut, 2*time.Minute, 4*time.Minute)
}
