//go:build linux

package rootd

// The hostname gateway's per-flow cost in each privilege mode, measured
// the paired way (TestKernelCreateBudget): an executable lookup for one
// new flow of a per-binary rule, read in process by sandboxd's procid
// resolver (single) and asked of the helper over its socket (split), in
// turns within every round. Root, a cgroup v2 hierarchy, and
// AEROL_BUDGET_ROUNDS.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/internal/rootclient"
)

func TestKernelMatchProcessBudget(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("AEROL_BUDGET_ROUNDS"))
	if rounds <= 0 {
		t.Skip("a measurement: set AEROL_BUDGET_ROUNDS")
	}
	needRoot(t)
	k, _ := kernelRig(t)
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		c.Policy.Namespace = "aerolvm"
		c.Policy.CgroupParent = ""
		o.Network = k
	})
	c := rootclient.New(rootclient.Config{Socket: r.cfg.Socket, HelperUID: uint32(os.Geteuid())})
	t.Cleanup(func() { _ = c.Close() })

	// A sandbox's process holding one TCP connection: the flow looked up.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, conn)
		}
	}()
	cg := filepath.Join("/sys/fs/cgroup/aerolvm", "sb-"+shortID(t))
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Skipf("no writable cgroup v2 here: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	proc := exec.Command("bash", "-c", fmt.Sprintf("exec 3<>/dev/tcp/127.0.0.1/%d; exec sleep 600", port))
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Process.Kill(); _ = proc.Wait(); _ = os.Remove(cg) })
	if err := os.WriteFile(filepath.Join(cg, "cgroup.procs"), []byte(strconv.Itoa(proc.Process.Pid)), 0o644); err != nil {
		t.Skipf("cannot move a process into %s: %v", cg, err)
	}
	pid := proc.Process.Pid
	remote := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	var local netip.AddrPort
	for range 100 {
		if local, err = connLocal(pid, remote); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("the process's connection: %v", err)
	}
	paths := []string{"/usr/bin/sleep", "/bin/sleep", "/usr/bin/curl"}
	ctx := context.Background()
	single := func() ([]string, error) {
		is, err := procid.Resolver{}.Matcher(pid, local, remote)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, p := range paths {
			if is(p) {
				out = append(out, p)
			}
		}
		return out, nil
	}
	split := func() ([]string, error) {
		m, _, err := c.MatchProcess(ctx, uint32(pid), local.String(), remote.String(), paths)
		return m, err
	}
	// Both say the same.
	a, errA := single()
	b, errB := split()
	if errA != nil || errB != nil || !slices.Equal(a, b) || len(a) == 0 {
		t.Fatalf("single %v %v, split %v %v", a, errA, b, errB)
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	per := 20
	var s, p []float64
	var loads []float64
	for r := range rounds {
		loads = append(loads, budgetLoad())
		var rs, rp []float64
		for k := range per {
			for _, sp := range [][]bool{{false, true}, {true, false}}[(r+k)%2] {
				t0 := time.Now()
				if sp {
					_, err = split()
				} else {
					_, err = single()
				}
				if err != nil {
					t.Fatal(err)
				}
				if sp {
					rp = append(rp, ms(time.Since(t0)))
				} else {
					rs = append(rs, ms(time.Since(t0)))
				}
			}
		}
		s, p = append(s, budgetMedian(rs)), append(p, budgetMedian(rp))
	}
	t.Logf("executable lookup for one flow: %s", budgetPaired(s, p))
	t.Logf("load average (1 min) over the rounds: %.2f to %.2f", slices.Min(loads), slices.Max(loads))
}

// connLocal is the local end of pid's one TCP connection to remote, from
// the host's table (the test's process shares the host's namespace).
func connLocal(pid int, remote netip.AddrPort) (netip.AddrPort, error) {
	out, err := exec.Command("ss", "-Htnp", "dst", remote.String()).Output()
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.Contains(line, "pid="+strconv.Itoa(pid)+",") {
			continue
		}
		return netip.ParseAddrPort(f[3])
	}
	return netip.AddrPort{}, fmt.Errorf("no connection of process %d to %s yet", pid, remote)
}
