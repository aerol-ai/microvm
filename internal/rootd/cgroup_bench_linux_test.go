//go:build linux

package rootd

// The budget of a create's cgroup work (M1 PR 6, F10), split against
// single, on the real kernel, as a paired measurement in the shape of
// TestKernelCreateBudget: every round runs both modes, in turns (which
// goes first turns each time), so load on the machine falls on both
// alike. A create marks its sandbox's group twice, right after its task
// starts and once it answers:
//
//	single: the containerd driver writes the group's files in process;
//	split:  the same driver asks the helper, PrepareSandbox's cgroup part
//	        alone, one call per mark, with sandboxd's client.
//
// Each sandbox's group holds AEROL_BUDGET_PROCS processes (default 8: a
// gVisor sandbox runs about seven, and runsc). The series:
//
//   - the two marks alone, split into the time inside the helper's two
//     calls and the client's round trips around them;
//   - a cold create's root work: the namespace and firewall call (PR 5)
//     and the two marks;
//   - a warm create's: the firewall call and the two marks.
//
// Runs only with AEROL_BUDGET_ROUNDS set, as root on a writable cgroup v2
// mount (see cgroup_kernel_linux_test.go), with the real CNI plugins for
// the real numbers:
//
//	AEROL_KT_CNI_DIR=/opt/cni/bin AEROL_BUDGET_ROUNDS=25 go test -run TestKernelCgroupBudget -v ./internal/rootd/

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"

	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
)

// sleepers starts n `sleep` processes in group at OOM score -999 (as
// gVisor's processes inherit the shim's), stopped at cleanup.
func (l *f10Layout) sleepers(group string, n int) []int {
	l.t.Helper()
	fd, err := os.Open(l.dir(group))
	if err != nil {
		l.t.Fatal(err)
	}
	defer fd.Close()
	var pids []int
	for range n {
		cmd := exec.Command("sleep", "3600")
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
		if err := cmd.Start(); err != nil {
			l.t.Fatal(err)
		}
		p := &f10Proc{name: "sleep", cmd: cmd, done: make(chan struct{})}
		go func() { p.err = cmd.Wait(); close(p.done) }()
		l.procs = append(l.procs, p)
		pids = append(pids, cmd.Process.Pid)
	}
	return pids
}

// unmark puts a group back as the runtime makes it: memory.oom.group 0,
// and its processes at -999.
func (l *f10Layout) unmark(group string, pids []int) {
	l.t.Helper()
	l.write(group, "memory.oom.group", "0")
	for _, pid := range pids {
		if err := os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid), []byte("-999"), 0); err != nil {
			l.t.Fatal(err)
		}
	}
}

func TestKernelCgroupBudget(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("AEROL_BUDGET_ROUNDS"))
	if rounds <= 0 {
		t.Skip("a measurement: set AEROL_BUDGET_ROUNDS")
	}
	per, procs := 5, 8
	if v, err := strconv.Atoi(os.Getenv("AEROL_BUDGET_PER_ROUND")); err == nil && v > 0 {
		per = v
	}
	if v, err := strconv.Atoi(os.Getenv("AEROL_BUDGET_PROCS")); err == nil && v > 0 {
		procs = v
	}
	l := newF10Layout(t)
	// The helper's own time in the calls since the last reset (calls here
	// are one at a time).
	var inside atomic.Int64
	f := newFirewallBenchWith(t, func(c *Config) { c.Policy.CgroupParent = l.parent() },
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			t0 := time.Now()
			resp, err := h(ctx, req)
			inside.Add(int64(time.Since(t0)))
			return resp, err
		}))
	ctx := context.Background()
	single := cntr.New(cntr.Config{CgroupParent: l.parent()}, nil, nil)
	split := cntr.New(cntr.Config{CgroupParent: l.parent()}, nil, nil)
	split.SetCgroupMarker(f.c)
	groups := map[bool]string{false: l.parent() + "/sb-a", true: l.parent() + "/sb-b"}
	pids := map[bool][]int{false: l.sleepers(groups[false], procs), true: l.sleepers(groups[true], procs)}
	// The first call of the part, once, outside the series (the client's
	// handshake is done: the firewall bench made calls already).
	t0 := time.Now()
	if err := split.MarkOOMVictim(ctx, groups[true]); err != nil {
		t.Fatal(err)
	}
	t.Logf("first mark through the helper: %.2f ms", float64(time.Since(t0).Microseconds())/1000)

	// marks is a create's two marks; it answers their time and the time
	// inside the helper's calls.
	marks := func(splitMode bool) (time.Duration, time.Duration) {
		l.unmark(groups[splitMode], pids[splitMode])
		d := single
		if splitMode {
			d = split
		}
		inside.Store(0)
		t0 := time.Now()
		for range 2 {
			if err := d.MarkOOMVictim(ctx, groups[splitMode]); err != nil {
				t.Fatal(err)
			}
		}
		took := time.Since(t0)
		if got, _ := f10Marked(t, groups[splitMode]); got != "1" {
			t.Fatalf("not marked: memory.oom.group %s", got)
		}
		return took, time.Duration(inside.Load())
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	type series struct{ single, split, inside []float64 }
	var mk, cold, warm series
	var loads []float64
	n := 0
	for r := range rounds {
		loads = append(loads, budgetLoad())
		var ms1, mp, mi, cs, cp, ws, wp []float64
		for k := range per {
			for _, splitMode := range [][]bool{{false, true}, {true, false}}[(r+k)%2] {
				n++
				// Cold: the namespace and rules, then the two marks.
				name := fmt.Sprintf("c%d", n)
				t0 := time.Now()
				var ip string
				var err error
				if splitMode {
					ip, err = f.splitCold(ctx, f.c, name)
				} else {
					ip, err = f.singleCold(ctx, name)
				}
				prep := time.Since(t0)
				if err != nil {
					t.Fatal(err)
				}
				m1, in1 := marks(splitMode)
				if err := f.splitRelease(ctx, name, ip); err != nil {
					t.Fatal(err)
				}
				// Warm: a realized slot's rules, then the two marks.
				name = fmt.Sprintf("w%d", n)
				if _, ip, err = f.k.steps.Realize(ctx, name); err != nil {
					t.Fatal(err)
				}
				t0 = time.Now()
				if splitMode {
					err = f.splitWarm(ctx, name, ip)
				} else {
					err = f.singleRules(ip)
				}
				rules := time.Since(t0)
				if err != nil {
					t.Fatal(err)
				}
				m2, in2 := marks(splitMode)
				if err := f.splitRelease(ctx, name, ip); err != nil {
					t.Fatal(err)
				}
				if splitMode {
					mp, mi = append(mp, ms(m1), ms(m2)), append(mi, ms(in1), ms(in2))
					cp, wp = append(cp, ms(prep+m1)), append(wp, ms(rules+m2))
				} else {
					ms1 = append(ms1, ms(m1), ms(m2))
					cs, ws = append(cs, ms(prep+m1)), append(ws, ms(rules+m2))
				}
			}
		}
		mk.single, mk.split, mk.inside = append(mk.single, budgetMedian(ms1)), append(mk.split, budgetMedian(mp)), append(mk.inside, budgetMedian(mi))
		cold.single, cold.split = append(cold.single, budgetMedian(cs)), append(cold.split, budgetMedian(cp))
		warm.single, warm.split = append(warm.single, budgetMedian(ws)), append(warm.split, budgetMedian(wp))
	}
	t.Logf("a create's two marks (%d processes in the group): %s", procs, budgetPaired(mk.single, mk.split))
	t.Logf("  inside the helper's two calls vs single: %s", budgetPaired(mk.single, mk.inside))
	t.Logf("  the client's round trips (split - inside): %s", budgetPaired(mk.inside, mk.split))
	t.Logf("cold create (namespace, CNI, block-all, policy, two marks): %s", budgetPaired(cold.single, cold.split))
	t.Logf("warm create (block-all, policy, two marks): %s", budgetPaired(warm.single, warm.split))
	t.Logf("load average (1 min) over the rounds: %.2f to %.2f", slices.Min(loads), slices.Max(loads))
	if s, scores := f10Marked(t, groups[true]); s != "1" || len(scores) != procs || slices.ContainsFunc(scores, func(v string) bool { return v != "500" }) {
		t.Fatalf("split's group: memory.oom.group %s, scores %s", s, strings.Join(scores, " "))
	}
}
