//go:build linux && kerneltest

package supervisor

// The root helper's own cgroup on a real cgroup v2 tree, as root with a
// writable cgroup mount (a privileged container with its own cgroup
// namespace):
//
//	go test -tags kerneltest ./internal/supervisor/ -run KernelHelperGroup -v
//
// A real keeper runs signed helpers (shell scripts) in a real group. The
// first helper starts a process that outlives it, as a CNI plugin's IPAM
// plugin can, then stops: it crashes, drains on a swap, or ignores SIGTERM
// and is killed after KillAfter. That process holds a FIFO open, so the
// test sees the moment it is gone. The next helper must start only after
// it, both with cgroup.kill and with the freeze-and-kill-each way kernels
// before 5.14 need. Without the group it is still there at the next start,
// so the check can fail.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// kernelHelper is a helper as a script. It says it serves (descriptor 4)
// and, the first time any helper runs, leaves a process that writes its
// pid into the FIFO and keeps it open; then it crashes, or runs until
// SIGTERM (drain), or ignores SIGTERM (kill).
func kernelHelper(rec, mode string) []byte {
	return fmt.Appendf(nil, `#!/bin/sh
rec=%q
mode=%q
if [ "$mode" = ignore ]; then trap '' TERM; else trap 'exit 0' TERM; fi
printf 1 >&4
exec 4>&-
if [ ! -e "$rec/left" ]; then
	: >"$rec/left"
	sh -c 'echo "left $$"; exec sleep 1000' >"$rec/fifo" 3>&- &
	if [ "$mode" = crash ]; then sleep 0.3; exit 1; fi
fi
while :; do sleep 0.05; done
`, rec, mode)
}

var kernelGroupSeq atomic.Int64

func TestKernelHelperGroupEmptiesBeforeTheNextHelper(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, mode := range []string{"crash", "drain", "ignore"} {
		for _, byHand := range []bool{false, true} {
			// The kernel's way: cgroup.kill, or on a kernel without it
			// the fallback Empty must choose by itself.
			how := "the kernel's way"
			if byHand {
				how = "freeze and kill each"
			}
			t.Run(mode+"/"+how, func(t *testing.T) { kernelHelperGroup(t, mode, byHand, true) })
		}
	}
	t.Run("crash/without the group", func(t *testing.T) { kernelHelperGroup(t, "crash", false, false) })
}

func kernelHelperGroup(t *testing.T, mode string, byHand, useGroup bool) {
	parent := filepath.Join(CgroupRoot, fmt.Sprintf("aerolvm-helper-test-%d-%d", os.Getpid(), kernelGroupSeq.Add(1)))
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Skipf("needs a writable cgroup v2 mount: %v", err)
	}
	dir := filepath.Join(parent, helperGroup)
	g := NewHelperGroup(dir).(*helperCgroup)
	g.noKillFile = byHand
	t.Cleanup(func() {
		_ = g.Empty() // what a failed run, or the run without the group, left
		_ = g.Remove()
		_ = os.Remove(parent)
	})
	_, statErr := os.Stat(filepath.Join(parent, "cgroup.kill"))
	hasKill := statErr == nil
	if !hasKill && !byHand {
		t.Log("this kernel has no cgroup.kill (before 5.14): Empty must find that out and kill by hand")
	}

	rec := shortDir(t)
	fifo := filepath.Join(rec, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// Raw and non-blocking, so a read says EAGAIN while a writer holds the
	// FIFO and EOF once none does (os.File would wait instead).
	fd, err := unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	var mu sync.Mutex
	var wrote string
	// writerAlive reads what the leftover wrote and says whether it still
	// holds the FIFO.
	writerAlive := func() bool {
		buf := make([]byte, 256)
		for {
			n, err := unix.Read(fd, buf)
			switch {
			case n > 0:
				wrote += string(buf[:n])
			case errors.Is(err, unix.EAGAIN):
				return true
			case err == nil:
				return false
			default:
				t.Errorf("read the FIFO: %v", err)
				return false
			}
		}
	}

	r := newKeeperRig(t, func(k *HelperKeeper) {
		k.Tick, k.ReadyWait, k.KillAfter = 20*time.Millisecond, 10*time.Second, 300*time.Millisecond
	})
	if useGroup {
		r.k.Group = g
	} else {
		r.k.Group = nil
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	type atStart struct {
		alive     bool // the leftover still held the FIFO
		populated bool
		wrote     string
	}
	var starts []atStart // at every start after the first
	n := 0
	r.k.Start = func(bin string, env []string, files []*os.File) (Child, error) {
		mu.Lock()
		if n++; n > 1 {
			populated, err := g.event("populated")
			if err != nil {
				t.Error(err)
			}
			starts = append(starts, atStart{alive: writerAlive(), populated: populated, wrote: wrote})
		}
		mu.Unlock()
		return StartHelper(dir, bin, env, files)
	}

	r.rel.stage(kernelHelper(rec, mode), "v1.0.0")
	r.run()
	if mode != "crash" {
		eventually(t, "the leftover running", func() bool {
			mu.Lock()
			defer mu.Unlock()
			writerAlive()
			return strings.Contains(wrote, "left ")
		})
		r.rel.stage(kernelHelper(rec, "serve"), "v1.0.1")
	}
	eventually(t, "the next helper's start", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(starts) > 0
	})
	eventually(t, "the next helper serving", func() bool { return strings.Count(r.logs.String(), "the root helper serves") >= 2 })
	r.stop()

	mu.Lock()
	first := starts[0]
	mu.Unlock()
	logs := r.logs.String()
	if !strings.Contains(first.wrote, "left ") {
		t.Fatalf("the first helper's leftover never ran (read %q); logs:\n%s", first.wrote, logs)
	}
	if !useGroup {
		if !first.alive || !first.populated {
			t.Fatalf("without the group the leftover was gone at the next start (alive %v, populated %v): the test cannot fail", first.alive, first.populated)
		}
		t.Logf("without the group, %s still held the FIFO when the next helper started", strings.TrimSpace(first.wrote))
		return
	}
	if first.alive || first.populated {
		t.Fatalf("the next helper started while the leftover (%s) ran: alive %v, populated %v; logs:\n%s",
			strings.TrimSpace(first.wrote), first.alive, first.populated, logs)
	}
	want := map[string]string{"crash": "the root helper exited", "drain": "swapping the root helper", "ignore": "did not stop in time; killing it"}[mode]
	if !strings.Contains(logs, want) {
		t.Fatalf("logs lack %q:\n%s", want, logs)
	}
	if mode == "drain" && strings.Contains(logs, "did not stop in time") {
		t.Fatalf("the drain was a kill:\n%s", logs)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the group outlived the keeper: %v", err)
	}
	if g.noKillFile != (byHand || !hasKill) {
		t.Fatalf("killed by hand = %v on a kernel with cgroup.kill = %v (forced: %v)", g.noKillFile, hasKill, byHand)
	}
	t.Logf("%s was gone before the next helper started", strings.TrimSpace(first.wrote))
}
