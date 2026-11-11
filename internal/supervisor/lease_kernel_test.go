//go:build linux && kerneltest

package supervisor

// The ownership lease on a real cgroup v2 tree, as root with a writable
// cgroup mount (a privileged container with its own cgroup namespace):
//
//	go test -tags kerneltest ./internal/supervisor/ -run KernelLease -v
//
// A process in a sandbox group is frozen when the lease runs out (the
// kernel reports the group frozen and the process stops advancing), stays
// frozen through a lease that does not prove it owned, and runs again
// after one that does.

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

func groupFrozen(t *testing.T, dir string) bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.events"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(raw), "frozen 1")
}

func waitFrozen(t *testing.T, dir string, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for groupFrozen(t, dir) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s frozen=%v, want %v", dir, !want, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestKernelLeaseFreezesAndThaws(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	root := filepath.Join(CgroupRoot, "aerolvm-lease-test-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Skipf("needs a writable cgroup v2 mount: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	dir := filepath.Join(root, "sb-1")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })

	// A process that counts into a file: it advances only while it runs.
	counter := filepath.Join(t.TempDir(), "count")
	cmd := exec.Command("sh", "-c", `i=0; while :; do i=$((i+1)); echo $i > `+counter+`; sleep 0.02; done`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = SetCgroupFrozen(dir, false)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	count := func() string { b, _ := os.ReadFile(counter); return string(b) }

	file := filepath.Join(t.TempDir(), "ownership-lease")
	var logs bytes.Buffer
	g := &LeaseGuard{File: file, SandboxesDir: root, SetFrozen: SetCgroupFrozen, Now: time.Now, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	now := time.Now().UnixMilli()
	write := func(confirmed int64, owned ...string) {
		if err := ownerlease.Write(file, ownerlease.Lease{ConfirmedUnixMs: confirmed, WrittenUnixMs: now, LeaseMs: 15_000, Fence: []string{"sb-1"}, Owned: owned}); err != nil {
			t.Fatal(err)
		}
	}

	// Run out: confirmed 16 s before it was written.
	write(now - 16_000)
	g.Check()
	waitFrozen(t, dir, true)
	before := count()
	time.Sleep(300 * time.Millisecond)
	if after := count(); after != before {
		t.Fatalf("the frozen process kept counting: %s → %s", before, after)
	}

	// A later read that does not prove it owned (it moved): still frozen.
	now = time.Now().UnixMilli()
	write(now)
	g.Check()
	time.Sleep(200 * time.Millisecond)
	if !groupFrozen(t, dir) {
		t.Fatal("thawed without proof of ownership")
	}

	// A later read that proves it: running again.
	now = time.Now().UnixMilli() + 1
	write(now, "sb-1")
	g.Check()
	waitFrozen(t, dir, false)
	before = count()
	time.Sleep(300 * time.Millisecond)
	if after := count(); after == before {
		t.Fatal("the thawed process does not run")
	}
	t.Logf("log: %s", logs.String())
}
