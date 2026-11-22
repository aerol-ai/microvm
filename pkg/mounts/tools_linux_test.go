//go:build linux

package mounts

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A start in the cgroup that fails, then works plainly: the cgroup is
// turned off and the tool runs, as spawnHelper does.
func TestMountToolCgroupFallback(t *testing.T) {
	r := newToolRig(t)
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	r.m.cgroup = &helperCgroup{logger: r.m.logger, dir: dir}
	r.m.cgroup.setup.Do(func() {})
	inner := startToolCmd
	inCgroup := 0
	startToolCmd = func(cmd *exec.Cmd) error {
		if cmd.SysProcAttr.UseCgroupFD {
			inCgroup++
			return errors.New("clone3: no cgroup")
		}
		return inner(cmd)
	}
	if _, err := r.m.MountAll(context.Background(), "sb-1", toolSpecs()[1:2]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.m.UnmountAll("sb-1") })
	if _, ok := r.m.cgroup.fd(); ok || inCgroup != 1 {
		t.Fatalf("cgroup still on, %d starts in it", inCgroup)
	}
	// Both fail: the tool's own error.
	startToolCmd = func(*exec.Cmd) error { return exec.ErrNotFound }
	r.m.cgroup = &helperCgroup{logger: r.m.logger, dir: dir}
	r.m.cgroup.setup.Do(func() {})
	if _, err := r.m.MountAll(context.Background(), "sb-2", toolSpecs()[1:2]); !errors.Is(err, ErrMountToolUnavailable) {
		t.Fatal(err)
	}
}

// TestCredMemfd: the credentials descriptor holds the body, is the tool
// user's alone (0400), and is sealed: nothing can write or grow it.
func TestCredMemfd(t *testing.T) {
	f, err := newCredMemfd([]byte("[sandbox]\nkey = v\n"), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil || st.Mode&0o777 != 0o400 || st.Uid != uint32(os.Getuid()) {
		t.Fatalf("mode %o uid %d: %v", st.Mode&0o777, st.Uid, err)
	}
	// What a tool does with /dev/fd/4: open it by path, and read.
	b, err := os.ReadFile(filepath.Join("/proc/self/fd", strconv.Itoa(int(f.Fd()))))
	if err != nil || string(b) != "[sandbox]\nkey = v\n" {
		t.Fatalf("read %q: %v", b, err)
	}
	if _, err := unix.Write(int(f.Fd()), []byte("x")); err == nil {
		t.Fatal("a sealed memfd took a write")
	}
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&unix.F_SEAL_SEAL == 0 || seals&unix.F_SEAL_WRITE == 0 {
		t.Fatalf("seals %x: %v", seals, err)
	}
}

// TestStartNoNewPrivs: a tool starts with no-new-privs, which the child
// shows in its status, and the goroutine that set it took its thread with
// it, so the next start from the test's own goroutine has none.
func TestStartNoNewPrivs(t *testing.T) {
	out := filepath.Join(t.TempDir(), "status")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cat", "/proc/self/status")
	cmd.Stdout = f
	if err := startNoNewPrivs(cmd); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if got := statusField(t, out, "NoNewPrivs"); got != "1" {
		t.Fatalf("the tool's NoNewPrivs is %q", got)
	}
	if statusField(t, "/proc/thread-self/status", "NoNewPrivs") != "0" {
		return // the test runs with no-new-privs itself (a hardened CI)
	}
	plain := exec.Command("cat", "/proc/thread-self/status")
	b, err := plain.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "NoNewPrivs:\t0") {
		t.Fatalf("a plain start has no-new-privs: %s", b)
	}
}

func statusField(t *testing.T, path, name string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), name+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// TestOpenFuseFD (root, with /dev/fuse): the helper's own FUSE mount is
// nosuid, nodev, allow_other, owned by the tool's user, read-only when
// asked, and of the tool's subtype. No tool serves it here, so nothing
// looks inside it; it is unmounted (detached) when the test ends.
func TestOpenFuseFD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}
	dir := t.TempDir()
	f, err := openFuseFD(dir, "mount-s3", 4242, 4243, true)
	if err != nil {
		t.Skipf("no FUSE mount here: %v", err)
	}
	defer f.Close()
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(l); len(fields) > 4 && fields[4] == dir {
			line = l
		}
	}
	for _, want := range []string{"nosuid", "nodev", " ro", "fuse.mount-s3", "user_id=4242", "group_id=4243", "allow_other"} {
		if !strings.Contains(line, want) {
			t.Fatalf("mount %q lacks %s", line, want)
		}
	}
	// Never a path under the mount: no tool serves it, and a lookup there
	// would wait for one.
	if _, err := openFuseFD(filepath.Join(t.TempDir(), "missing"), "x", 1, 1, false); err == nil {
		t.Fatal("a mount at a missing path passed")
	}
}
