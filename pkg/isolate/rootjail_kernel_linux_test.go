//go:build linux

package isolate

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRootJailOnTheKernel builds a group's jail as the root helper does,
// with this test binary standing in for workerd: the base tree, the
// group's chroot linked from it, its two writable tmpfs folders (the run
// folder the agent's with the jail's group, setgid; tmp the jail user's
// alone), the shim's spec, and the teardown. Root only.
func TestRootJailOnTheKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: mounts and device nodes")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	r := RootJail{ChrootBase: base, WorkerdPath: self, UID: 1000, GID: 1001, AgentUID: 65531, SeccompMode: SeccompEnforce, ShimPath: self}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := r.PrepareBase(); err != nil {
		t.Fatal(err)
	}
	run, err := r.Prepare("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Teardown("tenant-a") })
	if run != r.RunDir("tenant-a") || !r.Prepared("tenant-a") {
		t.Fatalf("run %s prepared %v", run, r.Prepared("tenant-a"))
	}
	for dir, want := range map[string]struct {
		uid, gid int
		mode     uint32
	}{
		run:                                    {65531, 1001, unix.S_ISGID | 0o770},
		filepath.Join(base, "tenant-a", "tmp"): {1000, 1001, 0o700},
	} {
		var st unix.Stat_t
		if err := unix.Stat(dir, &st); err != nil {
			t.Fatal(err)
		}
		if int(st.Uid) != want.uid || int(st.Gid) != want.gid || st.Mode&0o7777 != want.mode {
			t.Errorf("%s: uid %d gid %d mode %o, want %d %d %o", dir, st.Uid, st.Gid, st.Mode&0o7777, want.uid, want.gid, want.mode)
		}
		var fs unix.Statfs_t
		if err := unix.Statfs(dir, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
			t.Errorf("%s is not a tmpfs: %x %v", dir, fs.Type, err)
		}
	}
	// What the agent writes there is the jail group's.
	f := filepath.Join(run, "config.capnp")
	if err := os.WriteFile(f, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(f, &st); err != nil || st.Gid != 1001 {
		t.Fatalf("a file in the run folder has group %d (%v)", st.Gid, err)
	}
	// A second Prepare answers the jail as it is.
	if again, err := r.Prepare("tenant-a"); err != nil || again != run {
		t.Fatalf("second Prepare = %s, %v", again, err)
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatal("a second Prepare rebuilt the jail:", err)
	}
	cmd, err := r.Command("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != self || len(cmd.Args) != 2 || cmd.Args[1] != JailShimFlag || len(cmd.Env) != 1 {
		t.Fatalf("command %v %v", cmd.Args, cmd.Env)
	}
	spec, err := decodeJailShimSpec(strings.TrimPrefix(cmd.Env[0], jailShimSpecEnv+"="))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Chroot != filepath.Join(base, "tenant-a") || spec.UID != 1000 || spec.GID != 1001 || spec.Umask == nil || *spec.Umask != 0 ||
		len(spec.Seccomp) == 0 || spec.Argv[len(spec.Argv)-1] != "/run/config.capnp" {
		t.Fatalf("spec %+v", spec)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWPID == 0 || !cmd.SysProcAttr.Setpgid {
		t.Fatalf("proc attr %+v", cmd.SysProcAttr)
	}
	// Off, the filter is left out, never half-built.
	r.SeccompMode = SeccompOff
	if cmd, err = r.Command("tenant-a"); err != nil {
		t.Fatal(err)
	}
	if spec, _ = decodeJailShimSpec(strings.TrimPrefix(cmd.Env[0], jailShimSpecEnv+"=")); len(spec.Seccomp) != 0 {
		t.Fatal("a filter with seccomp off")
	}
	if err := r.Teardown("tenant-a"); err != nil {
		t.Fatal(err)
	}
	if mounted(run) || r.Prepared("tenant-a") {
		t.Fatal("teardown left a mount")
	}
	if _, err := os.Stat(filepath.Join(base, "tenant-a")); !os.IsNotExist(err) {
		t.Fatal("teardown left the chroot")
	}
	// The base tree stays for the next group.
	if !JailBasePrepared(base) {
		t.Fatal("teardown took the base tree")
	}
}
