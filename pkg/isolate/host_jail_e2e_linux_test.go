//go:build linux

package isolate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The jail end-to-end test needs a "workerd" that runs inside the chroot
// and a jail shim. This test binary is both: TestMain turns it into the
// shim when the host re-execs it with JailShimFlag, and into a fake workerd
// when the shim execs it as /workerd serve --experimental <config>. The
// fake reads the config the host wrote and serves the control socket it
// names, which is exactly what a real workerd needs from the run dir.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case JailShimFlag:
			if err := RunJailShim(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(125)
			}
		case "serve":
			os.Exit(fakeWorkerd(os.Args[len(os.Args)-1]))
		}
	}
	os.Exit(m.Run())
}

var fakeControlAddr = regexp.MustCompile(`name = "control", address = "unix:([^"]+)"`)

// fakeWorkerd serves the control socket the config names, or exits 1 when
// it cannot read the config (what a real workerd does with a missing one).
func fakeWorkerd(configPath string) int {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake workerd:", err)
		return 1
	}
	match := fakeControlAddr.FindSubmatch(raw)
	if match == nil {
		fmt.Fprintln(os.Stderr, "fake workerd: no control socket in config")
		return 1
	}
	ln, err := net.Listen("unix", string(match[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake workerd:", err)
		return 1
	}
	_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("fake-workerd"))
	}))
	return 0
}

// jailE2ECgroupRoot makes a writable cgroup v2 parent for the test, or
// skips: the test needs root, cgroup v2 and controllers it may enable.
func jailE2ECgroupRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the jail end-to-end test needs root")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("no cgroup v2 hierarchy")
	}
	root := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("aerolvm-isolate-e2e-%d", os.Getpid()))
	cg := cgroupFS{root: root}
	dir, err := cg.ensure("probe", 0, 0, 0)
	if err != nil {
		_ = os.Remove(root)
		t.Skipf("cannot make a cgroup with cpu/memory/pids here: %v", err)
	}
	_ = cg.remove(dir)
	t.Cleanup(func() { _ = os.Remove(root) })
	return root
}

// TestJailedHostStartsWithItsRunDirVisible is the regression test for the
// T14 jail-on failure: every jailed spawn timed out because the noexec
// tmpfs on <chroot>/run was mounted after the host wrote its config and
// sockets there, hiding them from workerd. The fake workerd exits at once
// without its config, so this test fails fast on that order.
func TestJailedHostStartsWithItsRunDirVisible(t *testing.T) {
	cgRoot := jailE2ECgroupRoot(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "jail")
	if err := PrepareJailBase(base, self); err != nil {
		t.Fatalf("PrepareJailBase: %v", err)
	}
	chroot := filepath.Join(base, "g1")
	h, err := NewHost(HostConfig{
		WorkerdPath:  self,
		GroupKey:     "g1",
		RunDir:       filepath.Join(chroot, JailRunDirName),
		StartTimeout: 10 * time.Second,
		Jail: JailConfig{
			Require: true, ChrootDir: chroot, UID: 65534, GID: 65534,
			CgroupRoot: cgRoot, CgroupName: "aerolvm-isolate-g1",
			SeccompMode: SeccompOff, ShimPath: self,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := h.Start(context.Background()); err != nil {
		t.Fatalf("jailed Start: %v", err)
	}
	t.Logf("jailed host ready in %s", time.Since(start))
	req, _ := http.NewRequest(http.MethodGet, "http://ctrl/", nil)
	resp, err := h.Invoke(context.Background(), "sb-1", req)
	if err != nil {
		_ = h.Stop()
		t.Fatalf("Invoke: %v", err)
	}
	_ = resp.Body.Close()
	procs, _ := os.ReadFile(filepath.Join(cgRoot, "aerolvm-isolate-g1", "cgroup.procs"))
	if strings.TrimSpace(string(procs)) == "" {
		_ = h.Stop()
		t.Fatal("workerd is not in its group cgroup")
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := os.Stat(chroot); !os.IsNotExist(err) {
		t.Fatalf("chroot left after Stop: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cgRoot, "aerolvm-isolate-g1")); !os.IsNotExist(err) {
		t.Fatalf("cgroup left after Stop: %v", err)
	}
}
