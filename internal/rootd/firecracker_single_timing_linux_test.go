//go:build linux

package rootd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestFirecrackerSingleModeSpawnTiming is one round of the same VM start
// as TestE2EFirecrackerSpawnTiming, done as privilege mode single does it:
// as root, in-process, in the driver's order (internal/runtime/firecracker
// vmm.Start, then the overlay's mkfs.ext4 -F, then chrootFilePath's link
// and chown), timed by the same steps (AEROL_E2E_FC_TIMING, as root, in
// the 9b box).
func TestFirecrackerSingleModeSpawnTiming(t *testing.T) {
	if os.Getenv("AEROL_E2E_FC_TIMING") == "" || os.Geteuid() != 0 {
		t.Skip("a live run as root: set AEROL_E2E_FC_TIMING")
	}
	base := "/srv/jailer-single"
	id := "sb-timing"
	root := filepath.Join(base, "firecracker", id, "root")
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(root, "vmlinux")
	if err := os.Link("/var/lib/aerolvm-rootd/kernel/vmlinux", kernel); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	if err := os.Chown(kernel, 0, 1500); err != nil {
		t.Fatal(err)
	}
	tPrep := lap()
	cmd := exec.Command("/usr/local/bin/jailer", "--id", id, "--exec-file", "/usr/local/bin/firecracker",
		"--uid", strconv.Itoa(1500), "--gid", strconv.Itoa(1500), "--chroot-base-dir", base, "--", "--api-sock", "api.socket")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "api.socket")); err == nil {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("no API socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tSpawn := lap()
	ov := filepath.Join(root, "overlay.ext4")
	if err := os.WriteFile(ov, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(ov, 64<<20); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/sbin/mkfs.ext4", "-F", ov).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	tMkfs := lap()
	if err := os.Chown(ov, 1500, 1500); err != nil {
		t.Fatal(err)
	}
	tStage := lap()
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if err := os.RemoveAll(filepath.Join(base, "firecracker", id)); err != nil {
		t.Fatal(err)
	}
	tStop := lap()
	ms := func(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }
	fmt.Printf("timing\tsingle\tjail=%s\tmkfs=%s\tstage=%s\tspawn=%s\tstop=%s\n", ms(tPrep), ms(tMkfs), ms(tStage), ms(tSpawn), ms(tStop))
}
