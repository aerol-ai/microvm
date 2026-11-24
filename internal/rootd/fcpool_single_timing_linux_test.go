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

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestFirecrackerSingleModeClaimTiming is TestE2EFirecrackerClaimTiming's
// round as privilege mode single does it: as root, in-process. A warm
// claim's overlay is made in the slot's chroot, given its filesystem by
// mkfs.ext4 and handed to the jailer's user (tryAcquireWarm, chrootFilePath)
// beside a running jailer; the export VM's image is made by mkfs.ext4 as
// root from the same folder and renamed into place
// (buildExportHelperImage). AEROL_E2E_FC_POOL_WORK holds the image's source
// folder, src.
func TestFirecrackerSingleModeClaimTiming(t *testing.T) {
	work := os.Getenv("AEROL_E2E_FC_POOL_WORK")
	if work == "" || os.Geteuid() != 0 {
		t.Skip("a live run as root: set AEROL_E2E_FC_POOL_WORK")
	}
	const jailer = 1500
	base, id := "/srv/jailer-single", "vmms-00000000e2e0000s"
	root := filepath.Join(base, "firecracker", id, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/local/bin/jailer", "--id", id, "--exec-file", "/usr/local/bin/firecracker",
		"--uid", strconv.Itoa(jailer), "--gid", strconv.Itoa(jailer), "--chroot-base-dir", base, "--", "--api-sock", "api.socket")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.RemoveAll(filepath.Join(base, "firecracker", id))
	}()
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	ov := filepath.Join(root, rootpolicy.FirecrackerOverlay)
	if err := os.WriteFile(ov, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(ov, poolDiskBytes); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("/sbin/mkfs.ext4", "-F", ov).CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v: %s", err, b)
	}
	if err := os.Chown(ov, jailer, jailer); err != nil {
		t.Fatal(err)
	}
	tClaim := lap()
	tmp := filepath.Join(work, "single.ext4.tmp")
	if b, err := exec.Command("/sbin/mkfs.ext4", "-q", "-F", "-t", "ext4", "-L", "aerolvm-export", "-E", "root_owner=0:0",
		"-d", filepath.Join(work, "src"), tmp, "128M").CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4 -d: %v: %s", err, b)
	}
	if err := os.Rename(tmp, filepath.Join(work, "single.ext4")); err != nil {
		t.Fatal(err)
	}
	tImage := lap()
	_ = os.Remove(filepath.Join(work, "single.ext4"))
	fmt.Printf("timing\tsingle\tclaim=%.3f\timage=%.3f\n", msOf(tClaim), msOf(tImage))
}
