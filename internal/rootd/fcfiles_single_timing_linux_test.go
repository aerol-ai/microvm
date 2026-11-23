//go:build linux

package rootd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestFirecrackerSingleModeLoadTiming is TestE2EFirecrackerLoadTiming's
// round as privilege mode single does it: as root, in-process, in the
// driver's order (the jail and the kernel linked; the TAP with the
// snapshot's MAC, taphost.Host as sandboxd runs it; the jailer until its
// API socket; the template's memory, state and disk linked into the chroot
// and given root's owner and the jailer's group, as chrootSharedFile does;
// the overlay made and given to the jailer's user, as chrootFilePath does;
// then the stop). AEROL_E2E_FC_SINGLE_TEMPLATE names a template folder of
// root's.
func TestFirecrackerSingleModeLoadTiming(t *testing.T) {
	tpl := os.Getenv("AEROL_E2E_FC_SINGLE_TEMPLATE")
	if tpl == "" || os.Geteuid() != 0 {
		t.Skip("a live run as root: set AEROL_E2E_FC_SINGLE_TEMPLATE")
	}
	const jailer = 1500
	base, id := "/srv/jailer-single", "sb-load-timing"
	root := filepath.Join(base, "firecracker", id, "root")
	start := time.Now()
	lap := func() time.Duration { d := time.Since(start); start = time.Now(); return d }
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(root, rootpolicy.FirecrackerKernel)
	if err := os.Link("/var/lib/aerolvm-rootd/kernel/vmlinux", kernel); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	if err := os.Chown(kernel, 0, jailer); err != nil {
		t.Fatal(err)
	}
	tJail := lap()
	slot, err := taphost.SlotAt("172.16.0.0/20", 256, 10)
	if err != nil {
		t.Fatal(err)
	}
	slot.GuestMAC = taphost.MACFromCID(7)
	h := taphost.NewHost("")
	h.Owner = &taphost.Owner{UID: jailer, GID: jailer}
	if err := h.Ensure(context.Background(), slot); err != nil {
		t.Fatal(err)
	}
	tTap := lap()
	cmd := exec.Command("/usr/local/bin/jailer", "--id", id, "--exec-file", "/usr/local/bin/firecracker",
		"--uid", strconv.Itoa(jailer), "--gid", strconv.Itoa(jailer), "--chroot-base-dir", base, "--", "--api-sock", "api.socket")
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
	for _, n := range []string{rootpolicy.FirecrackerMemory, rootpolicy.FirecrackerState, rootpolicy.FirecrackerRootfs} {
		dst := filepath.Join(root, n)
		_ = os.Remove(dst)
		if err := os.Link(filepath.Join(tpl, n), dst); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dst, 0, jailer); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dst, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	tShare := lap()
	ov := filepath.Join(root, rootpolicy.FirecrackerOverlay)
	if err := os.WriteFile(ov, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(ov, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(ov, jailer, jailer); err != nil {
		t.Fatal(err)
	}
	tOverlay := lap()
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if err := os.RemoveAll(filepath.Join(base, "firecracker", id)); err != nil {
		t.Fatal(err)
	}
	if err := h.Remove(context.Background(), slot.TapName); err != nil {
		t.Fatal(err)
	}
	tStop := lap()
	fmt.Printf("timing\tsingle\tjail=%.3f\ttap=%.3f\tspawn=%.3f\tshare=%.3f\toverlay=%.3f\tsockets=%.3f\tstop=%.3f\n",
		msOf(tJail), msOf(tTap), msOf(tSpawn), msOf(tShare), msOf(tOverlay), 0.0, msOf(tStop))
}
