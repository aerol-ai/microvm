//go:build linux && kerneltest

package firecracker

// Boots a real Firecracker guest kernel with the driver's command line and
// checks what guestNoIPv6Arg does inside the guest: no IPv6 address on any
// interface (no link-local), while AF_INET6 sockets still open and a [::]
// listener takes IPv4. Firecracker itself needs /dev/kvm, which a container
// on a laptop rarely has, so the kernel runs under QEMU (TCG) instead; the
// IPv6 behaviour is the kernel's, not the VMM's.
//
//	curl -fsSLo /tmp/vmlinux https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/aarch64/vmlinux-5.10.245
//	docker run --rm --privileged -v "$PWD":/src -v /tmp/vmlinux:/vmlinux -w /src \
//	  -e AEROLVM_GUEST_KERNEL=/vmlinux <go 1.26 image with qemu-system-arm> \
//	  go test -tags kerneltest -run KernelGuestIPv6 -v ./internal/runtime/firecracker/
//
// The production guest kernel is the Firecracker CI build the installer
// pins (Ansible firecracker_kernel_ci_version / firecracker_kernel_version),
// which has CONFIG_IPV6=y: the ipv6 module parameters are honoured on the
// command line. Wired for arm64 hosts (QEMU's virt machine).

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"
)

// newcArchive writes a gzip'd cpio (newc) archive holding the given
// directories and one executable file at /init.
func newcArchive(t *testing.T, dirs []string, init []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	ino := 1
	entry := func(name string, mode uint32, data []byte) {
		fmt.Fprintf(&raw, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
		ino++
		raw.WriteString(name)
		raw.WriteByte(0)
		for raw.Len()%4 != 0 {
			raw.WriteByte(0)
		}
		raw.Write(data)
		for raw.Len()%4 != 0 {
			raw.WriteByte(0)
		}
	}
	for _, d := range dirs {
		entry(d, 0o040755, nil)
	}
	entry("init", 0o100755, init)
	entry("TRAILER!!!", 0, nil)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return gz.Bytes()
}

// bootGuest boots kernel with cmdline and returns the probe's key=value
// report.
func bootGuest(t *testing.T, qemu, kernel, initrd, cmdline string) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, qemu, "-M", "virt", "-cpu", "max", "-m", "512", "-nographic", "-no-reboot",
		"-kernel", kernel, "-initrd", initrd, "-append", cmdline,
		"-device", "virtio-serial-device", "-chardev", "stdio,id=con,mux=on", "-device", "virtconsole,chardev=con",
		"-serial", "none", "-monitor", "none",
		"-netdev", "user,id=n0", "-device", "virtio-net-device,netdev=n0")
	out, err := cmd.CombinedOutput()
	got := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := strings.TrimSpace(strings.ReplaceAll(s.Text(), "\r", ""))
		if rest, ok := strings.CutPrefix(line, "V6PROBE "); ok {
			if k, v, ok := strings.Cut(rest, "="); ok {
				got[k] = v
			}
		}
	}
	if got["done"] != "1" {
		t.Fatalf("guest with %q did not finish the probe (qemu: %v):\n%s", cmdline, err, out)
	}
	return got
}

// TestKernelGuestIPv6BootArg is the guest-side regression test for the
// IPv6 hole and for workload compatibility: with guestNoIPv6Arg the guest
// has no IPv6 address (no link-local to reach a neighbour or the node
// from), and a listener on [::] still works and takes IPv4. Without it
// (control) the guest has link-local addresses, so the probe would see a
// regression. With ipv6.disable=1 (rejected) every AF_INET6 socket fails,
// which is what broke [::] listeners.
func TestKernelGuestIPv6BootArg(t *testing.T) {
	kernel := os.Getenv("AEROLVM_GUEST_KERNEL")
	if kernel == "" {
		t.Skip("AEROLVM_GUEST_KERNEL is unset: point it at a Firecracker guest kernel (see the file comment)")
	}
	if goruntime.GOARCH != "arm64" {
		t.Skip("wired for arm64 hosts (QEMU virt); an x86 host checks this in the live Firecracker lanes")
	}
	qemu, err := exec.LookPath("qemu-system-aarch64")
	if err != nil {
		t.Skip("qemu-system-aarch64 is not installed")
	}
	dir := t.TempDir()
	probe := filepath.Join(dir, "v6probe")
	build := exec.Command("go", "build", "-o", probe, "./testdata/v6probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the probe: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	initrd := filepath.Join(dir, "initramfs.gz")
	if err := os.WriteFile(initrd, newcArchive(t, []string{"proc", "sys", "dev"}, bin), 0o644); err != nil {
		t.Fatal(err)
	}

	// The driver's own command line, with QEMU's console in place of the
	// VMM's serial port and the probe as init.
	cmdline := func(ipv6Arg string) string {
		var out []string
		for _, f := range strings.Fields(coldBootArgs(nil, false)) {
			switch {
			case strings.HasPrefix(f, "console="):
				out = append(out, "console=hvc0")
			case f == guestNoIPv6Arg:
				if ipv6Arg != "" {
					out = append(out, ipv6Arg)
				}
			default:
				out = append(out, f)
			}
		}
		return strings.Join(append(out, "rdinit=/init"), " ")
	}
	if !strings.Contains(coldBootArgs(nil, false), guestNoIPv6Arg) {
		t.Fatalf("coldBootArgs lacks %q", guestNoIPv6Arg)
	}

	control := bootGuest(t, qemu, kernel, initrd, cmdline(""))
	if control["ipv6_addresses"] == "0" || control["af_inet6_socket"] != "ok" {
		t.Fatalf("control boot (IPv6 on) should have addresses and AF_INET6: %v", control)
	}
	t.Logf("IPv6 on (control): %s addresses (%s)", control["ipv6_addresses"], control["ipv6_address_list"])

	off := bootGuest(t, qemu, kernel, initrd, cmdline(guestNoIPv6Arg))
	for k, want := range map[string]string{
		"ipv6_addresses":       "0",
		"disable_ipv6_eth0":    "1",
		"disable_ipv6_lo":      "1",
		"disable_ipv6_default": "1",
		"af_inet6_socket":      "ok",
		"af_inet6_bind_any":    "ok",
		"listen_any":           "[::]:18081",
		"ipv4_client_to_any":   "hi",
	} {
		if off[k] != want {
			t.Errorf("with %s: %s = %q, want %q (report %v)", guestNoIPv6Arg, k, off[k], want, off)
		}
	}
	t.Logf("with %s: %s addresses, AF_INET6 socket %s, bind [::] %s, listener %s, IPv4 client to it %q",
		guestNoIPv6Arg, off["ipv6_addresses"], off["af_inet6_socket"], off["af_inet6_bind_any"], off["listen_any"], off["ipv4_client_to_any"])

	stack := bootGuest(t, qemu, kernel, initrd, cmdline("ipv6.disable=1"))
	if !strings.HasPrefix(stack["af_inet6_socket"], "error") {
		t.Errorf("with ipv6.disable=1 an AF_INET6 socket opened: %v", stack)
	}
	t.Logf("with ipv6.disable=1 (rejected): AF_INET6 socket %s", stack["af_inet6_socket"])
}
