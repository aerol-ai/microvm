package caddy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// stubFirecrackerDownloads replaces the steps of --with-firecracker that
// download (the release and the guest kernel) or check the host (KVM) with
// ones that log, and moves the jailer's base and split's kernel folder into
// the temp dir. The kernel step stands in for a download: it writes a
// "pinned kernel" where it is pointed, unless a kernel is there already
// (which it keeps, as the real one does). The rest of install_firecracker
// runs as it is: which kernel is used, which folder it goes to, and when it
// and the templates folder are made.
func (r *runRig) stubFirecrackerDownloads() {
	r.t.Helper()
	raw, err := os.ReadFile(r.script)
	if err != nil {
		r.t.Fatal(err)
	}
	const mainFlow = "\nif [[ \"$CONFIG_ONLY\" == \"true\" ]]; then\n\tif [[ $FAKE_EUID -ne 0 ]]; then\n"
	stubs := `firecracker_preflight() { echo "firecracker_preflight" >>"$LOG"; }
install_firecracker_release() { echo "install_firecracker_release $1" >>"$LOG"; }
install_firecracker_kernel() {
	local kernel="${5:-$FIRECRACKER_KERNEL_PATH}"
	echo "install_firecracker_kernel path=$kernel" >>"$LOG"
	if [[ ! -f "$kernel" ]]; then
		mkdir -p "${kernel%/*}"
		printf 'pinned kernel\n' >"$kernel"
		printf 'CONFIG_VMGENID=y\n' >"$kernel.config"
	fi
}
`
	src := strings.Replace(string(raw), mainFlow, "\n"+stubs+mainFlow, 1)
	src = strings.Replace(src, `JAILER_CHROOT_BASE="/srv/jailer"`, `JAILER_CHROOT_BASE="`+r.path("srv-jailer")+`"`, 1)
	src = strings.Replace(src, `SPLIT_FIRECRACKER_KERNEL_PATH="/usr/local/lib/aerolvm-firecracker/vmlinux"`,
		`SPLIT_FIRECRACKER_KERNEL_PATH="`+r.path("rootlib-firecracker/vmlinux")+`"`, 1)
	if src == string(raw) || !strings.Contains(src, r.path("srv-jailer")) || !strings.Contains(src, r.path("rootlib-firecracker")) {
		r.t.Fatal("could not stub the Firecracker downloads")
	}
	if err := os.WriteFile(r.script, []byte(src), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// switchBackRig is a split node with Firecracker whose data folder still
// has a guest kernel from an earlier single period, one sandboxd's user
// could have changed while the node ran split.
func switchBackRig(t *testing.T, splitKernel string) *runRig {
	t.Helper()
	r := newRunRig(t)
	r.stubEngineSteps()
	r.stubFirecrackerDownloads()
	if splitKernel != "" {
		r.write("rootlib-firecracker/vmlinux", splitKernel, 0o644)
		r.write("rootlib-firecracker/vmlinux.config", "CONFIG_VMGENID=y\n", 0o644)
	}
	split := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split", "--with-firecracker")
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), split...); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, r.calls()+out)
	}
	calls := r.calls()
	r.inOrder(calls, "install_firecracker_kernel path="+r.path("rootlib-firecracker/vmlinux"), "systemctl enable --now aerolvm-rootd")
	if strings.Contains(calls, r.path("varlib/firecracker")) {
		t.Fatalf("split wrote in sandboxd's data folder:\n%s", calls)
	}
	r.write("varlib/firecracker/vmlinux", "kernel left from single, open to sandboxd's user in split\n", 0o644)
	r.write("varlib/firecracker/vmlinux.config", "CONFIG_VMGENID=y\n", 0o644)
	r.resetLog()
	return r
}

// A switch back to single with --with-firecracker puts the guest kernel and
// the templates folder in sandboxd's data folder, which sandboxd's user
// owned in split. Root writes there only after leave_split_mode has removed
// that user's links and given the folder back to root. The kernel already
// there is replaced, not kept: by a copy of split's kernel, from a folder
// only root writes, so nothing is downloaded after the cleanup. A single
// node, and split, install the kernel in install_firecracker as before.
func TestInstallFirecrackerWaitsForTheSwitchBack(t *testing.T) {
	r := switchBackRig(t, "operator kernel\n")
	out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), append(r.splitRelease("helper v0.7.9\n"), "--privilege-mode", "single")...)
	if err != nil {
		t.Fatalf("switch back: %v\n%s", err, r.calls()+out)
	}
	calls := r.calls()
	varlib, from := r.path("varlib"), r.path("rootlib-firecracker/vmlinux")
	r.inOrder(calls, "install_firecracker_release", "systemctl stop sandboxd", "find "+varlib+" -xdev -type l -delete",
		"find "+varlib+" -xdev -uid 990 -exec chown -h root {} +",
		"install -m 0644 "+from+".config "+varlib+"/firecracker/vmlinux.config",
		"install -m 0644 "+from+" "+varlib+"/firecracker/vmlinux",
		"install -d -m 0755 "+varlib+"/firecracker/templates")
	if strings.Contains(calls, "install_firecracker_kernel") {
		t.Fatalf("the switch back ran the kernel step (a download) instead of copying split's kernel:\n%s", calls)
	}
	if got := r.read("varlib/firecracker/vmlinux"); got != "operator kernel\n" {
		t.Fatalf("single's kernel after the switch back: %q, want a copy of split's", got)
	}
	if !strings.Contains(out, "Replaced the guest kernel at "+varlib+"/firecracker/vmlinux with a copy of "+from) {
		t.Errorf("the switch back did not say it replaced the kernel:\n%s", out)
	}

	// Single again: nothing waits and nothing is replaced, as before.
	r.resetLog()
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), r.splitRelease("helper v0.7.9\n")...); err != nil {
		t.Fatalf("single re-run: %v\n%s", err, out)
	}
	r.inOrder(r.calls(), "install_firecracker_release", "install_firecracker_kernel path="+varlib+"/firecracker/vmlinux",
		"install -d -m 0755 "+varlib+"/firecracker/templates", "systemctl daemon-reload")
	if got := r.read("varlib/firecracker/vmlinux"); got != "operator kernel\n" {
		t.Fatalf("a single re-run changed the kernel: %q", got)
	}
}

// Split had no kernel of its own to copy (it ran without --with-firecracker,
// say): the pinned kernel is downloaded into a folder of root's before the
// cleanup stops sandboxd, and copied over single's after it.
func TestInstallFirecrackerSwitchBackDownloadsBeforeTheCleanup(t *testing.T) {
	r := switchBackRig(t, "")
	for _, f := range []string{"rootlib-firecracker/vmlinux", "rootlib-firecracker/vmlinux.config"} {
		if err := os.Remove(r.path(f)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), append(r.splitRelease("helper v0.7.9\n"), "--privilege-mode", "single")...)
	if err != nil {
		t.Fatalf("switch back: %v\n%s", err, r.calls()+out)
	}
	calls := r.calls()
	stage := regexp.MustCompile(`install_firecracker_kernel path=(\S+)/vmlinux`).FindStringSubmatch(calls)
	if stage == nil || strings.HasPrefix(stage[1], r.path("varlib")) {
		t.Fatalf("no download into a folder of root's:\n%s", calls)
	}
	varlib := r.path("varlib")
	r.inOrder(calls, "install_firecracker_kernel path="+stage[1]+"/vmlinux", "systemctl stop sandboxd",
		"find "+varlib+" -xdev -uid 990 -exec chown -h root {} +",
		"install -m 0644 "+stage[1]+"/vmlinux "+varlib+"/firecracker/vmlinux")
	if got := r.read("varlib/firecracker/vmlinux"); got != "pinned kernel\n" {
		t.Fatalf("single's kernel after the switch back: %q, want the pinned one", got)
	}
	if _, err := os.Stat(stage[1]); err == nil {
		t.Errorf("the download folder %s is still there", stage[1])
	}
}
