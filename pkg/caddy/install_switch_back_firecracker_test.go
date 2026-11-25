package caddy

import (
	"os"
	"strings"
	"testing"
)

// stubFirecrackerDownloads replaces the steps of --with-firecracker that
// download (the release and the guest kernel) or check the host (KVM) with
// ones that log, and moves the jailer's base into the temp dir. The rest of
// install_firecracker runs as it is: which folder the kernel goes to, and
// when it and the templates folder are made.
func (r *runRig) stubFirecrackerDownloads() {
	r.t.Helper()
	raw, err := os.ReadFile(r.script)
	if err != nil {
		r.t.Fatal(err)
	}
	const mainFlow = "\nif [[ \"$CONFIG_ONLY\" == \"true\" ]]; then\n\tif [[ $FAKE_EUID -ne 0 ]]; then\n"
	stubs := `firecracker_preflight() { echo "firecracker_preflight" >>"$LOG"; }
install_firecracker_release() { echo "install_firecracker_release $1" >>"$LOG"; }
install_firecracker_kernel() { echo "install_firecracker_kernel path=$FIRECRACKER_KERNEL_PATH" >>"$LOG"; }
`
	src := strings.Replace(string(raw), mainFlow, "\n"+stubs+mainFlow, 1)
	src = strings.Replace(src, `JAILER_CHROOT_BASE="/srv/jailer"`, `JAILER_CHROOT_BASE="`+r.path("srv-jailer")+`"`, 1)
	if src == string(raw) || !strings.Contains(src, r.path("srv-jailer")) {
		r.t.Fatal("could not stub the Firecracker downloads")
	}
	if err := os.WriteFile(r.script, []byte(src), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// A switch back to single with --with-firecracker puts the guest kernel and
// the templates folder in sandboxd's data folder, which sandboxd's user
// owned in split. Root writes there only after leave_split_mode has removed
// that user's links and given the folder back to root: never through a path
// the user could have pointed elsewhere. A single node, and split (whose
// kernel is in a folder only root writes), install them in
// install_firecracker as before.
func TestInstallFirecrackerWaitsForTheSwitchBack(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	r.stubFirecrackerDownloads()
	split := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split", "--with-firecracker")
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), split...); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, r.calls()+out)
	}
	calls := r.calls()
	r.inOrder(calls, "install_firecracker_kernel path=/usr/local/lib/aerolvm-firecracker/vmlinux", "systemctl enable --now aerolvm-rootd")
	if strings.Contains(calls, r.path("varlib/firecracker")) {
		t.Fatalf("split wrote in sandboxd's data folder:\n%s", calls)
	}

	r.resetLog()
	out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), append(r.splitRelease("helper v0.7.9\n"), "--privilege-mode", "single")...)
	if err != nil {
		t.Fatalf("switch back: %v\n%s", err, r.calls()+out)
	}
	calls = r.calls()
	varlib := r.path("varlib")
	r.inOrder(calls, "install_firecracker_release", "systemctl stop sandboxd", "find "+varlib+" -xdev -type l -delete",
		"find "+varlib+" -xdev -uid 990 -exec chown -h root {} +",
		"install_firecracker_kernel path="+varlib+"/firecracker/vmlinux",
		"install -d -m 0755 "+varlib+"/firecracker/templates")
	if strings.Count(calls, "install_firecracker_kernel") != 1 {
		t.Fatalf("want the kernel step once:\n%s", calls)
	}

	// Single again: nothing waits, as before.
	r.resetLog()
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), r.splitRelease("helper v0.7.9\n")...); err != nil {
		t.Fatalf("single re-run: %v\n%s", err, out)
	}
	r.inOrder(r.calls(), "install_firecracker_release", "install_firecracker_kernel path="+varlib+"/firecracker/vmlinux",
		"install -d -m 0755 "+varlib+"/firecracker/templates", "systemctl daemon-reload")
}
