package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// switchBackKernelStubs stand in for what install_firecracker does besides
// the guest kernel: apt, the release download, the jailer's user. The
// kernel download (curl_download) writes a "pinned kernel" and its config
// where it is pointed, and logs; firecracker_verify passes. install logs,
// then copies for real (inside the test's folder). Every other program is
// a real one from PATH, which holds only the few the kernel steps use.
const switchBackKernelStubs = `
uname() { echo x86_64; }
apt-get() { echo "apt-get $*" >>"$LOG"; }
install_firecracker_release() { echo "install_firecracker_release $1" >>"$LOG"; }
getent() { return 0; }
useradd() { echo "useradd $*" >>"$LOG"; }
firecracker_verify() { return 0; }
curl_download() {
	echo "curl_download $1" >>"$LOG"
	case "$1" in
	*.config) printf 'CONFIG_VMGENID=y\n' >"$3" ;;
	*) printf 'pinned kernel\n' >"$3" ;;
	esac
}
install() { echo "install $*" >>"$LOG"; command install "$@"; }
`

type kernelHost struct {
	t                                 *testing.T
	dir, bin, single, split, template string
}

func newKernelHost(t *testing.T) *kernelHost {
	t.Helper()
	h := &kernelHost{t: t, dir: t.TempDir()}
	h.bin = filepath.Join(h.dir, "bin")
	h.single = filepath.Join(h.dir, "varlib", "firecracker", "vmlinux")
	h.split = filepath.Join(h.dir, "rootlib", "vmlinux")
	h.template = filepath.Join(h.dir, "varlib", "firecracker", "templates")
	mustMkdir(t, h.bin)
	mustMkdir(t, filepath.Join(h.dir, "tmp"))
	for _, tool := range []string{"grep", "install", "rm", "rmdir", "mkdir", "mktemp"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available", tool)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// kernel writes a kernel and its config at path.
func (h *kernelHost) kernel(path, body, config string) {
	h.t.Helper()
	mustMkdir(h.t, filepath.Dir(path))
	mustWrite(h.t, path, body)
	mustWrite(h.t, path+".config", config)
}

func (h *kernelHost) read(path string) string {
	h.t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(raw)
}

// run runs install_firecracker, then CLEANUP (where leave_split_mode runs in
// the main flow), then finish_firecracker_after_switch_back, as a run in
// mode on a node that ran in previous. It returns the log, stdout+stderr,
// and whether the run succeeded.
func (h *kernelHost) run(mode, previous string) (calls, out string, ok bool) {
	h.t.Helper()
	src := installShSource(h.t)
	funcs := ""
	for _, name := range []string{"agent_may_own_folders", "install_firecracker_kernel", "install_firecracker", "stage_switch_back_kernel",
		"make_firecracker_templates_dir", "finish_firecracker_after_switch_back"} {
		funcs += extractShellFunc(h.t, src, name)
	}
	log := filepath.Join(h.dir, "calls.log")
	_ = os.Remove(log)
	script := "set -euo pipefail\nPATH='" + h.bin + "'\nLOG='" + log + "'\nTMPDIR='" + filepath.Join(h.dir, "tmp") + "'\n" +
		"HOME='" + filepath.Join(h.dir, "home") + "'\n" +
		"PRIVILEGE_MODE='" + mode + "'\nPREVIOUS_PRIVILEGE_MODE='" + previous + "'\n" +
		"FIRECRACKER_KERNEL_PATH='" + h.single + "'\nFIRECRACKER_TEMPLATES_DIR='" + h.template + "'\n" +
		"SPLIT_FIRECRACKER_KERNEL_PATH='" + h.split + "'\nJAILER_CHROOT_BASE='" + filepath.Join(h.dir, "jailer") + "'\n" +
		"JAILER_USER=sandboxd-jailer\nFIRECRACKER_KERNEL_CI_VERSION=v1\nFIRECRACKER_KERNEL_VERSION=5.10\n" +
		"FIRECRACKER_KERNEL_SHA256_X86_64=x\nFIRECRACKER_KERNEL_CONFIG_SHA256_X86_64=x\n" +
		"FIRECRACKER_KERNEL_FOR_SWITCH_BACK=''\nFIRECRACKER_KERNEL_STAGE=''\n"
	if mode == "split" {
		// check_privilege_mode's doing for split.
		script += "FIRECRACKER_KERNEL_PATH=\"$SPLIT_FIRECRACKER_KERNEL_PATH\"\n"
	}
	script += switchBackKernelStubs + funcs +
		"install_firecracker\necho CLEANUP >>\"$LOG\"\nfinish_firecracker_after_switch_back\necho DONE\n"
	raw, err := exec.Command("bash", "-c", script).CombinedOutput()
	logRaw, _ := os.ReadFile(log)
	return string(logRaw), string(raw), err == nil && strings.Contains(string(raw), "DONE")
}

// TestInstallSwitchBackReplacesTheGuestKernel: on a switch back, single's
// guest kernel in /var/lib/sandboxd sat in a folder sandboxd's user
// controlled in split, and every new VM boots it. It is replaced, never
// kept: by a copy of split's kernel (a folder only root writes; an
// operator's own kernel stays the operator's), or, when split has none, by
// the pinned kernel, downloaded before the cleanup. After the cleanup only a
// copy runs, so a failed download cannot leave sandboxd stopped. Single to
// single and split to split keep their kernel as before.
func TestInstallSwitchBackReplacesTheGuestKernel(t *testing.T) {
	const left = "kernel left from single, open to sandboxd's user in split\n"
	const vmgenid = "CONFIG_VMGENID=y\n"

	t.Run("switch back: a copy of split's kernel", func(t *testing.T) {
		h := newKernelHost(t)
		h.kernel(h.single, left, vmgenid)
		h.kernel(h.split, "operator kernel\n", vmgenid)
		calls, out, ok := h.run("single", "split")
		if !ok {
			t.Fatalf("run failed:\n%s", out)
		}
		if got := h.read(h.single); got != "operator kernel\n" {
			t.Fatalf("single's kernel = %q, want a copy of split's", got)
		}
		if strings.Contains(calls, "curl_download") {
			t.Fatalf("downloaded although split had a kernel:\n%s", calls)
		}
		checkCalls(t, strings.Split(calls, "\n"), []string{"CLEANUP", "install -m 0644 " + h.split + ".config " + h.single + ".config",
			"install -m 0644 " + h.split + " " + h.single, "install -d -m 0755 " + h.template}, nil)
		if h.read(h.split) != "operator kernel\n" {
			t.Fatal("split's kernel changed")
		}
	})

	t.Run("switch back: split has no kernel, the pinned one is downloaded first", func(t *testing.T) {
		h := newKernelHost(t)
		h.kernel(h.single, left, vmgenid)
		calls, out, ok := h.run("single", "split")
		if !ok {
			t.Fatalf("run failed:\n%s", out)
		}
		if got := h.read(h.single); got != "pinned kernel\n" {
			t.Fatalf("single's kernel = %q, want the pinned one", got)
		}
		checkCalls(t, strings.Split(calls, "\n"), []string{"curl_download", "CLEANUP", "install -m 0644 "}, nil)
		if after := calls[strings.Index(calls, "CLEANUP"):]; strings.Contains(after, "curl_download") {
			t.Fatalf("downloaded after the cleanup:\n%s", calls)
		}
		if entries, _ := os.ReadDir(filepath.Join(h.dir, "tmp")); len(entries) != 0 {
			t.Errorf("left %d folders in TMPDIR", len(entries))
		}
	})

	t.Run("switch back: split's config lacks VMGENID, the run stops before the cleanup", func(t *testing.T) {
		h := newKernelHost(t)
		h.kernel(h.single, left, vmgenid)
		h.kernel(h.split, "operator kernel\n", "# no vmgenid\n")
		calls, out, ok := h.run("single", "split")
		if ok || !strings.Contains(out, "does not set CONFIG_VMGENID=y") || strings.Contains(calls, "CLEANUP") {
			t.Fatalf("want a stop before the cleanup; ok=%v\n%s\n%s", ok, out, calls)
		}
		if h.read(h.single) != left {
			t.Fatal("single's kernel changed")
		}
	})

	t.Run("single to single: the kernel stays", func(t *testing.T) {
		h := newKernelHost(t)
		h.kernel(h.single, "operator's single kernel\n", vmgenid)
		h.kernel(h.split, "operator kernel\n", vmgenid)
		calls, out, ok := h.run("single", "single")
		if !ok || !strings.Contains(out, "Keeping the guest kernel already at "+h.single) {
			t.Fatalf("run: ok=%v\n%s", ok, out)
		}
		if h.read(h.single) != "operator's single kernel\n" || strings.Contains(out, "Replaced") {
			t.Fatalf("single to single replaced the kernel:\n%s", calls)
		}
	})

	t.Run("split to split: split's kernel stays, single's folder untouched", func(t *testing.T) {
		h := newKernelHost(t)
		h.kernel(h.single, left, vmgenid)
		h.kernel(h.split, "operator kernel\n", vmgenid)
		calls, out, ok := h.run("split", "split")
		if !ok || !strings.Contains(out, "Keeping the guest kernel already at "+h.split) {
			t.Fatalf("run: ok=%v\n%s", ok, out)
		}
		if h.read(h.single) != left || strings.Contains(calls, h.single) || strings.Contains(calls, h.template) {
			t.Fatalf("split touched single's folder:\n%s", calls)
		}
	})
}
