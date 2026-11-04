package firecracker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// scripts/install.sh --with-firecracker sets a host up for this driver. These
// tests run install.sh's real Firecracker functions. uname, curl_download,
// apt-get, getent, useradd and id are bash stubs; PATH holds only the real
// tools the functions use (tar, install, sha256sum ...), so a call nobody
// stubbed fails instead of reaching the host; and every install path points
// into a temp dir. Downloads are fixture files whose SHA-256 the test pins,
// so the checksum checks are the real ones.

const installShPath = "../../../scripts/install.sh"

func installShSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(installShPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// installShFunctions returns the source of install.sh's top-level functions
// names, cut the way pkg/caddy's installShFunctions cuts them: a function
// runs to the next top-level function definition.
func installShFunctions(t *testing.T, src string, names ...string) string {
	t.Helper()
	nextFunc := regexp.MustCompile(`\n[a-z_]+\(\) \{\n`)
	var out strings.Builder
	for _, name := range names {
		start := strings.Index(src, "\n"+name+"() {\n")
		if start < 0 {
			t.Fatalf("install.sh has no %s()", name)
		}
		body := src[start+1:]
		if loc := nextFunc.FindStringIndex(body[len(name)+5:]); loc != nil {
			body = body[:len(name)+5+loc[0]+1]
		}
		out.WriteString(body)
	}
	return out.String()
}

// installShVar returns the value of install.sh's top-level NAME="value".
func installShVar(t *testing.T, src, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + name + `="([^"]*)"$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("install.sh has no top-level %s=\"...\"", name)
	}
	return m[1]
}

// installToolPath returns a directory holding only the real programs the
// Firecracker functions run.
func installToolPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mktemp", "rm", "tar", "gzip", "install", "grep", "cat", "sha256sum"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s not available", name)
		}
		if err := os.Symlink(path, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// runInstallFunctions runs script under bash with set -euo pipefail, env as
// shell variables, and PATH set to pathDir. It returns the calls the stubs
// logged, stdout, stderr and the exit error.
func runInstallFunctions(t *testing.T, script string, env map[string]string, pathDir string) (calls []string, stdout, stderr string, err error) {
	t.Helper()
	bash, lookErr := exec.LookPath("bash")
	if lookErr != nil {
		t.Skip("bash not available")
	}
	log := filepath.Join(t.TempDir(), "calls.log")
	vars := "set -euo pipefail\nPATH='" + pathDir + "'\nLOG='" + log + "'\n"
	for k, v := range env {
		vars += k + "='" + v + "'\n"
	}
	cmd := exec.Command(bash, "-c", vars+script)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	raw, _ := os.ReadFile(log)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			calls = append(calls, line)
		}
	}
	return calls, out.String(), errOut.String(), err
}

// checkCallsInOrder fails unless want appears in calls in this order and
// nothing in never appears at all.
func checkCallsInOrder(t *testing.T, calls, want, never []string) {
	t.Helper()
	joined := strings.Join(calls, "\n")
	at := 0
	for _, w := range want {
		i := strings.Index(joined[at:], w)
		if i < 0 {
			t.Fatalf("want %q after offset %d, in order %q; calls:\n%s", w, at, want, joined)
		}
		at += i + len(w)
	}
	for _, n := range never {
		if strings.Contains(joined, n) {
			t.Errorf("unexpected call %q; calls:\n%s", n, joined)
		}
	}
}

// fcStubs replaces the programs that would change the host or reach the
// network. curl_download serves a fixture named like the URL's last path
// element; FAKE_DOWNLOAD_OK=0 fails every download. getent reports the jailer
// user present when FAKE_JAILER_USER=1.
const fcStubs = `
uname() { case "$1" in -s) echo "$FAKE_OS" ;; -m) echo "$FAKE_ARCH" ;; esac; }
apt-get() { echo "apt-get $*" >>"$LOG"; }
curl_download() {
	echo "curl_download $1" >>"$LOG"
	[[ "$FAKE_DOWNLOAD_OK" == 1 && -f "$FIXTURES/${1##*/}" ]] || return 1
	cat "$FIXTURES/${1##*/}" >"$3"
}
getent() { echo "getent $*" >>"$LOG"; [[ "$FAKE_JAILER_USER" == 1 ]]; }
useradd() { echo "useradd $*" >>"$LOG"; }
id() { case "$1" in -u) echo 997 ;; -g) echo 996 ;; esac; }
`

const fcVMGenIDConfig = "CONFIG_ACPI=y\nCONFIG_VMGENID=y\n"

// fakeVersionBinary is a firecracker/jailer stand-in that answers --version
// like the real one ("Firecracker v1.15.1", then a blank line).
func fakeVersionBinary(product, version string) []byte {
	return []byte("#!/bin/sh\nprintf '%s\\n\\n' '" + product + " " + version + "'\n")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// fcReleaseTarball is the upstream release layout:
// release-<v>-<arch>/{firecracker,jailer}-<v>-<arch>.
func fcReleaseTarball(t *testing.T, version, arch string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	dir := "release-" + version + "-" + arch + "/"
	for name, body := range map[string][]byte{
		dir + "firecracker-" + version + "-" + arch: fakeVersionBinary("Firecracker", version),
		dir + "jailer-" + version + "-" + arch:      fakeVersionBinary("Jailer", version),
		dir + "LICENSE":                             []byte("Apache-2.0\n"),
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fcHost is one test's fake host: where install.sh's Firecracker functions
// install, the fixtures they download, and the variables that point them
// there.
type fcHost struct {
	root, fixtures string
	bin, jailer    string
	kernel, config string
	templates      string
	chroot, tmp    string
	env            map[string]string
}

func newFCHost(t *testing.T, src, arch, kernelConfig string) *fcHost {
	t.Helper()
	root := t.TempDir()
	h := &fcHost{
		root:      root,
		fixtures:  filepath.Join(root, "fixtures"),
		bin:       filepath.Join(root, "usr/local/bin/firecracker"),
		jailer:    filepath.Join(root, "usr/local/bin/jailer"),
		kernel:    filepath.Join(root, "var/lib/sandboxd/firecracker/vmlinux"),
		config:    filepath.Join(root, "var/lib/sandboxd/firecracker/vmlinux.config"),
		templates: filepath.Join(root, "var/lib/sandboxd/firecracker/templates"),
		chroot:    filepath.Join(root, "srv/jailer"),
		tmp:       filepath.Join(root, "tmp"),
	}
	for _, d := range []string{h.fixtures, filepath.Dir(h.bin), h.tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	version := installShVar(t, src, "FIRECRACKER_VERSION")
	kernelVersion := installShVar(t, src, "FIRECRACKER_KERNEL_VERSION")
	tarball := fcReleaseTarball(t, version, arch)
	kernel := []byte("vmlinux " + arch + "\n")
	fixtures := map[string][]byte{
		"firecracker-" + version + "-" + arch + ".tgz": tarball,
		"vmlinux-" + kernelVersion:                     kernel,
		"vmlinux-" + kernelVersion + ".config":         []byte(kernelConfig),
	}
	for name, body := range fixtures {
		if err := os.WriteFile(filepath.Join(h.fixtures, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	suffix := map[string]string{"x86_64": "X86_64", "aarch64": "AARCH64"}[arch]
	h.env = map[string]string{
		"FAKE_OS": "Linux", "FAKE_ARCH": arch, "FAKE_DOWNLOAD_OK": "1", "FAKE_JAILER_USER": "0",
		"FIXTURES": h.fixtures, "TMPDIR": h.tmp,
		"FIRECRACKER_VERSION":           version,
		"FIRECRACKER_KERNEL_CI_VERSION": installShVar(t, src, "FIRECRACKER_KERNEL_CI_VERSION"),
		"FIRECRACKER_KERNEL_VERSION":    kernelVersion,
		"FIRECRACKER_BIN":               h.bin,
		"JAILER_BIN":                    h.jailer,
		"FIRECRACKER_KERNEL_PATH":       h.kernel,
		"FIRECRACKER_TEMPLATES_DIR":     h.templates,
		"JAILER_CHROOT_BASE":            h.chroot,
		"JAILER_USER":                   installShVar(t, src, "JAILER_USER"),
	}
	// Both architectures' hashes are set, as in install.sh; only this
	// arch's fixtures exist, so the other arch's hashes are never used.
	for _, a := range []string{"X86_64", "AARCH64"} {
		h.env["FIRECRACKER_SHA256_"+a] = strings.Repeat("e", 64)
		h.env["FIRECRACKER_KERNEL_SHA256_"+a] = strings.Repeat("e", 64)
		h.env["FIRECRACKER_KERNEL_CONFIG_SHA256_"+a] = strings.Repeat("e", 64)
	}
	h.env["FIRECRACKER_SHA256_"+suffix] = sha256Hex(tarball)
	h.env["FIRECRACKER_KERNEL_SHA256_"+suffix] = sha256Hex(kernel)
	h.env["FIRECRACKER_KERNEL_CONFIG_SHA256_"+suffix] = sha256Hex([]byte(kernelConfig))
	return h
}

func writeHostFile(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

func TestInstallShInstallsFirecracker(t *testing.T) {
	src := installShSource(t)
	funcs := installShFunctions(t, src, "firecracker_binary_version", "firecracker_verify",
		"install_firecracker_release", "install_firecracker_kernel", "install_firecracker")
	version := installShVar(t, src, "FIRECRACKER_VERSION")
	kciVersion := installShVar(t, src, "FIRECRACKER_KERNEL_CI_VERSION")
	kVersion := installShVar(t, src, "FIRECRACKER_KERNEL_VERSION")
	releaseURL := func(arch string) string {
		return "curl_download https://github.com/firecracker-microvm/firecracker/releases/download/" + version + "/firecracker-" + version + "-" + arch + ".tgz"
	}
	kernelURL := func(arch string) string {
		return "curl_download https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/" + kciVersion + "/" + arch + "/vmlinux-" + kVersion
	}
	const (
		apt     = "apt-get install -y skopeo umoci e2fsprogs iproute2"
		lookup  = "getent passwd sandboxd-jailer"
		useradd = "useradd --system --no-create-home --shell /usr/sbin/nologin --user-group sandboxd-jailer"
	)
	// installedPinned puts the pinned firecracker and jailer, a kernel and its
	// config where a previous run left them.
	installedPinned := func(t *testing.T, h *fcHost) {
		writeHostFile(t, h.bin, fakeVersionBinary("Firecracker", version), 0o755)
		writeHostFile(t, h.jailer, fakeVersionBinary("Jailer", version), 0o755)
		writeHostFile(t, h.kernel, []byte("operator kernel\n"), 0o644)
		writeHostFile(t, h.config, []byte(fcVMGenIDConfig), 0o644)
	}

	cases := []struct {
		name    string
		arch    string
		config  string // the kernel config fixture; default fcVMGenIDConfig
		env     map[string]string
		setup   func(t *testing.T, h *fcHost)
		want    []string // calls, in this order
		never   []string // calls that must not happen
		wantErr string   // on stderr; "" means the install succeeds
		// After the run: the pinned firecracker and jailer are installed
		// (the release step runs first, so a later step's failure leaves
		// them, and a re-run skips them); the downloaded kernel is
		// installed; the operator's kernel from setup is still there.
		wantRelease, wantKernel, keepsKernel bool
	}{
		{name: "x86_64: fresh host gets everything, checked, and the jailer user", arch: "x86_64",
			want:        []string{apt, releaseURL("x86_64"), kernelURL("x86_64"), kernelURL("x86_64") + ".config", lookup, useradd},
			wantRelease: true, wantKernel: true},
		{name: "aarch64 fetches the aarch64 release and kernel", arch: "aarch64",
			want:        []string{apt, releaseURL("aarch64"), kernelURL("aarch64"), kernelURL("aarch64") + ".config", useradd},
			never:       []string{"x86_64"},
			wantRelease: true, wantKernel: true},
		{name: "re-run with everything in place downloads nothing", arch: "x86_64",
			env: map[string]string{"FAKE_JAILER_USER": "1"}, setup: installedPinned,
			want: []string{apt, lookup}, never: []string{"curl_download", "useradd"},
			wantRelease: true, keepsKernel: true},
		{name: "another firecracker version is replaced; the kernel stays", arch: "x86_64",
			setup: func(t *testing.T, h *fcHost) {
				installedPinned(t, h)
				writeHostFile(t, h.bin, fakeVersionBinary("Firecracker", "v1.10.1"), 0o755)
			},
			want: []string{releaseURL("x86_64")}, never: []string{kernelURL("x86_64")},
			wantRelease: true, keepsKernel: true},
		{name: "a jailer from another version is replaced too", arch: "x86_64",
			setup: func(t *testing.T, h *fcHost) {
				installedPinned(t, h)
				writeHostFile(t, h.jailer, fakeVersionBinary("Jailer", "v1.10.1"), 0o755)
			},
			want: []string{releaseURL("x86_64")}, never: []string{kernelURL("x86_64")},
			wantRelease: true, keepsKernel: true},
		{name: "a release that fails its checksum installs nothing", arch: "x86_64",
			env:     map[string]string{"FIRECRACKER_SHA256_X86_64": strings.Repeat("0", 64)},
			want:    []string{releaseURL("x86_64")},
			never:   []string{kernelURL("x86_64"), "useradd"},
			wantErr: "checksum verification failed for firecracker-" + version + "-x86_64.tgz"},
		{name: "a kernel that fails its checksum is not installed", arch: "x86_64",
			env:     map[string]string{"FIRECRACKER_KERNEL_SHA256_X86_64": strings.Repeat("0", 64)},
			want:    []string{kernelURL("x86_64")},
			never:   []string{"useradd"},
			wantErr: "checksum verification failed for vmlinux", wantRelease: true},
		{name: "a kernel config that fails its checksum is not installed", arch: "aarch64",
			env:     map[string]string{"FIRECRACKER_KERNEL_CONFIG_SHA256_AARCH64": strings.Repeat("0", 64)},
			want:    []string{kernelURL("aarch64") + ".config"},
			wantErr: "checksum verification failed for vmlinux.config", wantRelease: true},
		{name: "a pinned kernel without CONFIG_VMGENID=y is refused before it is installed", arch: "x86_64",
			config:  "CONFIG_ACPI=y\n# CONFIG_VMGENID is not set\n",
			never:   []string{"useradd"},
			wantErr: "does not set CONFIG_VMGENID=y", wantRelease: true},
		{name: "an operator's kernel stays when its config sets CONFIG_VMGENID=y", arch: "x86_64",
			setup: func(t *testing.T, h *fcHost) {
				writeHostFile(t, h.kernel, []byte("operator kernel\n"), 0o644)
				writeHostFile(t, h.config, []byte(fcVMGenIDConfig), 0o644)
			},
			want: []string{releaseURL("x86_64")}, never: []string{kernelURL("x86_64")},
			wantRelease: true, keepsKernel: true},
		{name: "an operator's kernel without CONFIG_VMGENID=y is refused", arch: "x86_64",
			setup: func(t *testing.T, h *fcHost) {
				writeHostFile(t, h.kernel, []byte("operator kernel\n"), 0o644)
				writeHostFile(t, h.config, []byte("# CONFIG_VMGENID is not set\n"), 0o644)
			},
			never:   []string{kernelURL("x86_64"), "useradd"},
			wantErr: "does not set CONFIG_VMGENID=y", wantRelease: true, keepsKernel: true},
		{name: "an operator's kernel with no config next to it is refused", arch: "x86_64",
			setup: func(t *testing.T, h *fcHost) {
				writeHostFile(t, h.kernel, []byte("operator kernel\n"), 0o644)
			},
			never:   []string{kernelURL("x86_64"), "useradd"},
			wantErr: "has no build config", wantRelease: true, keepsKernel: true},
		{name: "a failed download stops the install", arch: "x86_64",
			env:     map[string]string{"FAKE_DOWNLOAD_OK": "0"},
			want:    []string{releaseURL("x86_64")},
			never:   []string{kernelURL("x86_64"), "useradd"},
			wantErr: "failed to download"},
		{name: "an unsupported architecture is refused before anything is installed", arch: "x86_64",
			env:     map[string]string{"FAKE_ARCH": "riscv64"},
			never:   []string{"apt-get", "curl_download"},
			wantErr: "unsupported architecture riscv64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kernelConfig := tc.config
			if kernelConfig == "" {
				kernelConfig = fcVMGenIDConfig
			}
			h := newFCHost(t, src, tc.arch, kernelConfig)
			for k, v := range tc.env {
				h.env[k] = v
			}
			if tc.setup != nil {
				tc.setup(t, h)
			}
			calls, stdout, stderr, err := runInstallFunctions(t, fcStubs+funcs+"install_firecracker\necho DONE\n", h.env, installToolPath(t))
			if tc.wantErr != "" {
				if err == nil || strings.Contains(stdout, "DONE") {
					t.Fatalf("install succeeded, want %q\nstdout: %s\nstderr: %s", tc.wantErr, stdout, stderr)
				}
				if !strings.Contains(stderr, tc.wantErr) {
					t.Fatalf("stderr = %q, want %q", stderr, tc.wantErr)
				}
			} else if err != nil || !strings.Contains(stdout, "DONE") {
				t.Fatalf("install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
			}
			checkCallsInOrder(t, calls, tc.want, tc.never)

			if tc.wantRelease {
				for path, want := range map[string]string{h.bin: "Firecracker " + version, h.jailer: "Jailer " + version} {
					got, err := exec.Command(path, "--version").Output()
					if err != nil || !strings.HasPrefix(string(got), want+"\n") {
						t.Errorf("%s --version = %q, %v; want %q", path, got, err, want)
					}
				}
			} else if _, err := os.Stat(h.bin); err == nil {
				t.Errorf("firecracker installed by a run that failed before it")
			}
			kernel, kernelErr := os.ReadFile(h.kernel)
			switch {
			case tc.wantKernel:
				if string(kernel) != "vmlinux "+tc.arch+"\n" {
					t.Errorf("installed kernel = %q, want the %s fixture", kernel, tc.arch)
				}
				if cfg, _ := os.ReadFile(h.config); string(cfg) != kernelConfig {
					t.Errorf("installed kernel config = %q, want %q", cfg, kernelConfig)
				}
			case tc.keepsKernel:
				if string(kernel) != "operator kernel\n" {
					t.Errorf("kernel = %q, want the operator's kernel kept", kernel)
				}
			case !os.IsNotExist(kernelErr):
				t.Errorf("kernel installed by a failed run: %q, %v", kernel, kernelErr)
			}
			if tc.wantErr == "" {
				for _, dir := range []string{h.templates, h.chroot} {
					if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
						t.Errorf("%s not created: %v", dir, err)
					}
				}
				// The download directory is removed when the install returns.
				if left, _ := os.ReadDir(h.tmp); len(left) != 0 {
					t.Errorf("temp dir left behind: %v", left)
				}
			}
		})
	}
}

func TestInstallShFirecrackerPreflight(t *testing.T) {
	src := installShSource(t)
	funcs := installShFunctions(t, src, "firecracker_preflight")
	cases := []struct {
		name, os, arch string
		kvm            bool
		wantErr        string
	}{
		{name: "x86_64 Linux with KVM", os: "Linux", arch: "x86_64", kvm: true},
		{name: "aarch64 Linux with KVM", os: "Linux", arch: "aarch64", kvm: true},
		{name: "no /dev/kvm: refused, with what to do about it", os: "Linux", arch: "x86_64",
			wantErr: "use a bare-metal instance type"},
		{name: "macOS", os: "Darwin", arch: "arm64", kvm: true, wantErr: "Firecracker runs on Linux only"},
		{name: "an architecture Firecracker does not support", os: "Linux", arch: "armv7l", kvm: true,
			wantErr: "unsupported architecture armv7l"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kvm := filepath.Join(t.TempDir(), "kvm")
			if tc.kvm {
				writeHostFile(t, kvm, nil, 0o600)
			}
			env := map[string]string{"FAKE_OS": tc.os, "FAKE_ARCH": tc.arch, "KVM_DEVICE": kvm}
			_, stdout, stderr, err := runInstallFunctions(t, fcStubs+funcs+"firecracker_preflight\necho DONE\n", env, t.TempDir())
			if tc.wantErr == "" {
				if err != nil || !strings.Contains(stdout, "DONE") {
					t.Fatalf("preflight refused: %v\nstderr: %s", err, stderr)
				}
				return
			}
			if err == nil || strings.Contains(stdout, "DONE") || !strings.Contains(stderr, tc.wantErr) {
				t.Fatalf("preflight = %v, stderr %q; want refusal with %q", err, stderr, tc.wantErr)
			}
		})
	}
}

// What install.sh writes to sandboxd.env must load into a config that runs
// this driver with the jailer user, and install.sh's install paths must be
// the daemon's defaults, since it writes no path settings.
func TestInstallShFirecrackerEnvironmentLoadsIntoTheDaemonConfig(t *testing.T) {
	src := installShSource(t)
	funcs := installShFunctions(t, src, "firecracker_environment")
	_, stdout, stderr, err := runInstallFunctions(t, fcStubs+funcs+"firecracker_environment\n",
		map[string]string{"JAILER_USER": "sandboxd-jailer"}, t.TempDir())
	if err != nil {
		t.Fatalf("firecracker_environment: %v\nstderr: %s", err, stderr)
	}
	want := "SB_ENABLE_FIRECRACKER=true\nSB_JAILER_UID=997\nSB_JAILER_GID=996\n"
	if stdout != want {
		t.Fatalf("firecracker_environment = %q, want %q", stdout, want)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		k, v, _ := strings.Cut(line, "=")
		t.Setenv(k, v)
	}
	for _, k := range []string{"SB_FIRECRACKER_BINARY", "SB_JAILER_BINARY", "SB_FIRECRACKER_KERNEL",
		"SB_FIRECRACKER_TEMPLATES_DIR", "SB_JAILER_CHROOT_BASE", "SB_FIRECRACKER_USE_JAILER"} {
		t.Setenv(k, "")
	}
	t.Setenv("SB_ENTERPRISE_MODE", "false")
	t.Setenv("SB_PAT_TOKEN", "pat-token")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load with install.sh's Firecracker settings: %v", err)
	}
	if !cfg.EnableFirecracker || !cfg.UseJailer || cfg.JailerUID != 997 || cfg.JailerGID != 996 {
		t.Fatalf("EnableFirecracker=%v UseJailer=%v jailer=%d:%d, want true true 997:996",
			cfg.EnableFirecracker, cfg.UseJailer, cfg.JailerUID, cfg.JailerGID)
	}
	for _, p := range []struct{ shVar, daemon string }{
		{"FIRECRACKER_BIN", cfg.FirecrackerBinary},
		{"JAILER_BIN", cfg.JailerBinary},
		{"FIRECRACKER_KERNEL_PATH", cfg.FirecrackerKernelImage},
		{"FIRECRACKER_TEMPLATES_DIR", cfg.FirecrackerTemplatesDir},
		{"JAILER_CHROOT_BASE", cfg.JailerChrootBase},
	} {
		if got := installShVar(t, src, p.shVar); got != p.daemon {
			t.Errorf("install.sh %s=%q, but sandboxd looks in %q", p.shVar, got, p.daemon)
		}
	}
}

// install.sh, Terraform and Ansible install the same Firecracker and kernel,
// so a node set up by hand runs what the cluster tooling is tested on.
func TestInstallShFirecrackerPinsMatchTerraformAndAnsible(t *testing.T) {
	src := installShSource(t)
	tf, err := os.ReadFile("../../../Terraform/variables.tf")
	if err != nil {
		t.Fatal(err)
	}
	ansible, err := os.ReadFile("../../../Ansible/inventory/group_vars/all/defaults.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ shVar, tfKey, ansibleKey string }{
		{"FIRECRACKER_VERSION", "version", "firecracker_version"},
		{"FIRECRACKER_KERNEL_CI_VERSION", "kernel_ci_version", "firecracker_kernel_ci_version"},
		{"FIRECRACKER_KERNEL_VERSION", "kernel_version", "firecracker_kernel_version"},
	} {
		want := installShVar(t, src, p.shVar)
		tfm := regexp.MustCompile(`(?m)^\s+` + p.tfKey + `\s+= optional\(string, "([^"]+)"\)`).FindSubmatch(tf)
		if tfm == nil || string(tfm[1]) != want {
			t.Errorf("Terraform firecracker.%s = %q, install.sh %s = %q", p.tfKey, tfm, p.shVar, want)
		}
		am := regexp.MustCompile(`(?m)^` + p.ansibleKey + `: "([^"]+)"$`).FindSubmatch(ansible)
		if am == nil || string(am[1]) != want {
			t.Errorf("Ansible %s = %q, install.sh %s = %q", p.ansibleKey, am, p.shVar, want)
		}
	}
	hexSHA := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, v := range []string{"FIRECRACKER_SHA256", "FIRECRACKER_KERNEL_SHA256", "FIRECRACKER_KERNEL_CONFIG_SHA256"} {
		for _, arch := range []string{"X86_64", "AARCH64"} {
			if got := installShVar(t, src, v+"_"+arch); !hexSHA.MatchString(got) {
				t.Errorf("%s_%s = %q, want a SHA-256", v, arch, got)
			}
		}
	}
}

// --with-firecracker is wired into the install: the KVM check runs before any
// package is installed, the install after them, and its settings land in
// sandboxd.env. A --local or --cli-only run refuses it before doing anything.
func TestInstallShWiresWithFirecracker(t *testing.T) {
	src := installShSource(t)
	preflight := strings.Index(src, "\n\tfirecracker_preflight\nfi\n")
	packages := strings.Index(src, "\ninstall_packages\n")
	install := strings.Index(src, "\n\tinstall_firecracker\nfi\n")
	if preflight < 0 || packages < 0 || install < 0 || !(preflight < packages && packages < install) {
		t.Fatalf("want firecracker_preflight (%d) < install_packages (%d) < install_firecracker (%d) in the main flow",
			preflight, packages, install)
	}
	if env := installShFunctions(t, src, "write_environment"); !strings.Contains(env,
		"if [[ \"$WITH_FIRECRACKER\" == \"true\" ]]; then\n\t\tfirecracker_environment >> /etc/sandboxd/sandboxd.env\n") {
		t.Fatal("write_environment does not append firecracker_environment under --with-firecracker")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	for _, args := range [][]string{{"--with-firecracker", "--local"}, {"--cli-only", "--with-firecracker"}} {
		cmd := exec.Command(bash, append([]string{mustAbs(t, installShPath)}, args...)...)
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "--with-firecracker sets up a server node") {
			t.Fatalf("install.sh %s = %v:\n%s", strings.Join(args, " "), err, out)
		}
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// Before install.sh restarts sandboxd it moves the Firecracker VMs an older
// release started inside sandboxd's cgroup into the VMs' own, so the
// restart does not stop them. Nothing else in the unit moves.
func TestInstallShKeepsFirecrackerVMsThroughARestart(t *testing.T) {
	src := installShSource(t)
	fn := installShFunctions(t, src, "keep_firecracker_vms_running")
	root := t.TempDir()
	cgroups, procs := filepath.Join(root, "cgroup"), filepath.Join(root, "proc")
	unit := filepath.Join(cgroups, "system.slice", "sandboxd.service")
	for _, dir := range []string{unit, procs} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(cgroups, "cgroup.controllers"), "cpu memory\n")
	write(filepath.Join(unit, "cgroup.procs"), "100\n101\n102\n")
	write(filepath.Join(procs, "100", "cmdline"), "/usr/local/bin/sandboxd\x00")
	write(filepath.Join(procs, "101", "cmdline"), "/firecracker\x00--id\x00sb-a\x00--api-sock\x00api.socket\x00")
	write(filepath.Join(procs, "102", "cmdline"), "/usr/bin/rclone\x00mount\x00")
	run := func() string {
		t.Helper()
		script := "set -euo pipefail\nCGROUP_ROOT=" + cgroups + "\nPROC_ROOT=" + procs + "\n" +
			"systemctl() { echo /system.slice/sandboxd.service; }\n" + fn + "\nkeep_firecracker_vms_running\n"
		out, err := exec.Command("bash", "-c", script).CombinedOutput()
		if err != nil {
			t.Fatalf("keep_firecracker_vms_running: %v: %s", err, out)
		}
		moved, _ := os.ReadFile(filepath.Join(cgroups, "aerolvm-vmm", "cgroup.procs"))
		return string(moved)
	}
	if got := run(); got != "101\n" {
		t.Fatalf("moved %q, want only the VM (101)", got)
	}
	// A VM whose output is a pipe (an older release's) also gets a reader,
	// moved in after it. (Here the "pipe" is a dangling link, so the reader
	// exits at once; what is checked is that one was started and moved.)
	if err := os.MkdirAll(filepath.Join(procs, "101", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pipe:[4242]", filepath.Join(procs, "101", "fd", "1")); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(run()); got == "101" || got == "" || strings.Trim(got, "0123456789") != "" {
		t.Fatalf("last moved %q, want the reader's pid after the VM", got)
	}
	// No cgroup v2, or no unit cgroup: nothing to do, and no error under
	// set -e.
	if err := os.Remove(filepath.Join(unit, "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	run()
	if err := os.Remove(filepath.Join(cgroups, "cgroup.controllers")); err != nil {
		t.Fatal(err)
	}
	run()
}
