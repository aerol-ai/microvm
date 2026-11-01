package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// install.sh --local skips install_packages, which used to be the only place
// the mount tools (fuse3, sshfs, nfs-common, rclone, mount-s3) were
// installed. A local-mode server then failed every platform-volume create:
// UC-81..84 on the local-mode scenario, main f34b607e, with
// `exec: "mount-s3": executable file not found in $PATH`. The tools now live
// in install_mount_tools, which both Linux install paths call. These tests
// run install.sh's real functions with apt-get, uname, curl and the rest
// replaced by bash functions, and PATH pointed at an empty directory so no
// real program on the test machine is reached.

// installShSource is install.sh as it is on this branch.
func installShSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// installShFunction returns the source of one of install.sh's top-level
// functions, cut the way pkg/caddy's installShFunctions cuts it: a function
// runs to the next top-level function definition.
func installShFunction(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "\n"+name+"() {\n")
	if start < 0 {
		t.Fatalf("install.sh has no %s()", name)
	}
	body := src[start+1:]
	nextFunc := regexp.MustCompile(`\n[a-z_]+\(\) \{\n`)
	if loc := nextFunc.FindStringIndex(body[len(name)+5:]); loc != nil {
		body = body[:len(name)+5+loc[0]+1]
	}
	return body
}

// localModeBranch returns install.sh's top-level --local branch, from its
// `if` to the `exit 0` that ends it.
func localModeBranch(t *testing.T, src string) string {
	t.Helper()
	const open = "\nif [[ \"$LOCAL_MODE\" == \"true\" ]]; then\n"
	start := strings.Index(src, open)
	if start < 0 {
		t.Fatal("install.sh has no top-level --local branch")
	}
	body := src[start+1:]
	end := strings.Index(body, "\n\texit 0\nfi\n")
	if end < 0 {
		t.Fatal("the --local branch no longer ends in exit 0")
	}
	return body[:end+len("\n\texit 0\nfi\n")]
}

// mountToolStubs replaces every program install_mount_tools runs. Each stub
// logs its call to $LOG; the FAKE_* variables pick what it answers. Nothing
// is written to /fake-tmp: mktemp, curl, apt-get and rm are all stubs.
const mountToolStubs = `
uname() { case "$1" in -s) echo "$FAKE_OS" ;; -m) echo "$FAKE_ARCH" ;; esac; }
mktemp() { echo /fake-tmp/mount-s3.deb; }
rm() { echo "rm $*" >>"$LOG"; }
curl_download() { echo "curl_download $*" >>"$LOG"; [[ "$FAKE_DOWNLOAD_OK" == 1 ]]; }
`

// fakeAptGet answers like apt-get: FAKE_UPDATE_OK, FAKE_PKGS_OK and
// FAKE_DEB_OK fail one call each. Defined only when the host "has" apt-get.
const fakeAptGet = `
apt-get() {
	echo "apt-get $*" >>"$LOG"
	case "$*" in
		update) [[ "$FAKE_UPDATE_OK" == 1 ]] ;;
		"install -y fuse3 sshfs nfs-common rclone") [[ "$FAKE_PKGS_OK" == 1 ]] ;;
		*mount-s3.deb) [[ "$FAKE_DEB_OK" == 1 ]] ;;
		*) return 0 ;;
	esac
}
`

// runInstallSh runs script under bash with set -euo pipefail and PATH set to
// an empty directory, and returns the calls the stubs logged, stdout and
// stderr. A non-zero exit fails the test: nothing here may stop an install.
func runInstallSh(t *testing.T, script string, env map[string]string) (calls []string, stdout, stderr string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty-path")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "calls.log")
	vars := "set -euo pipefail\nPATH='" + empty + "'\nLOG='" + log + "'\n"
	for k, v := range env {
		vars += k + "='" + v + "'\n"
	}
	cmd := exec.Command(bash, "-c", vars+script)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("exited %v\nstdout: %s\nstderr: %s", err, out.String(), errOut.String())
	}
	raw, _ := os.ReadFile(log)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			calls = append(calls, line)
		}
	}
	return calls, out.String(), errOut.String()
}

func TestInstallMountToolsInstallsOrWarns(t *testing.T) {
	src := installShSource(t)
	fn := installShFunction(t, src, "install_mount_tools")

	const (
		update   = "apt-get update"
		pkgs     = "apt-get install -y fuse3 sshfs nfs-common rclone"
		dlAMD64  = "curl_download https://s3.amazonaws.com/mountpoint-s3-release/latest/x86_64/mount-s3.deb"
		dlARM64  = "curl_download https://s3.amazonaws.com/mountpoint-s3-release/latest/arm64/mount-s3.deb"
		debStep  = "apt-get install -y /fake-tmp/mount-s3.deb"
		warnDL   = "Warning: failed to download mountpoint-s3; s3 mounts will be unavailable until installed manually"
		warnDeb  = "Warning: mountpoint-s3 install failed; s3 mounts will be unavailable until installed manually"
		warnUpd  = "Warning: apt-get update failed; installing the mount tools from the existing package index"
		warnApt  = "Warning: only apt-based distributions get the mount tools from this installer"
		skipDarw = "Skipping the mount tools (fuse3, sshfs, nfs-common, rclone, mount-s3): Linux only"
	)
	ok := map[string]string{"FAKE_OS": "Linux", "FAKE_ARCH": "x86_64", "APT_UPDATED": "false",
		"FAKE_UPDATE_OK": "1", "FAKE_PKGS_OK": "1", "FAKE_DEB_OK": "1", "FAKE_DOWNLOAD_OK": "1"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range ok {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	cases := []struct {
		name     string
		env      map[string]string
		noAptGet bool     // a Linux host without apt-get
		mountS3  bool     // mount-s3 is already on PATH
		want     []string // calls, in this order
		never    []string // calls that must not happen
		warning  string   // on stderr
	}{
		{name: "--local: refreshes the index, then installs everything", env: ok,
			want: []string{update, pkgs, dlAMD64, debStep, "rm -f /fake-tmp/mount-s3.deb"}},
		{name: "after install_packages: the index is fresh, so no second update", env: with("APT_UPDATED", "true"),
			want: []string{pkgs, dlAMD64}, never: []string{update}},
		{name: "arm64 fetches the arm64 mount-s3", env: with("FAKE_ARCH", "aarch64"),
			want: []string{update, pkgs, dlARM64}},
		{name: "mount-s3 already installed is not fetched again", env: ok, mountS3: true,
			want: []string{update, pkgs}, never: []string{"curl_download"}},
		{name: "no mount-s3 build for the architecture: no fetch, as before", env: with("FAKE_ARCH", "armv7l"),
			want: []string{update, pkgs}, never: []string{"curl_download"}},
		{name: "a failed apt-get update warns and still installs", env: with("FAKE_UPDATE_OK", "0"),
			want: []string{update, pkgs, dlAMD64}, warning: warnUpd},
		{name: "a failed package install does not stop the install", env: with("FAKE_PKGS_OK", "0"),
			want: []string{pkgs, dlAMD64}},
		{name: "a failed mount-s3 download warns", env: with("FAKE_DOWNLOAD_OK", "0"),
			want: []string{pkgs, dlAMD64}, never: []string{debStep}, warning: warnDL},
		{name: "a failed mount-s3 install warns", env: with("FAKE_DEB_OK", "0"),
			want: []string{dlAMD64, debStep}, warning: warnDeb},
		{name: "a Linux host without apt-get warns and installs nothing", env: ok, noAptGet: true,
			never: []string{"apt-get", "curl_download"}, warning: warnApt},
		{name: "macOS skips the mount tools", env: with("FAKE_OS", "Darwin"),
			never: []string{"apt-get", "curl_download"}, warning: skipDarw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := mountToolStubs + fn
			if !tc.noAptGet {
				script += fakeAptGet
			}
			if tc.mountS3 {
				script += "mount-s3() { :; }\n"
			}
			script += "install_mount_tools\necho DONE\n"
			calls, stdout, stderr := runInstallSh(t, script, tc.env)
			if !strings.Contains(stdout, "DONE") {
				t.Fatalf("the install did not continue past install_mount_tools; stdout: %s", stdout)
			}
			joined := strings.Join(calls, "\n")
			at := 0
			for _, w := range tc.want {
				i := strings.Index(joined[at:], w)
				if i < 0 {
					t.Fatalf("want %q after offset %d, in order %q; calls:\n%s", w, at, tc.want, joined)
				}
				at += i + len(w)
			}
			for _, n := range tc.never {
				if strings.Contains(joined, n) {
					t.Errorf("unexpected call %q; calls:\n%s", n, joined)
				}
			}
			if tc.warning != "" && !strings.Contains(stderr, tc.warning) {
				t.Errorf("stderr lacks %q:\n%s", tc.warning, stderr)
			}
			if tc.warning == "" && strings.Contains(stderr, "Warning") {
				t.Errorf("unexpected warning:\n%s", stderr)
			}
		})
	}
}

// The non-local install must do exactly what it did before the extraction:
// one apt-get update, the base packages, the mount tools, then Docker. The
// sequence below is what main's inline block produced under the same stubs.
func TestInstallPackagesStillInstallsMountToolsInOrder(t *testing.T) {
	src := installShSource(t)
	funcs := installShFunction(t, src, "install_mount_tools") + installShFunction(t, src, "install_packages")
	script := mountToolStubs + fakeAptGet + funcs +
		"drop_caddy_apt_source() { echo drop_caddy_apt_source >>\"$LOG\"; }\n" +
		"ensure_docker() { echo ensure_docker >>\"$LOG\"; }\n" +
		"install_caddy_package() { echo install_caddy_package >>\"$LOG\"; }\n" +
		"install_packages\necho DONE\n"
	calls, stdout, _ := runInstallSh(t, script, map[string]string{
		"FAKE_OS": "Linux", "FAKE_ARCH": "x86_64", "APT_UPDATED": "false", "BUILD_FROM_SOURCE": "false",
		"FAKE_UPDATE_OK": "1", "FAKE_PKGS_OK": "1", "FAKE_DEB_OK": "1", "FAKE_DOWNLOAD_OK": "1",
	})
	if !strings.Contains(stdout, "DONE") {
		t.Fatalf("install_packages did not finish; stdout: %s", stdout)
	}
	want := []string{
		"drop_caddy_apt_source",
		"apt-get update",
		"apt-get install -y build-essential ca-certificates curl gnupg lsb-release software-properties-common",
		"apt-get install -y fuse3 sshfs nfs-common rclone",
		"curl_download https://s3.amazonaws.com/mountpoint-s3-release/latest/x86_64/mount-s3.deb -o /fake-tmp/mount-s3.deb",
		"apt-get install -y /fake-tmp/mount-s3.deb",
		"rm -f /fake-tmp/mount-s3.deb",
		"ensure_docker",
		"install_caddy_package",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("install_packages calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
}

// The --local branch must run install_mount_tools on Linux, before Docker as
// install_packages does, and a macOS --local run must leave through
// install_darwin_local before it. The branch runs with every step stubbed;
// $EUID is read-only in bash, so the root check reads a stand-in.
func TestLocalInstallRunsMountToolsOnLinuxOnly(t *testing.T) {
	branch := localModeBranch(t, installShSource(t))
	if !strings.Contains(branch, "$EUID") {
		t.Fatal("the --local branch no longer checks for root; update this test's stand-in")
	}
	branch = strings.ReplaceAll(branch, "$EUID", "$FAKE_EUID")
	steps := []string{"install_darwin_local", "install_binaries", "record_sandboxd_state", "write_local_environment",
		"install_mount_tools", "ensure_docker", "write_local_systemd_unit", "write_egress_gateway_units",
		"write_healthcheck_script", "write_healthcheck_units", "restart_sandboxd_if_reconfigured", "systemctl"}
	stubs := "uname() { echo \"$FAKE_OS\"; }\n"
	for _, s := range steps {
		stubs += s + "() { echo \"" + s + " $*\" >>\"$LOG\"; }\n"
	}
	cases := []struct {
		os    string
		want  []string
		never []string
	}{
		{os: "Linux", want: []string{"install_binaries", "write_local_environment", "install_mount_tools", "ensure_docker",
			"write_local_systemd_unit", "systemctl enable --now sandboxd"}, never: []string{"install_darwin_local"}},
		{os: "Darwin", want: []string{"install_darwin_local"}, never: []string{"install_mount_tools", "ensure_docker", "install_binaries"}},
	}
	for _, tc := range cases {
		t.Run(tc.os, func(t *testing.T) {
			calls, _, _ := runInstallSh(t, stubs+branch, map[string]string{
				"FAKE_OS": tc.os, "FAKE_EUID": "0", "LOCAL_MODE": "true", "DOMAIN": "", "DNS_PROVIDER": "", "PAT_TOKEN": "t",
			})
			joined := strings.Join(calls, "\n")
			at := 0
			for _, w := range tc.want {
				i := strings.Index(joined[at:], w)
				if i < 0 {
					t.Fatalf("want %q after offset %d, in order %q; calls:\n%s", w, at, tc.want, joined)
				}
				at += i + len(w)
			}
			for _, n := range tc.never {
				if strings.Contains(joined, n) {
					t.Errorf("unexpected call %q; calls:\n%s", n, joined)
				}
			}
		})
	}
}

// The mount packages live in install_mount_tools alone. A copy left in
// install_packages would let the --local path drift from the server path
// again.
func TestMountPackagesLiveOnlyInInstallMountTools(t *testing.T) {
	src := installShSource(t)
	pkgs := installShFunction(t, src, "install_packages")
	if !strings.Contains(pkgs, "\t\tinstall_mount_tools\n\t\tensure_docker\n") {
		t.Error("install_packages must call install_mount_tools right before ensure_docker, where the inline block was")
	}
	for _, tool := range []string{"fuse3", "sshfs", "nfs-common", "rclone", "mount-s3", "mountpoint-s3"} {
		if strings.Contains(pkgs, tool) {
			t.Errorf("install_packages still names %q; the mount tools belong in install_mount_tools", tool)
		}
	}
	tools := installShFunction(t, src, "install_mount_tools")
	for _, want := range []string{"apt-get install -y fuse3 sshfs nfs-common rclone || true", "mountpoint-s3-release/latest/${arch_suffix}/mount-s3.deb"} {
		if !strings.Contains(tools, want) {
			t.Errorf("install_mount_tools is missing %q", want)
		}
	}
	if !strings.Contains(localModeBranch(t, src), "\tinstall_mount_tools\n") {
		t.Error("the --local branch does not call install_mount_tools")
	}
}
