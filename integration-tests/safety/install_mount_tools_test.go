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
// in install_mount_tools, which both Linux install paths call. It also turns
// off the rpcbind that nfs-common brings in, which otherwise listens on port
// 111 on every address. These tests run install.sh's real functions with
// apt-get, dpkg-query, systemctl, uname, curl and the rest replaced by bash
// functions, and PATH pointed at an empty directory so no real program on
// the test machine is reached.

// installShSource is install.sh as it is on this branch.
func installShSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// installShFunction returns the source of install.sh's top-level functions
// names, cut the way pkg/caddy's installShFunctions cuts them: a function
// runs to the next top-level function definition.
func installShFunction(t *testing.T, src string, names ...string) string {
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

// mountToolFuncs is install_mount_tools and the helper it calls.
func mountToolFuncs(t *testing.T, src string) string {
	t.Helper()
	return installShFunction(t, src, "rpcbind_on_host", "install_mount_tools")
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
// dpkg-query reports rpcbind installed when it was there before the run
// (FAKE_RPCBIND_BEFORE) or the stubbed nfs-common install brought it in.
const mountToolStubs = `
uname() { case "$1" in -s) echo "$FAKE_OS" ;; -m) echo "$FAKE_ARCH" ;; esac; }
mktemp() { echo /fake-tmp/mount-s3.deb; }
rm() { echo "rm $*" >>"$LOG"; }
curl_download() { echo "curl_download $*" >>"$LOG"; [[ "$FAKE_DOWNLOAD_OK" == 1 ]]; }
dpkg-query() {
	echo "dpkg-query $*" >>"$LOG"
	if [[ "$FAKE_RPCBIND_BEFORE" == 1 || -e "$RPCBIND_MARK" ]]; then printf 'install ok installed'; fi
}
`

// fakeAptGet answers like apt-get: FAKE_UPDATE_OK, FAKE_PKGS_OK and
// FAKE_DEB_OK fail one call each. Defined only when the host "has" apt-get.
// A successful nfs-common install brings rpcbind in, as on Ubuntu.
const fakeAptGet = `
apt-get() {
	echo "apt-get $*" >>"$LOG"
	case "$*" in
		update) [[ "$FAKE_UPDATE_OK" == 1 ]] ;;
		"install -y fuse3 sshfs nfs-common rclone") [[ "$FAKE_PKGS_OK" == 1 ]] && : >"$RPCBIND_MARK" ;;
		*mount-s3.deb) [[ "$FAKE_DEB_OK" == 1 ]] ;;
		*) return 0 ;;
	esac
}
`

// fakeRPCSystemctl answers is-enabled with FAKE_RPCBIND_ENABLED (an rpcbind
// unit enabled before the run) and disable with FAKE_DISABLE_OK. Defined
// only when the host "has" systemctl.
const fakeRPCSystemctl = `
systemctl() {
	echo "systemctl $*" >>"$LOG"
	case "$1" in
		is-enabled) [[ "$FAKE_RPCBIND_ENABLED" == 1 ]] ;;
		disable) [[ "$FAKE_DISABLE_OK" == 1 ]] ;;
		*) return 0 ;;
	esac
}
`

// serverPathStubs stand in for the rest of install_packages.
const serverPathStubs = `
drop_caddy_apt_source() { echo drop_caddy_apt_source >>"$LOG"; }
ensure_docker() { echo ensure_docker >>"$LOG"; }
install_caddy_package() { echo install_caddy_package >>"$LOG"; }
`

// mountToolEnv is a Linux x86_64 host where every step works, the apt index
// is not refreshed yet (the --local path) and rpcbind is not there yet. kv
// overrides it.
func mountToolEnv(kv ...string) map[string]string {
	m := map[string]string{"FAKE_OS": "Linux", "FAKE_ARCH": "x86_64", "APT_UPDATED": "false", "BUILD_FROM_SOURCE": "false",
		"FAKE_UPDATE_OK": "1", "FAKE_PKGS_OK": "1", "FAKE_DEB_OK": "1", "FAKE_DOWNLOAD_OK": "1",
		"FAKE_RPCBIND_BEFORE": "0", "FAKE_RPCBIND_ENABLED": "0", "FAKE_DISABLE_OK": "1"}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

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
	vars := "set -euo pipefail\nPATH='" + empty + "'\nLOG='" + log + "'\nRPCBIND_MARK='" + filepath.Join(dir, "rpcbind-installed") + "'\n"
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

// checkCalls fails unless want appears in calls in this order and nothing in
// never appears at all.
func checkCalls(t *testing.T, calls, want, never []string) {
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

func TestInstallMountToolsInstallsOrWarns(t *testing.T) {
	fn := mountToolFuncs(t, installShSource(t))

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
	ok := mountToolEnv()
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
		{name: "after install_packages: the index is fresh, so no second update", env: mountToolEnv("APT_UPDATED", "true"),
			want: []string{pkgs, dlAMD64}, never: []string{update}},
		{name: "arm64 fetches the arm64 mount-s3", env: mountToolEnv("FAKE_ARCH", "aarch64"),
			want: []string{update, pkgs, dlARM64}},
		{name: "mount-s3 already installed is not fetched again", env: ok, mountS3: true,
			want: []string{update, pkgs}, never: []string{"curl_download"}},
		{name: "no mount-s3 build for the architecture: no fetch, as before", env: mountToolEnv("FAKE_ARCH", "armv7l"),
			want: []string{update, pkgs}, never: []string{"curl_download"}},
		{name: "a failed apt-get update warns and still installs", env: mountToolEnv("FAKE_UPDATE_OK", "0"),
			want: []string{update, pkgs, dlAMD64}, warning: warnUpd},
		{name: "a failed package install does not stop the install", env: mountToolEnv("FAKE_PKGS_OK", "0"),
			want: []string{pkgs, dlAMD64}},
		{name: "a failed mount-s3 download warns", env: mountToolEnv("FAKE_DOWNLOAD_OK", "0"),
			want: []string{pkgs, dlAMD64}, never: []string{debStep}, warning: warnDL},
		{name: "a failed mount-s3 install warns", env: mountToolEnv("FAKE_DEB_OK", "0"),
			want: []string{dlAMD64, debStep}, warning: warnDeb},
		{name: "a Linux host without apt-get warns and installs nothing", env: ok, noAptGet: true,
			never: []string{"apt-get", "curl_download", "systemctl"}, warning: warnApt},
		{name: "macOS skips the mount tools", env: mountToolEnv("FAKE_OS", "Darwin"),
			never: []string{"apt-get", "curl_download", "systemctl"}, warning: skipDarw},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := mountToolStubs + fakeRPCSystemctl + fn
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
			checkCalls(t, calls, tc.want, tc.never)
			if tc.warning != "" && !strings.Contains(stderr, tc.warning) {
				t.Errorf("stderr lacks %q:\n%s", tc.warning, stderr)
			}
			if tc.warning == "" && strings.Contains(stderr, "Warning") {
				t.Errorf("unexpected warning:\n%s", stderr)
			}
		})
	}
}

// nfs-common pulls in rpcbind, whose package enables and starts it on port
// 111 on every address. install_mount_tools disables both units when this
// run brought rpcbind in, and leaves an rpcbind that was there before alone.
// It never masks: rpc-statd.service Requires=rpcbind.socket, so a mask would
// fail every NFSv3 mount that locks. Every case runs through both entry
// points: the --local branch's direct call, and install_packages.
func TestInstallMountToolsDisablesOnlyANewRpcbind(t *testing.T) {
	src := installShSource(t)
	fn := mountToolFuncs(t, src)
	pkgsFn := installShFunction(t, src, "install_packages")

	const (
		checkBefore = "dpkg-query -W -f=${Status} rpcbind"
		pkgs        = "apt-get install -y fuse3 sshfs nfs-common rclone"
		disable     = "systemctl disable --now rpcbind.socket rpcbind.service"
	)
	cases := []struct {
		name        string
		env         map[string]string
		noSystemctl bool
		want, never []string
		message     string // on stderr
		warning     bool   // message is a warning
	}{
		{name: "fresh host: both units disabled, never masked", env: mountToolEnv(),
			want: []string{checkBefore, "systemctl is-enabled --quiet rpcbind.socket", "systemctl is-enabled --quiet rpcbind.service", pkgs, disable}},
		{name: "rpcbind package installed before: left alone", env: mountToolEnv("FAKE_RPCBIND_BEFORE", "1"),
			want: []string{checkBefore, pkgs}, never: []string{"systemctl disable"},
			message: "rpcbind was on this host before this run; leaving it as it is"},
		{name: "an rpcbind unit enabled before: left alone", env: mountToolEnv("FAKE_RPCBIND_ENABLED", "1"),
			want: []string{"systemctl is-enabled --quiet rpcbind.socket", pkgs}, never: []string{"systemctl disable"},
			message: "rpcbind was on this host before this run; leaving it as it is"},
		{name: "no systemctl: skipped with a message", env: mountToolEnv(), noSystemctl: true,
			want: []string{checkBefore, pkgs}, never: []string{"systemctl"},
			message: "Skipping the rpcbind disable: no systemctl on this host"},
		{name: "a failed disable warns and the install continues", env: mountToolEnv("FAKE_DISABLE_OK", "0"),
			want:    []string{pkgs, disable},
			message: "Warning: could not disable rpcbind, so it may listen on port 111; run: systemctl disable --now rpcbind.socket rpcbind.service", warning: true},
		{name: "nfs-common did not install: nothing to disable", env: mountToolEnv("FAKE_PKGS_OK", "0"),
			want: []string{pkgs}, never: []string{"systemctl disable"}},
	}
	paths := []struct {
		name, run string
		extraWant []string
	}{
		{name: "local", run: "install_mount_tools\n"},
		{name: "server", run: serverPathStubs + pkgsFn + "install_packages\n",
			extraWant: []string{"ensure_docker", "install_caddy_package"}},
	}
	for _, tc := range cases {
		for _, p := range paths {
			t.Run(tc.name+"/"+p.name, func(t *testing.T) {
				script := mountToolStubs + fakeAptGet + fn
				if !tc.noSystemctl {
					script += fakeRPCSystemctl
				}
				script += p.run + "echo DONE\n"
				calls, stdout, stderr := runInstallSh(t, script, tc.env)
				if !strings.Contains(stdout, "DONE") {
					t.Fatalf("the install did not continue; stdout: %s", stdout)
				}
				checkCalls(t, calls, append(append([]string{}, tc.want...), p.extraWant...), append([]string{"mask"}, tc.never...))
				if n := strings.Count(strings.Join(calls, "\n"), disable); n > 1 {
					t.Errorf("rpcbind disabled %d times, want at most once", n)
				}
				if tc.message != "" && !strings.Contains(stderr, tc.message) {
					t.Errorf("stderr lacks %q:\n%s", tc.message, stderr)
				}
				if !tc.warning && strings.Contains(stderr, "Warning") {
					t.Errorf("unexpected warning:\n%s", stderr)
				}
			})
		}
	}
}

// The non-local install must do what it did before the extraction, plus the
// rpcbind check and disable around the package install: one apt-get update,
// the base packages, the mount tools, then Docker. Without the dpkg-query,
// is-enabled and disable lines, the sequence below is exactly what main's
// inline block produced under the same stubs.
func TestInstallPackagesStillInstallsMountToolsInOrder(t *testing.T) {
	src := installShSource(t)
	script := mountToolStubs + fakeAptGet + fakeRPCSystemctl + serverPathStubs +
		mountToolFuncs(t, src) + installShFunction(t, src, "install_packages") +
		"install_packages\necho DONE\n"
	calls, stdout, _ := runInstallSh(t, script, mountToolEnv())
	if !strings.Contains(stdout, "DONE") {
		t.Fatalf("install_packages did not finish; stdout: %s", stdout)
	}
	want := []string{
		"drop_caddy_apt_source",
		"apt-get update",
		"apt-get install -y build-essential ca-certificates curl gnupg lsb-release software-properties-common",
		"dpkg-query -W -f=${Status} rpcbind",
		"systemctl is-enabled --quiet rpcbind.socket",
		"systemctl is-enabled --quiet rpcbind.service",
		"apt-get install -y fuse3 sshfs nfs-common rclone",
		"dpkg-query -W -f=${Status} rpcbind",
		"systemctl disable --now rpcbind.socket rpcbind.service",
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
// install_packages does, which also disables the rpcbind it brought in. A
// macOS --local run must leave through install_darwin_local before it. The
// branch runs with the real install_mount_tools and every other step
// stubbed; $EUID is read-only in bash, so the root check reads a stand-in.
func TestLocalInstallRunsMountToolsOnLinuxOnly(t *testing.T) {
	src := installShSource(t)
	branch := localModeBranch(t, src)
	if !strings.Contains(branch, "$EUID") {
		t.Fatal("the --local branch no longer checks for root; update this test's stand-in")
	}
	branch = strings.ReplaceAll(branch, "$EUID", "$FAKE_EUID")
	steps := []string{"install_darwin_local", "install_binaries", "record_sandboxd_state", "write_local_environment",
		"ensure_docker", "write_local_systemd_unit", "write_egress_gateway_units",
		"write_healthcheck_script", "write_healthcheck_units", "restart_sandboxd_if_reconfigured"}
	stubs := mountToolStubs + fakeAptGet + fakeRPCSystemctl + mountToolFuncs(t, src)
	for _, s := range steps {
		stubs += s + "() { echo \"" + s + " $*\" >>\"$LOG\"; }\n"
	}
	cases := []struct {
		os    string
		want  []string
		never []string
	}{
		{os: "Linux", want: []string{"install_binaries", "write_local_environment",
			"apt-get update", "apt-get install -y fuse3 sshfs nfs-common rclone", "systemctl disable --now rpcbind.socket rpcbind.service",
			"ensure_docker", "write_local_systemd_unit", "systemctl enable --now sandboxd"},
			never: []string{"install_darwin_local", "mask"}},
		{os: "Darwin", want: []string{"install_darwin_local"},
			never: []string{"apt-get", "systemctl", "ensure_docker", "install_binaries"}},
	}
	for _, tc := range cases {
		t.Run(tc.os, func(t *testing.T) {
			calls, _, _ := runInstallSh(t, stubs+branch, mountToolEnv(
				"FAKE_OS", tc.os, "FAKE_EUID", "0", "LOCAL_MODE", "true", "DOMAIN", "", "DNS_PROVIDER", "", "PAT_TOKEN", "t"))
			checkCalls(t, calls, tc.want, tc.never)
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
	for _, tool := range []string{"fuse3", "sshfs", "nfs-common", "rclone", "mount-s3", "mountpoint-s3", "rpcbind"} {
		if strings.Contains(pkgs, tool) {
			t.Errorf("install_packages still names %q; the mount tools belong in install_mount_tools", tool)
		}
	}
	tools := installShFunction(t, src, "install_mount_tools")
	for _, want := range []string{"apt-get install -y fuse3 sshfs nfs-common rclone || true", "mountpoint-s3-release/latest/${arch_suffix}/mount-s3.deb",
		"systemctl disable --now rpcbind.socket rpcbind.service"} {
		if !strings.Contains(tools, want) {
			t.Errorf("install_mount_tools is missing %q", want)
		}
	}
	if strings.Contains(tools, "systemctl mask") {
		t.Error("install_mount_tools masks rpcbind; a mask fails every NFSv3 mount that locks")
	}
	if !strings.Contains(localModeBranch(t, src), "\tinstall_mount_tools\n") {
		t.Error("the --local branch does not call install_mount_tools")
	}
}
