package caddy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// install.sh --privilege-mode (plans/security-gaps-m1-m4.md M1 PR 10).
// These run the whole install.sh on the rig's fake machine: split writes
// the two units with the plan's hardening, the helper's settings and the
// drop-ins, and installs the helper only through the new sandboxd's
// signature check; single writes exactly what it did before; a re-run
// changes nothing; --privilege-mode single goes back.

// singleUnit is sandboxd.service as install.sh wrote it before privilege
// mode existed (origin/main at f4e97b0b2), with PREFIX for the install
// prefix. Single mode must write exactly this.
const singleUnit = `[Unit]
Description=AerolVM daemon
After=docker.service caddy.service network-online.target
Wants=network-online.target
Requires=docker.service
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
EnvironmentFile=/etc/sandboxd/sandboxd.env
ExecStartPre=/bin/mkdir -p /var/lib/sandboxd/mounts /run/sandboxd
ExecStartPre=/bin/chmod 0700 /var/lib/sandboxd/mounts /run/sandboxd
ExecStart=PREFIX/sandboxd
# MountFlags=shared lets bind-mounts created by sandboxd (FUSE mounts under
# /var/lib/sandboxd/mounts/<id>/) propagate into the Docker daemon's view
# so containers actually see the storage. Without this some configurations
# leave the daemon with a private mount namespace and the bind appears empty.
MountFlags=shared
Restart=always
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30
# Stopping sandboxd stops what runs in its cgroup. Firecracker VMs are not
# there: sandboxd moves each into the aerolvm-vmm cgroup, so a restart or an
# upgrade leaves them running and the next sandboxd takes them over.
KillMode=control-group

[Install]
WantedBy=multi-user.target
`

// singleGatewaySocket is the egress gateway's socket unit before privilege
// mode existed; split changes it only with a drop-in.
const singleGatewaySocket = `[Unit]
Description=AerolVM egress gateway control socket

[Socket]
ListenStream=/run/aerolvm/egress-gateway.sock
SocketUser=root
SocketGroup=root
SocketMode=0600
DirectoryMode=0755

[Install]
WantedBy=sockets.target
`

// fakeSplitSandboxd is the release's new sandboxd: `upgrade root-helper`
// stands in for the signature check (tested in internal/nodeupgrade) and
// copies the staged helper into --dir, or refuses it with ROOTD_REFUSE.
const fakeSplitSandboxd = `#!/usr/bin/env bash
echo "sandboxd $*" >>"$LOG"
if [[ "${1:-} ${2:-}" == "upgrade root-helper" ]]; then
	from="" dir="" prev=""
	for a in "$@"; do
		[[ "$prev" == "--from" ]] && from="$a"
		[[ "$prev" == "--dir" ]] && dir="$a"
		prev="$a"
	done
	if [[ -n "${ROOTD_REFUSE:-}" ]]; then
		echo "sandboxd upgrade root-helper: root helper: staged root helper refused ($ROOTD_REFUSE): no" >&2
		exit 1
	fi
	for f in aerolvm-rootd aerolvm-rootd.manifest aerolvm-rootd.sig; do
		[[ -f "$from/$f" ]] || { echo "no $f staged" >&2; exit 1; }
	done
	if cmp -s "$from/aerolvm-rootd" "$dir/aerolvm-rootd" 2>/dev/null; then
		echo "root helper v0.7.8 is already installed in $dir"
		exit 0
	fi
	mkdir -p "$dir"
	cp "$from/aerolvm-rootd" "$from/aerolvm-rootd.manifest" "$from/aerolvm-rootd.sig" "$dir/"
	echo "installed root helper v0.7.8 (API 3) in $dir; signature checked"
	exit 0
fi
echo "SANDBOXD RAN $*" >>"$LOG"
`

// splitRelease writes a release with the signed helper's three files and
// returns the flags that point install.sh at it.
func (r *runRig) splitRelease(helper string) []string {
	r.t.Helper()
	files := map[string]string{
		"sandboxd_linux_amd64":               fakeSplitSandboxd,
		"toolboxd_linux_amd64":               "new toolboxd\n",
		"aerolvm-rootd_linux_amd64":          helper,
		"aerolvm-rootd_linux_amd64.manifest": "{\"kind\":\"aerolvm-rootd\"}\n",
		"aerolvm-rootd_linux_amd64.sig":      "c2ln\n",
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, n := range names {
		r.write("rel/"+n, files[n], 0o755)
		fmt.Fprintf(&sums, "%s  %s\n", sha256Hex([]byte(files[n])), n)
	}
	r.write("rel/checksums.txt", sums.String(), 0o644)
	rel := "file://" + r.path("rel")
	return []string{"--sandboxd-url", rel + "/sandboxd_linux_amd64", "--toolboxd-url", rel + "/toolboxd_linux_amd64",
		"--checksums-url", rel + "/checksums.txt", "--caddy-binary-url", rel + "/toolboxd_linux_amd64",
		"--install-prefix", r.path("bin"), "--public-host", "203.0.113.9"}
}

// stubEngineSteps replaces the steps of --with-containerd-engine that
// download (CNI plugins, BuildKit; tested in integration-tests/safety) and
// find, whose chowns a test cannot make, with ones that log.
func (r *runRig) stubEngineSteps() {
	r.t.Helper()
	raw, err := os.ReadFile(r.script)
	if err != nil {
		r.t.Fatal(err)
	}
	const mainFlow = "\nif [[ \"$CONFIG_ONLY\" == \"true\" ]]; then\n\tif [[ $FAKE_EUID -ne 0 ]]; then\n"
	stubs := `install_cni_plugins() { echo "install_cni_plugins" >>"$LOG"; }
install_buildkit() { echo "install_buildkit rootless=$BUILDKIT_ROOTLESS mode=$PRIVILEGE_MODE" >>"$LOG"; }
find() { echo "find $*" >>"$LOG"; }
`
	src := strings.Replace(string(raw), mainFlow, "\n"+stubs+mainFlow, 1)
	if src == string(raw) {
		r.t.Fatal("could not stub the engine steps")
	}
	if err := os.WriteFile(r.script, []byte(src), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

func lines(s string) map[string]bool {
	out := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		out[l] = true
	}
	return out
}

func TestInstallPrivilegeModeSplit(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	args := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split")
	out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), args...)
	if err != nil {
		t.Fatalf("install.sh: %v\n%s\ncalls:\n%s", err, out, r.calls())
	}
	prefix, rootdDir := r.path("bin"), r.path("rootd-bin")

	// sandboxd.service: every line of the plan's hardening, after and with
	// the helper, and nothing of single's Docker or mount sharing.
	unit := r.read("systemd/system/sandboxd.service")
	got := lines(unit)
	for _, want := range []string{
		"Description=AerolVM daemon (privilege mode split)",
		"After=aerolvm-rootd.service containerd.service caddy.service network-online.target",
		"Requires=aerolvm-rootd.service",
		"User=sandboxd",
		"Group=sandboxd",
		"SupplementaryGroups=aerolvm aerolvm-wasm",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"ReadWritePaths=" + r.path("varlib") + " -/run/aerolvm-procid -" + r.path("sandboxd") + "/tls -" + r.path("sandboxd") + "/cluster-ca",
		"RuntimeDirectory=sandboxd",
		"RuntimeDirectoryMode=0700",
		"RuntimeDirectoryPreserve=yes",
		"ExecStartPre=-+" + prefix + "/sandboxd upgrade recover --env-file " + r.path("sandboxd") + "/sandboxd.env",
		"ExecStartPre=+" + rootdDir + "/aerolvm-rootd agent-folders --user sandboxd",
		"ExecStartPre=+/usr/bin/install -d -m 0755 -o sandboxd -g sandboxd /run/aerolvm-procid",
		"ExecStart=" + prefix + "/sandboxd",
		"Restart=always",
		"KillMode=control-group",
	} {
		if !got[want] {
			t.Errorf("split sandboxd.service has no line %q:\n%s", want, unit)
		}
	}
	for _, never := range []string{"Requires=docker.service", "MountFlags=shared"} {
		if got[never] {
			t.Errorf("split sandboxd.service has %q", never)
		}
	}

	// The helper's unit: root, before sandboxd, restarted at once.
	rootd := r.read("systemd/system/aerolvm-rootd.service")
	got = lines(rootd)
	for _, want := range []string{
		"Description=AerolVM root helper (aerolvm-rootd)",
		"Before=sandboxd.service",
		"EnvironmentFile=" + r.path("sandboxd") + "/sandboxd.env",
		"EnvironmentFile=-" + r.path("sandboxd") + "/cluster.env",
		"EnvironmentFile=" + r.path("sandboxd") + "/rootd.env",
		"ExecStart=" + rootdDir + "/aerolvm-rootd",
		"Restart=always",
	} {
		if !got[want] {
			t.Errorf("aerolvm-rootd.service has no line %q:\n%s", want, rootd)
		}
	}
	if strings.Contains(rootd, "User=") {
		t.Errorf("the helper runs as root, but its unit names a user:\n%s", rootd)
	}

	// The helper's own settings: root's file.
	env := r.read("sandboxd/rootd.env")
	for _, want := range []string{"SB_ROOTD_AGENT_UID=990", "SB_ROOTD_AGENT_CGROUP=sandboxd.service", "SB_ROOTD_SOCKET_GROUP=aerolvm", "SB_ROOTD_MOUNT_USER=aerolvm-mounts"} {
		if !lines(env)[want] {
			t.Errorf("rootd.env has no %q:\n%s", want, env)
		}
	}
	if st, err := os.Stat(r.path("sandboxd/rootd.env")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("rootd.env mode: %v %v", st.Mode(), err)
	}
	sbEnv := r.read("sandboxd/sandboxd.env")
	for _, want := range []string{"SB_PRIVILEGE_MODE=split", "SB_DOCKER_ENABLED=false", "SB_REMOTE_UPGRADE=false",
		"SB_UPGRADE_STATE_DIR=" + r.path("upgrade-root"), "SB_ROOTD_SOCKET=/run/aerolvm-rootd/sock/root.sock",
		"SB_ROOTD_BIN_DIR=" + rootdDir, "SB_EGRESS_PROCID_SOCKET=/run/aerolvm-procid/egress-procid.sock",
		"SB_CONTAINERD_BUILDKIT_ROOTLESS=true", "SB_CONTAINER_ENGINE=containerd"} {
		if !lines(sbEnv)[want] {
			t.Errorf("sandboxd.env has no %q", want)
		}
	}
	nodeJSON := r.read("sandboxd/node.json")
	for _, want := range []string{`"privilege_mode": "split"`, `"buildkit_rootless": true`} {
		if !strings.Contains(nodeJSON, want) {
			t.Errorf("node.json has no %s:\n%s", want, nodeJSON)
		}
	}

	// The egress gateway: its units as before, plus split's drop-ins.
	if got := r.read("systemd/system/aerolvm-egress-gateway.socket"); got != singleGatewaySocket {
		t.Errorf("the gateway's socket unit changed:\n%s", got)
	}
	if got := r.read("systemd/system/aerolvm-egress-gateway.socket.d/privilege-split.conf"); !lines(got)["SocketUser=sandboxd"] || !lines(got)["SocketGroup=sandboxd"] {
		t.Errorf("socket drop-in:\n%s", got)
	}
	if got := r.read("systemd/system/aerolvm-egress-gateway.service.d/privilege-split.conf"); !lines(got)["Environment=SB_EGRESS_PEER_UIDS=990"] {
		t.Errorf("gateway drop-in:\n%s", got)
	}

	// The helper came through the new sandboxd's check, from a folder of
	// root's, and runs before sandboxd starts.
	if got := r.read("rootd-bin/aerolvm-rootd"); got != "helper v0.7.8\n" {
		t.Errorf("helper %q", got)
	}
	calls := r.calls()
	r.mustCall(calls, "sandboxd upgrade root-helper --from ", "--dir "+rootdDir)
	r.inOrder(calls, "install_buildkit rootless=true mode=split", "sandboxd upgrade root-helper",
		"systemctl daemon-reload", "systemctl enable --now aerolvm-rootd", "systemctl enable --now caddy sandboxd")
	if !strings.Contains(out, "installed root helper v0.7.8") {
		t.Errorf("output:\n%s", out)
	}

	// A re-run with no flags: the saved split node, nothing changed, so
	// nothing restarts.
	r.resetLog()
	out, err = r.run(r.env("SANDBOXD_ACTIVE=true"), r.splitRelease("helper v0.7.8\n")...)
	if err != nil {
		t.Fatalf("re-run: %v\n%s", err, out)
	}
	calls = r.calls()
	for _, never := range []string{"systemctl restart aerolvm-rootd", "systemctl restart sandboxd", "systemctl stop sandboxd", "useradd"} {
		if strings.Contains(calls, never) {
			t.Errorf("the re-run did %q; calls:\n%s", never, calls)
		}
	}
	if r.read("systemd/system/sandboxd.service") != unit {
		t.Error("the re-run changed sandboxd.service")
	}

	// A new helper: installed through the check, and the running helper
	// restarts onto it.
	r.resetLog()
	if out, err = r.run(r.env("SANDBOXD_ACTIVE=true"), r.splitRelease("helper v0.7.9\n")...); err != nil {
		t.Fatalf("re-run with a new helper: %v\n%s", err, out)
	}
	r.mustCall(r.calls(), "systemctl restart aerolvm-rootd")

	// A helper that fails its check: nothing installed, the run stops.
	r.resetLog()
	out, err = r.run(r.env("SANDBOXD_ACTIVE=true", "ROOTD_REFUSE=bad_signature"), r.splitRelease("helper evil\n")...)
	if err == nil || !strings.Contains(out, "failed its signature check") {
		t.Fatalf("a refused helper: err %v\n%s", err, out)
	}
	if got := r.read("rootd-bin/aerolvm-rootd"); got != "helper v0.7.9\n" {
		t.Errorf("the refused helper replaced the installed one: %q", got)
	}
	// One older than the installed helper: kept, with a warning.
	out, err = r.run(r.env("SANDBOXD_ACTIVE=true", "ROOTD_REFUSE=older"), r.splitRelease("helper v0.7.7\n")...)
	if err != nil || !strings.Contains(out, "keeping the newer root helper") {
		t.Fatalf("an older helper: err %v\n%s", err, out)
	}

	// Back to single: today's unit, byte for byte; the helper and its
	// drop-ins gone; sandboxd's files back to root. What the root sandboxd
	// would act on by path at its first boot, and sandboxd's user could
	// write in split, goes first: a record planted in single mode's
	// upgrade folder, the runtime folders, every link.
	r.write("varlib/upgrade/planted.json", "{}", 0o600)
	r.resetLog()
	out, err = r.run(r.env("SANDBOXD_ACTIVE=true"), append(r.splitRelease("helper v0.7.9\n"), "--privilege-mode", "single")...)
	if err != nil {
		t.Fatalf("switch back: %v\n%s", err, out)
	}
	if got, want := r.read("systemd/system/sandboxd.service"), strings.ReplaceAll(strings.NewReplacer("/etc/sandboxd", r.path("sandboxd"),
		"/var/lib/sandboxd", r.path("varlib"), "/run/sandboxd", r.path("run")).Replace(singleUnit), "PREFIX", prefix); got != want {
		t.Errorf("single sandboxd.service after the switch back:\n%s\nwant:\n%s", got, want)
	}
	for _, gone := range []string{"systemd/system/aerolvm-rootd.service", "sandboxd/rootd.env",
		"systemd/system/aerolvm-egress-gateway.socket.d/privilege-split.conf", "systemd/system/aerolvm-egress-gateway.service.d/privilege-split.conf"} {
		if _, err := os.Stat(r.path(gone)); err == nil {
			t.Errorf("%s is still there after the switch back", gone)
		}
	}
	calls = r.calls()
	r.inOrder(calls, "systemctl stop sandboxd", "find "+r.path("varlib/upgrade")+" -xdev -delete",
		"find "+r.path("run")+" -xdev -delete", "find "+r.path("varlib")+" -xdev -type l -delete",
		"find "+r.path("varlib")+" -xdev -uid 990 -exec chown -h root {} +",
		"systemctl disable --now aerolvm-rootd.service", "systemctl daemon-reload", "systemctl restart sandboxd")
	if !strings.Contains(r.read("sandboxd/sandboxd.env"), "SB_CONTAINERD_BUILDKIT_ROOTLESS=true") || strings.Contains(r.read("sandboxd/sandboxd.env"), "SB_PRIVILEGE_MODE") {
		t.Errorf("sandboxd.env after the switch back:\n%s", r.read("sandboxd/sandboxd.env"))
	}
}

// The whole script, on a split node: --config-only refuses to render single
// and writes nothing; a switch back stopped after sandboxd.env said single
// (the marker still there) is finished by the next --privilege-mode single
// run, warning included; after that --config-only renders single.
func TestInstallPrivilegeModeSwitchBackFinishesAndConfigOnlyRefuses(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	args := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split")
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), args...); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	unit, env := r.read("systemd/system/sandboxd.service"), r.read("sandboxd/sandboxd.env")

	out, err := r.run(r.env(), "--config-only", "--privilege-mode", "single")
	if err == nil || !strings.Contains(out, "--config-only never changes a node's privilege mode: this node runs split") {
		t.Fatalf("config-only to single: err %v\n%s", err, out)
	}
	if r.read("systemd/system/sandboxd.service") != unit || r.read("sandboxd/sandboxd.env") != env {
		t.Fatal("the refused config-only run changed sandboxd.service or sandboxd.env")
	}

	// A switch back that stopped after write_environment: sandboxd.env says
	// single, the marker says the cleanup is owed.
	r.write("sandboxd/sandboxd.env", strings.ReplaceAll(env, "SB_PRIVILEGE_MODE=split\n", ""), 0o600)
	r.write("sandboxd/privilege-mode-switch-back", "unfinished\n", 0o644)
	if out, err := r.run(r.env(), "--config-only"); err == nil || !strings.Contains(out, "did not finish") {
		t.Fatalf("config-only on an unfinished switch: err %v\n%s", err, out)
	}
	r.resetLog()
	out, err = r.run(r.env("SANDBOXD_ACTIVE=true"), append(r.splitRelease("helper v0.7.9\n"), "--privilege-mode", "single")...)
	if err != nil {
		t.Fatalf("finishing the switch back: %v\n%s", err, out)
	}
	if !strings.Contains(out, "did not finish; finishing it now") || strings.Count(out, "warning: in single mode, sandboxd runs as root") != 1 {
		t.Fatalf("the re-run did not finish the switch with one warning:\n%s", out)
	}
	r.inOrder(r.calls(), "systemctl stop sandboxd", "find "+r.path("varlib")+" -xdev -type l -delete",
		"find "+r.path("varlib")+" -xdev -uid 990 -exec chown -h root {} +", "systemctl disable --now aerolvm-rootd.service")
	if _, err := os.Stat(r.path("sandboxd/privilege-mode-switch-back")); err == nil {
		t.Fatal("the marker is still there after the switch finished")
	}
	if out, err := r.run(r.env(), "--config-only"); err != nil {
		t.Fatalf("config-only after the switch: %v\n%s", err, out)
	}
}

// A switch from single to split removes single mode's upgrade folder: split
// never reads it, and in split it sits in the folder sandboxd's user owns
// (M1 PR 10 review). A fresh split install has none to remove.
func TestInstallPrivilegeModeSwitchForgetsTheUpgradeFolder(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	r.write("sandboxd/sandboxd.env", "SB_PAT_TOKEN=kept-pat\nSB_CONTAINER_ENGINE=containerd\n", 0o600)
	r.write("varlib/upgrade/op.json", "{}", 0o600)
	args := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split")
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), args...); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	r.inOrder(r.calls(), "find "+r.path("varlib/upgrade")+" -xdev -delete", "systemctl stop sandboxd", "systemctl enable --now aerolvm-rootd")
}

// Single, the default, writes what install.sh wrote before privilege mode
// existed: sandboxd.service byte for byte, the gateway's units with no
// drop-in, no helper.
func TestInstallPrivilegeModeSingleIsUnchanged(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	out, err := r.run(r.env(), append(r.splitRelease("unused\n"), "--with-containerd-engine")...)
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	want := strings.NewReplacer("/etc/sandboxd", r.path("sandboxd"), "/var/lib/sandboxd", r.path("varlib"),
		"/run/sandboxd", r.path("run"), "PREFIX", r.path("bin")).Replace(singleUnit)
	if got := r.read("systemd/system/sandboxd.service"); got != want {
		t.Fatalf("single sandboxd.service:\n%s\nwant:\n%s", got, want)
	}
	if got := r.read("systemd/system/aerolvm-egress-gateway.socket"); got != singleGatewaySocket {
		t.Fatalf("gateway socket:\n%s", got)
	}
	for _, never := range []string{"systemd/system/aerolvm-rootd.service", "sandboxd/rootd.env", "rootd-bin",
		"systemd/system/aerolvm-egress-gateway.socket.d", "systemd/system/aerolvm-egress-gateway.service.d"} {
		if _, err := os.Stat(r.path(never)); err == nil {
			t.Errorf("single mode wrote %s", never)
		}
	}
	calls := r.calls()
	for _, never := range []string{"aerolvm-rootd", "root-helper", "useradd", "groupadd", "apt-get install -y acl"} {
		if strings.Contains(calls, never) {
			t.Errorf("single mode ran %q; calls:\n%s", never, calls)
		}
	}
	env := r.read("sandboxd/sandboxd.env")
	for _, never := range []string{"SB_PRIVILEGE_MODE", "SB_ROOTD", "SB_DOCKER_ENABLED", "SB_UPGRADE_STATE_DIR", "SB_REMOTE_UPGRADE", "SB_EGRESS_PROCID_SOCKET"} {
		if strings.Contains(env, never) {
			t.Errorf("single sandboxd.env has %s", never)
		}
	}
	if !strings.Contains(r.read("sandboxd/node.json"), `"privilege_mode": "single"`) {
		t.Errorf("node.json:\n%s", r.read("sandboxd/node.json"))
	}
}

// Split runs only what the helper covers; anything else is refused before
// the host is touched. V8 isolates and Firecracker are the helper's since
// M1 PRs 9, 9b, 14 and 14b (TestInstallPrivilegeModeSplitRunsIsolatesAndFirecracker).
func TestInstallPrivilegeModeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"not a mode", []string{"--privilege-mode", "half"}, "must be single or split"},
		{"Docker", []string{"--privilege-mode", "split"}, "needs --with-containerd-engine"},
		{"local", []string{"--privilege-mode", "split", "--local"}, "does not work with --cli-only or --local"},
		{"root BuildKit", []string{"--privilege-mode", "split", "--with-containerd-engine", "--no-buildkit-rootless"}, "drop --no-buildkit-rootless"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunRig(t)
			out, err := r.run(r.env(), tc.args...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("err %v, want %q:\n%s", err, tc.want, out)
			}
			if calls := r.calls(); strings.Contains(calls, "apt-get") || strings.Contains(calls, "systemctl") {
				t.Fatalf("a refused run touched the host:\n%s", calls)
			}
		})
	}
}

// stubRuntimeSteps replaces the steps of --with-firecracker and
// --with-isolate that need KVM or download (tested in
// internal/runtime/firecracker and integration-tests/safety) with ones that
// log what they would install where.
func (r *runRig) stubRuntimeSteps() {
	r.t.Helper()
	raw, err := os.ReadFile(r.script)
	if err != nil {
		r.t.Fatal(err)
	}
	const mainFlow = "\nif [[ \"$CONFIG_ONLY\" == \"true\" ]]; then\n\tif [[ $FAKE_EUID -ne 0 ]]; then\n"
	stubs := `firecracker_preflight() { echo "firecracker_preflight" >>"$LOG"; }
install_firecracker() { echo "install_firecracker kernel=$FIRECRACKER_KERNEL_PATH" >>"$LOG"; }
register_isolate_runtime() { echo "register_isolate_runtime" >>"$LOG"; }
`
	src := strings.Replace(string(raw), mainFlow, "\n"+stubs+mainFlow, 1)
	if src == string(raw) {
		r.t.Fatal("could not stub the runtime steps")
	}
	if err := os.WriteFile(r.script, []byte(src), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// The lines --with-isolate and --with-firecracker wrote before split could
// run them, with the rig's ids (990) and paths. Single must write exactly
// these, and split these and more.
func runtimeLines(r *runRig) []string {
	return []string{
		"SB_ENABLE_FIRECRACKER=true",
		"SB_JAILER_UID=990",
		"SB_JAILER_GID=990",
		"SB_ENABLE_ISOLATE=true",
		"SB_ISOLATE_JAIL_UID=990",
		"SB_ISOLATE_JAIL_GID=990",
		"SB_ISOLATE_JAIL_CHROOT_BASE=" + r.path("srv-isolate"),
		"SB_ISOLATE_JAIL_CGROUP_ROOT=/sys/fs/cgroup/aerolvm-isolate",
	}
}

// splitRuntimeLines are what split adds: the helper runs each V8 group in
// its jail and each VM through the jailer, from this same file, so both
// sides name one jailer, firecracker, chroot base and kernel, and the
// kernel sits in a folder only root writes.
var splitRuntimeLines = []string{
	"SB_ISOLATE_USE_JAIL=true",
	"SB_FIRECRACKER_USE_JAILER=true",
	"SB_JAILER_BINARY=/usr/local/bin/jailer",
	"SB_FIRECRACKER_BINARY=/usr/local/bin/firecracker",
	"SB_JAILER_CHROOT_BASE=/srv/jailer",
	"SB_FIRECRACKER_KERNEL=/usr/local/lib/aerolvm-firecracker/vmlinux",
}

// --privilege-mode split with --with-isolate and --with-firecracker: no
// refusal; sandboxd.env carries what the helper needs for both; the kernel
// is installed to root's folder; sandboxd may write the VMs' stage folders
// under the jailer's chroot base (owners keep everything else root's); and
// a re-run that changes nothing restarts nothing.
func TestInstallPrivilegeModeSplitRunsIsolatesAndFirecracker(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	r.stubRuntimeSteps()
	args := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split",
		"--with-isolate", "--with-firecracker")
	out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), args...)
	if err != nil {
		t.Fatalf("install.sh: %v\n%s\ncalls:\n%s", err, out, r.calls())
	}
	env := lines(r.read("sandboxd/sandboxd.env"))
	for _, want := range append(append(runtimeLines(r), splitRuntimeLines...), "SB_PRIVILEGE_MODE=split") {
		if !env[want] {
			t.Errorf("split sandboxd.env has no %q:\n%s", want, r.read("sandboxd/sandboxd.env"))
		}
	}
	calls := r.calls()
	r.inOrder(calls, "firecracker_preflight", "register_isolate_runtime",
		"install_firecracker kernel=/usr/local/lib/aerolvm-firecracker/vmlinux", "sandboxd upgrade root-helper",
		"systemctl enable --now aerolvm-rootd", "systemctl enable --now caddy sandboxd")
	unit := r.read("systemd/system/sandboxd.service")
	if want := "ReadWritePaths=" + r.path("varlib") + " -/run/aerolvm-procid -" + r.path("sandboxd") + "/tls -" +
		r.path("sandboxd") + "/cluster-ca -/srv/jailer"; !lines(unit)[want] {
		t.Errorf("split sandboxd.service has no line %q:\n%s", want, unit)
	}
	// The V8 group's run folder is the helper's tmpfs, mounted after
	// sandboxd starts: the jail base itself stays read-only to sandboxd.
	if strings.Contains(unit, "srv-isolate") {
		t.Errorf("split sandboxd.service makes the V8 jail base writable:\n%s", unit)
	}
	nodeJSON := r.read("sandboxd/node.json")
	for _, want := range []string{`"privilege_mode": "split"`, `"with_firecracker": true`, `"with_isolate": true`} {
		if !strings.Contains(nodeJSON, want) {
			t.Errorf("node.json has no %s:\n%s", want, nodeJSON)
		}
	}

	// A re-run that changes nothing: the saved node, nothing restarts.
	r.resetLog()
	if out, err = r.run(r.env("SANDBOXD_ACTIVE=true"), r.splitRelease("helper v0.7.8\n")...); err != nil {
		t.Fatalf("re-run: %v\n%s", err, out)
	}
	for _, never := range []string{"systemctl restart aerolvm-rootd", "systemctl restart sandboxd"} {
		if strings.Contains(r.calls(), never) {
			t.Errorf("the re-run did %q; calls:\n%s", never, r.calls())
		}
	}
}

// A split node that gets --with-isolate later: only sandboxd.env changes,
// which the helper reads too, so the running helper starts again to serve
// V8 groups (before, it restarted only for its own unit or rootd.env).
func TestInstallPrivilegeModeSplitRestartsTheHelperForSharedSettings(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	r.stubRuntimeSteps()
	base := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split")
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), base...); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	r.resetLog()
	out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), append(r.splitRelease("helper v0.7.8\n"), "--with-isolate")...)
	if err != nil {
		t.Fatalf("re-run with --with-isolate: %v\n%s", err, out)
	}
	if !lines(r.read("sandboxd/sandboxd.env"))["SB_ISOLATE_USE_JAIL=true"] {
		t.Fatalf("sandboxd.env:\n%s", r.read("sandboxd/sandboxd.env"))
	}
	r.mustCall(r.calls(), "systemctl restart aerolvm-rootd")
}

// Single with --with-isolate and --with-firecracker writes what it wrote
// before: the same runtime lines, none of split's, the kernel in sandboxd's
// data folder (install.sh's default, sandboxd's too), and today's unit.
func TestInstallPrivilegeModeSingleRuntimesUnchanged(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	r.stubRuntimeSteps()
	out, err := r.run(r.env(), append(r.splitRelease("unused\n"), "--with-containerd-engine", "--with-isolate", "--with-firecracker")...)
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	raw := r.read("sandboxd/sandboxd.env")
	env := lines(raw)
	for _, want := range runtimeLines(r) {
		if !env[want] {
			t.Errorf("single sandboxd.env has no %q:\n%s", want, raw)
		}
	}
	for _, never := range append(splitRuntimeLines, "SB_PRIVILEGE_MODE=split") {
		if env[never] {
			t.Errorf("single sandboxd.env has split's %q", never)
		}
	}
	// The block install.sh wrote before, in its order and nothing between.
	if want := strings.Join(runtimeLines(r)[3:], "\n") + "\n"; !strings.Contains(raw, want) {
		t.Errorf("single sandboxd.env's V8 lines changed; want the block\n%s\nin:\n%s", want, raw)
	}
	r.mustCall(r.calls(), "install_firecracker kernel="+r.path("varlib")+"/firecracker/vmlinux")
	want := strings.NewReplacer("/etc/sandboxd", r.path("sandboxd"), "/var/lib/sandboxd", r.path("varlib"),
		"/run/sandboxd", r.path("run"), "PREFIX", r.path("bin")).Replace(singleUnit)
	if got := r.read("systemd/system/sandboxd.service"); got != want {
		t.Fatalf("single sandboxd.service:\n%s\nwant:\n%s", got, want)
	}
}

// A node from before node.json keeps split when its sandboxd.env says so;
// --config-only renders split for a node a full run set up, and refuses
// one it did not.
func TestInstallPrivilegeModeSavedAndConfigOnly(t *testing.T) {
	r := newRunRig(t)
	prefix := r.path("bin")
	r.write("sandboxd/sandboxd.env", "SB_PAT_TOKEN=kept-pat\nSB_PUBLIC_HOST=203.0.113.9\nSB_CONTAINER_ENGINE=containerd\nSB_PRIVILEGE_MODE=split\nSB_TOOLBOX_BINARY_PATH="+prefix+"/toolboxd\n", 0o600)
	r.write("bin/sandboxd", "the installed sandboxd\n", 0o755)
	r.write("bin/toolboxd", "the installed toolboxd\n", 0o755)
	out, err := r.run(r.env(), "--config-only")
	if err == nil || !strings.Contains(out, "run that first") {
		t.Fatalf("config-only with no helper: err %v\n%s", err, out)
	}
	r.write("rootd-bin/aerolvm-rootd", "helper\n", 0o755)
	out, err = r.run(r.env(), "--config-only")
	if err != nil {
		t.Fatalf("config-only: %v\n%s", err, out)
	}
	if !strings.Contains(r.read("systemd/system/sandboxd.service"), "NoNewPrivileges=yes") ||
		!strings.Contains(r.read("systemd/system/aerolvm-rootd.service"), "ExecStart="+r.path("rootd-bin")+"/aerolvm-rootd") {
		t.Fatalf("config-only did not render split:\n%s", r.read("systemd/system/sandboxd.service"))
	}
	if calls := r.calls(); hostEffects.MatchString(calls) || strings.Contains(calls, "useradd") {
		t.Fatalf("config-only touched the host:\n%s", calls)
	}
	if !strings.Contains(r.read("sandboxd/node.json"), `"privilege_mode": "split"`) {
		t.Fatalf("node.json:\n%s", r.read("sandboxd/node.json"))
	}
}

func (r *runRig) mustCall(calls string, parts ...string) {
	r.t.Helper()
	for _, l := range strings.Split(calls, "\n") {
		all := true
		for _, p := range parts {
			if !strings.Contains(l, p) {
				all = false
				break
			}
		}
		if all {
			return
		}
	}
	r.t.Fatalf("no call has %q; calls:\n%s", parts, calls)
}

func (r *runRig) inOrder(calls string, steps ...string) {
	r.t.Helper()
	at := 0
	for _, s := range steps {
		i := strings.Index(calls[at:], s)
		if i < 0 {
			r.t.Fatalf("calls do not have %q after offset %d; want the order %q; calls:\n%s", s, at, steps, calls)
		}
		at += i + len(s)
	}
}

var _ = filepath.Join
