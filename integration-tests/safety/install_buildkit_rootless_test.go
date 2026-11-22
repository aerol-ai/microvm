package safety

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/buildnet"
)

// Rootless BuildKit (install.sh --buildkit-rootless, plans/security-gaps-
// m1-m4.md PR 10b). These run install.sh's own functions with every
// command that would change the machine stubbed: systemctl, apt-get,
// useradd, usermod and id record their calls, `install -d` only records
// (it would chown to the build user), downloads come from a fake server,
// and PATH holds only the tools the functions need.

// tarGz is a .tar.gz of files (name -> body), each 0755.
func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[n])); err != nil {
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

// rootlessBuildkitBins are what the rootless path installs from the
// BuildKit release: the root path's two plus the runc its OCI worker runs.
// Steps' links come from the node's own CNI plugins.
var rootlessBuildkitBins = []string{"buildctl", "buildkit-runc", "buildkitd"}

type rootlessRig struct {
	dir, bin, unit, netUnit, profile, log string
	// cfgDir holds rootless buildkitd's config and its steps' CNI config;
	// envDir the node's sandboxd.env.
	cfgDir, envDir   string
	tarball, rk      []byte
	origin, rkOrigin string
	// rkSHA is the pin the run checks RootlessKit's tarball against: the
	// real stand-in's, whatever rk is changed to after.
	rkSHA string
	// mode is install.sh's --privilege-mode for the run; empty leaves
	// PRIVILEGE_MODE unset, as on a node from before the flag.
	mode string
}

func newRootlessRig(t *testing.T) *rootlessRig {
	t.Helper()
	src := installShSource(t)
	r := &rootlessRig{dir: t.TempDir()}
	r.bin = filepath.Join(r.dir, "bin")
	r.unit = filepath.Join(r.dir, "buildkit.service")
	r.netUnit = filepath.Join(r.dir, "aerolvm-build-net.service")
	r.profile = filepath.Join(r.dir, "aerolvm-rootlesskit")
	r.log = filepath.Join(r.dir, "calls.log")
	r.cfgDir = filepath.Join(r.dir, "etc-aerolvm-buildkit")
	r.envDir = filepath.Join(r.dir, "etc-sandboxd")
	mustMkdir(t, r.bin)
	mustMkdir(t, r.cfgDir)
	mustMkdir(t, r.envDir)
	mustWrite(t, filepath.Join(r.envDir, "sandboxd.env"), "SB_CONTAINER_ENGINE=containerd\nSB_CONTAINERD_CNI_PLUGIN_DIR=/opt/cni/custom\n")
	files := map[string]string{}
	for _, b := range rootlessBuildkitBins {
		files["bin/"+b] = b
	}
	r.tarball = tarGz(t, files)
	r.rk = tarGz(t, map[string]string{"rootlesskit": "#!/bin/sh\necho 'rootlesskit version 3.3.0'\n", "rootlessctl": "x"})
	r.rkSHA = sha256Hex(r.rk)
	bk := installShVarSafety(t, src, "BUILDKIT_VERSION")
	rkv := installShVarSafety(t, src, "ROOTLESSKIT_VERSION")
	r.origin = "https://github.com/moby/buildkit/releases/download/" + bk + "/buildkit-" + bk + ".linux-amd64.tar.gz"
	r.rkOrigin = "https://github.com/rootless-containers/rootlesskit/releases/download/" + rkv + "/rootlesskit-x86_64.tar.gz"
	return r
}

// run runs install_buildkit with rootless set to rootless, after pre sets
// the node up. It returns the calls made and stderr.
func (r *rootlessRig) run(t *testing.T, rootless bool, pre func()) (calls []string, stderr string, err error) {
	t.Helper()
	src := installShSource(t)
	serve, tools := filepath.Join(r.dir, "serve"), filepath.Join(r.dir, "tools")
	for _, d := range []string{serve, tools} {
		_ = os.MkdirAll(d, 0o755)
	}
	for url, body := range map[string][]byte{r.origin: r.tarball, r.rkOrigin: r.rk} {
		if err := os.WriteFile(filepath.Join(serve, serveKey(url)), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"mktemp", "rm", "tar", "gzip", "cat", "tr", "shasum", "sha256sum", "awk", "mkdir", "grep", "sh", "tail"} {
		if p, err := exec.LookPath(name); err == nil {
			_ = os.Symlink(p, filepath.Join(tools, name))
		}
	}
	realInstall, err := exec.LookPath("install")
	if err != nil {
		t.Skip("no install(1)")
	}
	if pre != nil {
		pre()
	}
	_ = os.Remove(r.log)
	flag := "false"
	if rootless {
		flag = "true"
	}
	script := "set -euo pipefail\nPATH='" + tools + "'\nLOG='" + r.log + "'\nSERVE='" + serve + "'\nTMPDIR='" + r.dir + "'\n" +
		"DOWNLOAD_MIRROR='" + testMirror + "'\nBUILDKIT_BIN_DIR='" + r.bin + "'\nBUILDKIT_UNIT_FILE='" + r.unit + "'\n" +
		"BUILD_NET_UNIT_FILE='" + r.netUnit + "'\nROOTLESSKIT_APPARMOR_PROFILE='" + r.profile + "'\n" +
		"APPARMOR_USERNS_KNOB='" + filepath.Join(r.dir, "no-knob") + "'\n" +
		"BUILDKIT_ROOTLESS_CONFIG_DIR='" + r.cfgDir + "'\nSANDBOXD_ENV_DIR='" + r.envDir + "'\n" +
		"BUILDKIT_BUILD_USER=aerolvm-build\nBUILDKIT_ROOTLESS_STATE_DIR=/var/lib/aerolvm-buildkit\nBUILDKIT_SUBID_RANGE=2100000000-2100065535\n" +
		"INSTALL_PREFIX=/usr/local/bin\nBUILDKIT_ROOTLESS='" + flag + "'\nAPT_UPDATED=true\nSANDBOXD_USER=sandboxd\n" +
		"BUILDKIT_SHA256_AMD64='" + sha256Hex(r.tarball) + "'\nROOTLESSKIT_SHA256_X86_64='" + r.rkSHA + "'\n" +
		"uname() { echo x86_64; }\n" +
		"systemctl() { echo \"systemctl $*\" >>\"$LOG\"; }\n" +
		"apt-get() { echo \"apt-get $*\" >>\"$LOG\"; }\n" +
		"useradd() { echo \"useradd $*\" >>\"$LOG\"; }\n" +
		"usermod() { echo \"usermod $*\" >>\"$LOG\"; }\n" +
		"id() { return 1; }\n" +
		"chown() { echo \"chown $*\" >>\"$LOG\"; }\n" +
		"chmod() { echo \"chmod $*\" >>\"$LOG\"; }\n" +
		// install(1) records every call; -d only records (it would chown to
		// the build user), and a file install runs without its owner.
		"install() { echo \"install $*\" >>\"$LOG\"; [[ \"$1\" == -d ]] && return 0; local a=(); while (($#)); do case \"$1\" in -o|-g) shift 2 ;; *) a+=(\"$1\"); shift ;; esac; done; '" + realInstall + "' \"${a[@]}\"; }\n" +
		fetchStubs + installShPinsDefaults(t, src) + fetchFuncs(t, src)
	for _, fn := range []string{"install_buildkit", "install_buildkit_rootless", "buildkit_unit", "buildkit_rootless_unit",
		"build_net_unit", "buildkit_version_at", "rootlesskit_version_at", "buildkit_unit_is_ours_on_host_net",
		"buildkit_unit_is_ours_rootless", "ensure_buildkit_build_user", "ensure_rootlesskit_apparmor",
		"buildkit_steps_conflist", "buildkit_rootless_config", "node_env_value", "buildkit_split_dropin"} {
		script += extractShellFunc(t, src, fn)
	}
	if r.mode != "" {
		script += "PRIVILEGE_MODE='" + r.mode + "'\n"
	}
	script += "install_buildkit\necho DONE\n"
	cmd := exec.Command("bash", "-c", script)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	if err == nil && !strings.Contains(out.String(), "DONE") {
		err = os.ErrInvalid
	}
	raw, _ := os.ReadFile(r.log)
	t.Logf("calls:\n%s\nstderr:\n%s", raw, errOut.String())
	return strings.Split(strings.TrimSpace(string(raw)), "\n"), errOut.String(), err
}

func TestInstallBuildkitRootlessFreshNode(t *testing.T) {
	r := newRootlessRig(t)
	calls, _, err := r.run(t, true, nil)
	if err != nil {
		t.Fatalf("install_buildkit: %v", err)
	}
	checkCalls(t, calls, []string{
		// The user first: RootlessKit is installed for its group.
		"useradd --system --user-group --no-create-home --home-dir /var/lib/aerolvm-buildkit --shell /usr/sbin/nologin aerolvm-build",
		"usermod --add-subuids 2100000000-2100065535 aerolvm-build",
		"usermod --add-subgids 2100000000-2100065535 aerolvm-build",
		"GET " + r.origin, "GET " + r.rkOrigin,
		// RootlessKit for root and the build user only (review F5).
		"install -m 0750 -o root -g aerolvm-build",
		"chown root:aerolvm-build " + r.bin + "/rootlesskit",
		"chmod 0750 " + r.bin + "/rootlesskit",
		"install -d -m 0755 /var/lib/cni " + r.cfgDir,
		"install -d -m 0700 -o aerolvm-build -g aerolvm-build /var/lib/aerolvm-buildkit /var/lib/aerolvm-buildkit/cni",
		"systemctl daemon-reload",
		"systemctl enable --now --no-block aerolvm-build-net.service buildkit.service",
		"systemctl restart --no-block buildkit.service",
	}, nil)
	entries, _ := os.ReadDir(r.bin)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := append(append([]string{}, rootlessBuildkitBins...), "rootlesskit")
	sort.Strings(want)
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Fatalf("installed %v, want %v", names, want)
	}
	unit, _ := os.ReadFile(r.unit)
	for _, w := range []string{
		"Description=BuildKit (aerolvm rootless)",
		"User=aerolvm-build",
		"NetworkNamespacePath=/run/netns/aerolvm.build",
		"BindReadOnlyPaths=/run/aerolvm-build-net/resolv.conf:/etc/resolv.conf",
		"BindPaths=/var/lib/aerolvm-buildkit/cni:/var/lib/cni",
		"PartOf=aerolvm-build-net.service",
		// The step guard runs first, inside RootlessKit, then buildkitd.
		r.bin + "/rootlesskit --state-dir=/run/aerolvm-buildkit/rootlesskit --net=gvisor-tap-vsock --cidr=" + buildnet.UplinkRange +
			" --detach-netns --copy-up=/etc /usr/local/bin/sandboxd host build-network guard -- " + r.bin + "/buildkitd --config " + r.cfgDir + "/buildkitd.toml",
		"--addr unix:///run/aerolvm-buildkit/buildkitd.sock",
	} {
		if !strings.Contains(string(unit), w) {
			t.Errorf("buildkit.service lacks %q:\n%s", w, unit)
		}
	}
	// No root-level socket, no containerd, no shared bridge for steps.
	for _, never := range []string{"containerd.sock", "--containerd-worker=true", "User=root", "--oci-worker-net=bridge"} {
		if strings.Contains(string(unit), never) {
			t.Errorf("buildkit.service has %q:\n%s", never, unit)
		}
	}
	// Each step a point-to-point link of its own, in the guard's range; no
	// bridge for steps to share.
	conflist, _ := os.ReadFile(filepath.Join(r.cfgDir, "steps.conflist"))
	var cl struct {
		Plugins []struct {
			Type string `json:"type"`
			IPAM struct {
				Ranges [][]struct {
					Subnet string `json:"subnet"`
				} `json:"ranges"`
			} `json:"ipam"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(conflist, &cl); err != nil || len(cl.Plugins) != 2 || cl.Plugins[0].Type != "loopback" || cl.Plugins[1].Type != "ptp" ||
		cl.Plugins[1].IPAM.Ranges[0][0].Subnet != buildnet.StepRange {
		t.Errorf("steps.conflist %s (%v): want loopback then ptp on %s", conflist, err, buildnet.StepRange)
	}
	cfg, _ := os.ReadFile(filepath.Join(r.cfgDir, "buildkitd.toml"))
	for _, w := range []string{`networkMode = "cni"`, `cniConfigPath = "` + r.cfgDir + `/steps.conflist"`, `cniBinaryPath = "/opt/cni/custom"`, "[worker.containerd]\n  enabled = false"} {
		if !strings.Contains(string(cfg), w) {
			t.Errorf("buildkitd.toml lacks %q:\n%s", w, cfg)
		}
	}
	net, _ := os.ReadFile(r.netUnit)
	for _, w := range []string{
		"Type=oneshot", "RemainAfterExit=yes", "After=sandboxd.service",
		`ExecStartPre=/bin/sh -c 'test -s "$${SB_CONTAINERD_CNI_CONF_PATH:-/etc/cni/net.d/aerolvm.conflist}"'`,
		"ExecStart=/usr/local/bin/sandboxd host build-network up",
		"ExecStop=/usr/local/bin/sandboxd host build-network down",
		"Restart=on-failure", "StartLimitIntervalSec=0",
	} {
		if !strings.Contains(string(net), w) {
			t.Errorf("aerolvm-build-net.service lacks %q:\n%s", w, net)
		}
	}
}

// A node already set up is left as it is: nothing downloaded, nothing
// rewritten, nothing restarted; the units are still enabled.
func TestInstallBuildkitRootlessRerun(t *testing.T) {
	r := newRootlessRig(t)
	if _, _, err := r.run(t, true, nil); err != nil {
		t.Fatal(err)
	}
	// The first run installed stand-ins; make buildkitd report the pin.
	src := installShSource(t)
	mustWrite(t, filepath.Join(r.bin, "buildkitd"), "#!/bin/sh\necho 'buildkitd github.com/moby/buildkit "+installShVarSafety(t, src, "BUILDKIT_VERSION")+" 0123abcd'\n")
	calls, _, err := r.run(t, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkCalls(t, calls, []string{"systemctl enable --now --no-block aerolvm-build-net.service buildkit.service"},
		[]string{"GET ", "daemon-reload", "systemctl restart", "systemctl stop"})
}

// Today's root unit, ours, moves to rootless; an operator's own unit is
// kept, with a warning.
func TestInstallBuildkitRootlessReplacesOnlyOurUnit(t *testing.T) {
	r := newRootlessRig(t)
	calls, _, err := r.run(t, true, func() { mustWrite(t, r.unit, bootstrapBuildkitUnit(t)) })
	if err != nil {
		t.Fatal(err)
	}
	checkCalls(t, calls, []string{"systemctl daemon-reload", "systemctl restart --no-block buildkit.service"}, nil)
	if got, _ := os.ReadFile(r.unit); !strings.Contains(string(got), "Description=BuildKit (aerolvm rootless)") {
		t.Fatalf("our root unit was not replaced:\n%s", got)
	}

	r = newRootlessRig(t)
	const operators = "[Unit]\nDescription=BuildKit (ours, by hand)\n"
	_, stderr, err := r.run(t, true, func() { mustWrite(t, r.unit, operators) })
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(r.unit); string(got) != operators {
		t.Fatalf("the operator's unit was rewritten:\n%s", got)
	}
	if !strings.Contains(stderr, "is not one this installer wrote") {
		t.Fatalf("no warning about the operator's unit: %s", stderr)
	}
}

// --no-buildkit-rootless: our rootless unit goes back to the root one, and
// the build network's unit is stopped.
func TestInstallBuildkitBackFromRootless(t *testing.T) {
	r := newRootlessRig(t)
	if _, _, err := r.run(t, true, nil); err != nil {
		t.Fatal(err)
	}
	src := installShSource(t)
	mustWrite(t, filepath.Join(r.bin, "buildkitd"), "#!/bin/sh\necho 'buildkitd github.com/moby/buildkit "+installShVarSafety(t, src, "BUILDKIT_VERSION")+" 0123abcd'\n")
	calls, _, err := r.run(t, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkCalls(t, calls, []string{"systemctl disable --now aerolvm-build-net.service", "systemctl daemon-reload",
		"systemctl enable --now buildkit.service", "systemctl restart buildkit.service"}, []string{"GET "})
	if got, _ := os.ReadFile(r.unit); string(got) != bootstrapBuildkitUnit(t) {
		t.Fatalf("unit after --no-buildkit-rootless:\n%s", got)
	}
}

// A tarball that is not the pinned one installs nothing.
func TestInstallBuildkitRootlessRefusesAnUnpinnedTarball(t *testing.T) {
	r := newRootlessRig(t)
	r.rk = []byte("not rootlesskit")
	_, stderr, err := r.run(t, true, func() {})
	if err == nil || !strings.Contains(stderr, "failed its checksum") {
		t.Fatalf("install_buildkit = %v, want a checksum refusal:\n%s", err, stderr)
	}
	if _, err := os.Stat(filepath.Join(r.bin, "rootlesskit")); err == nil {
		t.Fatal("an unpinned rootlesskit was installed")
	}
}

// --buildkit-rootless is a server-node setting, refused before install.sh
// touches the machine, like --with-containerd-engine.
func TestInstallRefusesBuildkitRootlessOutsideAServerInstall(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"--local", "--cli-only"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command("bash", script, mode, "--buildkit-rootless")
			cmd.Dir = t.TempDir()
			cmd.Env = noInstallEnv(t)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "--buildkit-rootless sets up a server node's BuildKit; it does not work with --cli-only or --local") {
				t.Fatalf("install.sh %s --buildkit-rootless = %v:\n%s", mode, err, out)
			}
		})
	}
}

// On a host that lets only profiled programs make user namespaces, RootlessKit
// gets a profile that allows that, for it alone; elsewhere nothing is written.
func TestRootlessKitAppArmorProfile(t *testing.T) {
	src := installShSource(t)
	for _, tc := range []struct {
		knob    string
		profile bool
	}{{"1", true}, {"0", false}, {"", false}} {
		dir := t.TempDir()
		knob, profile, log := filepath.Join(dir, "knob"), filepath.Join(dir, "profile"), filepath.Join(dir, "log")
		if tc.knob != "" {
			mustWrite(t, knob, tc.knob+"\n")
		}
		script := "set -euo pipefail\nAPPARMOR_USERNS_KNOB='" + knob + "'\nROOTLESSKIT_APPARMOR_PROFILE='" + profile + "'\n" +
			"BUILDKIT_BIN_DIR=/usr/local/bin\nLOG='" + log + "'\n" +
			"apparmor_parser() { echo \"apparmor_parser $*\" >>\"$LOG\"; }\n" +
			extractShellFunc(t, src, "ensure_rootlesskit_apparmor") + "ensure_rootlesskit_apparmor\n"
		if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil {
			t.Fatalf("knob %q: %v\n%s", tc.knob, err, out)
		}
		body, err := os.ReadFile(profile)
		if !tc.profile {
			if err == nil {
				t.Fatalf("knob %q: a profile was written:\n%s", tc.knob, body)
			}
			continue
		}
		for _, w := range []string{"profile aerolvm-rootlesskit /usr/local/bin/rootlesskit flags=(unconfined) {", "  userns,", "abi <abi/4.0>,"} {
			if !strings.Contains(string(body), w) {
				t.Errorf("profile lacks %q:\n%s", w, body)
			}
		}
		if calls, _ := os.ReadFile(log); strings.TrimSpace(string(calls)) != "apparmor_parser -r "+profile {
			t.Errorf("apparmor_parser calls %q", calls)
		}
	}
}

// Privilege mode split (M1 PR 10): sandboxd's user reaches rootless
// BuildKit's socket by an ACL that a drop-in sets as root, never by joining
// aerolvm-build, whose members may run RootlessKit and make user
// namespaces. The rootless unit itself is the same in both modes.
func TestInstallBuildkitRootlessSplitACL(t *testing.T) {
	r := newRootlessRig(t)
	if _, _, err := r.run(t, true, nil); err != nil {
		t.Fatal(err)
	}
	single, _ := os.ReadFile(r.unit)
	dropin := r.unit + ".d/privilege-split.conf"
	if _, err := os.Stat(dropin); err == nil {
		t.Fatal("single mode wrote the split drop-in")
	}
	src := installShSource(t)
	mustWrite(t, filepath.Join(r.bin, "buildkitd"), "#!/bin/sh\necho 'buildkitd github.com/moby/buildkit "+installShVarSafety(t, src, "BUILDKIT_VERSION")+" 0123abcd'\n")

	r.mode = "split"
	calls, _, err := r.run(t, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkCalls(t, calls, []string{"systemctl daemon-reload", "systemctl restart --no-block buildkit.service"}, []string{"GET ", "aerolvm-build sandboxd", "usermod -aG"})
	if got, _ := os.ReadFile(r.unit); string(got) != string(single) {
		t.Fatalf("split changed the rootless unit itself:\n%s", got)
	}
	got, err := os.ReadFile(dropin)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"ExecStartPre=-+/usr/bin/setfacl -m u:sandboxd:x /run/aerolvm-buildkit",
		// systemd reads $$ as $: the shell sees $((i+1)) and $i.
		"ExecStartPost=-+/bin/sh -c 'i=0; while [ ! -S /run/aerolvm-buildkit/buildkitd.sock ]; do i=$$((i+1)); [ $$i -lt 600 ] || exit 1; sleep 0.2; done; exec /usr/bin/setfacl -m u:sandboxd:rw /run/aerolvm-buildkit/buildkitd.sock'",
	} {
		if !strings.Contains(string(got), w+"\n") {
			t.Errorf("drop-in lacks %q:\n%s", w, got)
		}
	}
	// Again: nothing changed, nothing restarts.
	calls, _, err = r.run(t, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkCalls(t, calls, nil, []string{"daemon-reload", "systemctl restart"})

	// Back to single: the drop-in goes, and BuildKit restarts without it.
	r.mode = "single"
	calls, _, err = r.run(t, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	checkCalls(t, calls, []string{"systemctl daemon-reload", "systemctl restart --no-block buildkit.service"}, nil)
	if _, err := os.Stat(dropin); err == nil {
		t.Fatal("the split drop-in outlived the switch back to single")
	}

	// From split straight to the root BuildKit: the drop-in, which names
	// the rootless socket's folder, goes too.
	r.mode = "split"
	if _, _, err := r.run(t, true, nil); err != nil {
		t.Fatal(err)
	}
	r.mode = ""
	if _, _, err := r.run(t, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dropin); err == nil {
		t.Fatal("the split drop-in outlived --no-buildkit-rootless")
	}
}
