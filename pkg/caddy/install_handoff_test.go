package caddy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/release"
)

// fakeUpgrader is an installed sandboxd that has `sandboxd upgrade node`:
// it carries the command's usage text, logs what it is asked, copies the
// --from directory to $CAPTURE, and answers like the real one with -o json.
const fakeUpgrader = `#!/usr/bin/env bash
# usage: sandboxd upgrade node <version> --sha256 <file>=<hash> ...
echo "sandboxd $*" >>"$LOG"
if [[ "${1:-} ${2:-}" == "upgrade node" ]]; then
	[[ "${3:-}" == "--help" ]] && exit 0
	from="" prev=""
	for a in "$@"; do
		[[ "$prev" == "--from" ]] && from="$a"
		prev="$a"
	done
	cp -R "$from" "$CAPTURE"
	if [[ -n "${UPGRADER_FAIL:-}" ]]; then
		echo "upgrade failed: $UPGRADER_FAIL" >&2
		exit 1
	fi
	printf '{\n  "op": "x",\n  "result": "%s"\n}\n' "${UPGRADER_RESULT:-upgraded}"
	exit 0
fi
echo "BOOTED A SECOND DAEMON" >>"$LOG"
`

// oldSandboxd predates the command: run with any argument it would boot a
// second daemon, so install.sh must never run it.
const oldSandboxd = "#!/usr/bin/env bash\necho \"OLD SANDBOXD RAN $*\" >>\"$LOG\"\n"

// release writes a release's files and checksums.txt under rel/ and returns
// the flags that point install.sh at them.
func (r *runRig) release(version string, withMeta bool, withCaddy bool) []string {
	r.t.Helper()
	files := map[string]string{
		"sandboxd_linux_amd64": "new sandboxd " + version + "\n",
		"toolboxd_linux_amd64": "new toolboxd " + version + "\n",
	}
	if withCaddy {
		files["caddy_linux_amd64"] = "new caddy " + version + "\n"
	}
	if withMeta {
		meta, err := release.Marshal(release.Metadata{Version: version, UpgradeFromMin: "v0.6.0", OneWayMigrations: []int{},
			HostSetupSHA256: strings.Repeat("a", 64), EgressGatewayProtocol: []int{1}, FSMOpsVersion: 9})
		if err != nil {
			r.t.Fatal(err)
		}
		files["release.json"] = string(meta)
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
	args := []string{"--sandboxd-url", rel + "/sandboxd_linux_amd64", "--toolboxd-url", rel + "/toolboxd_linux_amd64", "--checksums-url", rel + "/checksums.txt"}
	return args
}

func (r *runRig) hash(rel string) string { return sha256Hex([]byte(r.read(rel))) }

// eng D7: a re-run on a node whose sandboxd has `upgrade node` downloads
// and checks the files as before, then hands them to the upgrader instead
// of copying them over the installed ones; the upgrader's restart replaces
// install.sh's. A node whose sandboxd predates the command, or a release
// with no release.json, keeps the direct install, and the old binary is
// never run.
func TestInstallHandsBinariesToTheUpgrader(t *testing.T) {
	cases := []struct {
		name        string
		installed   string
		meta        bool
		env         []string
		extra       []string
		wantHandoff bool
		wantRestart bool
		wantFail    string
	}{
		{name: "upgrader present", installed: fakeUpgrader, meta: true, wantHandoff: true},
		{name: "upgrader present, nothing to upgrade, settings changed", installed: fakeUpgrader, meta: true,
			env: []string{"UPGRADER_RESULT=noop"}, extra: []string{"--node-name", "renamed"}, wantHandoff: true, wantRestart: true},
		{name: "upgrader fails", installed: fakeUpgrader, meta: true, env: []string{"UPGRADER_FAIL=health"}, wantHandoff: true, wantFail: "sandboxd upgrade node failed"},
		{name: "sandboxd predates the command", installed: oldSandboxd, meta: true},
		{name: "release without release.json", installed: fakeUpgrader, meta: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunRig(t)
			prefix := r.path("bin")
			r.write("bin/sandboxd", tc.installed, 0o755)
			r.write("bin/toolboxd", "old toolboxd\n", 0o755)
			r.write("sandboxd/sandboxd.env", "SB_PAT_TOKEN=kept-pat\nSB_API_HOST=127.0.0.1\nSB_TOOLBOX_BINARY_PATH="+prefix+"/toolboxd\n", 0o600)
			args := append(r.release("v0.6.12", tc.meta, false), "--local", "--install-prefix", prefix)
			args = append(args, tc.extra...)
			out, err := r.run(r.env(tc.env...), args...)
			calls := r.calls()
			if tc.wantFail != "" {
				if err == nil || !strings.Contains(out, tc.wantFail) || !strings.Contains(out, "upgrade failed: health") {
					t.Fatalf("err = %v, want %q:\n%s", err, tc.wantFail, out)
				}
				if strings.Contains(calls, "systemctl enable --now sandboxd") {
					t.Fatal("the install carried on after the upgrader failed")
				}
				return
			}
			if err != nil {
				t.Fatalf("install.sh: %v\n%s\ncalls:\n%s", err, out, calls)
			}
			if strings.Contains(calls, "BOOTED A SECOND DAEMON") || strings.Contains(calls, "OLD SANDBOXD RAN") {
				t.Fatalf("install.sh ran a sandboxd that cannot take the command; calls:\n%s", calls)
			}
			handedOff := strings.Contains(calls, "sandboxd upgrade node v0.6.12")
			if handedOff != tc.wantHandoff {
				t.Fatalf("handed off = %v, want %v; output:\n%s\ncalls:\n%s", handedOff, tc.wantHandoff, out, calls)
			}
			if !tc.wantHandoff {
				// The direct install, as before.
				if got := r.read("bin/sandboxd"); got != "new sandboxd v0.6.12\n" {
					t.Fatalf("installed sandboxd = %q", got)
				}
				return
			}
			// The installed files are the upgrader's to replace.
			if r.read("bin/sandboxd") != tc.installed || r.read("bin/toolboxd") != "old toolboxd\n" {
				t.Fatal("install.sh replaced the binaries itself")
			}
			want := fmt.Sprintf("sandboxd upgrade node v0.6.12 --from %%s --sha256 release.json=%s --sha256 sandboxd=%s --sha256 toolboxd=%s --skip-host-apply -o json",
				r.hash("rel/release.json"), r.hash("rel/sandboxd_linux_amd64"), r.hash("rel/toolboxd_linux_amd64"))
			var line string
			for _, l := range strings.Split(calls, "\n") {
				if strings.HasPrefix(l, "sandboxd upgrade node v0.6.12") {
					line = l
				}
			}
			from := strings.Fields(line)[5]
			if line != fmt.Sprintf(want, from) {
				t.Fatalf("upgrader call =\n%s\nwant\n%s", line, fmt.Sprintf(want, from))
			}
			// What the upgrader was given is the checked files.
			for name, src := range map[string]string{"sandboxd": "rel/sandboxd_linux_amd64", "toolboxd": "rel/toolboxd_linux_amd64", "release.json": "rel/release.json"} {
				if got := r.read(filepath.Join("capture", name)); got != r.read(src) {
					t.Fatalf("handed %s = %q", name, got)
				}
			}
			if _, err := os.Stat(from); !os.IsNotExist(err) {
				t.Fatalf("the hand-off directory %s was left behind", from)
			}
			// Settings are written and loaded before the upgrader restarts.
			at := func(s string) int { return strings.Index(calls, s) }
			if !(at("systemctl daemon-reload") < at("sandboxd upgrade node v0.6.12") && at("sandboxd upgrade node v0.6.12") < at("systemctl enable --now sandboxd")) {
				t.Fatalf("the hand-off is out of order; calls:\n%s", calls)
			}
			if restarted := strings.Contains(calls, "systemctl restart sandboxd"); restarted != tc.wantRestart {
				t.Fatalf("install.sh restarted sandboxd = %v, want %v; calls:\n%s", restarted, tc.wantRestart, calls)
			}
		})
	}
}

// The main (non-local) path hands Caddy to the upgrader too when it comes
// from the release, so the upgrader swaps and restarts it only when it
// changed.
func TestInstallHandsCaddyToTheUpgrader(t *testing.T) {
	r := newRunRig(t)
	prefix := r.path("bin")
	r.write("bin/sandboxd", fakeUpgrader, 0o755)
	r.write("bin/toolboxd", "old toolboxd\n", 0o755)
	r.write("sandboxd/sandboxd.env", "SB_PAT_TOKEN=kept-pat\nSB_TOOLBOX_BINARY_PATH="+prefix+"/toolboxd\n", 0o600)
	args := append(r.release("v0.6.12", true, true), "--install-prefix", prefix, "--public-host", "203.0.113.9")
	out, err := r.run(r.env(), append(args, "--caddy-binary-url", "file://"+r.path("rel/caddy_linux_amd64"))...)
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	calls := r.calls()
	// An explicit --caddy-binary-url is not checked against checksums.txt,
	// so it is installed directly, as before.
	if strings.Contains(calls, "--sha256 caddy=") {
		t.Fatalf("an unchecked Caddy was handed to the upgrader; calls:\n%s", calls)
	}
	if got := r.read("usrbin/caddy"); got != "new caddy v0.6.12\n" {
		t.Fatalf("the explicit Caddy was not installed: %q", got)
	}

	// From the release itself it is checked, and handed over.
	r2 := newRunRig(t)
	prefix2 := r2.path("bin")
	r2.write("bin/sandboxd", fakeUpgrader, 0o755)
	r2.write("bin/toolboxd", "old toolboxd\n", 0o755)
	r2.write("sandboxd/sandboxd.env", "SB_PAT_TOKEN=kept-pat\nSB_TOOLBOX_BINARY_PATH="+prefix2+"/toolboxd\n", 0o600)
	args2 := append(r2.release("v0.6.12", true, true), "--install-prefix", prefix2, "--public-host", "203.0.113.9")
	// resolve_release_urls fills CADDY_BINARY_URL from the release base,
	// which is GitHub; point the default at the local release instead.
	script, err := os.ReadFile(r2.script)
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.Replace(string(script), `CADDY_BINARY_URL="${CADDY_BINARY_URL:-${release_base}/download/${VERSION}/caddy_${platform}}"`,
		`CADDY_BINARY_URL="${CADDY_BINARY_URL:-file://`+r2.path("rel")+`/caddy_${platform}}"`, 1)
	patched = strings.Replace(patched, `CADDY_BINARY_URL="${CADDY_BINARY_URL:-${release_base}/latest/download/caddy_${platform}}"`,
		`CADDY_BINARY_URL="${CADDY_BINARY_URL:-file://`+r2.path("rel")+`/caddy_${platform}}"`, 1)
	if patched == string(script) {
		t.Fatal("could not point the default Caddy URL at the local release")
	}
	if err := os.WriteFile(r2.script, []byte(patched), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err = r2.run(r2.env(), args2...)
	if err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	calls = r2.calls()
	if !strings.Contains(calls, "--sha256 caddy="+r2.hash("rel/caddy_linux_amd64")) {
		t.Fatalf("Caddy was not handed to the upgrader; calls:\n%s", calls)
	}
	if strings.Contains(calls, "systemctl stop caddy") {
		t.Fatalf("install.sh stopped Caddy itself; calls:\n%s", calls)
	}
	if got := r2.read("capture/caddy"); got != "new caddy v0.6.12\n" {
		t.Fatalf("handed caddy = %q", got)
	}
	if got := r2.read("usrbin/caddy"); got != installedCaddy {
		t.Fatalf("install.sh replaced Caddy itself: %q", got)
	}
}
