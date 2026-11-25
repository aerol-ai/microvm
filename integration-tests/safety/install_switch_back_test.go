package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// switchBackWarning is the start of the line install.sh prints when a node
// goes from privilege mode split back to single.
const switchBackWarning = "warning: in single mode, sandboxd runs as root and trusts its database"

// switchBackStubs replace every program setup_privilege_mode and
// leave_split_mode run. Each logs its call to $LOG and changes nothing:
// find, chown and the rest never reach a real file. id finds no sandboxd
// user, so the owner loop is skipped. rm removes only the switch-back
// marker, which is in the test's folder. PATH holds awk (env_file_value
// reads the saved mode with it) and rm alone; any other program would fail
// the run.
const switchBackStubs = `
split_fingerprint() { echo fingerprint; }
split_shared_env_fingerprint() { echo fingerprint; }
ensure_split_users() { echo ensure_split_users >>"$LOG"; }
apt-get() { echo "apt-get $*" >>"$LOG"; }
setfacl() { echo "setfacl $*" >>"$LOG"; }
mktemp() { return 1; }
install() { echo "install $*" >>"$LOG"; }
chmod() { echo "chmod $*" >>"$LOG"; }
find() { echo "find $*" >>"$LOG"; }
systemctl() { echo "systemctl $*" >>"$LOG"; }
id() { return 1; }
chown() { echo "chown $*" >>"$LOG"; }
chgrp() { echo "chgrp $*" >>"$LOG"; }
rm() {
	echo "rm $*" >>"$LOG"
	if [[ "$1" == -f && "$2" == "$PRIVILEGE_SWITCH_BACK_MARKER" && "$2" == "$TEST_DIR"/* ]]; then
		command rm -f -- "$2"
	fi
}
`

// switchBackHost is a stand-in node for the privilege mode functions: its
// sandboxd.env and switch-back marker live in a temp folder.
type switchBackHost struct {
	t                     *testing.T
	dir, bin, env, marker string
	funcs                 string
}

func newSwitchBackHost(t *testing.T, env string) *switchBackHost {
	t.Helper()
	h := &switchBackHost{t: t, dir: t.TempDir()}
	h.bin = filepath.Join(h.dir, "bin")
	h.env = filepath.Join(h.dir, "sandboxd.env")
	h.marker = filepath.Join(h.dir, "privilege-mode-switch-back")
	mustMkdir(t, h.bin)
	for _, tool := range []string{"awk", "rm"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available", tool)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if env != "" {
		mustWrite(t, h.env, env)
	}
	h.funcs = installShFunction(t, installShSource(t), "env_file_value", "running_privilege_mode", "check_privilege_mode_change",
		"setup_privilege_mode", "forget_single_upgrade_folder", "mark_switch_back", "leave_split_mode")
	return h
}

// run runs script after the functions and stubs, as a run in mode, with
// extra settings on top.
func (h *switchBackHost) run(mode, script string, extra ...string) (calls []string, stdout, stderr string) {
	h.t.Helper()
	env := map[string]string{
		"PATH":                         h.bin,
		"HOME":                         filepath.Join(h.dir, "home"),
		"TEST_DIR":                     h.dir,
		"PRIVILEGE_MODE":               mode,
		"SANDBOXD_ENV_FILE":            h.env,
		"PRIVILEGE_SWITCH_BACK_MARKER": h.marker,
		"SANDBOXD_USER":                "sandboxd",
		"APT_UPDATED":                  "true",
		"CLI_ONLY":                     "false",
		"CONFIG_ONLY":                  "false",
		"LOCAL_MODE":                   "false",
		"SPLIT_UPGRADE_STATE_DIR":      filepath.Join(h.dir, "upgrade-state"),
		"ROOTD_BIN_DIR":                filepath.Join(h.dir, "rootd-bin"),
		"SPLIT_PROCID_DIR":             filepath.Join(h.dir, "procid"),
	}
	for i := 0; i+1 < len(extra); i += 2 {
		env[extra[i]] = extra[i+1]
	}
	return runInstallSh(h.t, switchBackStubs+h.funcs+script, env)
}

func (h *switchBackHost) markerThere() bool {
	_, err := os.Lstat(h.marker)
	return err == nil
}

// TestInstallWarnsOnSwitchBackToSingle runs install.sh's real
// setup_privilege_mode (which reads the mode the node ran in from
// sandboxd.env) and leave_split_mode, in the order the installer runs them.
// A switch from split back to single prints the warning once: single mode's
// root sandboxd trusts the database and files sandboxd's user wrote. A fresh
// single install, a single node run again, and any run into split print
// nothing. No run leaves the switch-back marker behind.
func TestInstallWarnsOnSwitchBackToSingle(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    string // sandboxd.env before the run; "" = no file (a fresh install)
		mode   string // --privilege-mode of this run
		warned bool
	}{
		{name: "fresh install in single", mode: "single"},
		{name: "single node run again", env: "SB_API_PORT=21212\n", mode: "single"},
		{name: "fresh install in split", mode: "split"},
		{name: "single node switched to split", env: "SB_API_PORT=21212\n", mode: "split"},
		{name: "split node run again", env: "SB_API_PORT=21212\nSB_PRIVILEGE_MODE=split\n", mode: "split"},
		{name: "split node switched back to single", env: "SB_API_PORT=21212\nSB_PRIVILEGE_MODE=split\n", mode: "single", warned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSwitchBackHost(t, tc.env)
			calls, stdout, stderr := h.run(tc.mode, writeEnvMarks+"setup_privilege_mode\nwrite_environment\nleave_split_mode\n")
			want := 0
			if tc.warned {
				want = 1
			}
			if got := strings.Count(stdout+stderr, switchBackWarning); got != want {
				t.Fatalf("warning printed %d times, want %d\nstdout: %s\nstderr: %s", got, want, stdout, stderr)
			}
			if tc.warned {
				// On stderr, with the other warnings, and naming what to do.
				if !strings.Contains(stderr, switchBackWarning) || !strings.Contains(stderr, "rebuild the machine instead") {
					t.Errorf("the warning is not on stderr, or does not say to rebuild:\n%s", stderr)
				}
				// The switch itself still runs after it.
				checkCalls(t, calls, []string{"systemctl stop sandboxd", "systemctl disable --now aerolvm-rootd.service"}, nil)
			} else {
				checkCalls(t, calls, nil, []string{"systemctl stop sandboxd", "aerolvm-rootd.service"})
			}
			if h.markerThere() {
				t.Error("the run left the switch-back marker")
			}
		})
	}
}

// writeEnvMarks stands in for install.sh's main flow at the env rewrite:
// mark_switch_back, then write_environment
// (TestInstallMarksTheSwitchBackOnlyWithTheEnvRewrite checks that order).
const writeEnvMarks = "write_environment() { mark_switch_back; }\n"

// TestInstallMarksTheSwitchBackOnlyWithTheEnvRewrite: the marker covers
// only the window where sandboxd.env says single and the cleanup is not
// done. A switch-back run that stops before write_environment (on a
// download, say: the downloads all come before it) has changed no setting.
// It leaves no marker, sandboxd.env still says split, and the next plain
// run is a normal split run, not refused and not finishing anything.
func TestInstallMarksTheSwitchBackOnlyWithTheEnvRewrite(t *testing.T) {
	const splitEnv = "SB_API_PORT=21212\nSB_PRIVILEGE_MODE=split\n"
	h := newSwitchBackHost(t, splitEnv)
	// The run stops after setup_privilege_mode, where the downloads start.
	_, stdout, stderr := h.run("single", writeEnvMarks+"setup_privilege_mode\nexit 0\n")
	if h.markerThere() {
		t.Fatal("a switch-back run that stopped before sandboxd.env changed left the marker")
	}
	if strings.Contains(stdout+stderr, switchBackWarning) {
		t.Fatalf("it warned:\n%s%s", stdout, stderr)
	}
	if raw, _ := os.ReadFile(h.env); string(raw) != splitEnv {
		t.Fatalf("sandboxd.env changed:\n%s", raw)
	}
	// The next plain run (node.json still says split) goes on as split.
	calls, stdout, stderr := h.run("split", writeEnvMarks+"check_privilege_mode_change\nsetup_privilege_mode\nwrite_environment\nleave_split_mode\necho PREVIOUS=$PREVIOUS_PRIVILEGE_MODE\n")
	if !strings.Contains(stdout, "PREVIOUS=split") || strings.Contains(stdout+stderr, "did not finish") || h.markerThere() {
		t.Fatalf("the split re-run was not a plain split run:\nstdout: %s\nstderr: %s", stdout, stderr)
	}
	checkCalls(t, calls, nil, []string{"systemctl stop sandboxd", "aerolvm-rootd.service"})

	// In install.sh's main flow, mark_switch_back runs right before
	// write_environment and after every download (install_custom_caddy,
	// install_binaries); it is the only place the marker is written.
	src := installShSource(t)
	if n := strings.Count(src, ">\"$PRIVILEGE_SWITCH_BACK_MARKER\""); n != 1 {
		t.Fatalf("install.sh writes the marker in %d places, want 1 (mark_switch_back)", n)
	}
	if n := strings.Count(src, "\n\tmark_switch_back\n") + strings.Count(src, "\nmark_switch_back\n"); n != 1 {
		t.Fatalf("install.sh calls mark_switch_back %d times, want once", n)
	}
	flow := src[strings.Index(src, "\nsetup_privilege_mode\n"):]
	at := strings.Index(flow, "\nmark_switch_back\nwrite_environment\n")
	if at < 0 {
		t.Fatal("the main flow does not call mark_switch_back right before write_environment")
	}
	for _, download := range []string{"\ninstall_custom_caddy ", "\ninstall_binaries\n"} {
		if i := strings.Index(flow, download); i < 0 || i > at {
			t.Errorf("%q does not run before mark_switch_back in the main flow", strings.TrimSpace(download))
		}
	}
}

// TestInstallFinishesAnInterruptedSwitchBack: write_environment rewrites
// sandboxd.env (single, no SB_PRIVILEGE_MODE) before leave_split_mode
// cleans up. A switch-back run stopped between the two used to leave a node
// that every later run read as single: no cleanup, no warning, and root
// writing in folders sandboxd's user still owned. The marker
// (mark_switch_back, right before write_environment) makes the next run
// finish the switch.
func TestInstallFinishesAnInterruptedSwitchBack(t *testing.T) {
	h := newSwitchBackHost(t, "SB_API_PORT=21212\nSB_PRIVILEGE_MODE=split\n")
	// write_environment as far as the mode goes: the marker first, then
	// sandboxd.env says single.
	writeEnv := "write_environment() { mark_switch_back; printf 'SB_API_PORT=21212\\n' >\"$SANDBOXD_ENV_FILE\"; }\n"

	// The switch-back run stops right after sandboxd.env is rewritten.
	calls, stdout, stderr := h.run("single", writeEnv+"setup_privilege_mode\nwrite_environment\nexit 0\n")
	if !h.markerThere() {
		t.Fatal("no marker after a switch-back run that stopped part way")
	}
	if strings.Contains(stdout+stderr, switchBackWarning) {
		t.Fatalf("the stopped run warned before its cleanup:\n%s%s", stdout, stderr)
	}
	checkCalls(t, calls, nil, []string{"systemctl stop sandboxd"})
	if raw, _ := os.ReadFile(h.env); strings.Contains(string(raw), "SB_PRIVILEGE_MODE") {
		t.Fatalf("sandboxd.env still says split:\n%s", raw)
	}

	// The next run reads split, finishes the cleanup, warns once, and
	// removes the marker.
	calls, stdout, stderr = h.run("single", writeEnv+"setup_privilege_mode\nwrite_environment\nleave_split_mode\n")
	if !strings.Contains(stdout, "did not finish; finishing it now") {
		t.Errorf("the re-run did not say it finishes the switch:\n%s", stdout)
	}
	if got := strings.Count(stderr, switchBackWarning); got != 1 {
		t.Fatalf("warning printed %d times on the re-run, want 1:\n%s", got, stderr)
	}
	checkCalls(t, calls, []string{"systemctl stop sandboxd", "systemctl disable --now aerolvm-rootd.service", "rm -f " + h.marker}, nil)
	if h.markerThere() {
		t.Fatal("the marker is still there after the switch finished")
	}

	// Done: a third run is a plain single run.
	calls, stdout, stderr = h.run("single", writeEnv+"setup_privilege_mode\nwrite_environment\nleave_split_mode\n")
	if strings.Contains(stdout+stderr, switchBackWarning) || strings.Contains(stdout, "did not finish") {
		t.Fatalf("a finished switch was finished again:\n%s%s", stdout, stderr)
	}
	checkCalls(t, calls, nil, []string{"systemctl stop sandboxd"})
}

// TestInstallConfigOnlyNeverSwitchesPrivilegeMode: --config-only renders a
// node's files and restarts nothing, so it cannot do a switch's cleanup.
// It refuses a mode other than the one the node runs, in both directions,
// and every run but a full --privilege-mode single while a switch back is
// unfinished. The check runs before anything is written (it is called at
// the top level, right after check_privilege_mode).
func TestInstallConfigOnlyNeverSwitchesPrivilegeMode(t *testing.T) {
	const split, single = "SB_API_PORT=21212\nSB_PRIVILEGE_MODE=split\n", "SB_API_PORT=21212\n"
	for _, tc := range []struct {
		name   string
		env    string
		marker bool
		mode   string
		extra  []string
		refuse string // "" = goes on
	}{
		{name: "config-only: split node asked for single", env: split, mode: "single", extra: []string{"CONFIG_ONLY", "true"}, refuse: "this node runs split, and this run asks for single"},
		{name: "config-only: single node asked for split", env: single, mode: "split", extra: []string{"CONFIG_ONLY", "true"}, refuse: "this node runs single, and this run asks for split"},
		{name: "config-only: split node in split", env: split, mode: "split", extra: []string{"CONFIG_ONLY", "true"}},
		{name: "config-only: single node in single", env: single, mode: "single", extra: []string{"CONFIG_ONLY", "true"}},
		{name: "config-only: local node", env: single, mode: "single", extra: []string{"CONFIG_ONLY", "true", "LOCAL_MODE", "true"}},
		{name: "full run: split node to single", env: split, mode: "single"},
		{name: "full run: single node to split", env: single, mode: "split"},
		{name: "unfinished: config-only", env: single, marker: true, mode: "single", extra: []string{"CONFIG_ONLY", "true"}, refuse: "did not finish"},
		{name: "unfinished: a split run", env: single, marker: true, mode: "split", refuse: "did not finish"},
		{name: "unfinished: --local", env: single, marker: true, mode: "single", extra: []string{"LOCAL_MODE", "true"}, refuse: "did not finish"},
		{name: "unfinished: a single run finishes it", env: single, marker: true, mode: "single"},
		{name: "unfinished: --cli-only installs no node", env: single, marker: true, mode: "single", extra: []string{"CLI_ONLY", "true", "CONFIG_ONLY", "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSwitchBackHost(t, tc.env)
			if tc.marker {
				mustWrite(t, h.marker, "unfinished\n")
			}
			bash, err := exec.LookPath("bash")
			if err != nil {
				t.Skip("bash not available")
			}
			script := "set -euo pipefail\nPATH='" + h.bin + "'\nLOG='" + filepath.Join(h.dir, "calls.log") + "'\n" +
				"PRIVILEGE_MODE='" + tc.mode + "'\nSANDBOXD_ENV_FILE='" + h.env + "'\nPRIVILEGE_SWITCH_BACK_MARKER='" + h.marker + "'\n" +
				"CLI_ONLY=false\nCONFIG_ONLY=false\nLOCAL_MODE=false\n"
			for i := 0; i+1 < len(tc.extra); i += 2 {
				script += tc.extra[i] + "='" + tc.extra[i+1] + "'\n"
			}
			script += switchBackStubs + h.funcs + "check_privilege_mode_change\necho WENT-ON\n"
			out, err := exec.Command(bash, "-c", script).CombinedOutput()
			if tc.refuse == "" {
				if err != nil || !strings.Contains(string(out), "WENT-ON") {
					t.Fatalf("refused: %v\n%s", err, out)
				}
				return
			}
			if err == nil || strings.Contains(string(out), "WENT-ON") || !strings.Contains(string(out), tc.refuse) {
				t.Fatalf("want a refusal naming %q, got %v\n%s", tc.refuse, err, out)
			}
		})
	}

	// It is wired in before anything is written: at the top level, right
	// after check_privilege_mode, long before apply_config_only.
	src := installShSource(t)
	if !strings.Contains(src, "\ncheck_privilege_mode\ncheck_privilege_mode_change\n") {
		t.Fatal("install.sh no longer calls check_privilege_mode_change right after check_privilege_mode")
	}
	if strings.Index(src, "\ncheck_privilege_mode_change\n") > strings.Index(src, "\n\tapply_config_only\n") {
		t.Fatal("check_privilege_mode_change runs after apply_config_only")
	}
}
