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
// find, chown and rm never reach a real file. id finds no sandboxd user, so
// the owner loop is skipped. PATH holds awk alone (env_file_value reads the
// saved mode with it); any other program would fail the run.
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
rm() { echo "rm $*" >>"$LOG"; }
`

// TestInstallWarnsOnSwitchBackToSingle runs install.sh's real
// setup_privilege_mode (which reads the mode the node ran in from
// sandboxd.env) and leave_split_mode, in the order the installer runs them.
// A switch from split back to single prints the warning once: single mode's
// root sandboxd trusts the database and files sandboxd's user wrote. A fresh
// single install, a single node run again, and any run into split print
// nothing.
func TestInstallWarnsOnSwitchBackToSingle(t *testing.T) {
	src := installShSource(t)
	fn := installShFunction(t, src, "env_file_value", "setup_privilege_mode", "forget_single_upgrade_folder", "leave_split_mode")
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("awk not available")
	}

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
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			mustMkdir(t, bin)
			if err := os.Symlink(awk, filepath.Join(bin, "awk")); err != nil {
				t.Fatal(err)
			}
			envFile := filepath.Join(dir, "sandboxd.env")
			if tc.env != "" {
				mustWrite(t, envFile, tc.env)
			}
			calls, stdout, stderr := runInstallSh(t, switchBackStubs+fn+"setup_privilege_mode\nleave_split_mode\n", map[string]string{
				"PATH":                    bin,
				"HOME":                    filepath.Join(dir, "home"),
				"PRIVILEGE_MODE":          tc.mode,
				"SANDBOXD_ENV_FILE":       envFile,
				"SANDBOXD_USER":           "sandboxd",
				"APT_UPDATED":             "true",
				"SPLIT_UPGRADE_STATE_DIR": filepath.Join(dir, "upgrade-state"),
				"ROOTD_BIN_DIR":           filepath.Join(dir, "rootd-bin"),
				"SPLIT_PROCID_DIR":        filepath.Join(dir, "procid"),
			})
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
		})
	}
}
