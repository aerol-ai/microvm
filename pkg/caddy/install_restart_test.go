package caddy

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// installShFunctions returns the source of install.sh's top-level functions
// names, cut the way renderInstall cuts them: a function runs to the next
// top-level function definition.
func installShFunctions(t *testing.T, raw string, names ...string) string {
	t.Helper()
	nextFunc := regexp.MustCompile(`\n[a-z_]+\(\) \{\n`)
	var out strings.Builder
	for _, name := range names {
		start := strings.Index(raw, "\n"+name+"() {\n")
		if start < 0 {
			t.Fatalf("install.sh has no %s()", name)
		}
		body := raw[start+1:]
		if loc := nextFunc.FindStringIndex(body[len(name)+5:]); loc != nil {
			body = body[:len(name)+5+loc[0]+1]
		}
		out.WriteString(body)
	}
	return out.String()
}

// A re-run of install.sh used to leave a running sandboxd on its old
// settings: `systemctl enable --now` only starts a stopped unit. Under
// --pat-scope host that was an outage, because Caddy came back pointed at a
// public socket the old process never made. restart_sandboxd_if_reconfigured
// restarts sandboxd only when it was running and the run changed its
// settings file or unit, and waits for it (and its socket) before Caddy
// starts. These cases run install.sh's real functions with systemctl, curl
// and sleep replaced by bash functions.
func TestInstallRestartsSandboxdOnlyWhenARerunChangedIt(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	funcs := installShFunctions(t, string(raw), "sandboxd_config_fingerprint", "record_sandboxd_state",
		"wait_for_sandboxd_ready", "restart_sandboxd_if_reconfigured")

	cases := []struct {
		name         string
		active       bool
		envBefore    string // "" = no file yet
		envAfter     string
		unitBefore   string
		unitAfter    string
		patScope     string
		socket       bool // the restarted sandboxd makes its public socket
		wantRestart  bool
		wantWarning  bool
		wantHealthUp bool
	}{
		{name: "fresh install", active: false, envAfter: "SB_PAT_TOKEN=a\n", unitAfter: "unit-1", patScope: "any"},
		{name: "stopped unit", active: false, envBefore: "SB_PAT_TOKEN=a\n", envAfter: "SB_PAT_TOKEN=b\n", unitBefore: "unit-1", unitAfter: "unit-1", patScope: "any"},
		{name: "re-run that changes nothing", active: true, envBefore: "SB_PAT_TOKEN=a\n", envAfter: "SB_PAT_TOKEN=a\n", unitBefore: "unit-1", unitAfter: "unit-1", patScope: "any"},
		{name: "re-run that changes the settings", active: true, envBefore: "SB_PAT_TOKEN=a\n", envAfter: "SB_PAT_TOKEN=a\nSB_PAT_SCOPE=any\n", unitBefore: "unit-1", unitAfter: "unit-1", patScope: "any",
			wantRestart: true, wantHealthUp: true},
		{name: "re-run that changes the unit", active: true, envBefore: "SB_PAT_TOKEN=a\n", envAfter: "SB_PAT_TOKEN=a\n", unitBefore: "unit-1", unitAfter: "unit-2", patScope: "any",
			wantRestart: true, wantHealthUp: true},
		{name: "--pat-scope host, socket made", active: true, envBefore: "SB_PAT_TOKEN=a\n", envAfter: "SB_PAT_TOKEN=a\nSB_PAT_SCOPE=host\n", unitBefore: "unit-1", unitAfter: "unit-1", patScope: "host", socket: true,
			wantRestart: true, wantHealthUp: true},
		{name: "--pat-scope host, no socket", active: true, envBefore: "SB_PAT_TOKEN=a\n", envAfter: "SB_PAT_TOKEN=a\nSB_PAT_SCOPE=host\n", unitBefore: "unit-1", unitAfter: "unit-1", patScope: "host",
			wantRestart: true, wantWarning: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env, unit := filepath.Join(dir, "sandboxd.env"), filepath.Join(dir, "sandboxd.service")
			// A unix socket path must stay under ~104 bytes; t.TempDir can be
			// longer on macOS.
			sockDir, err := os.MkdirTemp("", "isr")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
			sock := filepath.Join(sockDir, "api.sock")
			if tc.socket {
				l, err := net.Listen("unix", sock)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = l.Close() })
			}
			for path, content := range map[string]string{env: tc.envBefore, unit: tc.unitBefore} {
				if content != "" {
					if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			active := "false"
			if tc.active {
				active = "true"
			}
			script := "set -euo pipefail\n" +
				"SANDBOXD_ENV_FILE='" + env + "'\nSANDBOXD_UNIT_FILE='" + unit + "'\n" +
				"SANDBOXD_HEALTH_URL='http://127.0.0.1:21212/health'\nSANDBOXD_READY_TRIES=3\n" +
				"SANDBOXD_WAS_ACTIVE=false\nSANDBOXD_CONFIG_BEFORE=''\n" +
				"PAT_SCOPE='" + tc.patScope + "'\nPUBLIC_API_SOCKET='" + sock + "'\n" +
				"LOG='" + filepath.Join(dir, "calls.log") + "'\nUP='" + filepath.Join(dir, "up") + "'\n" +
				funcs +
				// The stubs. sandboxd answers /health only once restarted.
				"systemctl() { echo \"systemctl $*\" >> \"$LOG\"; case \"$*\" in\n" +
				"  'is-active --quiet sandboxd') [[ '" + active + "' == true ]] ;;\n" +
				"  'restart sandboxd') : > \"$UP\" ;;\n" +
				"esac; }\n" +
				"curl() { echo \"curl $*\" >> \"$LOG\"; [[ -f \"$UP\" ]]; }\n" +
				"sleep() { echo \"sleep $*\" >> \"$LOG\"; }\n" +
				"record_sandboxd_state\n" +
				"printf '%s' '" + tc.envAfter + "' > \"$SANDBOXD_ENV_FILE\"\n" +
				"printf '%s' '" + tc.unitAfter + "' > \"$SANDBOXD_UNIT_FILE\"\n" +
				"restart_sandboxd_if_reconfigured\n" +
				"echo DONE\n"
			cmd := exec.Command(bash, "-c", script)
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("run: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "DONE") {
				t.Fatalf("the install did not continue past the restart step: %s", stdout.String())
			}
			calls, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
			restarted := strings.Contains(string(calls), "systemctl restart sandboxd")
			if restarted != tc.wantRestart {
				t.Fatalf("restarted = %v, want %v; calls:\n%s", restarted, tc.wantRestart, calls)
			}
			if got := strings.Contains(stderr.String(), "warning: sandboxd is not answering"); got != tc.wantWarning {
				t.Fatalf("warning = %v, want %v; stderr: %s", got, tc.wantWarning, stderr.String())
			}
			if tc.wantHealthUp && !strings.Contains(string(calls), "curl -fsS --max-time 2 -o /dev/null http://127.0.0.1:21212/health") {
				t.Fatalf("the restart did not wait for /health; calls:\n%s", calls)
			}
			if tc.wantWarning && strings.Count(string(calls), "sleep 1") != 3 {
				t.Fatalf("the wait for the socket is not bounded by SANDBOXD_READY_TRIES; calls:\n%s", calls)
			}
		})
	}
}

// The order is what fixes the outage: the state is recorded before the
// settings are written, and the restart runs after daemon-reload and before
// Caddy starts, on both Linux install paths.
func TestInstallRestartsSandboxdBeforeCaddyStarts(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	inOrder := func(t *testing.T, from int, steps ...string) {
		t.Helper()
		at := from
		for _, step := range steps {
			i := strings.Index(src[at:], step)
			if i < 0 {
				t.Fatalf("after offset %d install.sh does not run %q next; want the order %q", at, step, steps)
			}
			at += i + len(step)
		}
	}
	local := strings.Index(src, "\tinstall_binaries\n\trecord_sandboxd_state\n\twrite_local_environment\n")
	if local < 0 {
		t.Fatal("the local install path does not record sandboxd's state right before writing its settings")
	}
	inOrder(t, local, "write_local_environment", "write_local_systemd_unit", "systemctl daemon-reload",
		"restart_sandboxd_if_reconfigured", "systemctl enable --now sandboxd sandboxd-healthcheck.timer")

	main := strings.Index(src, "\ninstall_binaries\nrecord_sandboxd_state\nwrite_environment\n")
	if main < 0 {
		t.Fatal("the main install path does not record sandboxd's state right before writing its settings")
	}
	inOrder(t, main, "write_environment", "write_caddyfile", "write_systemd_unit", "systemctl daemon-reload",
		"restart_sandboxd_if_reconfigured", "systemctl enable --now caddy sandboxd sandboxd-healthcheck.timer")
}
