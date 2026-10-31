package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// install.sh writes sandboxd-healthcheck, which a 30-second timer runs. A
// node whose key store was unreachable at boot (wrapped server-key custody,
// plans/customer-key-custody.md §3) fails its starts past systemd's
// StartLimitBurst and is then never restarted by systemd again: the live
// UC-301 found it staying down after the key store came back. The script
// must start a FAILED unit again, and must leave alone a unit an operator
// stopped (inactive) as well as a healthy one. Checked here against a fake
// systemctl and curl on PATH.

const fakeSystemctl = `#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$FAKE_LOG"
case "$1" in
  is-failed) [[ "$FAKE_UNIT" == failed ]] ;;
  is-active) [[ "$FAKE_UNIT" == active ]] ;;
  *) exit 0 ;;
esac
`

const fakeCurl = `#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$FAKE_LOG"
[[ "$FAKE_HEALTHY" == 1 ]] || exit 7
`

// healthcheckScript is the script install.sh writes, read out of its heredoc.
func healthcheckScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const start = `cat > "$INSTALL_PREFIX/sandboxd-healthcheck" <<'EOF'` + "\n"
	_, body, ok := strings.Cut(string(raw), start)
	if !ok {
		t.Fatal("install.sh no longer writes sandboxd-healthcheck from a heredoc")
	}
	body, _, ok = strings.Cut(body, "\nEOF\n")
	if !ok {
		t.Fatal("the sandboxd-healthcheck heredoc has no end")
	}
	return body + "\n"
}

func TestHealthcheckRestartsAFailedUnitOnly(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"systemctl": fakeSystemctl, "curl": fakeCurl, "logger": "#!/usr/bin/env bash\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(dir, "sandboxd-healthcheck")
	if err := os.WriteFile(script, []byte(healthcheckScript(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, unit, healthy string
		want, never         []string
	}{
		{name: "failed past the start limit is started again", unit: "failed", healthy: "0",
			want: []string{"systemctl reset-failed sandboxd.service", "systemctl start sandboxd.service"}, never: []string{"curl ", "systemctl restart"}},
		{name: "stopped by an operator is left alone", unit: "inactive", healthy: "0",
			never: []string{"reset-failed", "systemctl start", "systemctl restart", "curl "}},
		{name: "active and healthy is left alone", unit: "active", healthy: "1",
			want: []string{"curl "}, never: []string{"reset-failed", "systemctl start", "systemctl restart"}},
		{name: "active and unhealthy is restarted", unit: "active", healthy: "0",
			want: []string{"systemctl restart sandboxd.service"}, never: []string{"reset-failed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "log")
			cmd := exec.Command("bash", script)
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_LOG="+log, "FAKE_UNIT="+tc.unit, "FAKE_HEALTHY="+tc.healthy)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("healthcheck exited %v:\n%s", err, out)
			}
			calls, _ := os.ReadFile(log)
			for _, w := range tc.want {
				if !strings.Contains(string(calls), w) {
					t.Errorf("want a call %q; calls:\n%s", w, calls)
				}
			}
			for _, n := range tc.never {
				if strings.Contains(string(calls), n) {
					t.Errorf("unexpected call %q; calls:\n%s", n, calls)
				}
			}
		})
	}
}
