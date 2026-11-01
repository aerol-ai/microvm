package safety

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// install.sh writes sandboxd-healthcheck, which a 30-second timer runs. Two
// live incidents shape it:
//
//   - UC-301: a node whose key store was unreachable at boot (wrapped
//     server-key custody, plans/customer-key-custody.md §3) fails its starts
//     past systemd's StartLimitBurst and is then never restarted by systemd
//     again. The script must start a FAILED unit again, and must leave alone
//     a unit an operator stopped (inactive).
//   - The bank flagship ramp (2026-11-01): one /health probe that timed out
//     under a list storm restarted an alive, busy node; the restart's stop
//     ran into SIGKILL, and the next timer run — due at once — saw the new
//     daemon 50 ms into its boot, got "connection refused", and restarted it
//     again. The script must restart only a daemon that has stopped
//     answering its liveness socket for 3 probes in a row over 90 s, of the
//     same run, past its boot grace, with no restart already under way.
//
// Checked here against fake systemctl, curl, ps, date, flock and logger on
// PATH; each case runs the script once per timer tick against one state
// directory, as the timer does.

const fakeSystemctl = `#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$FAKE_LOG"
case "$1" in
  is-failed) [[ "$FAKE_UNIT" == failed ]] ;;
  show)
    case "$3" in
      ActiveState) printf '%s\n' "$FAKE_UNIT" ;;
      MainPID) printf '4242\n' ;;
      InvocationID)
        # FAKE_INVOCATION_LATER, when set, is what every read after the
        # first returns: a restart that began while the probe ran.
        n=$(cat "$FAKE_DIR/inv-reads" 2>/dev/null || echo 0)
        echo $((n + 1)) >"$FAKE_DIR/inv-reads"
        if [[ "$n" -gt 0 && -n "${FAKE_INVOCATION_LATER:-}" ]]; then
          printf '%s\n' "$FAKE_INVOCATION_LATER"
        else
          printf '%s\n' "$FAKE_INVOCATION"
        fi ;;
    esac ;;
  list-jobs) [[ -z "${FAKE_JOBS:-}" ]] || printf '%s\n' "$FAKE_JOBS" ;;
  *) exit 0 ;;
esac
`

const fakeCurl = `#!/usr/bin/env bash
printf 'curl %s\n' "$*" >>"$FAKE_LOG"
case " $* " in
  *" --unix-socket "*) [[ "$FAKE_LIVE" == 1 ]] || exit 28 ;;
  *) [[ "$FAKE_HEALTHY" == 1 ]] || exit 7 ;;
esac
`

const fakeLogger = `#!/usr/bin/env bash
printf 'logger %s\n' "$*" >>"$FAKE_LOG"
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

// watchdogRig is one node: fake tools on PATH, a liveness socket path, and a
// state directory that survives between ticks.
type watchdogRig struct {
	t      *testing.T
	script string
	bin    string
	dir    string
	socket string
}

func newWatchdogRig(t *testing.T) *watchdogRig {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakes := map[string]string{
		"systemctl": fakeSystemctl,
		"curl":      fakeCurl,
		"logger":    fakeLogger,
		// ps -o etimes= -p PID: the daemon's age in seconds.
		"ps": "#!/usr/bin/env bash\nprintf '%s\\n' \"${FAKE_AGE:-3600}\"\n",
		// date +%s: the tick's clock.
		"date":  "#!/usr/bin/env bash\nprintf '%s\\n' \"$FAKE_NOW\"\n",
		"flock": "#!/usr/bin/env bash\nexit 0\n",
	}
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(dir, "sandboxd-healthcheck")
	if err := os.WriteFile(script, []byte(healthcheckScript(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	// A Unix socket path must stay short (about 104 bytes on macOS).
	sockDir, err := os.MkdirTemp("", "wd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	return &watchdogRig{t: t, script: script, bin: bin, dir: dir, socket: filepath.Join(sockDir, "live.sock")}
}

// withSocket makes the liveness socket exist, as a daemon that has one does.
func (r *watchdogRig) withSocket() {
	r.t.Helper()
	ln, err := net.Listen("unix", r.socket)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = ln.Close() })
}

// tick is one timer run. It returns the calls the script made.
type tick struct {
	unit       string // the unit's ActiveState ("failed" for is-failed)
	live       bool   // the liveness probe answers
	healthy    bool   // /health answers (the fallback probe)
	now        int    // date +%s
	age        int    // the daemon's age in seconds
	invocation string
	later      string // InvocationID on every read after the first
	jobs       string // queued jobs on the unit
}

func (r *watchdogRig) tick(tk tick) string {
	r.t.Helper()
	log := filepath.Join(r.t.TempDir(), "log")
	if tk.invocation == "" {
		tk.invocation = "inv-a"
	}
	if tk.age == 0 {
		tk.age = 3600
	}
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	fakeDir := r.t.TempDir()
	cmd := exec.Command("bash", r.script)
	cmd.Env = append(os.Environ(),
		"PATH="+r.bin+":"+os.Getenv("PATH"),
		"SANDBOXD_HEALTHCHECK_STATE_DIR="+filepath.Join(r.dir, "state"),
		"SB_LIVENESS_SOCKET="+r.socket,
		"FAKE_LOG="+log, "FAKE_DIR="+fakeDir,
		"FAKE_UNIT="+tk.unit, "FAKE_LIVE="+b(tk.live), "FAKE_HEALTHY="+b(tk.healthy),
		"FAKE_NOW="+strconv.Itoa(tk.now), "FAKE_AGE="+strconv.Itoa(tk.age),
		"FAKE_INVOCATION="+tk.invocation, "FAKE_INVOCATION_LATER="+tk.later, "FAKE_JOBS="+tk.jobs,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		r.t.Fatalf("healthcheck exited %v:\n%s", err, out)
	}
	calls, _ := os.ReadFile(log)
	return string(calls)
}

const restartCall = "systemctl --no-block restart sandboxd.service"

func mustCall(t *testing.T, calls string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(calls, w) {
			t.Errorf("want a call %q; calls:\n%s", w, calls)
		}
	}
}

func mustNotCall(t *testing.T, calls string, never ...string) {
	t.Helper()
	for _, n := range never {
		if strings.Contains(calls, n) {
			t.Errorf("unexpected call %q; calls:\n%s", n, calls)
		}
	}
}

func TestHealthcheckRestartsAFailedUnitOnly(t *testing.T) {
	cases := []struct {
		name        string
		tk          tick
		want, never []string
	}{
		{name: "failed past the start limit is started again", tk: tick{unit: "failed"},
			want: []string{"systemctl reset-failed sandboxd.service", "systemctl start sandboxd.service"}, never: []string{"curl ", "restart"}},
		{name: "stopped by an operator is left alone", tk: tick{unit: "inactive"},
			never: []string{"reset-failed", "systemctl start", "restart", "curl "}},
		{name: "a start under way is left alone", tk: tick{unit: "activating"},
			never: []string{"systemctl start", "restart", "curl "}},
		{name: "a stop under way is left alone", tk: tick{unit: "deactivating"},
			never: []string{"systemctl start", "restart", "curl "}},
		{name: "a queued restart is not doubled", tk: tick{unit: "active", jobs: "1234 sandboxd.service restart waiting"},
			never: []string{"restart sandboxd", "curl "}},
		{name: "active and alive is left alone", tk: tick{unit: "active", live: true},
			want: []string{"curl ", "--unix-socket"}, never: []string{"reset-failed", "systemctl start", "restart"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newWatchdogRig(t)
			rig.withSocket()
			calls := rig.tick(tc.tk)
			mustCall(t, calls, tc.want...)
			mustNotCall(t, calls, tc.never...)
		})
	}
}

// The ramp's failure: a daemon slow to answer once is busy, not dead. Only a
// streak of 3 failed probes of one run, over at least 90 s, restarts it, and
// the restart does not wait for systemd (a 30 s stop must not keep the
// watchdog running into its own next tick).
func TestHealthcheckRestartsOnlyAfterAStreakOverTime(t *testing.T) {
	rig := newWatchdogRig(t)
	rig.withSocket()
	for i, now := range []int{1000, 1030, 1060} {
		calls := rig.tick(tick{unit: "active", now: now})
		mustCall(t, calls, "--unix-socket", "liveness probe failed ("+strconv.Itoa(i+1)+" in a row")
		mustNotCall(t, calls, "restart sandboxd")
	}
	calls := rig.tick(tick{unit: "active", now: 1090})
	mustCall(t, calls, restartCall, "4 times in a row over 90s")
	mustNotCall(t, calls, "systemctl restart sandboxd.service")

	// The streak was cleared with the restart: the next failure starts over.
	calls = rig.tick(tick{unit: "active", now: 1120})
	mustCall(t, calls, "liveness probe failed (1 in a row")
	mustNotCall(t, calls, "restart sandboxd")
}

// Three quick failures are not enough on their own: the window matters, so a
// burst of slow answers inside one minute never restarts.
func TestHealthcheckNeedsTheWholeWindow(t *testing.T) {
	rig := newWatchdogRig(t)
	rig.withSocket()
	for _, now := range []int{1000, 1010, 1020, 1030, 1040, 1080} {
		mustNotCall(t, rig.tick(tick{unit: "active", now: now}), "restart sandboxd")
	}
	mustCall(t, rig.tick(tick{unit: "active", now: 1090}), restartCall)
}

// One answered probe ends the streak.
func TestHealthcheckAnAnswerResetsTheStreak(t *testing.T) {
	rig := newWatchdogRig(t)
	rig.withSocket()
	for _, tk := range []tick{
		{unit: "active", now: 1000}, {unit: "active", now: 1030}, {unit: "active", now: 1060, live: true},
		{unit: "active", now: 1090}, {unit: "active", now: 1120},
	} {
		mustNotCall(t, rig.tick(tk), "restart sandboxd")
	}
}

// Failures of an earlier run of the daemon say nothing about the new one: a
// streak is tied to the unit's InvocationID.
func TestHealthcheckStreakBelongsToOneDaemonRun(t *testing.T) {
	rig := newWatchdogRig(t)
	rig.withSocket()
	for _, now := range []int{1000, 1030, 1060} {
		rig.tick(tick{unit: "active", now: now, invocation: "inv-a"})
	}
	calls := rig.tick(tick{unit: "active", now: 1090, invocation: "inv-b"})
	mustCall(t, calls, "liveness probe failed (1 in a row")
	mustNotCall(t, calls, "restart sandboxd")
}

// The ramp's second restart, replayed: right after a restart the new daemon
// has no listener yet. Whatever it answers, a daemon in its first two
// minutes is never restarted — and with no liveness socket the probe falls
// back to /health on the API port.
func TestHealthcheckNeverRestartsABootingDaemon(t *testing.T) {
	rig := newWatchdogRig(t) // no socket: the daemon has not made it yet
	for i, now := range []int{1000, 1030, 1060, 1090, 1110} {
		calls := rig.tick(tick{unit: "active", now: now, age: 5 + 25*i, invocation: "inv-new"})
		mustCall(t, calls, "curl ", "127.0.0.1:21212/health", "never restarted")
		mustNotCall(t, calls, "restart sandboxd", "--unix-socket")
	}
	// Past the grace, the same unanswered streak restarts it.
	mustCall(t, rig.tick(tick{unit: "active", now: 1140, age: 150, invocation: "inv-new"}), restartCall)
}

// A restart that began while the probe ran is not repeated.
func TestHealthcheckLastLookBeforeRestarting(t *testing.T) {
	rig := newWatchdogRig(t)
	rig.withSocket()
	for _, now := range []int{1000, 1030, 1060} {
		rig.tick(tick{unit: "active", now: now})
	}
	calls := rig.tick(tick{unit: "active", now: 1090, later: "inv-b"})
	mustNotCall(t, calls, "restart sandboxd")
}

// An old daemon (or SB_LIVENESS_SOCKET=off) has no socket: /health is the
// probe, with the same streak rule.
func TestHealthcheckFallsBackToHealthWithoutASocket(t *testing.T) {
	rig := newWatchdogRig(t)
	calls := rig.tick(tick{unit: "active", healthy: true, now: 1000})
	mustCall(t, calls, "127.0.0.1:21212/health")
	mustNotCall(t, calls, "--unix-socket", "restart sandboxd")
	for _, now := range []int{1030, 1060, 1090} {
		mustNotCall(t, rig.tick(tick{unit: "active", now: now}), "restart sandboxd")
	}
	mustCall(t, rig.tick(tick{unit: "active", now: 1120}), restartCall)
}
