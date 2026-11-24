package safety

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The M1 EKS drill's exit path (k8s/m1/m1-eks.sh), run for real around
// stubs: review of PR #1434. Its EXIT trap read the run's steps from "$*",
// which in a trap is the arguments of the function bash exits from, so a
// command that failed inside a step (cluster.sh up, a Helm install) or a
// Ctrl-C left the cluster up until AWS's 5-hour timer. And its checks ran
// as `( set -e; step ) || rc=$?`, where bash ignores set -e, so a check
// went on past a failed command.

// m1Harness is a bash script holding m1-eks.sh's real step_estimate,
// step_up and stop_run and its whole "running steps" section (run_check,
// check_exit, stop_check, on_exit, the traps and the step loop), around
// stubs that log to $OUT/log. Each stubbed step logs "start <step>"; the
// one FAIL_STEP names then fails the way FAIL_HOW says: cmd (a command
// that fails), return (return 1), sleep (sleeps, for a signal), cordon
// (cordons worker-b in AerolVM and machine-1 in Kubernetes, then a command
// fails), cordonwait (the same cordons, then sleeps) or spawn (starts
// three background children that sleep SPAWN_SLEEP seconds, as f10's
// fills do, and waits) or stopself (logs its pid, then stops itself with
// SIGSTOP, as a check stopped by SIGTTIN at a terminal prompt is). x (what
// runs cluster.sh up) fails for
// FAIL_STEP=up FAIL_HOW=cmd. cost_check returns 4 after the step COST_STOP
// names. The cordon helpers are m1-lib.sh's own, with api and k stubbed.
// DOWN=real swaps the stubbed step_down for m1-eks.sh's own, whose hm
// (Helm) stub reads the terminal; refresh_credentials is m1-lib.sh's own.
func m1Harness(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(k8sFile(t, "m1/m1-eks.sh"))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(src), "\n# --- running steps")
	if i < 0 {
		t.Fatal(`m1-eks.sh has no "# --- running steps" section`)
	}
	var b strings.Builder
	b.WriteString(`set -euo pipefail
SELF="$0"
sd="$OUT"; dry=0; name=m1t-1; HERE="$M1_DIR"; K8S=/nonexistent; refused=0; gated=0; made_here=0
ns=aerolvm-system; workers=aerolvm-workers; release=aerolvm
# on_exit's teardown runs this file again as m1-eks.sh does: <name> <step>.
if [[ "${1:-}" == "$name" ]]; then shift; fi
log() { echo "$*" >> "$OUT/log"; }
say() { log "say $*"; }
result() { log "result $1 $2"; }
diag() { log "diag $1"; }
gw_keeper_start() { :; }
gw_keeper_stop() { log keeper-stop; }
gate() { gated=1; }
cost_check() { [[ "${COST_STOP:-}" != "$1" ]] || return 4; }
workers_in() { echo worker-a; }
api() { log "api $*"; echo 200; echo '{}'; }
k() { log "k $*"; }
x() { log "x $*"; [[ "${FAIL_STEP:-}:${FAIL_HOW:-}" != up:cmd ]]; }
step_down() { log down-start; command sleep 1; log down-done; }
same_account() { :; }
ctx_ok() { :; }
hm() {
  log "hm $*"; echo "hm output $*" >&2
  if [[ -n "${HM_CHILD:-}" ]]; then
    if /bin/bash "$HM_CHILD"; then log "child read the terminal"; else log "child: no terminal"; fi
  fi
  if read -r _ < /dev/tty; then log "hm read the terminal"; else log "hm: no terminal"; fi
}
behave() {
  log "start $1"
  if [[ "${FAIL_STEP:-}" == "$1" ]]; then
    case "${FAIL_HOW:-}" in
      cmd) false; log "after-false $1" ;;
      return) return 1 ;;
      sleep) command sleep 20 ;;
      cordon) api_cordon worker-b; node_cordon machine-1; false; log "after-false $1" ;;
      cordonwait) api_cordon worker-b; node_cordon machine-1; log "cordoned $1"; command sleep 20 ;;
      spawn)
        for _ in 1 2 3; do ( command sleep "$SPAWN_SLEEP"; true ) & done
        log "spawned $1"; wait ;;
      stopself) log "stopping $1 $BASHPID"; kill -STOP "$BASHPID"; log "continued $1" ;;
    esac
  fi
  log "end $1"
}
`)
	for _, s := range []string{"setup", "build", "install", "kernel", "switch1", "shape", "n1", "switch2", "moves", "switch3", "s2", "variants", "f10", "f8", "final", "verifynow"} {
		b.WriteString("step_" + s + "() { behave " + s + "; }\n")
	}
	for _, fn := range []string{"step_estimate", "step_up", "stop_run"} {
		b.WriteString(shellFunc(t, "m1/m1-eks.sh", fn))
	}
	// shellFuncIf: node_cordon, node_uncordon and forget are newer than
	// this harness; the code before them runs without (and shows what it
	// did).
	for _, fn := range []string{"api_cordon", "api_uncordon", "node_cordon", "node_uncordon", "forget", "lift_cordons", "refresh_credentials", "detach"} {
		b.WriteString(shellFuncIf(t, "m1/m1-lib.sh", fn))
	}
	b.WriteString("if [[ \"${DOWN:-}\" == real ]]; then\n" + shellFunc(t, "m1/m1-eks.sh", "step_down") + "fi\n")
	b.WriteString(`# TD_TICKS: a teardown that takes TD_TICKS seconds, a line a second, then
# a last line (for a terminal or a viewer that goes away half way).
if [[ -n "${TD_TICKS:-}" ]]; then
  step_down() {
    log down-start
    local i
    for i in $(seq 1 "$TD_TICKS"); do echo "teardown tick $i"; log "tick $i"; command sleep 1; done
    echo "teardown output last line"
    log down-done
  }
fi
`)
	b.WriteString(shellFuncIf(t, "m1/m1-lib.sh", "teardown_detached") + shellFuncIf(t, "m1/m1-eks.sh", "keep_copy"))
	b.WriteString(`# keep_copy (when the script has it): the teardown runs a copy of this
# file in $sd; ME is the folder this file is in.
ME="$(cd "$(dirname "$0")" && pwd)"
if declare -F keep_copy >/dev/null; then keep_copy; fi
`)
	b.WriteString(string(src[i:]))
	return b.String()
}

type m1Run struct {
	dir string
	cmd *exec.Cmd
}

// startM1 runs the harness with the given steps in its own process group
// (so a "Ctrl-C" can go to the whole group), with a Terraform state in
// $OUT as cluster.sh up leaves one.
func startM1(t *testing.T, steps []string, env ...string) m1Run {
	t.Helper()
	needTools(t, "python3")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte(`{"resources": [{"type": "aws_eks_cluster"}]}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	// From a file: on_exit's teardown runs it again ($0, step teardown).
	harness := writeHarness(t, dir, "m1-eks.sh", m1Harness(t))
	cmd := exec.Command("bash", append([]string{harness}, steps...)...)
	var clean []string
	for _, e := range cleanEnviron() {
		if !strings.HasPrefix(e, "M1_") {
			clean = append(clean, e)
		}
	}
	// A fake aws first on PATH: refresh_credentials is m1-lib.sh's own,
	// and the real aws CLI must never run here.
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte("#!/bin/sh\necho \"aws $*\" >> \"$OUT/log\"\necho 111122223333\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var noPath []string
	for _, e := range clean {
		if !strings.HasPrefix(e, "PATH=") {
			noPath = append(noPath, e)
		}
	}
	cmd.Env = append(append(noPath, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "OUT="+dir, "M1_DIR="+k8sFile(t, "m1")), env...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	return m1Run{dir: dir, cmd: cmd}
}

func (r m1Run) log(t *testing.T) string { return readLog(t, filepath.Join(r.dir, "log")) }

func (r m1Run) waitLog(t *testing.T, line string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(r.log(t), line) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in the log after 20 s:\n%s\n%s", line, r.log(t), readLog(t, filepath.Join(r.dir, "out")))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// end waits up to 30 s for the run to end and returns its exit code.
func (r m1Run) end(t *testing.T) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()
	select {
	case err := <-done:
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(30 * time.Second):
		t.Fatalf("the run did not end in 30 s:\n%s\n%s", r.log(t), readLog(t, filepath.Join(r.dir, "out")))
	}
	return -1
}

// A run that stops part way tears the cluster down when it was `all` (or
// the cost limit stopped it), and only then: whatever stopped it.
func TestM1ExitTearsDownWhatAllMade(t *testing.T) {
	for _, tc := range []struct {
		desc     string
		steps    []string
		env      []string
		teardown bool
		has, not []string
	}{
		{desc: "cluster.sh up fails inside step_up", steps: []string{"all"}, env: []string{"FAIL_STEP=up", "FAIL_HOW=cmd"},
			teardown: true, has: []string{"x /nonexistent/cluster.sh up"}, not: []string{"start setup"}},
		{desc: "a command fails inside a core step", steps: []string{"all"}, env: []string{"FAIL_STEP=install", "FAIL_HOW=cmd"},
			teardown: true, not: []string{"after-false install", "start kernel"}},
		{desc: "a core step returns 1", steps: []string{"all"}, env: []string{"FAIL_STEP=build", "FAIL_HOW=return"},
			teardown: true, not: []string{"start install"}},
		{desc: "the cost limit stops a single-step run", steps: []string{"kernel"}, env: []string{"COST_STOP=kernel"},
			teardown: true, has: []string{"result FAIL run-stopped"}},
		{desc: "a single-step run that fails", steps: []string{"setup"}, env: []string{"FAIL_STEP=setup", "FAIL_HOW=cmd"},
			teardown: false},
		{desc: "M1_KEEP=1 keeps it", steps: []string{"all"}, env: []string{"FAIL_STEP=build", "FAIL_HOW=return", "M1_KEEP=1"},
			teardown: false},
		// The state in $OUT is an older run's: an estimate past the ceiling
		// refuses before cluster.sh up, and never takes that cluster down.
		{desc: "a refused estimate", steps: []string{"all"}, env: []string{"M1_CEILING=1"},
			teardown: false, not: []string{"x /nonexistent/cluster.sh up"}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			r := startM1(t, tc.steps, tc.env...)
			if code := r.end(t); code == 0 {
				t.Errorf("exit 0 from a run that stopped:\n%s", r.log(t))
			}
			log := r.log(t)
			if got := strings.Contains(log, "down-done"); got != tc.teardown {
				t.Errorf("torn down: %v, want %v:\n%s\n%s", got, tc.teardown, log, readLog(t, filepath.Join(r.dir, "out")))
			}
			for _, s := range tc.has {
				if !strings.Contains(log, s) {
					t.Errorf("no %q:\n%s", s, log)
				}
			}
			for _, s := range tc.not {
				if strings.Contains(log, s) {
					t.Errorf("%q, which must not run:\n%s", s, log)
				}
			}
		})
	}
}

// A Ctrl-C (SIGINT to the whole group) during a core step, and during a
// check, tears an `all` run down; a second Ctrl-C and a TERM while down
// runs do not stop it (it runs in a process group of its own).
func TestM1CtrlCInAllTearsDownWhole(t *testing.T) {
	for _, step := range []string{"setup", "kernel"} {
		t.Run(step, func(t *testing.T) {
			r := startM1(t, []string{"all"}, "FAIL_STEP="+step, "FAIL_HOW=sleep")
			r.waitLog(t, "start "+step)
			_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGINT)
			r.waitLog(t, "down-start")
			_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGINT)
			_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGTERM)
			if code := r.end(t); code != 130 {
				t.Errorf("exit %d, want 130", code)
			}
			log := r.log(t)
			if !strings.Contains(log, "down-done") {
				t.Errorf("a second Ctrl-C stopped the teardown:\n%s", log)
			}
			if strings.Contains(log, "end "+step) {
				t.Errorf("the step went on after the Ctrl-C:\n%s", log)
			}
		})
	}
}

// A check that is stopped (SIGTTIN or SIGTTOU: it touched the terminal from
// its background process group, as an MFA prompt of aws eks get-token
// does) keeps the TERM stop_check sends pending; the wait for it never
// ended and the teardown never ran (review of #1439). A Ctrl-C then still
// tears an `all` run down.
func TestM1StoppedOnTheTerminalStillTearsDown(t *testing.T) {
	r := startM1(t, []string{"all"}, "FAIL_STEP=kernel", "FAIL_HOW=stopself")
	r.waitLog(t, "stopping kernel ")
	// The stopped check is in a process group of its own, which the
	// test's cleanup of the run's group would not reach.
	log := r.log(t)
	if f := strings.Fields(log[strings.Index(log, "stopping kernel ")+len("stopping kernel "):]); len(f) > 0 {
		if pid, err := strconv.Atoi(f[0]); err == nil {
			t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL); _ = syscall.Kill(pid, syscall.SIGKILL) })
		}
	}
	time.Sleep(200 * time.Millisecond)
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGINT)
	if code := r.end(t); code != 130 {
		t.Errorf("exit %d, want 130", code)
	}
	if log := r.log(t); !strings.Contains(log, "down-done") {
		t.Errorf("no teardown after a Ctrl-C while a check was stopped:\n%s", log)
	}
}

// A closed terminal (SIGHUP) during a step of an `all` run tears it down
// and exits 129. Before, bash ended on SIGHUP and ran on_exit with status
// 0, so it did not tear down.
func TestM1HangupInAllTearsDown(t *testing.T) {
	r := startM1(t, []string{"all"}, "FAIL_STEP=setup", "FAIL_HOW=sleep")
	r.waitLog(t, "start setup")
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGHUP)
	if code := r.end(t); code != 129 {
		t.Errorf("exit %d, want 129", code)
	}
	if log := r.log(t); !strings.Contains(log, "down-done") {
		t.Errorf("no teardown after a hangup:\n%s", log)
	}
}

// A command that fails inside a check ends that check (a FAIL line), lifts
// the cordons it left (AerolVM's and the machine's), and the run goes on
// to the next check.
func TestM1CheckStopsAtAFailedCommand(t *testing.T) {
	r := startM1(t, []string{"kernel", "shape"}, "FAIL_STEP=kernel", "FAIL_HOW=cordon")
	if code := r.end(t); code != 0 {
		t.Errorf("exit %d, want 0 (a failed check is a FAIL line, not the end of the run)", code)
	}
	log := r.log(t)
	for _, want := range []string{"result FAIL kernel", "api POST /v1/cluster/nodes/worker-b/uncordon", "k uncordon machine-1", "start shape", "end shape"} {
		if !strings.Contains(log, want) {
			t.Errorf("no %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "after-false kernel") || strings.Contains(log, "down-start") {
		t.Errorf("the check went on past the failed command, or the run tore down:\n%s", log)
	}
}

// A check stopped by a Ctrl-C in a run that is not `all` leaves nothing
// behind: no child process (f10's background fills outlived it by up to a
// minute), and neither its AerolVM cordon nor a switch's Kubernetes cordon
// of the machine (review of #1434).
func TestM1StoppedCheckLeavesNothing(t *testing.T) {
	needTools(t, "pgrep")
	t.Run("background children", func(t *testing.T) {
		// A sleep length no other process uses, to find the children by.
		marker := fmt.Sprintf("%d.%03d", 40+os.Getpid()%50, time.Now().Nanosecond()/1e6)
		r := startM1(t, []string{"f10"}, "FAIL_STEP=f10", "FAIL_HOW=spawn", "SPAWN_SLEEP="+marker)
		r.waitLog(t, "spawned f10")
		if out, _ := exec.Command("pgrep", "-f", "sleep "+marker).Output(); len(strings.Fields(string(out))) < 3 {
			t.Fatalf("the children did not start: %q", out)
		}
		_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGINT)
		if code := r.end(t); code != 130 {
			t.Errorf("exit %d, want 130", code)
		}
		var left []byte
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if left, _ = exec.Command("pgrep", "-f", "sleep "+marker).Output(); len(strings.TrimSpace(string(left))) == 0 {
				break
			}
		}
		if len(strings.TrimSpace(string(left))) != 0 {
			for _, pid := range strings.Fields(string(left)) {
				if n, err := strconv.Atoi(pid); err == nil {
					_ = syscall.Kill(n, syscall.SIGKILL)
				}
			}
			t.Errorf("children of the stopped check still run: pids %s", strings.Fields(string(left)))
		}
	})
	t.Run("cordons", func(t *testing.T) {
		r := startM1(t, []string{"switch1"}, "FAIL_STEP=switch1", "FAIL_HOW=cordonwait")
		r.waitLog(t, "cordoned switch1")
		_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGINT)
		if code := r.end(t); code != 130 {
			t.Errorf("exit %d, want 130", code)
		}
		log := r.log(t)
		for _, want := range []string{"api POST /v1/cluster/nodes/worker-b/uncordon", "k uncordon machine-1"} {
			if !strings.Contains(log, want) {
				t.Errorf("no %q after the stop:\n%s", want, log)
			}
		}
		if strings.Contains(log, "down-start") {
			t.Errorf("a single-step run tore down:\n%s", log)
		}
	})
}

// gw_keeper_stop signals only what this run started: a pid in its files
// that now belongs to another process is left alone.
func TestM1KeeperStopKillsOnlyItsOwn(t *testing.T) {
	needTools(t, "ps")
	sd := t.TempDir()
	start := func(argv0 string) *exec.Cmd {
		c := exec.Command("bash", "-c", `exec -a "$0" sleep 30`, argv0)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _, _ = c.Process.Wait() })
		return c
	}
	other := start("sleep")
	keeper := start("bash m1-eks.sh m1t-1 all")
	stranger := start("kubectl --kubeconfig /elsewhere/kubeconfig -n aerolvm-system port-forward svc/aerolvm-gateway 21410:21212")
	forward := start("kubectl --kubeconfig " + sd + "/kubeconfig -n aerolvm-system port-forward svc/aerolvm-gateway 21410:21212")
	stop := func(keeperPid, kubectlPid int) {
		t.Helper()
		for f, pid := range map[string]int{"gw-keeper.pid": keeperPid, "gw-kubectl.pid": kubectlPid} {
			if err := os.WriteFile(filepath.Join(sd, f), []byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		script := "set -euo pipefail\nsd=\"$SD\"; name=m1t-1; gw_lport=21410; gwkeeper=\"\"\n" +
			shellFunc(t, "m1/m1-lib.sh", "pid_runs") + shellFunc(t, "m1/m1-lib.sh", "gw_keeper_stop") + "gw_keeper_stop\n"
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(cleanEnviron(), "SD="+sd)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("gw_keeper_stop: %v\n%s", err, out)
		}
	}
	// alive: the process runs (a killed child stays a zombie until waited
	// for: that counts as gone).
	alive := func(c *exec.Cmd) bool {
		p, _ := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(c.Process.Pid)).Output()
		st := strings.TrimSpace(string(p))
		return st != "" && !strings.HasPrefix(st, "Z")
	}
	gone := func(c *exec.Cmd) bool {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if !alive(c) {
				return true
			}
		}
		return false
	}
	// Pids now held by a plain sleep and by another run's port-forward.
	stop(other.Process.Pid, stranger.Process.Pid)
	time.Sleep(300 * time.Millisecond)
	if !alive(other) || !alive(stranger) {
		t.Fatal("gw_keeper_stop killed a process that is not this run's keeper or port-forward")
	}
	// This run's own.
	stop(keeper.Process.Pid, forward.Process.Pid)
	if !gone(keeper) || !gone(forward) {
		t.Error("gw_keeper_stop left this run's keeper or port-forward running")
	}
	for _, f := range []string{"gw-keeper.pid", "gw-kubectl.pid"} {
		if b := readLog(t, filepath.Join(sd, f)); strings.TrimSpace(b) != "" {
			t.Errorf("%s not emptied: %q", f, b)
		}
	}
}
