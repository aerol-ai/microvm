package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The real on_exit, run_check, check_exit, stop_check, step_scale,
// scale_back and step_gateways11 from eks-bank.sh, with stubs for what
// reaches the cluster: what a stopped check puts back, and that the
// teardown runs whole (review of #1363, items 1-4).

// undoHarness is a bash script holding eks-bank.sh's real functions around
// stubs that log to $OUT/log. RUN_ALL decides whether on_exit tears down;
// $OUT/workers holds the worker counts ("fail" fails one read, then the
// counts are $OUT/workers-after-fail's, or 12 0 12); the drills stub sleeps
// DRILL_SLEEP seconds, fails ecr-storm when ECR_FAIL is set, and with
// BACK_FAIL set makes the first read on the way back fail. extra is bash
// that runs after the real functions (more stubs, a check of the test's
// own).
func undoHarness(t *testing.T, check string) string {
	t.Helper()
	return undoHarnessWith(t, "", check)
}

func undoHarnessWith(t *testing.T, extra, check string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(`set -euo pipefail
sd="$OUT"; dry=0; name=bank-1; ns=aerolvm-system; workers=aerolvm-workers; release=aerolvm; cname=aerolvm; HELM=true
base_workers=6; peak_workers=60; scale_minutes=60; back_minutes=20; gateways_peak=11
run_all="$RUN_ALL"; refused=0; downed=0; made_here=1; gated=1
in_scale=""; drill_pid=""; check_pid=""; check_rc=0; check_undo=""; failed_checks=()
step_drills=(setup static pull-storm slo-breach large-layers ecr-push); peak_drills=(ecr-storm thresholds)
all_drills=("${step_drills[@]}" "${peak_drills[@]}"); run_drills_list=("${step_drills[@]}"); run_peak_list=("${peak_drills[@]}")
refused=0; refuse() { log "refused: $*"; refused=1; exit 2; }
log() { echo "$*" >> "$OUT/log"; }
say() { :; }
result() { echo "$1 $2 $3" >> "$OUT/bank.txt"; }
now() { date +%s; }
sleep() { command sleep 0.1; }
api_token() { :; }
cap_schedule() { log cap_schedule; }
nodepool() { log "nodepool $1"; }
timeline() { :; }
set_min_workers() { log "set_min_workers $1"; }
wait_until() { return 0; }
end_extra_machines() { log end_extra_machines; }
x() { log "x $*"; }
tfout() { echo us-east-1; }
chart_dir() { echo /chart; }
hm() { log "hm $*"; }
kr() { :; }
serving() { echo 11; }
gateways_back() { log gateways_back; }
step_down() { log down-start; command sleep 2; log down-done; }
workers_now() {
  local v; v="$(cat "$OUT/workers")"
  if [[ "$v" == fail ]]; then cat "$OUT/workers-after-fail" 2>/dev/null > "$OUT/workers" || echo "12 0 12" > "$OUT/workers"; log "workers_now failed"; return 1; fi
  echo "$v"
}
fill_plan() { echo "2 55"; }
drills() {
  log "drills $1"
  # INTERRUPT_UNFILL: a TERM lands on the check while its normal end runs
  # scale_back (the first unfill only).
  if [[ "$1" == unfill && -n "${INTERRUPT_UNFILL:-}" && ! -f "$OUT/interrupted" ]]; then
    : > "$OUT/interrupted"
    kill -TERM "$BASHPID"
  fi
  case "$1" in
    ecr-storm) [[ -z "${ECR_FAIL:-}" ]] || return 3 ;;
    thresholds) if [[ -n "${BACK_FAIL:-}" ]]; then echo "6 0 6" > "$OUT/workers-after-fail"; echo fail > "$OUT/workers"; else echo "6 0 6" > "$OUT/workers"; fi ;;
  esac
  # What a drills-eks.sh the undo starts would inherit for TERM.
  [[ "$1" != unfill ]] || bash -c 'trap -p TERM' > "$OUT/unfill-term"
  [[ "$1" == unfill ]] || { command sleep "${DRILL_SLEEP:-0}" & echo $! >> "$OUT/drill-sleeps"; wait; }
}
`)
	for _, fn := range []string{"kill_tree", "run_check", "check_exit", "stop_check", "on_exit",
		"stop_scale_drills", "scale_back", "read_workers", "step_scale", "step_gateways11"} {
		b.WriteString(shellFunc(t, "eks-bank.sh", fn))
	}
	// Newer than some of the tests that use this harness: the code before
	// them runs without (and those tests show what it did).
	for _, fn := range []string{"peak_unfinished", "parse_drills"} {
		b.WriteString(shellFuncIf(t, "eks-bank.sh", fn))
	}
	b.WriteString(extra)
	b.WriteString(`
# The scale step's normal end alone: scale_back, as step_scale calls it.
scale_ending() { in_scale=1; scaled_back=0; scale_back; in_scale=""; }
trap on_exit EXIT
trap 'exit 130' INT TERM
echo $$ > "$OUT/run.pid"
run_check ` + check + `
log "after the check"
`)
	return b.String()
}

type undoRun struct {
	dir string
	cmd *exec.Cmd
}

// startUndo starts the harness in its own process group (so a "Ctrl-C" can
// be sent to the whole group), output to a file: a process that outlives
// the run must not hang the test on a pipe.
func startUndo(t *testing.T, check, workers string, env ...string) undoRun {
	t.Helper()
	return startUndoWith(t, "", check, workers, env...)
}

func startUndoWith(t *testing.T, extra, check, workers string, env ...string) undoRun {
	t.Helper()
	dir := t.TempDir()
	for f, body := range map[string]string{
		"run.tfvars.json":   `{"name": "bank-1", "ttl": "2099-01-01T00:00:00Z"}`,
		"terraform.tfstate": `{"resources": [{"type": "aws_vpc"}]}`,
		"workers":           workers,
	} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	cmd := exec.Command("bash", "-c", undoHarnessWith(t, extra, check))
	cmd.Env = append(append(cleanEnviron(), "OUT="+dir), env...)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Whatever a broken harness left: the group, by its id (this test
		// started it).
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	return undoRun{dir: dir, cmd: cmd}
}

// waitLog waits up to 15 s for line in the log.
func (r undoRun) waitLog(t *testing.T, line string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(readLog(t, filepath.Join(r.dir, "log")), line) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in the log after 15 s:\n%s\n%s", line, readLog(t, filepath.Join(r.dir, "log")), readLog(t, filepath.Join(r.dir, "out")))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// end waits up to 20 s for the run to end.
func (r undoRun) end(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = r.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("the run did not end in 20 s:\n%s", readLog(t, filepath.Join(r.dir, "log")))
	}
}

// after returns the log's lines after the first that starts with marker.
func (r undoRun) after(t *testing.T, marker string) string {
	t.Helper()
	log := readLog(t, filepath.Join(r.dir, "log"))
	i := strings.Index(log, marker)
	if i < 0 {
		return ""
	}
	return log[i+len(marker):]
}

// sleepsGone reports whether every sleep the drills stub started is gone.
func (r undoRun) sleepsGone(t *testing.T) bool {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	for _, l := range strings.Fields(readLog(t, filepath.Join(r.dir, "drill-sleeps"))) {
		if pid, _ := strconv.Atoi(l); pid > 0 && syscall.Kill(pid, 0) == nil {
			return false
		}
	}
	return true
}

// A TERM to a single-step scale run while the peak drills run: on_exit stops
// the check, whose exit handler puts the cell back (the drills stopped, the
// floor to 6, the fill gone, the NodePool's limit down). No teardown.
func TestScaleStoppedPutsTheCellBack(t *testing.T) {
	r := startUndo(t, "scale step_scale", "12 0 12", "RUN_ALL=0", "DRILL_SLEEP=20")
	r.waitLog(t, "drills ecr-storm")
	_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGTERM)
	r.end(t)
	rest := r.after(t, "drills ecr-storm")
	for _, want := range []string{"set_min_workers 6", "drills unfill", "nodepool 32"} {
		if !strings.Contains(rest, want) {
			t.Errorf("after the TERM, no %q:\n%s", want, rest)
		}
	}
	if strings.Contains(rest, "down-start") || strings.Contains(rest, "after the check") {
		t.Errorf("a single-step run tore down, or carried on:\n%s", rest)
	}
	// The undo's children get TERM's default: an ignored TERM is
	// inherited, and a port-forward loop started that way never ended.
	if d := readLog(t, filepath.Join(r.dir, "unfill-term")); strings.TrimSpace(d) != "" {
		t.Errorf("drills unfill ran with TERM set to %q", d)
	}
	if !r.sleepsGone(t) {
		t.Error("a peak drill outlived the run")
	}
}

// The same TERM in `all`: the check only stops its drills (the cell goes
// with the teardown), then down runs whole, a second Ctrl-C to the whole
// group notwithstanding.
func TestScaleStoppedInAllTearsDownWhole(t *testing.T) {
	r := startUndo(t, "scale step_scale", "12 0 12", "RUN_ALL=1", "DRILL_SLEEP=20")
	r.waitLog(t, "drills ecr-storm")
	_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGTERM)
	r.waitLog(t, "down-start")
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGINT)
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGTERM)
	r.end(t)
	rest := r.after(t, "drills ecr-storm")
	if !strings.Contains(rest, "down-done") {
		t.Errorf("a second Ctrl-C stopped the teardown:\n%s", rest)
	}
	if strings.Contains(rest, "set_min_workers 6") || strings.Contains(rest, "drills unfill") {
		t.Errorf("the cell was put back before a teardown:\n%s", rest)
	}
	if !r.sleepsGone(t) {
		t.Error("a peak drill outlived the run")
	}
}

// No signal: a failed worker read in a polling loop is waited out, not the
// end of the step; ecr-storm failing does not skip thresholds, and is
// recorded; a FAIL a check writes itself (scale-peak) stays in bank.txt.
func TestScaleGoesOnPastAFailedReadAndDrill(t *testing.T) {
	r := startUndo(t, "scale step_scale", "fail", "RUN_ALL=0", "ECR_FAIL=1")
	r.end(t)
	log, bank := readLog(t, filepath.Join(r.dir, "log")), readLog(t, filepath.Join(r.dir, "bank.txt"))
	for _, want := range []string{"workers_now failed", "drills ecr-storm", "drills thresholds", "after the check"} {
		if !strings.Contains(log, want) {
			t.Errorf("no %q:\n%s", want, log)
		}
	}
	if !strings.Contains(bank, "FAIL ecr-storm drills-eks.sh ecr-storm exited 3") || strings.Contains(bank, "FAIL scale exited") {
		t.Errorf("bank.txt:\n%s", bank)
	}
}

// A TERM during gateways11's shard-routes: a single-step run puts the
// gateways back to 3; in `all` it does not (the teardown takes them), and
// down runs.
func TestGateways11StoppedPutsTheGatewaysBack(t *testing.T) {
	for _, tc := range []struct {
		runAll string
		back   bool
	}{{"0", true}, {"1", false}} {
		r := startUndo(t, "gateways11 step_gateways11", "12 0 12", "RUN_ALL="+tc.runAll, "DRILL_SLEEP=20")
		r.waitLog(t, "drills shard-routes")
		_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGTERM)
		r.end(t)
		rest := r.after(t, "drills shard-routes")
		if got := strings.Contains(rest, "gateways_back"); got != tc.back {
			t.Errorf("RUN_ALL=%s: gateways put back %v, want %v:\n%s", tc.runAll, got, tc.back, rest)
		}
		if got := strings.Contains(rest, "down-done"); got == tc.back {
			t.Errorf("RUN_ALL=%s: down ran %v:\n%s", tc.runAll, got, rest)
		}
	}
}

// workers_now answers only numbers; anything else, three times, is 1.
func TestWorkersNowNeedsNumbers(t *testing.T) {
	for _, tc := range []struct {
		serving, want string
		code          int
	}{{"7", "7 1 8", 0}, {"", "", 1}, {"Error from server", "", 1}} {
		script := `set -euo pipefail
dry=0; ns=aerolvm-system
say() { :; }
sleep() { :; }
serving() { echo "$SERVING"; }
kr() { case "$*" in *aerolnodes*) echo '{"items": [{"spec": {"role": "worker"}, "status": {"state": "Joining"}, "metadata": {}}]}' ;;
  *nodeclaims*) printf '{"items": [%s]}' "$(for i in 1 2 3 4 5 6 7 8; do printf '{"metadata": {"labels": {"karpenter.sh/nodepool": "gvisor-general"}}}'; [[ $i == 8 ]] || printf ,; done)" ;; esac; }
` + shellFunc(t, "eks-bank.sh", "workers_now") + `
workers_now
`
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(cleanEnviron(), "SERVING="+tc.serving)
		out, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() != tc.code || strings.TrimSpace(string(out)) != tc.want {
			t.Errorf("serving %q: exit %d %q, want %d %q", tc.serving, cmd.ProcessState.ExitCode(), out, tc.code, tc.want)
		}
	}
}

// keep_forward (drills-lib.sh) ends with its owner. A script started with
// INT and TERM ignored (as an undo's child used to be) still stops its
// port-forward loop at exit; and a script killed with no cleanup at all
// leaves no loop behind either.
func TestKeepForwardEndsWithItsOwner(t *testing.T) {
	for _, tc := range []struct {
		desc, end string
		within    time.Duration
	}{
		// cleanup ends the loop and its port-forward at once (KILL, which
		// an ignored TERM cannot block);
		{"its cleanup, with INT and TERM ignored", "exit 0", 2 * time.Second},
		// with no cleanup, the loop sees its owner gone within a round.
		{"killed, no cleanup", "kill -KILL $$", 15 * time.Second},
	} {
		dir, bin := t.TempDir(), t.TempDir()
		// kubectl port-forward that never ends (its signals inherited
		// ignored), and a health check that always answers.
		for n, body := range map[string]string{
			"kubectl": "#!/bin/sh\necho $$ >> \"$OUT/forwards\"\nexec sleep 300\n",
			"curl":    "#!/bin/sh\nexit 0\n",
		} {
			if err := os.WriteFile(filepath.Join(bin, n), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		caller := filepath.Join(dir, "caller.sh")
		body := `set -euo pipefail
HERE="$K8S"; L="$K8S/drills-local"; ROOT="$K8S/../.."; sd="$OUT"; ctx=none; ctl_url=http://127.0.0.1:1
drills_own_steps=""
source "$K8S/drills-lib.sh"
keep_forward drills svc/drills-registry 15999 5001 /mode
echo "${keepers[*]}" > "$OUT/keepers"
` + tc.end + "\n"
		if err := os.WriteFile(caller, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		out, err := os.Create(filepath.Join(dir, "out"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", `trap '' INT TERM; exec bash "$0"`, caller)
		cmd.Env = append(cleanEnviron(), "OUT="+dir, "K8S="+filepath.Dir(k8sFile(t, "drills-lib.sh")),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		cmd.Stdout, cmd.Stderr = out, out
		// In this test's process group, not one of its own: a group that
		// is orphaned when the script ends sends its stopped members HUP
		// and CONT, which would end a keeper cleanup only stopped.
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait()
		out.Close()
		pids := strings.Fields(readLog(t, filepath.Join(dir, "keepers")) + " " + readLog(t, filepath.Join(dir, "forwards")))
		deadline := time.Now().Add(tc.within)
		var left []string
		for {
			left = left[:0]
			for _, p := range pids {
				if pid, _ := strconv.Atoi(p); pid > 0 && syscall.Kill(pid, 0) == nil {
					left = append(left, p)
				}
			}
			if len(left) == 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if len(left) > 0 {
			t.Errorf("%s: still running %s after the script ended: %v", tc.desc, tc.within, left)
		}
		// Whatever is left, this test started it: each goes, by its PID.
		for _, p := range left {
			if pid, _ := strconv.Atoi(p); pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
}

// A TERM that lands while the scale step's normal end runs scale_back: the
// exit handler finishes it. (scale_back marked itself done at its start,
// so the handler skipped the rest: the NodePool's limit stayed at the
// peak's. 2 runs in 30 of TestScaleStoppedPutsTheCellBack hit it.)
func TestScaleBackInterruptedIsFinished(t *testing.T) {
	r := startUndo(t, "scale scale_ending", "12 0 12", "RUN_ALL=0", "INTERRUPT_UNFILL=1")
	r.end(t)
	log := readLog(t, filepath.Join(r.dir, "log"))
	if strings.Count(log, "drills unfill") != 2 || !strings.Contains(log, "nodepool 32") {
		t.Errorf("an interrupted scale-back was not finished:\n%s", log)
	}
}
