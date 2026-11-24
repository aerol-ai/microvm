package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A teardown that touches the terminal (review of #1439). m1-eks.sh and
// eks-bank.sh run their teardown as a job in a process group of its own,
// so a second Ctrl-C cannot stop it. A process of a background group that
// reads the terminal is stopped (SIGTTIN), and the run then waited for the
// teardown forever, with the cluster up until AWS's 5-hour timer. The
// realistic trigger: an MFA assume-role profile, whose `aws eks get-token`
// (under kubectl and Helm) prompts on the terminal once its cached
// credentials expire. Now the credentials are refreshed in the foreground
// first (a prompt there can be answered), and the teardown runs with no
// controlling terminal (detach: a session of its own), so a prompt that
// still comes fails at once. Ignoring TTIN and TTOU (#1443) was not
// enough: macOS's bash 3.2 gives a script's children the default back,
// and a program may install its own (review of #1443). The refresh's time
// limit ends aws's whole tree, a prompting credential helper included, and
// puts the terminal's settings back (a killed prompt left echo off).
//
// These run the scripts' real exit paths under a pseudo-terminal (Python's
// pty module), type Ctrl-C, answer the foreground prompt, and check that
// the teardown reaches cluster.sh down (cell.sh down for the bank run).

// ttyDriver forks the run under a pty, waits for cfg.ready in the log,
// types Ctrl-C, answers cfg.prompt with cfg.answer if it shows, and waits
// up to cfg.timeout seconds for the run to end. A run that does not end is
// killed, every process whose command line holds cfg.marker (the harness
// file's name), and reported with each process's state.
const ttyDriver = `
import json, os, pty, select, signal, subprocess, sys, time
cfg = json.load(open(sys.argv[1]))
pid, fd = pty.fork()
if pid == 0:
    os.execvpe(cfg["argv"][0], cfg["argv"], cfg["env"])
screen = b""
def drain(t):
    global screen
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try: screen += os.read(fd, 4096)
            except OSError: return
def log():
    try: return open(cfg["log"]).read()
    except OSError: return ""
def wait_for(s, t):
    end = time.time() + t
    while time.time() < end:
        drain(0.1)
        if s in log(): return True
    return False
res = {"ready": wait_for(cfg["ready"], 30), "answered": False, "ended": False, "code": None, "stuck": [], "killed": []}
if cfg.get("replace"):
    # A new file in the script's place (as a branch switch writes one).
    with open(cfg["replace"] + ".new", "w") as f: f.write(cfg["replace_with"])
    os.replace(cfg["replace"] + ".new", cfg["replace"])
drain(0.3)
os.write(fd, b"\x03")
if cfg.get("prompt") and wait_for(cfg["prompt"], 8):
    os.write(fd, (cfg["answer"] + "\n").encode()); res["answered"] = True
closed = False
if cfg.get("close_at") and wait_for(cfg["close_at"], 20):
    os.close(fd); closed = True
if cfg.get("kill_at") and wait_for(cfg["kill_at"], 20):
    ps = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True).stdout.decode("utf-8", "replace")
    for line in ps.splitlines():
        if cfg["kill_pattern"] in line and "ps -axo" not in line:
            try: os.kill(int(line.split()[0]), signal.SIGKILL); res["killed"].append(line.split()[0])
            except Exception: pass
end = time.time() + cfg["timeout"]
while time.time() < end:
    if closed: time.sleep(0.2)
    else: drain(0.2)
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        res["ended"], res["code"] = True, os.waitstatus_to_exitcode(st); break
# A teardown that goes on after the run (it should not): give it time to
# show in the log.
if cfg.get("settle"):
    t_end = time.time() + cfg["settle"]
    while time.time() < t_end and "down-done" not in log(): time.sleep(0.2)
if not res["ended"]:
    ps = subprocess.run(["ps", "-axo", "pid=,stat=,command="], capture_output=True).stdout.decode("utf-8", "replace")
    for line in ps.splitlines():
        if cfg["marker"] in line:
            res["stuck"].append(" ".join(line.split()[:2]))
            try: os.kill(int(line.split()[0]), signal.SIGKILL)
            except Exception: pass
    try: os.waitpid(pid, 0)
    except Exception: pass
res["screen"] = screen.decode("utf-8", "replace")[-8000:]
print(json.dumps(res))
`

// ttyOpts: what runUnderTTY runs and how. awsMode picks the fake aws's
// behaviour for `sts get-caller-identity`: "" reads an answer from the
// terminal (answered with 246810), "helper" starts a credential helper
// that prompts (getpass) and waits for it, "getpass" prompts itself
// (getpass, echo off); neither of the last two is answered. after, when
// set, is shell that a wrapper runs once the run has ended, while the
// wrapper still holds the terminal (when the terminal's session leader
// ends, its foreground group gets SIGHUP, which would end a left-over
// prompt and hide it).
//
// replaceWith, when set, is written in the harness file's place (a new
// file, as a branch switch writes one) once the run is ready. closeAt
// closes the terminal when its line shows in the log; killAt SIGKILLs every
// process whose command line holds $OUT/teardown.log (the viewer, or the
// tee before it) when its line shows.
type ttyOpts struct {
	args, env             []string
	ready, awsMode, after string
	replaceWith           string
	closeAt, killAt       string
}

// writeHarness writes script to dir/checkout/<name> (the checkout: not
// $OUT, which stands for .state/<name>/, where keep_copy puts its copy),
// with an m1-lib.sh beside it for m1-eks.sh's keep_copy. It returns the
// path.
func writeHarness(t *testing.T, dir, name, script string) string {
	t.Helper()
	co := filepath.Join(dir, "checkout")
	if err := os.MkdirAll(co, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(co, "m1-lib.sh"), []byte("# the harness's functions are in the harness\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(co, name)
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// exit is the run's exit code as text ("none" when it never ended).
func (r ttyResult) exit() string {
	if r.Code == nil {
		return "none"
	}
	return strconv.Itoa(*r.Code)
}

type ttyResult struct {
	Ready, Answered, Ended bool
	Code                   *int
	Stuck, Killed          []string
	Screen                 string
}

// runUnderTTY writes script to dir/<marker>.sh and runs it under the
// driver, with a fake aws first on PATH (see ttyOpts). It returns the
// marker too: every process of the run, the credential helper's
// ($marker-helper) and the teardown child's included, carries it in its
// command line.
func runUnderTTY(t *testing.T, dir, script string, o ttyOpts) (ttyResult, string) {
	t.Helper()
	needTools(t, "python3", "ps")
	marker := fmt.Sprintf("ttyrun-%d-%d", os.Getpid(), time.Now().UnixNano())
	path := writeHarness(t, dir, marker+".sh", script)
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := `#!/bin/bash
echo "aws $*" >> "$OUT/log"
case "$*" in
  *"sts get-caller-identity"*)
    case "${AWS_MODE:-}" in
      helper)
        echo aws-helper >> "$OUT/log"
        python3 -I -c 'import getpass; getpass.getpass("helper code: ")' "$HELPER_MARK"
        echo "aws-helper-ended $?" >> "$OUT/log" ;;
      getpass)
        echo aws-getpass >> "$OUT/log"
        exec python3 -I -c 'import getpass; getpass.getpass("Enter MFA code: ")' ;;
      *)
        echo aws-prompt >> "$OUT/log"
        if IFS= read -r code < /dev/tty; then echo "aws-read $code" >> "$OUT/log"; else echo aws-read-failed >> "$OUT/log"; fi ;;
    esac
    echo 111122223333 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	var clean []string
	for _, e := range cleanEnviron() {
		if !strings.HasPrefix(e, "M1_") && !strings.HasPrefix(e, "PATH=") {
			clean = append(clean, e)
		}
	}
	envMap := map[string]string{}
	base := append(clean, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "OUT="+dir,
		"AWS_MODE="+o.awsMode, "HELPER_MARK="+marker+"-helper")
	for _, e := range append(base, o.env...) {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}
	argv := append([]string{"bash", path}, o.args...)
	if o.after != "" {
		argv = append([]string{"bash", "-c", `bash "$0" "$@"; rc=$?; ` + o.after + `; exit $rc`, path}, o.args...)
	}
	prompt := ""
	if o.awsMode == "" {
		prompt = "aws-prompt"
	}
	c := map[string]any{
		"argv": argv, "env": envMap, "log": filepath.Join(dir, "log"),
		"ready": o.ready, "prompt": prompt, "answer": "246810", "marker": marker, "timeout": 25,
		"close_at": o.closeAt, "kill_at": o.killAt, "kill_pattern": filepath.Join(dir, "teardown.log"),
	}
	if o.closeAt != "" || o.killAt != "" {
		c["settle"] = 8
	}
	if o.replaceWith != "" {
		c["replace"], c["replace_with"] = path, o.replaceWith
	}
	cfg, _ := json.Marshal(c)
	cfgPath := filepath.Join(dir, "driver.json")
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	drv := filepath.Join(dir, "driver.py")
	if err := os.WriteFile(drv, []byte(ttyDriver), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("python3", "-I", drv, cfgPath).Output()
	if err != nil {
		t.Fatalf("the pty driver: %v\n%s", err, out)
	}
	var r ttyResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("the pty driver said %q", out)
	}
	if !r.Ready {
		t.Fatalf("the run never reached %q:\n%s", o.ready, readLog(t, filepath.Join(dir, "log")))
	}
	return r, marker
}

// checkTTYTeardown: the run ended with exit 130 after the Ctrl-C, the
// credentials prompt came in the foreground and took the answer typed at
// the terminal, the teardown's own read of the terminal failed at once
// instead of stopping it, the teardown reached down, and what the
// teardown printed reached both the terminal and $OUT/teardown.log.
func checkTTYTeardown(t *testing.T, r ttyResult, dir, down string) {
	t.Helper()
	log := readLog(t, filepath.Join(dir, "log"))
	if !r.Ended {
		t.Fatalf("the run never ended: its teardown is stopped on the terminal (processes %v):\n%s", r.Stuck, log)
	}
	if r.Code == nil || *r.Code != 130 {
		t.Errorf("exit %v, want 130:\n%s", r.Code, log)
	}
	for _, want := range []string{"aws-read 246810", "hm: no terminal", down} {
		if !strings.Contains(log, want) {
			t.Errorf("no %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "aws-read-failed") {
		t.Errorf("the credentials prompt could not read the terminal (not in the foreground):\n%s", log)
	}
	if tl := readLog(t, filepath.Join(dir, "teardown.log")); !strings.Contains(tl, "hm output uninstall") {
		t.Errorf("the teardown's output is not in teardown.log: %q", tl)
	}
	if !strings.Contains(r.Screen, "hm output uninstall") {
		t.Errorf("the teardown's output did not reach the terminal: %q", r.Screen)
	}
}

// teardownRun is one script's exit path under the pty: its harness, the
// env and log line it needs, and the line its teardown writes when it
// reaches down.
type teardownRun struct {
	name, ready, down string
	harness           func(t *testing.T, dir string) (string, []string, []string)
}

func teardownRuns() []teardownRun {
	return []teardownRun{
		// m1-eks.sh: Ctrl-C during a check of an `all` run; the real
		// step_down, whose Helm call reads the terminal.
		{name: "m1-eks.sh", ready: "start kernel", down: "x /nonexistent/cluster.sh down m1t-1",
			harness: func(t *testing.T, dir string) (string, []string, []string) {
				if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				return m1Harness(t), []string{"all"},
					[]string{"M1_DIR=" + k8sFile(t, "m1"), "FAIL_STEP=kernel", "FAIL_HOW=sleep", "DOWN=real"}
			}},
		// eks-bank.sh: a check that sleeps; the real step_down, whose Helm
		// call reads the terminal before cell.sh down.
		{name: "eks-bank.sh", ready: "sleepy-start", down: "x /eksbank-test/cell.sh bank-1 down",
			harness: func(t *testing.T, dir string) (string, []string, []string) {
				for f, body := range map[string]string{
					"run.tfvars.json":   `{"name": "bank-1", "ttl": "2099-01-01T00:00:00Z"}`,
					"terraform.tfstate": `{"resources": [{"type": "aws_vpc"}]}`,
					"workers":           "12 0 12",
					"kubeconfig":        "apiVersion: v1",
				} {
					if err := os.WriteFile(filepath.Join(dir, f), []byte(body+"\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				extra := `
HERE=/eksbank-test
k() { log "k $*"; }
same_account() { :; }
left_after_down() { :; }
hm() {
  log "hm $*"; echo "hm output $*" >&2
  if [[ -n "${HM_CHILD:-}" ]]; then
    if /bin/bash "$HM_CHILD"; then log "child read the terminal"; else log "child: no terminal"; fi
  fi
  if read -r _ < /dev/tty; then log "hm read the terminal"; else log "hm: no terminal"; fi
}
sleepy() { log sleepy-start; command sleep 20; }
` + shellFunc(t, "eks-bank.sh", "step_down") + shellFuncIf(t, "eks-bank.sh", "refresh_credentials") + shellFuncIf(t, "eks-bank.sh", "detach") + `
if [[ -n "${TD_TICKS:-}" ]]; then
  step_down() {
    log down-start
    local i
    for i in $(seq 1 "$TD_TICKS"); do echo "teardown tick $i"; log "tick $i"; command sleep 1; done
    echo "teardown output last line"
    log down-done
  }
fi
`
				return undoHarnessWith(t, extra, "sleepy sleepy"), nil, []string{"RUN_ALL=1"}
			}},
	}
}

// The teardown's Helm call reads the terminal: with the credentials
// prompt answered in the foreground, the run ends with 130 and reaches
// down. Before #1443 the teardown stopped on the terminal for good.
func TestTeardownThatReadsTheTerminalFinishes(t *testing.T) {
	for _, tr := range teardownRuns() {
		t.Run(tr.name, func(t *testing.T) {
			dir := t.TempDir()
			script, args, env := tr.harness(t, dir)
			r, _ := runUnderTTY(t, dir, script, ttyOpts{args: args, env: env, ready: tr.ready})
			checkTTYTeardown(t, r, dir, tr.down)
		})
	}
}

// A program in the teardown that puts SIGTTIN back to the default (as
// macOS's bash 3.2 does for the children of a script it runs, such as
// cluster.sh or cell.sh) and reads the terminal: run here by /bin/bash
// from a script file. With TTIN ignored (#1443) it was stopped and the run
// never ended; with no controlling terminal its open of /dev/tty fails.
func TestTeardownChildThatResetsTTINFinishes(t *testing.T) {
	for _, tr := range teardownRuns() {
		t.Run(tr.name, func(t *testing.T) {
			dir := t.TempDir()
			script, args, env := tr.harness(t, dir)
			// It puts TTIN and TTOU back to the default and reads the
			// terminal; its command line names the file, to find it by.
			child := filepath.Join(dir, "child-of-teardown.sh")
			body := `python3 -I -c 'import signal
signal.signal(signal.SIGTTIN, signal.SIG_DFL); signal.signal(signal.SIGTTOU, signal.SIG_DFL)
open("/dev/tty").readline()' "$0"
`
			if err := os.WriteFile(child, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			r, _ := runUnderTTY(t, dir, script, ttyOpts{args: args, ready: tr.ready, env: append(env, "HM_CHILD="+child)})
			if left, _ := exec.Command("pgrep", "-f", child).Output(); len(strings.Fields(string(left))) > 0 {
				for _, pid := range strings.Fields(string(left)) {
					if n, err := strconv.Atoi(pid); err == nil {
						_ = syscall.Kill(n, syscall.SIGKILL)
					}
				}
			}
			checkTTYTeardown(t, r, dir, tr.down)
			if log := readLog(t, filepath.Join(dir, "log")); !strings.Contains(log, "child: no terminal") {
				t.Errorf("the child did not fail at once:\n%s", log)
			}
		})
	}
}

// A credential helper (credential_process) that prompts and is never
// answered: the refresh's time limit ends it with aws, and the run goes on
// to down. Before, only aws ended, and the helper read the terminal on
// after the run.
func TestRefreshEndsAPromptingCredentialHelper(t *testing.T) {
	for _, tr := range teardownRuns() {
		t.Run(tr.name, func(t *testing.T) {
			dir := t.TempDir()
			script, args, env := tr.harness(t, dir)
			r, marker := runUnderTTY(t, dir, script, ttyOpts{args: args, ready: tr.ready, awsMode: "helper",
				env:   append(env, "CRED_REFRESH_SECONDS=2"),
				after: `sleep 1; pgrep -f "$HELPER_MARK" > "$OUT/helper-after.txt"`})
			left, _ := exec.Command("pgrep", "-f", marker+"-helper").Output()
			for _, pid := range strings.Fields(string(left)) {
				if n, err := strconv.Atoi(pid); err == nil {
					_ = syscall.Kill(n, syscall.SIGKILL)
				}
			}
			log := readLog(t, filepath.Join(dir, "log"))
			if !r.Ended || r.Code == nil || *r.Code != 130 {
				t.Fatalf("ended %v, exit %v; want exit 130 (processes %v):\n%s", r.Ended, r.Code, r.Stuck, log)
			}
			if after := strings.Fields(readLog(t, filepath.Join(dir, "helper-after.txt"))); len(after) > 0 {
				t.Errorf("the credential helper outlived the refresh's time limit and the run: pids %s", after)
			}
			if !strings.Contains(log, tr.down) {
				t.Errorf("no %q:\n%s", tr.down, log)
			}
		})
	}
}

// A prompt (getpass: echo off) ended by the refresh's time limit leaves
// the terminal's echo on.
func TestRefreshPutsTheTerminalBack(t *testing.T) {
	for _, tr := range teardownRuns() {
		t.Run(tr.name, func(t *testing.T) {
			dir := t.TempDir()
			script, args, env := tr.harness(t, dir)
			r, _ := runUnderTTY(t, dir, script, ttyOpts{args: args, ready: tr.ready, awsMode: "getpass",
				env:   append(env, "CRED_REFRESH_SECONDS=2"),
				after: `stty -a > "$OUT/stty-after.txt" 2>&1`})
			log := readLog(t, filepath.Join(dir, "log"))
			if !r.Ended || r.Code == nil || *r.Code != 130 {
				t.Fatalf("ended %v, exit %v; want exit 130 (processes %v):\n%s", r.Ended, r.Code, r.Stuck, log)
			}
			st := readLog(t, filepath.Join(dir, "stty-after.txt"))
			if !regexp.MustCompile(`(^|\s)echo(\s|;|$)`).MatchString(st) || regexp.MustCompile(`(^|\s)-echo(\s|;|$)`).MatchString(st) {
				t.Errorf("echo is off after the run:\n%s", st)
			}
			if !strings.Contains(log, tr.down) {
				t.Errorf("no %q:\n%s", tr.down, log)
			}
		})
	}
}

// The teardown outlives whatever shows it (review of #1445). Its output
// went through a tee in this shell's process group: when the terminal
// closed, eks-bank.sh (which did not ignore HUP in on_exit) died with its
// tee, and the teardown died of SIGPIPE at its next line; a killed tee
// did the same to either script, and a tee that failed on a closed
// terminal made "down did not finish" show for a teardown that had
// finished. Now the teardown writes straight to teardown.log, a viewer
// shows it, and "down did not finish" is the teardown's own status.
func TestTeardownOutlivesItsViewer(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    ttyOpts
	}{
		{"the terminal closes", ttyOpts{closeAt: "tick 2"}},
		{"the viewer is killed", ttyOpts{killAt: "tick 2"}},
	} {
		for _, tr := range teardownRuns() {
			t.Run(tc.name+"/"+tr.name, func(t *testing.T) {
				dir := t.TempDir()
				script, args, env := tr.harness(t, dir)
				o := tc.o
				o.args, o.ready, o.env = args, tr.ready, append(env, "TD_TICKS=5")
				r, _ := runUnderTTY(t, dir, script, o)
				log := readLog(t, filepath.Join(dir, "log"))
				if !strings.Contains(log, "down-done") {
					t.Fatalf("the teardown died half way (ended %v, exit %s, killed %v):\n%s", r.Ended, r.exit(), r.Killed, log)
				}
				if tl := readLog(t, filepath.Join(dir, "teardown.log")); !strings.Contains(tl, "teardown output last line") {
					t.Errorf("teardown.log lacks the last line:\n%s", tl)
				}
				if strings.Contains(log, "did not finish") {
					t.Errorf("\"down did not finish\" for a teardown that finished:\n%s", log)
				}
				if !r.Ended || r.Code == nil || *r.Code != 130 {
					t.Errorf("ended %v, exit %s; want exit 130:\n%s", r.Ended, r.exit(), log)
				}
				if tc.o.killAt != "" && len(r.Killed) == 0 {
					t.Errorf("nothing held teardown.log open to kill (no viewer?)")
				}
			})
		}
	}
}

// The teardown runs the copy of the script made at the start, not the
// file in the checkout, which a branch switch may have replaced since
// (review of #1445: it ran the script again from disk).
func TestTeardownRunsTheCopyNotTheCheckout(t *testing.T) {
	for _, tr := range teardownRuns() {
		t.Run(tr.name, func(t *testing.T) {
			dir := t.TempDir()
			script, args, env := tr.harness(t, dir)
			r, _ := runUnderTTY(t, dir, script, ttyOpts{args: args, env: env, ready: tr.ready,
				replaceWith: "echo \"the replaced script ran\" >> \"$OUT/log\"\n"})
			log := readLog(t, filepath.Join(dir, "log"))
			if strings.Contains(log, "the replaced script ran") {
				t.Errorf("the teardown ran the replaced file:\n%s", log)
			}
			if !strings.Contains(log, tr.down) {
				t.Errorf("no %q (exit %s):\n%s", tr.down, r.exit(), log)
			}
		})
	}
}

// ticksExtra is the bank harness's extra for a teardown that takes
// TD_TICKS seconds, behind a check that sleeps.
const ticksExtra = `
sleepy() { log sleepy-start; command sleep 20; }
step_down() {
  log down-start
  local i
  for i in $(seq 1 "$TD_TICKS"); do echo "teardown tick $i"; log "tick $i"; command sleep 1; done
  echo "teardown output last line"
  log down-done
}
`

// tickingRun starts one script's `all` run with a teardown of `ticks`
// seconds, stops it (SIGINT; TERM for the bank run, as its harness waits in
// a check), and returns once the teardown has logged tick 2. It returns the
// run, the harness file in the checkout, and the env a second run of the
// same harness needs.
func tickingRun(t *testing.T, script string, ticks int) (m1Run, string, []string) {
	t.Helper()
	tk := fmt.Sprintf("TD_TICKS=%d", ticks)
	var r m1Run
	var harness string
	var env []string
	switch script {
	case "m1-eks.sh":
		r = startM1(t, []string{"all"}, "FAIL_STEP=kernel", "FAIL_HOW=sleep", tk)
		harness = filepath.Join(r.dir, "checkout", "m1-eks.sh")
		env = []string{"M1_DIR=" + k8sFile(t, "m1")}
		r.waitLog(t, "start kernel")
		_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGINT)
	default:
		u := startUndoWith(t, ticksExtra, "sleepy sleepy", "12 0 12", "RUN_ALL=1", tk)
		r = m1Run{dir: u.dir, cmd: u.cmd}
		harness = filepath.Join(r.dir, "checkout", "harness.sh")
		env = []string{"RUN_ALL=0"}
		r.waitLog(t, "sleepy-start")
		_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGTERM)
	}
	r.waitLog(t, "tick 2")
	// The detached teardown is in a session of its own, out of reach of the
	// run's group: ended by the copy's path once the test is done.
	t.Cleanup(func() {
		out, _ := exec.Command("pgrep", "-f", filepath.Join(r.dir, filepath.Base(harness))).Output()
		for _, pid := range strings.Fields(string(out)) {
			if n, err := strconv.Atoi(pid); err == nil {
				_ = syscall.Kill(n, syscall.SIGKILL)
			}
		}
	})
	return r, harness, env
}

// The viewer ends with the run: a run SIGKILLed during its teardown left
// the viewer polling teardown.log forever (review of #1445).
func TestViewerEndsWithTheRun(t *testing.T) {
	needTools(t, "pgrep", "perl")
	for _, script := range []string{"m1-eks.sh", "eks-bank.sh"} {
		t.Run(script, func(t *testing.T) {
			r, _, _ := tickingRun(t, script, 20)
			viewer := filepath.Join(r.dir, "teardown.log")
			if out, _ := exec.Command("pgrep", "-f", viewer).Output(); len(strings.Fields(string(out))) == 0 {
				t.Fatalf("no viewer of %s while the teardown ran", viewer)
			}
			_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGKILL)
			_ = r.cmd.Wait()
			var left []string
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
				out, _ := exec.Command("pgrep", "-f", viewer).Output()
				if left = strings.Fields(string(out)); len(left) == 0 {
					return
				}
			}
			t.Errorf("the viewer outlived the killed run by 5 s: pids %v", left)
		})
	}
}

// A second run of the same name (`down` by hand) while a teardown runs from
// the copy: keep_copy used to copy over the file the teardown's bash was
// reading, which then ran the new file's lines from where it was. Here the
// new file is the old one with a line added at its end.
func TestSecondCopyLeavesTheRunningTeardownAlone(t *testing.T) {
	needTools(t, "pgrep", "perl")
	for _, script := range []string{"m1-eks.sh", "eks-bank.sh"} {
		t.Run(script, func(t *testing.T) {
			r, harness, env := tickingRun(t, script, 5)
			src, err := os.ReadFile(harness)
			if err != nil {
				t.Fatal(err)
			}
			// The checkout's new file (a new file, as a branch switch
			// writes one: the run's own bash still reads the old one).
			if err := os.WriteFile(harness+".new", append(src, []byte("\nlog \"the second copy ran\"\n")...), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(harness+".new", harness); err != nil {
				t.Fatal(err)
			}
			second := exec.Command("bash", harness, "estimate")
			second.Env = append(append(cleanEnviron(), "OUT="+r.dir, "KEEP_ONLY=1"), env...)
			if out, err := second.CombinedOutput(); err != nil {
				t.Fatalf("the second run: %v\n%s", err, out)
			}
			r.end(t)
			log := r.log(t)
			if !strings.Contains(log, "down-done") {
				t.Errorf("the teardown did not finish:\n%s", log)
			}
			if strings.Contains(log, "the second copy ran") {
				t.Errorf("the running teardown read the second copy:\n%s", log)
			}
		})
	}
}
