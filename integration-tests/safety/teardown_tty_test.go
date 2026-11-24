package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
// first (a prompt there can be answered), and the teardown ignores TTIN
// and TTOU, so a prompt that still comes fails at once.
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
res = {"ready": wait_for(cfg["ready"], 30), "answered": False, "ended": False, "code": None, "stuck": []}
drain(0.3)
os.write(fd, b"\x03")
if cfg.get("prompt") and wait_for(cfg["prompt"], 8):
    os.write(fd, (cfg["answer"] + "\n").encode()); res["answered"] = True
end = time.time() + cfg["timeout"]
while time.time() < end:
    drain(0.2)
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        res["ended"], res["code"] = True, os.waitstatus_to_exitcode(st); break
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

type ttyResult struct {
	Ready, Answered, Ended bool
	Code                   *int
	Stuck                  []string
	Screen                 string
}

// runUnderTTY writes script to dir/<marker>.sh and runs it under the
// driver, with a fake aws first on PATH: it logs its arguments, and for
// `sts get-caller-identity` logs "aws-prompt" and reads a line from the
// terminal, as an MFA prompt does.
func runUnderTTY(t *testing.T, dir, script string, args, env []string, ready string) ttyResult {
	t.Helper()
	needTools(t, "python3", "ps")
	marker := fmt.Sprintf("ttyrun-%d-%d", os.Getpid(), time.Now().UnixNano())
	path := filepath.Join(dir, marker+".sh")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := `#!/bin/bash
echo "aws $*" >> "$OUT/log"
case "$*" in
  *"sts get-caller-identity"*)
    echo aws-prompt >> "$OUT/log"
    if IFS= read -r code < /dev/tty; then echo "aws-read $code" >> "$OUT/log"; else echo aws-read-failed >> "$OUT/log"; fi
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
	for _, e := range append(append(clean, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "OUT="+dir), env...) {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}
	cfg, _ := json.Marshal(map[string]any{
		"argv": append([]string{"bash", path}, args...), "env": envMap, "log": filepath.Join(dir, "log"),
		"ready": ready, "prompt": "aws-prompt", "answer": "246810", "marker": marker, "timeout": 20,
	})
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
		t.Fatalf("the run never reached %q:\n%s", ready, readLog(t, filepath.Join(dir, "log")))
	}
	return r
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

// m1-eks.sh: Ctrl-C during a check of an `all` run; the real step_down,
// whose `helm uninstall` reads the terminal.
func TestM1TeardownThatReadsTheTerminalFinishes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "terraform.tfstate"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runUnderTTY(t, dir, m1Harness(t), []string{"all"},
		[]string{"M1_DIR=" + k8sFile(t, "m1"), "FAIL_STEP=kernel", "FAIL_HOW=sleep", "DOWN=real"}, "start kernel")
	checkTTYTeardown(t, r, dir, "x /nonexistent/cluster.sh down m1t-1")
}

// eks-bank.sh: the same, with a check that sleeps, and its real step_down,
// whose `helm uninstall` reads the terminal before cell.sh down.
func TestEKSBankTeardownThatReadsTheTerminalFinishes(t *testing.T) {
	dir := t.TempDir()
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
hm() { log "hm $*"; echo "hm output $*" >&2; if read -r _ < /dev/tty; then log "hm read the terminal"; else log "hm: no terminal"; fi; }
sleepy() { log sleepy-start; command sleep 20; }
` + shellFunc(t, "eks-bank.sh", "step_down") + shellFuncIf(t, "eks-bank.sh", "refresh_credentials")
	r := runUnderTTY(t, dir, undoHarnessWith(t, extra, "sleepy sleepy"), nil, []string{"RUN_ALL=1"}, "sleepy-start")
	checkTTYTeardown(t, r, dir, "x /eksbank-test/cell.sh bank-1 down")
}
