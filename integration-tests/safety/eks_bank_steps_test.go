package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The bank run's fourth attempt (2026-11-18) ended at its gVisor check:
// the v1 sandbox answer has no node_id, so the worker lookup ran kubectl with
// an empty name, and then `runc="$(gw_call … | head -1)"` died of SIGPIPE
// (exit 141) under pipefail, which ended `all`. These hold the fixes: one
// check that fails is recorded and the run goes on; the gVisor owner comes
// from the placement route; no assignment takes a pipeline a reader that
// stops early can end; a drill step keeps set -e.

// shellFunc returns the top-level function name from script, as written.
func shellFunc(t *testing.T, script, name string) string {
	t.Helper()
	src, err := os.ReadFile(k8sFile(t, script))
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?s)\n` + regexp.QuoteMeta(name) + `\(\) \{.*?\n\}\n`).Find(src)
	if fn == nil {
		t.Fatalf("no %s() in %s", name, script)
	}
	return string(fn)
}

// earlyReader is a pipeline stage that can stop reading before the writer
// is done (head, grep -m, grep -q, sed Nq): under pipefail the writer's
// SIGPIPE fails the pipeline, and set -e ends the script on an assignment.
var earlyReader = regexp.MustCompile(`\|\s*(head\b|grep\s+(-[A-Za-z]*[mq]|--max-count|--quiet)|sed\s+(-n\s+)?['"]?[0-9]+q)`)

// assignment is a variable taking a command substitution.
var assignment = regexp.MustCompile(`^\s*(local\s+|export\s+)?[A-Za-z_][A-Za-z0-9_]*="?\$\(`)

// (a) No assignment in the bank run's scripts takes a pipeline into head,
// grep -m or grep -q: the output is read whole, then cut.
func TestEKSBankNoAssignmentFromAnEarlyReader(t *testing.T) {
	for _, f := range []string{"eks-bank.sh", "drills-eks.sh", "drills-lib.sh", "cluster.sh", "helm-fetch.sh"} {
		raw, err := os.ReadFile(k8sFile(t, f))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		for i := 0; i < len(lines); i++ {
			if strings.HasPrefix(strings.TrimSpace(lines[i]), "#") || !assignment.MatchString(lines[i]) {
				continue
			}
			// The whole substitution: on while a line ends in \ or |, or a
			// parenthesis is still open (at most 12 lines).
			cmd, j := lines[i], i
			for j+1 < len(lines) && j < i+12 {
				c := strings.TrimRight(cmd, " ")
				if !strings.HasSuffix(c, "\\") && !strings.HasSuffix(c, "|") && strings.Count(cmd, "(") <= strings.Count(cmd, ")") {
					break
				}
				j++
				cmd += "\n" + lines[j]
			}
			if earlyReader.MatchString(cmd) {
				t.Errorf("%s:%d: an assignment from a pipeline into an early reader:\n%s", f, i+1, cmd)
			}
			i = j
		}
	}
	// And no step is called under || or &&, where bash ignores set -e inside
	// it (ecr-storm called ecr-push as `[[ -f … ]] || step_ecr_push`).
	underList := regexp.MustCompile(`(\|\||&&)\s*step_[a-z_]+|^\s*if\s+!?\s*step_[a-z_]+`)
	for _, f := range []string{"eks-bank.sh", "drills-eks.sh", "drills-lib.sh", "drills-local.sh"} {
		raw, err := os.ReadFile(k8sFile(t, f))
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "#") && underList.MatchString(l) {
				t.Errorf("%s:%d: a step called under || or &&: %s", f, i+1, strings.TrimSpace(l))
			}
		}
	}
	// The check itself: the line that ended the fourth run is caught.
	if !earlyReader.MatchString(`runc="$(gw_call POST /v1/sandboxes '{}' | head -1)"`) ||
		!earlyReader.MatchString(`started="$(jq -r .stdout x | grep -m1 'Starting gVisor' || true)"`) {
		t.Fatal("the pattern no longer matches the lines it was written for")
	}
}

// checkHarness is run_check, check_exit, stop_check and kill_tree from
// eks-bank.sh with a result that writes to $OUT/bank.txt.
func checkHarness(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("set -euo pipefail\nin_scale=\"\"\nresult() { echo \"$1 $2 $3\" >> \"$OUT/bank.txt\"; }\nscale_back() { echo scale_back >> \"$OUT/log\"; }\n")
	for _, fn := range []string{"kill_tree", "run_check", "check_exit", "stop_check"} {
		b.WriteString(shellFunc(t, "eks-bank.sh", fn))
	}
	b.WriteString("check_pid=\"\"\ncheck_rc=0\ncheck_undo=\"\"\nfailed_checks=()\n")
	return b.String()
}

// (b, the mechanism) A check that fails stops at the failed command (set -e
// is on inside it), is recorded "FAIL <step> exited N", and the next check
// and the teardown still run; a later check's own answer is kept.
func TestRunCheckRecordsAFailureAndGoesOn(t *testing.T) {
	dir := t.TempDir()
	script := checkHarness(t) + `
first() { echo first >> "$OUT/log"; false; echo past-the-failure >> "$OUT/log"; }
second() { echo second >> "$OUT/log"; }
# A failure in a function the check calls ends the check there too.
inner() { false; echo inner-carried-on >> "$OUT/log"; }
third() { inner; echo third-carried-on >> "$OUT/log"; }
run_check first first
run_check second second
run_check third third
echo teardown >> "$OUT/log"
echo "failed: ${failed_checks[*]}" >> "$OUT/log"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "OUT="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the harness failed: %v\n%s", err, out)
	}
	log, bank := readLog(t, filepath.Join(dir, "log")), readLog(t, filepath.Join(dir, "bank.txt"))
	if log != "first\nsecond\nteardown\nfailed: first third\n" {
		t.Errorf("the checks ran as:\n%s", log)
	}
	if bank != "FAIL first exited 1\nFAIL third exited 1\n" {
		t.Errorf("recorded:\n%s", bank)
	}
}

// A signal to the run while a check runs: on_exit stops the check, whose
// own exit handler (here check_undo) finishes before the teardown.
func TestStopCheckLetsTheCheckUndoFirst(t *testing.T) {
	dir := t.TempDir()
	script := checkHarness(t) + `
undo() { echo undo >> "$OUT/log"; }
slow() { check_undo=undo; sleep 30 & echo $! > "$OUT/sleep.pid"; wait; }
trap 'stop_check; echo teardown >> "$OUT/log"' EXIT
trap 'exit 130' INT TERM
echo $$ > "$OUT/run.pid"
run_check slow slow
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "OUT="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "sleep.pid")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the check never started")
		}
		time.Sleep(50 * time.Millisecond)
	}
	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the run took %s to stop: the trap waited for the check", d)
	}
	if log := readLog(t, filepath.Join(dir, "log")); log != "undo\nteardown\n" {
		t.Errorf("after a TERM: %q, want the check's undo, then the teardown", log)
	}
	if alive(t, filepath.Join(dir, "sleep.pid")) {
		t.Error("the check's child outlived the run")
	}
}

// (b, the run) eks-bank.sh itself: three checks that fail on stubs, then
// down. Each is recorded, each next step runs, the teardown runs, and the
// run's answer is 1. (`all` runs the same loop; it cannot get past install
// offline.)
func TestEKSBankChecksFailAndTheRunGoesOn(t *testing.T) {
	needTools(t, "python3", "jq")
	k8s := bankRun(t, "bank-1", "arn:aws:eks:us-east-1:111122223333:cluster/bank-1", true)
	calls := filepath.Join(k8s, "scripts.log")
	stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"" + calls + "\"\nexit 0\n"
	for _, s := range []string{"cluster.sh", "cell.sh"} {
		if err := os.WriteFile(filepath.Join(k8s, s), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	st := filepath.Join(k8s, ".state", "bank-1")
	if err := os.WriteFile(filepath.Join(st, "terraform.tfstate"), []byte(`{"resources": [{"type": "aws_vpc"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env, _ := eksStubs(t)
	// An aws that answers every listing with nothing (and the account), so
	// down finds nothing left and ends cleanly: the run's 1 then comes from
	// the failed checks alone.
	awsDir := t.TempDir()
	// (a bucket that is gone answers head-bucket with an error, as S3 does)
	awsStub := "#!/bin/sh\ncase \"$*\" in *\"sts get-caller-identity\"*) echo 111122223333 ;; *\"s3api head-bucket\"*) exit 254 ;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(awsDir, "aws"), []byte(awsStub), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			env[i] = "PATH=" + awsDir + string(os.PathListSeparator) + strings.TrimPrefix(e, "PATH=")
		}
	}
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "enterprise", "nlb", "gvisor", "drills", "down")
	cmd.Env = env
	out, _ := cmd.CombinedOutput()
	bank := readLog(t, filepath.Join(st, "bank.txt"))
	for _, want := range []string{"FAIL enterprise exited ", "FAIL nlb exited ", "FAIL gvisor exited ", "FAIL drills-setup exited ",
		"FAIL drills-static skipped: drills-eks.sh setup exited ", "FAIL drills-ecr-push skipped: drills-eks.sh setup exited "} {
		if !strings.Contains(bank, want) {
			t.Errorf("no %q in bank.txt:\n%s\n%s", want, bank, out)
		}
	}
	steps := regexp.MustCompile(`--- (\w+)`).FindAllStringSubmatch(string(out), -1)
	var ran []string
	for _, m := range steps {
		ran = append(ran, m[1])
	}
	if strings.Join(ran, " ") != "enterprise nlb gvisor drills down" {
		t.Errorf("the steps that ran: %v", ran)
	}
	if !strings.Contains(readLog(t, calls), "cell.sh bank-1 down") {
		t.Errorf("the teardown did not run:\n%s", out)
	}
	if cmd.ProcessState.ExitCode() != 1 || !strings.Contains(string(out), "down: nothing of bank-1 is left") ||
		!strings.Contains(string(out), "checks that failed: enterprise nlb gvisor drills-setup drills-static drills-pull-storm drills-slo-breach drills-large-layers drills-ecr-push") {
		t.Errorf("exit %d, want 1 after a clean down, naming the failed checks:\n%s", cmd.ProcessState.ExitCode(), out)
	}
}

// (c) The gVisor check finds its sandbox's worker through the placement
// route, never with an empty name, and reads a large runc answer whole.
func TestGVisorOwnerFromThePlacementRoute(t *testing.T) {
	var fns strings.Builder
	for _, fn := range []string{"sandbox_machine", "step_gvisor"} {
		fns.WriteString(shellFunc(t, "eks-bank.sh", fn))
	}
	harness := `set -euo pipefail
dry=0; workers=aerolvm-workers
result() { echo "$1 $2 $3" >> "$OUT/bank.txt"; }
api_token() { :; }
admin_call() { echo "admin_call $*" >> "$OUT/calls"; echo "$PLACE_CODE"; echo "$PLACE_BODY"; }
kr() { echo "kr $*" >> "$OUT/calls"
  case "$*" in
    "-n aerolvm-workers get pod aerolvm-gvisor-general-x1 -o jsonpath={.spec.nodeName}") echo "$NODE" ;;
    "get node ip-10-0-0-1"*) echo "Amazon Linux 2023.9 | kernel 6.12 | containerd://2.1" ;;
    *) return 1 ;;
  esac; }
gw_call() { echo "gw_call $1 $2" >> "$OUT/calls"
  case "$1 $2" in
    "POST /v1/sandboxes") case "$3" in *gvisor*) echo 201; echo '{"id": "sb-1"}' ;;
      *) echo 422; head -c 200000 /dev/zero | tr '\0' x; echo ;; esac ;;
    "POST /v1/sandboxes/sb-1/toolbox/process/execute") echo 200; echo '{"stdout": "[ 0.0] Starting gVisor...\n4.19.0-gvisor\n"}' ;;
    *) echo 204 ;;
  esac; }
` + fns.String() + `
sd="$OUT"; step_gvisor
echo finished >> "$OUT/calls"
`
	placed := `{"owner": {"node_id": "aerolvm-gvisor-general-x1", "api_url": "http://w1:21212", "is_self": false}, "orphaned": false}`
	for _, tc := range []struct {
		desc, code, body, node, want, why string
	}{
		{"the owner and its machine", "200", placed, "ip-10-0-0-1", "PASS gvisor sandbox sb-1 ran under gVisor", ""},
		{"no owner (an orphaned placement)", "200", `{"owner": {"node_id": ""}, "orphaned": true}`, "", "FAIL gvisor", "no owner node: the placement route answered 200"},
		{"the placement route refuses", "404", `{"error": "no placement record"}`, "", "FAIL gvisor", "no owner node: the placement route answered 404"},
		{"the worker pod has no machine", "200", placed, "", "FAIL gvisor", "worker pod aerolvm-gvisor-general-x1 (the owner node) has no machine"},
	} {
		dir := t.TempDir()
		cmd := exec.Command("bash", "-c", harness)
		cmd.Env = append(os.Environ(), "OUT="+dir, "PLACE_CODE="+tc.code, "PLACE_BODY="+tc.body, "NODE="+tc.node)
		out, err := cmd.CombinedOutput()
		calls := readLog(t, filepath.Join(dir, "calls"))
		if err != nil || !strings.Contains(calls, "finished") {
			t.Errorf("%s: the step died: %v\n%s\n%s", tc.desc, err, out, calls)
			continue
		}
		if !strings.Contains(calls, "admin_call GET /v1/cluster/placements/sb-1") {
			t.Errorf("%s: the owner was not read from the placement route:\n%s", tc.desc, calls)
		}
		if regexp.MustCompile(`kr (-n \S+ )?get (pod|node)\s+-o`).MatchString(calls) {
			t.Errorf("%s: kubectl was asked for a resource with no name:\n%s", tc.desc, calls)
		}
		bank := readLog(t, filepath.Join(dir, "bank.txt"))
		if !strings.HasPrefix(bank, tc.want) || strings.Count(bank, "\n") != 1 {
			t.Errorf("%s: recorded %q, want one line starting %q", tc.desc, bank, tc.want)
		}
		if tc.want == "FAIL gvisor" && !strings.Contains(bank, tc.why) {
			t.Errorf("%s: the FAIL does not say %q:\n%s", tc.desc, tc.why, bank)
		}
		if !strings.Contains(bank, "a runc create answered 422") && !strings.Contains(bank, "runc create: 422") {
			t.Errorf("%s: the runc answer (a 200 kB body) was not read: %s", tc.desc, bank)
		}
	}
}

// A drill step keeps set -e: a step of the caller's own (drills_step) that
// fails ends the script there, without its PASS; a step that is not the
// caller's is refused as before.
func TestDrillsMainKeepsSetE(t *testing.T) {
	dir := t.TempDir()
	caller := `set -euo pipefail
HERE="$K8S"; L="$K8S/drills-local"; ROOT="$K8S/../.."; sd="$OUT"; ctx=none; ctl_url=http://127.0.0.1:1
drills_own_steps="push teardown"
step_push() { echo pushing >> "$OUT/log"; false; echo "PASS push" >> "$OUT/log"; }
drills_step() { case "$1" in push) step_push ;; teardown) echo teardown >> "$OUT/log" ;; *) return 127 ;; esac; }
source "$K8S/drills-lib.sh"
drills_main drills-test.sh "$@"
`
	run := func(steps ...string) (int, string) {
		cmd := exec.Command("bash", append([]string{"-c", caller, "bash"}, steps...)...)
		cmd.Env = append(os.Environ(), "OUT="+dir, "K8S="+filepath.Dir(k8sFile(t, "drills-lib.sh")))
		out, _ := cmd.CombinedOutput()
		return cmd.ProcessState.ExitCode(), string(out)
	}
	code, out := run("push", "teardown")
	if log := readLog(t, filepath.Join(dir, "log")); code == 0 || log != "pushing\n" {
		t.Errorf("a failed own step: exit %d, ran %q, want a non-zero exit after \"pushing\" only:\n%s", code, log, out)
	}
	code, out = run("nonsense")
	if code != 2 || !strings.Contains(out, "drills-test.sh: unknown step nonsense") {
		t.Errorf("an unknown step: exit %d:\n%s", code, out)
	}
	_ = os.Remove(filepath.Join(dir, "log"))
	if code, out = run("teardown"); code != 0 || readLog(t, filepath.Join(dir, "log")) != "teardown\n" {
		t.Errorf("an own step that passes: exit %d:\n%s", code, out)
	}
}

// read_workers: a worker count the cluster did not give ends the scale
// step; read from "$(workers_now)" directly took empty values, and an empty
// count passed "machines <= base".
func TestReadWorkersStopsOnAFailedCount(t *testing.T) {
	script := "set -euo pipefail\nworkers_now() { return 1; }\n" + shellFunc(t, "eks-bank.sh", "read_workers") +
		"w=x; p=x; m=x\nread_workers\necho carried-on\n"
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err == nil || strings.Contains(string(out), "carried-on") {
		t.Errorf("a failed count carried on: %v %s", err, out)
	}
	script = "set -euo pipefail\nworkers_now() { echo 7 1 8; }\n" + shellFunc(t, "eks-bank.sh", "read_workers") +
		"read_workers\necho \"$w $p $m\"\n"
	if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "7 1 8" {
		t.Errorf("a count: %v %q", err, out)
	}
}

// gw_call with no gateway pod answers 000 and calls nothing: no
// port-forward to "pod/".
func TestGwCallWithoutAGateway(t *testing.T) {
	dir := t.TempDir()
	script := `set -euo pipefail
dry=0; ns=aerolvm-system; sd="$OUT"
kr() { echo "kr $*" >> "$OUT/calls"; }
kubectl() { echo "kubectl $*" >> "$OUT/calls"; }
curl() { echo "curl $*" >> "$OUT/calls"; }
` + shellFunc(t, "eks-bank.sh", "gw_call") + `
gw_call GET /v1/whoami
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "OUT="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "000\n") || strings.Contains(readLog(t, filepath.Join(dir, "calls")), "kubectl") {
		t.Errorf("gw_call with no gateway: %v %q, calls %q", err, out, readLog(t, filepath.Join(dir, "calls")))
	}
}

// The NLB check with no load balancer under the Service's name records a
// FAIL and asks for no target group of an empty ARN.
func TestNLBWithoutALoadBalancer(t *testing.T) {
	dir := t.TempDir()
	script := `set -euo pipefail
dry=0; ns=aerolvm-system; release=aerolvm; cname=aerolvm; name=bank-1; sd="$OUT"
result() { echo "$1 $2 $3" >> "$OUT/bank.txt"; }
api_token() { :; }
tfout() { echo us-east-1; }
wait_until() { :; }
kr() { echo k8s-aerolvm-gw-1.elb.us-east-1.amazonaws.com; }
aws() { echo "aws $*" >> "$OUT/calls"; case "$*" in *describe-load-balancers*) echo '{"LoadBalancers": [{"DNSName": "other.elb.amazonaws.com", "LoadBalancerArn": "arn:x"}]}' ;; esac; }
` + shellFunc(t, "eks-bank.sh", "step_nlb") + `
step_nlb
echo finished >> "$OUT/calls"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "OUT="+dir)
	out, err := cmd.CombinedOutput()
	calls := readLog(t, filepath.Join(dir, "calls"))
	if err != nil || !strings.Contains(calls, "finished") || strings.Contains(calls, "describe-target-groups") {
		t.Fatalf("%v\n%s\n%s", err, out, calls)
	}
	if bank := readLog(t, filepath.Join(dir, "bank.txt")); bank != "FAIL nlb no load balancer in us-east-1 has the gateway Service's name k8s-aerolvm-gw-1.elb.us-east-1.amazonaws.com\n" {
		t.Errorf("recorded %q", bank)
	}
}
