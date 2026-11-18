package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
	for _, f := range []string{"eks-bank.sh", "drills-eks.sh", "drills-lib.sh", "cluster.sh", "helm-fetch.sh", "port-forward.sh"} {
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
	// And no step or check runs under ||, &&, if, while or !, where bash
	// ignores set -e inside it (ecr-storm called ecr-push as
	// `[[ -f … ]] || step_ecr_push`; a run_check there would carry on past
	// a failed command). The one exception is on_exit's teardown job,
	// `{ step_down || exit 1; } … &`, which is best effort on purpose and
	// says so.
	call := `(step_[a-z_]+|run_check|run_drills)\b`
	underList := regexp.MustCompile(`(\|\||&&|\bif\s+!?|\bwhile\s+!?|\buntil\s+|!)\s*` + call + `|` + call + `[^#]*?(\|\||&&)`)
	for _, f := range []string{"eks-bank.sh", "drills-eks.sh", "drills-lib.sh", "drills-local.sh"} {
		raw, err := os.ReadFile(k8sFile(t, f))
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(raw), "\n") {
			code := strings.TrimSpace(l)
			if strings.HasPrefix(code, "#") || regexp.MustCompile(`^(step_[a-z_]+|run_check|run_drills)\(\)`).MatchString(code) {
				continue
			}
			if underList.MatchString(code) && !strings.HasPrefix(code, `{ step_down || exit 1; } < /dev/null &`) {
				t.Errorf("%s:%d: a step or check run under a list or condition: %s", f, i+1, code)
			}
		}
	}
	for _, bad := range []string{`run_check scale step_scale || true`, `if run_check x y; then`, `[[ -f x ]] || step_ecr_push`, `step_scale && echo`} {
		if !underList.MatchString(bad) {
			t.Errorf("the scan misses %q", bad)
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
	b.WriteString("set -euo pipefail\nsd=\"$OUT\"\nin_scale=\"\"\nresult() { echo \"$1 $2 $3\" >> \"$OUT/bank.txt\"; }\nscale_back() { echo scale_back >> \"$OUT/log\"; }\nstop_scale_drills() { :; }\n")
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
	cmd.Env = append(cleanEnviron(), "OUT="+dir)
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
		!strings.Contains(string(out), "checks that failed: drills-ecr-push drills-large-layers drills-pull-storm drills-setup drills-slo-breach drills-static enterprise gvisor nlb (") {
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
		cmd.Env = append(cleanEnviron(), "OUT="+dir, "PLACE_CODE="+tc.code, "PLACE_BODY="+tc.body, "NODE="+tc.node)
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
		cmd.Env = append(cleanEnviron(), "OUT="+dir, "K8S="+filepath.Dir(k8sFile(t, "drills-lib.sh")))
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
	// In a polling loop (under ||, where set -e is off) a failed count is a
	// 1 the loop waits out, never empty counts that carry on.
	script = "set -euo pipefail\nworkers_now() { return 1; }\n" + shellFunc(t, "eks-bank.sh", "read_workers") +
		"w=x; p=x; m=x\nread_workers || echo \"waited: $w $p $m\"\n"
	if out, err := exec.Command("bash", "-c", script).CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "waited: x x x" {
		t.Errorf("a failed count under ||: %v %q", err, out)
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
	cmd.Env = append(cleanEnviron(), "OUT="+dir)
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
	cmd.Env = append(cleanEnviron(), "OUT="+dir)
	out, err := cmd.CombinedOutput()
	calls := readLog(t, filepath.Join(dir, "calls"))
	if err != nil || !strings.Contains(calls, "finished") || strings.Contains(calls, "describe-target-groups") {
		t.Fatalf("%v\n%s\n%s", err, out, calls)
	}
	if bank := readLog(t, filepath.Join(dir, "bank.txt")); bank != "FAIL nlb no load balancer in us-east-1 has the gateway Service's name k8s-aerolvm-gw-1.elb.us-east-1.amazonaws.com\n" {
		t.Errorf("recorded %q", bank)
	}
}

// The run's answer counts every FAIL it wrote, also one a check recorded
// itself before returning 0 (here gvisor: no gateway pod, so the create
// answered 000), and only this run's: a FAIL an earlier run left in
// bank.txt is not.
func TestEKSBankAnswersOneForARecordedFail(t *testing.T) {
	needTools(t, "python3", "jq")
	k8s := bankRun(t, "bank-1", "arn:aws:eks:us-east-1:111122223333:cluster/bank-1", true)
	st := filepath.Join(k8s, ".state", "bank-1")
	for f, body := range map[string]string{"api-token": "avm_x", "bank.txt": "FAIL nlb an earlier run's line\n"} {
		if err := os.WriteFile(filepath.Join(st, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env, _ := eksStubs(t)
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "gvisor")
	cmd.Env = env
	out, _ := cmd.CombinedOutput()
	bank := readLog(t, filepath.Join(st, "bank.txt"))
	if !strings.Contains(bank, "FAIL gvisor create answered 000: ") || strings.Contains(bank, "FAIL gvisor exited") {
		t.Errorf("bank.txt:\n%s\n%s", bank, out)
	}
	if cmd.ProcessState.ExitCode() != 1 || !strings.Contains(string(out), "checks that failed: gvisor (") {
		t.Errorf("exit %d, want 1 naming gvisor only:\n%s", cmd.ProcessState.ExitCode(), out)
	}
}

// drills-eks.sh's own steps, now under set -e, do not end on one call that
// fails on the way: an ingress-route read that fails counts against the
// shard-routes verdict (a FAIL, never a PASS), and a fault proxy that does
// not answer leaves the thresholds window to run.
func TestDrillStepsGoOnPastOneFailedCall(t *testing.T) {
	needTools(t, "python3")
	common := `set -euo pipefail
HERE="$K8S"; ROOT="$K8S/../.."; sd="$OUT"; ns=aerolvm-system; workers=aerolvm-workers; drill_reg=r; prom_port=1
log() { echo "$*" >> "$OUT/log"; }
say() { :; }
sleep() { :; }
result() { echo "$1 $2 $3" >> "$OUT/results"; }
jf() { python3 -c "import json, sys; d = json.loads(sys.argv[1]); print($2)" "$1"; }
vfield() { jf "$1" "d[\"$2\"]"; }
verdict() { python3 -I "$HERE/drills-eks/verdicts.py" "$@"; }
cleanup_run() { :; }
storm_start() { :; }
storm_wait() { :; }
`
	shard := common + `
kc() { echo "gw-a gw-b"; }
storm_fetch() { printf '{"id": "sb-1"}\n{"id": "sb-2"}\n' > "$2/$1.jsonl"; }
api() { case "$2" in */sb-2) return 1 ;; esac
  echo '{"code": 200, "body": {"sandbox_id": "sb-1", "owners": [{"node_id": "gw-a"}, {"node_id": "gw-b"}], "ring_version": "r1"}}'; }
caddy_get() { echo sb-1; }
` + shellFunc(t, "drills-eks.sh", "read_caddy") + shellFunc(t, "drills-eks.sh", "step_shard_routes") + `
step_shard_routes
log finished
`
	thresholds := common + `
drilled_alerts=(SandboxdImagePullErrors)
pull_cap=4
keep_forward() { :; }
kc() { printf 'w1\nw2\nw3\n'; }
proxy() { log "proxy $1"; return 7; }
watch_start() { :; }
watch_stop() { :; }
prom() { :; }
quiet_window() { log "quiet window on $3 workers"; }
step_pull_storm() { log pull-storm; }
` + shellFunc(t, "drills-eks.sh", "step_thresholds") + `
step_thresholds
log finished
`
	for _, tc := range []struct {
		desc, script, want, result string
	}{
		{"shard-routes", shard, "finished", "FAIL shard-routes"},
		{"thresholds", thresholds, "quiet window on 3 workers\npull-storm\nfinished", ""},
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", tc.script)
		cmd.Env = append(cleanEnviron(), "OUT="+dir, "K8S="+filepath.Dir(k8sFile(t, "drills-eks.sh")))
		out, err := cmd.CombinedOutput()
		log := readLog(t, filepath.Join(dir, "log"))
		if err != nil || !strings.Contains(log, tc.want) {
			t.Errorf("%s: %v, log %q, want %q:\n%s", tc.desc, err, log, tc.want, out)
		}
		if res := readLog(t, filepath.Join(dir, "results")); !strings.HasPrefix(res, tc.result) || strings.Contains(res, "PASS") {
			t.Errorf("%s: recorded %q, want it to start %q", tc.desc, res, tc.result)
		}
	}
}
