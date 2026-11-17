// Offline tests for the bank run's guards and verdicts (k8s/eks-bank.sh,
// k8s/drills-eks.sh, k8s/drills-eks/*.py, k8s/cluster.sh down): what the
// EKS harness review asked of each. Every AWS, kubectl and Helm call is a
// stub or a fake; nothing reaches AWS or a cluster.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func k8sFile(t *testing.T, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{integrationDir(t), "k8s"}, parts...)...)
}

// verdict runs drills-eks/verdicts.py and returns its verdict and detail.
func verdict(t *testing.T, args ...string) (string, string) {
	t.Helper()
	out, err := exec.Command("python3", append([]string{"-I", k8sFile(t, "drills-eks", "verdicts.py")}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("verdicts.py %v: %v\n%s", args, err, out)
	}
	var v struct {
		Verdict string `json:"verdict"`
		Detail  any    `json:"detail"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("verdicts.py %v: %s", args, out)
	}
	d, _ := json.Marshal(v.Detail)
	return v.Verdict, string(d)
}

func writeLines(t *testing.T, path string, rows ...any) {
	t.Helper()
	var b strings.Builder
	for _, r := range rows {
		j, _ := json.Marshal(r)
		b.Write(j)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakePrometheus answers /api/v1/alerts with the given alerts firing, and
// /api/v1/query and /api/v1/query_range with nothing.
func fakePrometheus(t *testing.T, firing ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data any
		switch r.URL.Path {
		case "/api/v1/alerts":
			var alerts []map[string]any
			for _, a := range firing {
				alerts = append(alerts, map[string]any{"labels": map[string]string{"alertname": a}, "state": "firing", "activeAt": "2026-11-17T10:00:00Z", "value": "1"})
			}
			data = map[string]any{"alerts": alerts}
		default:
			data = map[string]any{"resultType": "vector", "result": []any{}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": data})
	}))
}

var drilledAlerts = []string{"SandboxdImagePullQueueBacklog", "SandboxdImagePullBackoffRejects", "SandboxdImagePullErrors",
	"SandboxdCreateQueueBacklog", "SandboxdCreateErrors", "SandboxdNoAdmitWorkers", "SandboxdIngressRouteLag"}

// B1: thresholds-quiet passed when one of the seven alerts fired (prom.py
// wait waits for all of them) and when Prometheus could not be reached.
// Now: FAIL on any firing line or firing sample, and on a Prometheus that
// did not answer at the start or the end of the window.
func TestEKSBankThresholdsQuietVerdict(t *testing.T) {
	needTools(t, "python3")
	dir := t.TempDir()
	fired, history, empty := filepath.Join(dir, "fired.jsonl"), filepath.Join(dir, "history.jsonl"), filepath.Join(dir, "none.jsonl")
	writeLines(t, empty)

	// The review's case, end to end: Prometheus with one drilled alert
	// firing, prom.py wait over all seven, the verdict over its output.
	prom := fakePrometheus(t, "SandboxdCreateQueueBacklog")
	defer prom.Close()
	out, _ := exec.Command("python3", append([]string{k8sFile(t, "drills-local", "prom.py"), "--url", prom.URL, "wait"},
		append(drilledAlerts, "--state", "firing", "--timeout", "2")...)...).Output()
	if err := os.WriteFile(fired, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if v, d := verdict(t, "quiet", fired, empty, "1", "1"); v != "FAIL" || !strings.Contains(d, "SandboxdCreateQueueBacklog") {
		t.Errorf("one alert fired: %s %s (wait wrote %s)", v, d, out)
	}

	// Quiet: the wait timed out with all seven missing.
	writeLines(t, fired, map[string]any{"timeout": true, "missing": drilledAlerts})
	if v, d := verdict(t, "quiet", fired, empty, "1", "1"); v != "PASS" {
		t.Errorf("a quiet window: %s %s", v, d)
	}
	// A firing the wait missed (its port-forward was down) is in the history.
	writeLines(t, history, map[string]any{"alert": "SandboxdNoAdmitWorkers", "state": "firing", "first": 1, "last": 2, "samples": 2},
		map[string]any{"alert": "SandboxdCreateErrors", "state": "pending", "first": 1, "last": 2, "samples": 2})
	if v, d := verdict(t, "quiet", fired, history, "1", "1"); v != "FAIL" || !strings.Contains(d, "SandboxdNoAdmitWorkers") || strings.Contains(d, "SandboxdCreateErrors") {
		t.Errorf("a firing sample in the history: %s %s", v, d)
	}
	// Prometheus that did not answer, at the start or at the end.
	for _, se := range [][2]string{{"0", "1"}, {"1", "0"}, {"0", "0"}} {
		if v, d := verdict(t, "quiet", fired, empty, se[0], se[1]); v != "FAIL" || !strings.Contains(d, "Prometheus did not answer") {
			t.Errorf("Prometheus answered start=%s end=%s: %s %s", se[0], se[1], v, d)
		}
	}
	// And the step wires it so: the answers at both ends and the history
	// go into the verdict.
	src, err := os.ReadFile(k8sFile(t, "drills-eks.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`prom query 'vector(1)' > /dev/null 2>&1 && start_ok=1`, `prom history "$a" --since "$t0"`,
		`prom query 'vector(1)' > /dev/null 2>&1 || end_ok=0`, `verdict quiet "$out/quiet-fired.jsonl" "$out/quiet-history.jsonl" "$start_ok" "$end_ok"`,
		// The earlier steps' alerts cleared before the window (round 2).
		`if prom wait "${drilled_alerts[@]}" --state inactive --timeout $(( ${DRILL_CLEAR_MINUTES:-20} * 60 ))`} {
		if !strings.Contains(string(src), want) {
			t.Errorf("drills-eks.sh step_thresholds lacks %q", want)
		}
	}
}

// B2: "ECR throttled" came from a bare 429 grep over rows full of digits.
// Now only failed creates whose error names the registry's throttling
// count, and the pull error counter's rate_limited key must have moved.
func TestEKSBankECRStormVerdict(t *testing.T) {
	needTools(t, "python3")
	dir := t.TempDir()
	storm := filepath.Join(dir, "storm.jsonl")
	ok := func(i int) map[string]any {
		// Digits everywhere a grep would find 429: the account, the run tag,
		// timestamps, ids.
		return map[string]any{"t0": 1763429012.118 + float64(i), "ms": 4290, "caller": i, "code": 201, "class": "ok",
			"image": fmt.Sprintf("429429429429.dkr.ecr.us-east-1.amazonaws.com/bank-1/drill:1117142903-%d", i), "id": "sb-429f"}
	}
	throttled := func(i int) map[string]any {
		return map[string]any{"t0": 1763429012.0, "ms": 900, "caller": i, "code": 503, "class": "too many requests",
			"image": "x", "error": `{"error": "image pull unavailable: unexpected status from GET request to https://x/v2/: 429 Too Many Requests (toomanyrequests: Rate exceeded)"}`}
	}
	aerolvm429 := func(i int) map[string]any {
		return map[string]any{"t0": 1763429012.0, "ms": 5, "caller": i, "code": 429, "class": "too many requests", "image": "x",
			"error": `{"error": "429 Too Many Requests: the leader's reserve limit is reached; retry"}`}
	}
	other := func(i int) map[string]any {
		return map[string]any{"t0": 1763429012.0, "ms": 900, "caller": i, "code": 503, "class": "timeout", "image": "x", "error": `{"error": "pull timed out after 429s"}`}
	}
	rows := func(rs ...map[string]any) {
		var any_ []any
		for _, r := range rs {
			any_ = append(any_, r)
		}
		writeLines(t, storm, any_...)
	}
	for _, tc := range []struct {
		desc        string
		rows        []map[string]any
		wanted, rl  string
		after, want string
	}{
		{"no throttling, digits everywhere", []map[string]any{ok(0), ok(1), ok(2)}, "3", "0", "1", "INCONCLUSIVE"},
		{"no throttling, the counter moved nowhere, a 429 in a non-throttle error", []map[string]any{ok(0), other(1)}, "2", "0", "1", "INCONCLUSIVE"},
		{"throttled and said so", []map[string]any{ok(0), throttled(1)}, "2", "3", "1", "PASS"},
		{"throttled answers but the counter shows none", []map[string]any{ok(0), throttled(1)}, "2", "0", "1", "INCONCLUSIVE"},
		{"ECR throttled, creates failed without saying so", []map[string]any{ok(0), other(1)}, "2", "2", "1", "FAIL"},
		{"ECR throttled, retries absorbed it", []map[string]any{ok(0), ok(1)}, "2", "2", "1", "INCONCLUSIVE"},
		{"Prometheus did not answer", []map[string]any{ok(0), throttled(1)}, "2", "error", "1", "FAIL"},
		{"a create never answered", []map[string]any{ok(0)}, "2", "3", "1", "FAIL"},
		{"the create after the storm failed", []map[string]any{ok(0), throttled(1)}, "2", "3", "0", "FAIL"},
		// AerolVM's own 429 (its leader's reserve limit) is no registry
		// throttling, whatever its error says.
		{"AerolVM answered 429 itself", []map[string]any{ok(0), aerolvm429(1)}, "2", "0", "1", "INCONCLUSIVE"},
		{"AerolVM's 429 while ECR throttled", []map[string]any{ok(0), aerolvm429(1)}, "2", "3", "1", "FAIL"},
	} {
		rows(tc.rows...)
		if v, d := verdict(t, "ecr", storm, tc.wanted, tc.rl, tc.after); v != tc.want {
			t.Errorf("%s: %s, want %s (%s)", tc.desc, v, tc.want, d)
		}
	}
	// The step feeds the verdict the rate_limited counter and the storm's
	// rows, not a grep.
	src, err := os.ReadFile(k8sFile(t, "drills-eks.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`aerolvm_image_pull_errors_total{key=\"rate_limited\"}`, `verdict ecr "$out/ecr-$run.jsonl" "$n" "$rl" "$after_ok"`, `rl=error`} {
		if !strings.Contains(string(src), want) {
			t.Errorf("drills-eks.sh step_ecr_storm lacks %q", want)
		}
	}
	if strings.Contains(string(src), "grep -ciE 'toomanyrequests") {
		t.Error("drills-eks.sh still greps for throttling")
	}
	// The review's simulation: a thousand storms with no throttling at all,
	// none a PASS (the old grep passed 803).
	for trial := 0; trial < 200; trial++ {
		var rs []map[string]any
		for i := 0; i < 20; i++ {
			rs = append(rs, ok(trial*20+i))
		}
		rows(rs...)
		if v, _ := verdict(t, "ecr", storm, "20", "0", "1"); v == "PASS" {
			t.Fatalf("trial %d: a storm with no throttling passed", trial)
		}
	}
}

// Should-fix 8 and the large-layers nit: shard-routes passes only when every
// checked route is in exactly its owners' Caddy (none nowhere); "every worker
// still admits" fails when Prometheus did not answer.
func TestEKSBankShardAndAdmitVerdicts(t *testing.T) {
	needTools(t, "python3")
	dir := t.TempDir()
	gws := []string{"g1", "g2", "g3"}
	var routes []any
	owners := [][]string{{"g1", "g2"}, {"g2", "g3"}, {"g3", "g1"}}
	for i, o := range owners {
		var os_ []map[string]string
		for _, g := range o {
			os_ = append(os_, map[string]string{"node_id": g})
		}
		routes = append(routes, map[string]any{"code": 200, "body": map[string]any{"sandbox_id": "sb-" + strconv.Itoa(i), "owners": os_, "ring_version": "r1"}})
	}
	writeLines(t, filepath.Join(dir, "routes.jsonl"), routes...)
	caddy := func(present map[string][]string) {
		for _, g := range gws {
			var b strings.Builder
			for sid, in := range present {
				for _, h := range in {
					if h == g {
						b.WriteString(sid + "-80.bank.test ")
					}
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "caddy-"+g+".json"), []byte(b.String()), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	all := map[string][]string{"sb-0": {"g1", "g2"}, "sb-1": {"g2", "g3"}, "sb-2": {"g3", "g1"}}
	caddy(all)
	if v, d := verdict(t, append([]string{"shard", dir}, gws...)...); v != "PASS" {
		t.Errorf("every route on its owners: %s %s", v, d)
	}
	caddy(map[string][]string{"sb-0": {"g1", "g2"}})
	if v, d := verdict(t, append([]string{"shard", dir}, gws...)...); v != "FAIL" || !strings.Contains(d, `"caddy_route_nowhere":2`) {
		t.Errorf("two routes in no gateway: %s %s", v, d)
	}
	caddy(map[string][]string{"sb-0": {"g1", "g2", "g3"}, "sb-1": {"g2", "g3"}, "sb-2": {"g3", "g1"}})
	if v, d := verdict(t, append([]string{"shard", dir}, gws...)...); v != "FAIL" {
		t.Errorf("a route on a gateway that does not own it: %s %s", v, d)
	}

	admit := filepath.Join(dir, "admit.txt")
	write := func(s string) {
		if err := os.WriteFile(admit, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("pod=w1 1\npod=w2 1\n")
	if v, d := verdict(t, "admit", admit, "0", "2"); v != "PASS" {
		t.Errorf("both admit: %s %s", v, d)
	}
	write("")
	if v, d := verdict(t, "admit", admit, "1", "2"); v != "FAIL" || !strings.Contains(d, "did not answer") {
		t.Errorf("Prometheus did not answer: %s %s", v, d)
	}
	if v, _ := verdict(t, "admit", admit, "0", "2"); v != "FAIL" {
		t.Errorf("no series at all passed")
	}
	write("pod=w1 1\npod=w2 0\n")
	if v, _ := verdict(t, "admit", admit, "0", "2"); v != "FAIL" {
		t.Errorf("a worker at 0 passed")
	}
}

// realHelm is a Helm of 3.8 or later, by absolute path (the stubs put a
// fake helm first on PATH), or the test is skipped.
func realHelm(t *testing.T) string {
	t.Helper()
	h := os.Getenv("HELM")
	if h == "" {
		h = "helm"
	}
	p, err := exec.LookPath(h)
	if err != nil {
		t.Skip("helm not available (set HELM)")
	}
	out, _ := exec.Command(p, "version", "--short").Output()
	m := regexp.MustCompile(`v3\.(\d+)`).FindSubmatch(out)
	if m == nil {
		t.Skipf("helm %q is not 3.x", out)
	}
	if n, _ := strconv.Atoi(string(m[1])); n < 8 {
		t.Skipf("helm %s is older than 3.8", out)
	}
	p, _ = filepath.Abs(p)
	return p
}

// fakeChart writes a chart whose pod-templates ConfigMap gives each role
// the env lines in envs (role -> lines), the way the real chart writes them.
func fakeChart(t *testing.T, envs map[string][]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "aerolvm")
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	var cm strings.Builder
	cm.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}-pod-templates\ndata:\n")
	for _, role := range []string{"server", "gateway", "worker"} {
		cm.WriteString("  " + role + ": |\n    spec:\n      containers:\n        - name: agent\n          env:\n")
		for _, l := range envs[role] {
			cm.WriteString("            - " + l + "\n")
		}
	}
	files := map[string]string{
		"Chart.yaml":               "apiVersion: v2\nname: aerolvm\nversion: 0.0.1\n",
		"values.yaml":              "worker:\n  registryCA: {}\n",
		"values-bank-eks.yaml":     "enterprise:\n  enabled: true\n",
		"templates/templates.yaml": cm.String(),
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var enterpriseEnv = []string{`{ name: SB_ENTERPRISE_MODE, value: "true" }`, `{ name: SB_AUDIT_WITNESS_S3_BUCKET, value: "guard-witness" }`,
	`{ name: SB_AUDIT_EXPORT_BACKEND, value: s3 }`, `{ name: SB_AUDIT_EXPORT_S3_BUCKET, value: "guard-export" }`}

// bankUp copies eks-bank.sh and what up reads into a fresh k8s/ folder,
// with a cluster.sh that records its arguments (and makes a Terraform
// state when up is asked, so a later failure has something to tear down).
func bankUp(t *testing.T) (string, string) {
	t.Helper()
	k8s := bankRun(t, "bank-1", "", true)
	for _, f := range []string{"drills-eks/values-run.yaml", "drills-eks/chart_guard.py"} {
		raw, err := os.ReadFile(k8sFile(t, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(k8s, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(k8s, f), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	calls := filepath.Join(k8s, "scripts.log")
	for _, s := range []string{"cluster.sh", "cell.sh"} {
		// cluster.sh up <name> ...; cell.sh <name> <step>.
		body := `#!/bin/sh
echo "` + s + ` $*" >> "` + calls + `"
if [ "$1" = up ]; then mkdir -p "$(dirname "$0")/.state/$2"; echo '{}' > "$(dirname "$0")/.state/$2/terraform.tfstate"; exit "${STUB_UP_EXIT:-0}"; fi
exit "${STUB_SCRIPT_EXIT:-0}"
`
		if err := os.WriteFile(filepath.Join(k8s, s), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return k8s, calls
}

// B3 and should-fix 9: before Terraform makes anything, up renders the chart
// and refuses one that does not give the server, gateway and worker
// templates enterprise mode and the audit witness and export; and it reads
// the account's own cost traps (Inspector's ECR scanning, AWS Config,
// GuardDuty runtime monitoring), refusing unless they are accepted.
func TestEKSBankUpGuards(t *testing.T) {
	needTools(t, "python3", "jq")
	helm := realHelm(t)
	full := map[string][]string{"server": enterpriseEnv, "gateway": enterpriseEnv, "worker": enterpriseEnv}
	noWitness := map[string][]string{"server": enterpriseEnv, "gateway": enterpriseEnv, "worker": enterpriseEnv[:1]}
	// Everything but enterprise mode itself on the server.
	off := map[string][]string{"server": append([]string{`{ name: SB_ENTERPRISE_MODE, value: "false" }`}, enterpriseEnv[1:]...),
		"gateway": enterpriseEnv, "worker": enterpriseEnv}
	for _, tc := range []struct {
		desc   string
		chart  map[string][]string
		env    []string
		code   int
		want   string
		upCall bool
	}{
		{"a chart without enterprise mode on the server", off, nil, 3, "does not run enterprise mode", false},
		{"a worker without the audit store", noWitness, nil, 3, "worker: SB_AUDIT_WITNESS_S3_BUCKET", false},
		{"the chart and the account in order", full, nil, 0, "", true},
		{"Inspector scanning ECR", full, []string{"STUB_INSPECTOR=ENABLED"}, 3, "Inspector enhanced ECR scanning", false},
		{"AWS Config recording", full, []string{"STUB_CONFIG=1"}, 3, "AWS Config recording", false},
		{"Inspector unreadable", full, []string{"STUB_INSPECTOR=unreadable"}, 3, "Inspector enhanced ECR scanning (unreadable)", false},
		// About $18 of scanning on top of a $40 worst case: past $45.
		{"Inspector accepted, under the default ceiling", full, []string{"STUB_INSPECTOR=ENABLED", "EKS_BANK_ACCEPT_ACCOUNT_COSTS=1"}, 3, "passes the ceiling", false},
		{"Inspector accepted, under a higher ceiling", full, []string{"STUB_INSPECTOR=ENABLED", "EKS_BANK_ACCEPT_ACCOUNT_COSTS=1", "EKS_BANK_CEILING=60"}, 0, "accepted about $", true},
		{"AWS Config accepted", full, []string{"STUB_CONFIG=1", "EKS_BANK_ACCEPT_ACCOUNT_COSTS=1"}, 0, "accepted about $4", true},
		// A detector that cannot be read counts as on.
		{"a GuardDuty detector that cannot be read", full, []string{"STUB_GD=d-1"}, 3, "GuardDuty runtime monitoring (unreadable)", false},
		{"an EKS cluster of the name exists", full, []string{"STUB_CLUSTER_EXISTS=1"}, 3, "an EKS cluster named bank-1 already exists", false},
	} {
		k8s, calls := bankUp(t)
		env, log := eksStubs(t)
		cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "up")
		cmd.Env = append(append(env, "HELM="+helm, "EKS_BANK_CHART_DIR="+fakeChart(t, tc.chart)), tc.env...)
		out, _ := cmd.CombinedOutput()
		if code := cmd.ProcessState.ExitCode(); code != tc.code || !strings.Contains(string(out), tc.want) {
			t.Errorf("%s: exit %d, want %d and %q:\n%s", tc.desc, code, tc.code, tc.want, out)
		}
		scripts := readLog(t, calls)
		if got := strings.Contains(scripts, "cluster.sh up bank-1"); got != tc.upCall {
			t.Errorf("%s: cluster.sh up called %v, want %v", tc.desc, got, tc.upCall)
		}
		// The values the guard rendered: every placeholder filled, the
		// worker pool from the run's settings.
		if vals, err := os.ReadFile(filepath.Join(k8s, ".state", "bank-1", "values-guard.yaml")); err == nil {
			if regexp.MustCompile(`@@[A-Z_]+@@`).Match(vals) || !strings.Contains(string(vals), "minWorkers: 6\n") || !strings.Contains(string(vals), "maxWorkers: 60\n") {
				t.Errorf("%s: the run's values:\n%s", tc.desc, vals)
			}
		}
		// Up's own calls are reads: the account's settings and the render.
		for _, l := range strings.Split(strings.TrimSpace(readLog(t, log)), "\n") {
			if l != "" && !regexp.MustCompile(`^aws (inspector2 batch-get-account-status|configservice describe-configuration-recorder-status|guardduty (list-detectors|get-detector)|eks describe-cluster) `).MatchString(l) {
				t.Errorf("%s: up made a call that is not a read: %s", tc.desc, l)
			}
		}
	}
	// The worst case plus the accepted extra is held to the ceiling too.
	k8s, calls := bankUp(t)
	env, _ := eksStubs(t)
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "up")
	cmd.Env = append(env, "HELM="+helm, "EKS_BANK_CHART_DIR="+fakeChart(t, full), "STUB_INSPECTOR=ENABLED", "EKS_BANK_ACCEPT_ACCOUNT_COSTS=1",
		"EKS_BANK_CEILING=41")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 3 || !strings.Contains(string(out), "passes the ceiling") || strings.Contains(readLog(t, calls), "cluster.sh up") {
		t.Errorf("an accepted extra past the ceiling: exit %d\n%s", cmd.ProcessState.ExitCode(), out)
	}
}

// Should-fix 3: `all` stopped at the first failing step and left the run up
// until the teardown timer. Now it tears down, unless EKS_BANK_KEEP=1, and
// never after a refusal (wrong credentials would make Terraform forget the
// run) or when nothing was made.
func TestEKSBankAllTearsDownOnFailure(t *testing.T) {
	needTools(t, "python3", "jq")
	helm := realHelm(t)
	full := map[string][]string{"server": enterpriseEnv, "gateway": enterpriseEnv, "worker": enterpriseEnv}
	off := map[string][]string{"server": enterpriseEnv[1:], "gateway": enterpriseEnv, "worker": enterpriseEnv}
	for _, tc := range []struct {
		desc    string
		env     []string
		earlier bool // an earlier run's state is in .state/bank-1
		chart   map[string][]string
		down    bool
		want    string
	}{
		{desc: "up made the cell, then failed", env: []string{"STUB_UP_EXIT=1"}, chart: full, down: true},
		{desc: "the same, EKS_BANK_KEEP=1", env: []string{"STUB_UP_EXIT=1", "EKS_BANK_KEEP=1"}, chart: full},
		{desc: "refused by the estimate: nothing was made", env: []string{"EKS_BANK_CEILING=10"}, chart: full},
		// Round 2: an earlier run's state is not this process's to tear
		// down, and up does not make a run over it.
		{desc: "an earlier run's state, refused by the estimate", env: []string{"EKS_BANK_CEILING=10"}, earlier: true, chart: full, want: "REFUSED"},
		{desc: "an earlier run's state, refused by the guard", earlier: true, chart: off, want: "does not run enterprise mode"},
		{desc: "an earlier run's state, up over it", earlier: true, chart: full, want: "still holds a run's resources"},
	} {
		k8s, calls := bankUp(t)
		env, log := eksStubs(t)
		if tc.earlier {
			st := filepath.Join(k8s, ".state", "bank-1")
			if err := os.MkdirAll(st, 0o755); err != nil {
				t.Fatal(err)
			}
			for f, body := range map[string]string{"terraform.tfstate": `{"resources": [{"type": "aws_eks_cluster"}]}`,
				"run.tfvars.json": `{"name": "bank-1", "bank_drills": true, "aws_account": "111122223333"}`} {
				if err := os.WriteFile(filepath.Join(st, f), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "all")
		cmd.Env = append(append(env, "HELM="+helm, "EKS_BANK_CHART_DIR="+fakeChart(t, tc.chart)), tc.env...)
		out, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() == 0 || !strings.Contains(string(out), tc.want) {
			t.Errorf("%s: exit %d, want a failure saying %q:\n%s", tc.desc, cmd.ProcessState.ExitCode(), tc.want, out)
		}
		if got := strings.Contains(readLog(t, calls), "cell.sh bank-1 down"); got != tc.down {
			t.Errorf("%s: down ran %v, want %v:\n%s", tc.desc, got, tc.down, out)
		}
		// After a refusal, no AWS call at all.
		if tc.earlier {
			if strings.Contains(readLog(t, calls), "cluster.sh up") || strings.Contains(readLog(t, log), "aws ") {
				t.Errorf("%s: calls after the refusal: %s %s", tc.desc, readLog(t, calls), readLog(t, log))
			}
		}
	}
	// A gate refusal after up (the run's kubeconfig names a kind cluster)
	// tears nothing down.
	k8s, calls := bankUp(t)
	env, _ := eksStubs(t)
	stub := `#!/bin/sh
echo "cluster.sh $*" >> "` + calls + `"
d="$(dirname "$0")/.state/$2"; mkdir -p "$d"; echo '{}' > "$d/terraform.tfstate"
printf 'current-context: kind-x\n' > "$d/kubeconfig"; echo '{"name": "bank-1", "bank_drills": true}' > "$d/run.tfvars.json"
`
	if err := os.WriteFile(filepath.Join(k8s, "cluster.sh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "all")
	cmd.Env = append(env, "HELM="+helm, "EKS_BANK_CHART_DIR="+fakeChart(t, full))
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 2 || strings.Contains(readLog(t, calls), "cell.sh bank-1 down") {
		t.Errorf("a gate refusal: exit %d, scripts %q:\n%s", cmd.ProcessState.ExitCode(), readLog(t, calls), out)
	}
}

// Should-fix 4 and 5: scale refuses when the teardown timer is closer than
// the box, the way back and half an hour; DRY_RUN takes 0 or 1 and refuses
// anything else, in eks-bank.sh and reap.sh, before any call.
func TestEKSBankScaleTTLAndDryRunValues(t *testing.T) {
	needTools(t, "python3")
	const good = "arn:aws:eks:us-east-1:111122223333:cluster/bank-1"
	k8s := bankRun(t, "bank-1", good, true)
	ttl := func(minutes int) {
		raw, _ := json.Marshal(map[string]any{"name": "bank-1", "bank_drills": true,
			"ttl": timeIn(t, minutes)})
		if err := os.WriteFile(filepath.Join(k8s, ".state", "bank-1", "run.tfvars.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ttl(100)
	env, log := eksStubs(t)
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "scale")
	cmd.Env = env
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() == 0 || !strings.Contains(string(out), "scale: refused") || !strings.Contains(string(out), "the step needs 110") {
		t.Errorf("100 minutes left: exit %d\n%s", cmd.ProcessState.ExitCode(), out)
	}
	for _, l := range strings.Split(strings.TrimSpace(readLog(t, log)), "\n") {
		if l != "kubectl config current-context" && !strings.HasPrefix(l, "aws sts get-caller-identity") {
			t.Errorf("scale called %q before refusing", l)
		}
	}

	for _, v := range []string{"true", "yes", "2", "TRUE"} {
		for _, script := range [][]string{{filepath.Join(k8s, "eks-bank.sh"), "bank-1", "estimate"}, {k8sFile(t, "reap.sh")}} {
			env, log := eksStubs(t)
			cmd := exec.Command("bash", script...)
			cmd.Env = append(env, "DRY_RUN="+v)
			out, _ := cmd.CombinedOutput()
			if cmd.ProcessState.ExitCode() != 2 || !strings.Contains(string(out), "DRY_RUN must be 0 or 1") || strings.TrimSpace(readLog(t, log)) != "" {
				t.Errorf("%s DRY_RUN=%s: exit %d, calls %q:\n%s", filepath.Base(script[0]), v, cmd.ProcessState.ExitCode(), readLog(t, log), out)
			}
		}
	}
}

func timeIn(t *testing.T, minutes int) string {
	t.Helper()
	out, err := exec.Command("python3", "-c", fmt.Sprintf(
		`import datetime; print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=%d)).strftime("%%Y-%%m-%%dT%%H:%%M:%%SZ"))`, minutes)).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// chart_guard.py reads the chart's env lines per role, and refuses a render
// it cannot read.
func TestEKSBankChartGuard(t *testing.T) {
	needTools(t, "python3")
	dir := t.TempDir()
	run := func(render string, want ...string) (int, string) {
		p := filepath.Join(dir, "r.yaml")
		if err := os.WriteFile(p, []byte(render), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("python3", append([]string{"-I", k8sFile(t, "drills-eks", "chart_guard.py"), p}, want...)...)
		out, _ := cmd.CombinedOutput()
		return cmd.ProcessState.ExitCode(), string(out)
	}
	cm := func(lines map[string]string) string {
		var b strings.Builder
		b.WriteString("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: aerolvm-pod-templates\ndata:\n")
		for _, r := range []string{"server", "gateway", "worker"} {
			if l, ok := lines[r]; ok {
				b.WriteString("  " + r + ": |\n    spec:\n      containers:\n        - env:\n            - " + l + "\n")
			}
		}
		return b.String()
	}
	on := `{ name: SB_ENTERPRISE_MODE, value: "true" }`
	if code, out := run(cm(map[string]string{"server": on, "gateway": on, "worker": on}), "SB_ENTERPRISE_MODE=true"); code != 0 {
		t.Errorf("every role on: %d %s", code, out)
	}
	if code, out := run(cm(map[string]string{"server": on, "gateway": on}), "SB_ENTERPRISE_MODE=true"); code != 1 || !strings.Contains(out, "worker: no template") {
		t.Errorf("no worker template: %d %s", code, out)
	}
	if code, out := run(cm(map[string]string{"server": on, "gateway": on, "worker": `{ name: SB_ENTERPRISE_MODE, value: "" }`}), "SB_ENTERPRISE_MODE=*"); code != 1 {
		t.Errorf("an empty value for *: %d %s", code, out)
	}
	if code, out := run(cm(map[string]string{"server": `{ name: SB_ENTERPRISE_MODE, value: "false" }`, "gateway": on, "worker": on}), "SB_ENTERPRISE_MODE=true"); code != 1 || !strings.Contains(out, "server: SB_ENTERPRISE_MODE=true (has 'false')") {
		t.Errorf("enterprise mode off on the server: %d %s", code, out)
	}
	if code, _ := run("kind: Secret\n", "SB_ENTERPRISE_MODE=true"); code != 1 {
		t.Errorf("a render without the ConfigMap passed")
	}
}

// Should-fix 1: cluster.sh down could hang on a bucket S3 keeps entries of
// (an Errors list in a 200), or stop before destroying anything. Now the
// node groups go first, a bucket that cannot be emptied is reported and
// does not stop the destroy, and the failure is named at the end.
func TestClusterDownWithABucketS3Keeps(t *testing.T) {
	needTools(t, "jq", "python3")
	root := t.TempDir()
	for _, f := range []string{"k8s/cluster.sh", "lib/common.sh", "lib/stage.sh"} {
		raw, err := os.ReadFile(filepath.Join(integrationDir(t), f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(root, "k8s", ".state", "bank-1")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{"terraform.tfstate": "{}", "run.tfvars.json": `{"name": "bank-1", "bank_drills": true, "karpenter": false}`} {
		if err := os.WriteFile(filepath.Join(state, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bin, log := t.TempDir(), filepath.Join(t.TempDir(), "calls.log")
	stubs := map[string]string{
		// One entry S3 keeps, every time: a 200 with an Errors list.
		"aws": `echo "aws $*" >> "$STUB_LOG"
case "$*" in
  *list-object-versions*) echo '{"Versions":[{"Key":"heads/node=a/x","VersionId":"v1"}]}' ;;
  *delete-objects*) echo '{"Errors":[{"Key":"heads/node=a/x","VersionId":"v1","Code":"AccessDenied","Message":"denied"}]}' ;;
  *describe-*) echo "" ;;
esac
exit 0`,
		"terraform": `echo "terraform $*" >> "$STUB_LOG"
case "$*" in *"output"*witness_bucket*) echo bank-1-witness-1 ;; *"output"*export_bucket*) echo bank-1-export-1 ;; *"output"*region*) echo us-east-1 ;; esac
exit 0`,
		"kubectl": `echo "kubectl $*" >> "$STUB_LOG"; exit 0`,
	}
	for n, b := range stubs {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"+b+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", filepath.Join(root, "k8s", "cluster.sh"), "down", "bank-1")
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_LOG="+log)
	done := make(chan struct{})
	var out []byte
	go func() { out, _ = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("cluster.sh down did not finish in 60 s (a bucket S3 keeps made it loop)")
	}
	calls := readLog(t, log)
	targeted := strings.Index(calls, "-target=aws_eks_node_group.worker")
	list := strings.Index(calls, "list-object-versions")
	if targeted < 0 || list < 0 || targeted > list {
		t.Errorf("the buckets were emptied before the node groups went:\n%s", calls)
	}
	if n := strings.Count(calls, "delete-objects"); n != 2 {
		t.Errorf("%d delete-objects calls, want one a bucket (a refusal ends that bucket's emptying)", n)
	}
	fullDestroy := false
	for _, l := range strings.Split(calls[list:], "\n") {
		if strings.HasPrefix(l, "terraform ") && strings.Contains(l, " destroy ") && !strings.Contains(l, "-target=") {
			fullDestroy = true
		}
	}
	if !fullDestroy {
		t.Errorf("the full destroy never ran after the buckets:\n%s", calls)
	}
	if !strings.Contains(string(out), "S3 kept") {
		t.Errorf("the kept entry is not reported:\n%s", out)
	}
}

// The Ctrl-C nit: stopping the peak drills ended drills-eks.sh but left its
// port-forward loop running. kill_tree (eks-bank.sh's own, read from the
// script) ends the whole tree, deepest first, and the child's EXIT trap
// still runs.
func TestEKSBankKillTreeEndsTheDrillsTree(t *testing.T) {
	src, err := os.ReadFile(k8sFile(t, "eks-bank.sh"))
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?s)\nkill_tree\(\) \{.*?\n\}\n`).Find(src)
	if fn == nil {
		t.Fatal("no kill_tree in eks-bank.sh")
	}
	dir := t.TempDir()
	child := filepath.Join(dir, "child.sh")
	// drills-eks.sh's shape: an EXIT trap, a background loop (keep_forward),
	// a foreground child (prom wait).
	if err := os.WriteFile(child, []byte(`#!/usr/bin/env bash
set -euo pipefail
( trap 'exit 0' TERM; while :; do sleep 1; done ) &
echo "$!" > "$1.keeper"
trap 'echo cleanup-ran >> "$1"' EXIT
sleep 30
`), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	script := string(fn) + `
drills() { "` + child + `" "` + out + `"; }
drills & pid=$!
sleep 2
kill_tree "$pid"
wait "$pid" 2>/dev/null || true
sleep 1
k=$(cat "` + out + `.keeper")
if kill -0 "$k" 2>/dev/null; then echo "LOOP-LEFT $k"; kill "$k"; else echo loop-gone; fi
echo "trap: $(cat "` + out + `" 2>/dev/null)"
`
	got, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, got)
	}
	if !strings.Contains(string(got), "loop-gone") || !strings.Contains(string(got), "trap: cleanup-ran") {
		t.Errorf("kill_tree left part of the tree, or the EXIT trap did not run:\n%s", got)
	}
}

// Round 2: no down acts in another account. eks-bank.sh down without a
// kubeconfig, and cluster.sh down, check this machine's AWS account against
// the one up recorded before anything else; cluster.sh refuses a
// TF_VAR_region other than us-east-1 (the runs are us-east-1 only).
func TestDownRefusesAnotherAccount(t *testing.T) {
	needTools(t, "python3", "jq")
	k8s, calls := bankUp(t)
	st := filepath.Join(k8s, ".state", "bank-1")
	if err := os.MkdirAll(st, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{"terraform.tfstate": `{"resources": [{"type": "aws_vpc"}]}`,
		"run.tfvars.json": `{"name": "bank-1", "bank_drills": true, "aws_account": "999999999999"}`} {
		if err := os.WriteFile(filepath.Join(st, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env, log := eksStubs(t)
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "down")
	cmd.Env = env
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 2 || !strings.Contains(string(out), "bank-1 was made in 999999999999") {
		t.Errorf("eks-bank.sh down in another account: exit %d\n%s", cmd.ProcessState.ExitCode(), out)
	}
	if l := strings.TrimSpace(readLog(t, log)); l != "aws sts get-caller-identity --query Account --output text" || strings.Contains(readLog(t, calls), "down") {
		t.Errorf("eks-bank.sh down called more than the account check: %q %q", l, readLog(t, calls))
	}

	// cluster.sh down, the real one, against stubs.
	root := t.TempDir()
	for _, f := range []string{"k8s/cluster.sh", "lib/common.sh", "lib/stage.sh"} {
		raw, err := os.ReadFile(filepath.Join(integrationDir(t), f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cst := filepath.Join(root, "k8s", ".state", "bank-1")
	if err := os.MkdirAll(cst, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{"terraform.tfstate": "{}", "run.tfvars.json": `{"name": "bank-1", "aws_account": "999999999999", "region": "us-east-1"}`} {
		if err := os.WriteFile(filepath.Join(cst, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		desc, cmd string
		env       []string
		want      string
	}{
		{"another account", "down", nil, "the run was made in 999999999999"},
		{"another region", "down", []string{"TF_VAR_region=eu-west-1", "STUB_ACCOUNT=999999999999"}, "these runs are us-east-1 only"},
		// allow-ip writes to the cluster too (update-cluster-config).
		{"allow-ip in another account", "allow-ip", nil, "the run was made in 999999999999"},
	} {
		env, log := eksStubs(t)
		cmd := exec.Command("bash", filepath.Join(root, "k8s", "cluster.sh"), tc.cmd, "bank-1")
		cmd.Env = append(env, tc.env...)
		out, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() == 0 || !strings.Contains(string(out), tc.want) {
			t.Errorf("cluster.sh down, %s: exit %d\n%s", tc.desc, cmd.ProcessState.ExitCode(), out)
		}
		for _, l := range strings.Split(strings.TrimSpace(readLog(t, log)), "\n") {
			if l != "" && l != "aws sts get-caller-identity --query Account --output text" {
				t.Errorf("cluster.sh down, %s: called %q before refusing", tc.desc, l)
			}
		}
	}
}
