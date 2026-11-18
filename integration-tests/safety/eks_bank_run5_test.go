package safety

import (
	"context"
	"encoding/json"
	"net"
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

// The bank run's fifth attempt (2026-11-18) ran whole and tore down clean,
// but its FAIL lines were the harness's:
//   - gvisor: admin_call slept a fixed 3 s after starting its port-forward,
//     and the placement read got "connection refused";
//   - shard-routes: caddy_get sent `kc … port-forward &` to the background,
//     so $! was a subshell and its kubectl outlived the read; it held the
//     port, and the ten other gateways' reads all got that one's config;
//   - slo-alerts/routing/recover and scale-full: the fills used fixed sizes
//     (8, 4, 2, 1 CPU, and rounds of 8 1-CPU fillers) against a 2-CPU create
//     policy and workers of 18 CPUs, and the operator added a worker as the
//     cell filled, so no worker ran out;
//   - pull-alerts and pull-queue at 60 workers: the 6-worker storm (24 cold
//     creates, 10 min) queued nothing on 60 workers, and ended before two of
//     its alerts could fire;
//   - the closing "checks that failed" line left out the drills' FAILs.
// And the #1363 review's follow-ups: an undo that has begun is left to
// finish, the teardown runs in its own process group, and the way-back
// loop's wait on a failed read is held by a test. Each test below fails on
// the code before the fix (except the way-back one, which holds code that
// was right).

// cleanEnviron is os.Environ() without the bank run's own settings
// (EKS_BANK_*, DRILL_*, DRY_RUN): a value the caller exported, such as an
// EKS_BANK_DRILLS left over from a re-run, must not change what a test runs
// (TestEKSBankEstimateGuardsUp failed with one exported).
func cleanEnviron() []string {
	var env []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "EKS_BANK_") || strings.HasPrefix(e, "DRILL_") || strings.HasPrefix(e, "DRY_RUN=") {
			continue
		}
		env = append(env, e)
	}
	return env
}

// freePort is a local port nothing listens on (taken, then let go).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// fakeKubectlPy does what matters of kubectl port-forward: it binds the
// local port (and, as kubectl does, ends at once when it cannot), says
// "Forwarding from 127.0.0.1:<port> -> <port>" (after PF_DELAY seconds),
// and answers HTTP there with the pod it forwards to. PF_FAIL: it cannot
// listen. Each one's PID goes to $OUT/forwards.
const fakeKubectlPy = `#!/usr/bin/env python3
import http.server, json, os, sys, time
args = sys.argv[1:]
if "port-forward" not in args:
    sys.exit(1)
pair = [a for a in args if ":" in a and a.split(":")[0].isdigit()][-1]
lport, rport = pair.split(":")
pod = [a for a in args if a.startswith("pod/")][-1][4:]
with open(os.path.join(os.environ["OUT"], "forwards"), "a") as f:
    f.write("%d\n" % os.getpid())
if os.environ.get("PF_FAIL"):
    print("error: unable to listen on any of the requested ports: [{%s %s}]" % (lport, rport), file=sys.stderr)
    sys.exit(1)
time.sleep(float(os.environ.get("PF_DELAY") or 0))

class H(http.server.BaseHTTPRequestHandler):
    def answer(self):
        body = json.dumps({"pod": pod, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = answer
    do_POST = answer
    def log_message(self, *a):
        pass

try:
    srv = http.server.HTTPServer(("127.0.0.1", int(lport)), H)
except OSError as e:
    print("Unable to listen on port %s: %s" % (lport, e), file=sys.stderr)
    print("error: unable to listen on any of the requested ports: [{%s %s}]" % (lport, rport), file=sys.stderr)
    sys.exit(1)
print("Forwarding from 127.0.0.1:%s -> %s" % (lport, rport), flush=True)
srv.serve_forever()
`

// fakeKubectl puts fakeKubectlPy first on PATH and returns the PATH entry.
// Every fake it started is ended, by its PID, when the test ends.
func fakeKubectl(t *testing.T, out string) string {
	t.Helper()
	needTools(t, "python3", "curl")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(fakeKubectlPy), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { killForwards(t, out) })
	return "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")
}

// liveForwards lists the fake port-forwards still running.
func liveForwards(t *testing.T, out string) []int {
	t.Helper()
	var live []int
	for _, f := range strings.Fields(readLog(t, filepath.Join(out, "forwards"))) {
		if pid, _ := strconv.Atoi(f); pid > 0 && syscall.Kill(pid, 0) == nil {
			live = append(live, pid)
		}
	}
	return live
}

// killForwards ends the fakes this test started, each by its PID.
func killForwards(t *testing.T, out string) {
	t.Helper()
	for _, pid := range liveForwards(t, out) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// runBash runs script under a 60 s limit with env added. From a file, as
// the bank run's scripts run: under bash -c, bash execs the last command of
// a function sent to the background, so $! is kubectl itself there and the
// fifth run's orphaned port-forward does not happen.
func runBash(t *testing.T, script string, env ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := filepath.Join(t.TempDir(), "harness.sh")
	if err := os.WriteFile(f, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "bash", f)
	cmd.Env = append(cleanEnviron(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// shellFuncIf is shellFunc, or "" when the script has no such function (the
// code before the fix, run by the same harness).
func shellFuncIf(t *testing.T, script, name string) string {
	t.Helper()
	src, err := os.ReadFile(k8sFile(t, script))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "\n"+name+"() {") {
		return ""
	}
	return shellFunc(t, script, name)
}

// (1) admin_call and gw_call wait until their port-forward forwards (a
// fixed sleep 3 was too short: the gVisor check's placement read got
// "connection refused"), and fail clearly when it never does, or when the
// local port is another process's: an answer of 000 that says why.
func TestPortForwardWaitsUntilItForwards(t *testing.T) {
	needTools(t, "jq")
	for _, call := range []string{"admin_call", "gw_call"} {
		for _, tc := range []struct {
			desc, env, code, says string
			busy                  bool
		}{
			{desc: "forwards after 4 s", env: "PF_DELAY=4", code: "200", says: `"pod": "aerolvm-`},
			{desc: "never forwards", env: "PF_FAIL=1", code: "000", says: "kubectl ended before it forwarded: error: unable to listen"},
			{desc: "the port is another process's", busy: true, code: "000", says: "already answers on 127.0.0.1"},
		} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "api-token"), []byte("avm_x"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := fakeKubectl(t, dir)
			port := freePort(t)
			if tc.busy {
				l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { l.Close() })
			}
			script := `set -euo pipefail
dry=0; ns=aerolvm-system; cname=aerolvm; sd="$OUT"; admin_lport="$PORT"; gw_lport="$PORT"
kr() { case "$*" in *secret*) printf 'YWRtaW4=' ;; *gateway*) echo aerolvm-gateway-1 ;; esac; }
[[ ! -f "$K8S/port-forward.sh" ]] || source "$K8S/port-forward.sh"
` + shellFunc(t, "eks-bank.sh", call) + call + " GET /v1/cluster/placements/sb-1\n"
			out, err := runBash(t, script, "OUT="+dir, "PORT="+strconv.Itoa(port), "K8S="+filepath.Dir(k8sFile(t, "eks-bank.sh")), path, tc.env)
			lines := strings.SplitN(out, "\n", 2)
			if err != nil || lines[0] != tc.code || len(lines) < 2 || !strings.Contains(lines[1], tc.says) {
				t.Errorf("%s, %s: %v, answered %q, want %s saying %q", call, tc.desc, err, out, tc.code, tc.says)
			}
			if live := liveForwards(t, dir); len(live) > 0 {
				t.Errorf("%s, %s: port-forwards still running after the call: %v", call, tc.desc, live)
			}
			if tc.busy && readLog(t, filepath.Join(dir, "forwards")) != "" {
				t.Errorf("%s, %s: a port-forward was started on a port in use", call, tc.desc)
			}
		}
	}
}

// (2) caddy_get reads the gateway it names and nothing else: its kubectl
// ends with the read (it held the port in the fifth run, and every later
// read got its gateway's config), and a local port another process holds
// is a failed read, never a read through that process.
func TestCaddyGetReadsOnlyItsOwnGateway(t *testing.T) {
	dir := t.TempDir()
	path := fakeKubectl(t, dir)
	port := freePort(t)
	script := `set -euo pipefail
ns=aerolvm-system; ctx=none; sd="$OUT"; caddy_lport="$PORT"
kc() { kubectl --context "$ctx" "$@"; }
[[ ! -f "$K8S/port-forward.sh" ]] || source "$K8S/port-forward.sh"
` + shellFunc(t, "drills-eks.sh", "caddy_get") + `
for gw in $GWS; do
  caddy_get "$gw" > "$OUT/caddy-$gw.json" 2>> "$OUT/errors" || echo "$gw" >> "$OUT/unread"
done
`
	env := []string{"OUT=" + dir, "PORT=" + strconv.Itoa(port), "K8S=" + filepath.Dir(k8sFile(t, "drills-eks.sh")), path}
	if out, err := runBash(t, script, append(env, "GWS=aerolvm-gateway-a aerolvm-gateway-b")...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, gw := range []string{"aerolvm-gateway-a", "aerolvm-gateway-b"} {
		if got := readLog(t, filepath.Join(dir, "caddy-"+gw+".json")); !strings.Contains(got, `"pod": "`+gw+`"`) {
			t.Errorf("the read of %s got %q", gw, got)
		}
	}
	if live := liveForwards(t, dir); len(live) > 0 {
		t.Errorf("port-forwards still running after the reads: %v", live)
	}
	killForwards(t, dir)

	// The port held by another process: a failed read, with the reason,
	// and no port-forward started.
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := t.TempDir()
	t.Cleanup(func() { killForwards(t, busy) })
	env[0] = "OUT=" + busy
	if out, err := runBash(t, script, append(env, "GWS=aerolvm-gateway-c")...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if readLog(t, filepath.Join(busy, "unread")) != "aerolvm-gateway-c\n" || readLog(t, filepath.Join(busy, "caddy-aerolvm-gateway-c.json")) != "" ||
		!strings.Contains(readLog(t, filepath.Join(busy, "errors")), "already answers on 127.0.0.1") {
		t.Errorf("a read through a port in use: unread %q, config %q, errors %q", readLog(t, filepath.Join(busy, "unread")),
			readLog(t, filepath.Join(busy, "caddy-aerolvm-gateway-c.json")), readLog(t, filepath.Join(busy, "errors")))
	}
	if readLog(t, filepath.Join(busy, "forwards")) != "" {
		t.Error("a port-forward was started on a port in use")
	}
}

// (2) The shard verdict, given what the fifth run's reads could produce: a
// gateway whose config was not read, and two gateways with the same config
// that the routes give different sandboxes. Both passed before when the
// first 6 sandboxes did not touch them.
func TestShardVerdictNamesUnreadAndIdenticalConfigs(t *testing.T) {
	needTools(t, "python3")
	gws := []string{"g1", "g2", "g3"}
	// sb-0..sb-5 on g1 and g2 (the 6 the verdict samples), sb-6 on g3 and g1.
	write := func(dir string, configs map[string]string) {
		var routes []any
		for i := 0; i < 7; i++ {
			owners := []map[string]string{{"node_id": "g1"}, {"node_id": "g2"}}
			if i == 6 {
				owners = []map[string]string{{"node_id": "g3"}, {"node_id": "g1"}}
			}
			routes = append(routes, map[string]any{"code": 200, "body": map[string]any{"sandbox_id": "sb-" + strconv.Itoa(i), "owners": owners, "ring_version": "r1"}})
		}
		writeLines(t, filepath.Join(dir, "routes.jsonl"), routes...)
		for g, c := range configs {
			if err := os.WriteFile(filepath.Join(dir, "caddy-"+g+".json"), []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	first6 := "sb-0 sb-1 sb-2 sb-3 sb-4 sb-5"
	for _, tc := range []struct {
		desc    string
		configs map[string]string
		verdict string
		says    string
	}{
		{"every config read, each its own", map[string]string{"g1": first6 + " sb-6", "g2": first6, "g3": "sb-6"}, "PASS", `"caddy_unread":[]`},
		{"g3's config not read", map[string]string{"g1": first6 + " sb-6", "g2": first6, "g3": ""}, "FAIL", `"caddy_unread":["g3"]`},
		{"g1 and g2 the same, though g1 owns sb-6", map[string]string{"g1": first6, "g2": first6, "g3": "sb-6"}, "FAIL", `"caddy_identical":[["g1","g2"]]`},
	} {
		dir := t.TempDir()
		write(dir, tc.configs)
		if v, d := verdict(t, append([]string{"shard", dir}, gws...)...); v != tc.verdict || !strings.Contains(d, tc.says) {
			t.Errorf("%s: %s %s, want %s with %s", tc.desc, v, d, tc.verdict, tc.says)
		}
	}
}

// (3) fillplan.py sizes a fill from the members and the create policy.
func TestFillPlanSizesFromTheMembers(t *testing.T) {
	needTools(t, "python3")
	dir := t.TempDir()
	members := func(free ...float64) map[string]any {
		var ms []any
		ms = append(ms, map[string]any{"node_id": "s1", "role": "server", "capacity": map[string]any{"available_cpu": 99, "can_admit": true}})
		for i, f := range free {
			ms = append(ms, map[string]any{"node_id": "w" + strconv.Itoa(i), "role": "worker", "capacity": map[string]any{"available_cpu": f, "can_admit": f >= 1, "cpu_budget": 18}})
		}
		return map[string]any{"members": ms}
	}
	write := func(name string, v any) string {
		p := filepath.Join(dir, name)
		var raw []byte
		if s, ok := v.(string); ok {
			raw = []byte(s)
		} else {
			raw, _ = json.Marshal(v)
		}
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	limit2 := write("policy2.yaml", "version: 1\nlimits:\n  max_cpu: 2\n  max_memory_mb: 4096\n")
	flow := write("flow.yaml", "limits: { max_cpu: 2, max_memory_mb: 4096 }\n")
	none := write("none.yaml", "version: 1\n")
	six := members(18, 18, 18, 18, 18, 18)
	for _, tc := range []struct {
		desc    string
		members any
		policy  string
		args    []string
		want    map[string]float64
	}{
		{"six workers of 18, a 2-CPU limit", six, limit2, nil, map[string]float64{"workers": 6, "admitting": 6, "cpu": 2, "count": 54, "topup_cpu": 2}},
		{"the same, one past (the scale step)", six, limit2, []string{"--past", "1"}, map[string]float64{"count": 55}},
		{"the limit in flow style, the drills' wrapper", map[string]any{"code": 200, "body": six}, flow, nil, map[string]float64{"cpu": 2, "count": 54}},
		{"no limit: a worker's free CPU", six, none, nil, map[string]float64{"cpu": 18, "count": 6}},
		{"each worker counted on its own; under 1 CPU does not admit", members(5, 4.5, 0.5), limit2, nil,
			map[string]float64{"workers": 3, "admitting": 2, "free_cpu": 10, "cpu": 2, "count": 4, "topup_cpu": 2}},
		{"the top-up fits the fullest admitting worker", members(1.5, 9), limit2, nil, map[string]float64{"topup_cpu": 1}},
	} {
		out, err := exec.Command("python3", append([]string{"-I", k8sFile(t, "drills-local", "fillplan.py"), write("m.json", tc.members), tc.policy}, tc.args...)...).CombinedOutput()
		var got map[string]float64
		if err != nil || json.Unmarshal(out, &got) != nil {
			t.Errorf("%s: %v %s", tc.desc, err, out)
			continue
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: %s = %v, want %v (%s)", tc.desc, k, got[k], v, out)
			}
		}
	}
	if out, err := exec.Command("python3", "-I", k8sFile(t, "drills-local", "fillplan.py"), write("m.json", map[string]any{"members": []any{}}), none).CombinedOutput(); err == nil {
		t.Errorf("no worker in the answer gave a plan: %s", out)
	}
}

// fakeCellPy is a cell for the fill drills: workers of 18 CPUs, a 2-CPU
// create policy, placement on the worker with the most free CPU, and an
// operator that adds a worker once 75% of the CPU is taken, up to the
// pool's maxWorkers (as the fifth run's did, at 80 of 108), one at a time;
// with FLAKY=N it refuses every Nth create once.
// New workers serve at once, or with NEW=Pending one read of the counts
// later.
const fakeCellPy = `import json, os, sys
state_path, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
if os.path.exists(state_path):
    st = json.load(open(state_path))
else:
    st = {"workers": [{"name": "w%d" % i, "free": 18.0, "state": "Serving"} for i in range(6)],
          "budget": 18.0, "max_workers": 60, "min_workers": 6, "max_cpu": 2.0, "n": 0, "patches": []}
serving = lambda: [w for w in st["workers"] if w["state"] == "Serving"]

def save():
    json.dump(st, open(state_path, "w"))

def operator():
    total = st["budget"] * len(serving())
    used = sum(st["budget"] - w["free"] for w in serving())
    pending = any(w["state"] != "Serving" for w in st["workers"])
    if used >= 0.75 * total and len(st["workers"]) < st["max_workers"] and not pending:
        st["workers"].append({"name": "w%d" % len(st["workers"]), "free": st["budget"], "state": os.environ.get("NEW", "Serving")})

def create(cpu):
    # FLAKY=N: every Nth create is refused once, as placement does while its
    # view of a worker trails the creates before it.
    st["tries"] = st.get("tries", 0) + 1
    flaky = int(os.environ.get("FLAKY") or 0)
    if flaky and st["tries"] % flaky == 0:
        return 503, {"error": "no worker can admit (placement's view is behind)"}
    if cpu > st["max_cpu"]:
        return 403, {"error": "create refused by policy rule \"limits.max_cpu\": cpu %g is above this server's limit of %g" % (cpu, st["max_cpu"]), "code": "create_policy_denied"}
    fit = [w for w in serving() if w["free"] >= cpu]
    if not fit:
        return 503, {"error": "no worker can admit"}
    w = max(fit, key=lambda w: w["free"])
    w["free"] -= cpu
    st["n"] += 1
    operator()
    return 201, {"id": "sb-%d" % st["n"]}

def members():
    ms = [{"node_id": "s1", "role": "server", "capacity": {"can_admit": False}}]
    for w in serving():
        ms.append({"node_id": w["name"], "role": "worker", "capacity": {"available_cpu": w["free"], "can_admit": w["free"] >= 1, "cpu_budget": st["budget"]}})
    return {"members": ms}

def call(method, path, body):
    if method == "GET" and path == "/v1/cluster/members":
        return 200, members()
    if method == "POST" and path == "/v1/sandboxes":
        return create(float(json.loads(body)["cpu"]))
    return 200, {}

if cmd == "api":
    code, b = call(args[0], args[1], args[2] if len(args) > 2 else "{}")
    print(json.dumps({"code": code, "body": b}))
elif cmd == "gw":
    code, b = call(args[0], args[1], args[2] if len(args) > 2 else "{}")
    print(code)
    print(json.dumps(b))
elif cmd == "fill":
    for _ in range(int(args[0])):
        create(float(args[1]))
elif cmd == "unfill":
    st["workers"] = st["workers"][:st["min_workers"]]
    for w in st["workers"]:
        w["free"] = st["budget"]
elif cmd == "workers":
    s = len(serving())
    print(s, len(st["workers"]) - s, len(st["workers"]))
    for w in st["workers"]:
        w["state"] = "Serving"
elif cmd == "admitting":
    print(sum(1 for w in serving() if w["free"] >= 1), len(serving()))
elif cmd == "kc":
    a = " ".join(args)
    if "get configmap" in a:
        print("version: 1\nlimits:\n  max_cpu: %g\n  max_memory_mb: 4096" % st["max_cpu"])
    elif "get aerolcluster" in a and "maxWorkers" in a:
        print(st["max_workers"], end="")
    elif "get aerolcluster" in a and "minWorkers" in a:
        print(st["min_workers"], end="")
    elif "get aerolnodes" in a:
        print(json.dumps({"items": [{"spec": {"role": "worker"}, "status": {"state": w["state"]}} for w in st["workers"]]}))
    elif "patch aerolcluster" in a:
        p = json.loads(args[args.index("-p") + 1])[0]
        if p["path"].endswith("/maxWorkers"):
            st["max_workers"] = p["value"]
            st["patches"].append(p["value"])
    elif "field-selector" in a:
        print("gw-2 true true\ngw-3 true true\ngw-4 true true")
    elif "component=gateway" in a:
        print("gw-1", end="")
save()
`

// fakeCell writes fakeCellPy and returns its path.
func fakeCell(t *testing.T) string {
	t.Helper()
	needTools(t, "python3")
	p := filepath.Join(t.TempDir(), "cell.py")
	if err := os.WriteFile(p, []byte(fakeCellPy), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

type cellState struct {
	MaxWorkers int   `json:"max_workers"`
	Patches    []int `json:"patches"`
	Workers    []struct {
		Free float64 `json:"free"`
	} `json:"workers"`
}

func readCell(t *testing.T, dir string) cellState {
	t.Helper()
	var st cellState
	if err := json.Unmarshal([]byte(readLog(t, filepath.Join(dir, "cell.json"))), &st); err != nil {
		t.Fatalf("the cell's state: %v", err)
	}
	return st
}

// (3) The SLO drill's fill (step_slo_breach, part B) leaves no worker that
// can admit: the worker count is held while it fills, the fillers are
// sized from the members and the policy, and the pool's maxWorkers is put
// back after, also when the drill dies. Before: the policy refused the 8- and 4-CPU fillers, 82 CPUs
// were placed, the operator added a 7th worker, and every worker still
// admitted when the drill waited for SandboxdNoAdmitWorkers.
func TestSLOFillLeavesNoWorkerAdmitting(t *testing.T) {
	script := `set -euo pipefail
HERE="$K8S"; L="$K8S/drills-local"; ROOT="$K8S/../.."; sd="$OUT"; ctx=none; ctl_url=http://127.0.0.1:1
drill_reg=r; client_image=x; client_pull=Never; registry_where=here
drills_own_steps=""
source "$K8S/drills-lib.sh"
cell() { python3 "$CELL" "$OUT/cell.json" "$@"; }
kc() { cell kc "$@"; }
api() { cell api "$@"; }
keep_forward() { :; }; push_images() { :; }; forwarders() { :; }; watch_start() { :; }; watch_stop() { :; }
proxy() { :; }; caddy_admin() { echo 200; }; storm_start() { :; }; storm_stop() { :; }; storm_fetch() { :; }
cleanup_run() { :; }; wait_received() { :; }; sleep() { :; }
# The recovery's known-good create: by then the room is back.
smoke() { kc -n "$ns" get aerolcluster aerolvm -o jsonpath='{.spec.workerPools[0].maxWorkers}' > "$OUT/max-at-smoke"; echo 201; }
sum() { case "$1" in routing) echo '{"firing": [], "resolved": [], "wrong_route": {}}' ;; firedline) echo - ;; *) echo '{}' ;; esac; }
prom() { case "$*" in *"wait SandboxdNoAdmitWorkers --state firing"*) cell admitting > "$OUT/at-the-wait"; [[ -z "${DIE_AT_WAIT:-}" ]] || exit 9 ;; esac; }
step_slo_breach
echo finished >> "$OUT/log"
`
	cell, k8s := fakeCell(t), "K8S="+filepath.Dir(k8sFile(t, "drills-lib.sh"))
	// A drill that dies while the workers are held puts maxWorkers back
	// (its EXIT trap, cleanup).
	dead := t.TempDir()
	if _, err := runBash(t, script, "OUT="+dead, "CELL="+cell, k8s, "DIE_AT_WAIT=1"); err == nil {
		t.Fatal("the drill did not die where it was told to")
	}
	if st := readCell(t, dead); st.MaxWorkers != 60 || len(st.Patches) != 2 || st.Patches[0] != 6 {
		t.Errorf("a drill that died: maxWorkers %d (patches %v), want held at 6, then back to 60", st.MaxWorkers, st.Patches)
	}
	// Placement refuses every 10th create once: the top-up, sized from the
	// members each time, fills what the first pass left.
	dir := t.TempDir()
	out, err := runBash(t, script, "OUT="+dir, "CELL="+cell, k8s, "FLAKY=10")
	if err != nil || readLog(t, filepath.Join(dir, "log")) != "finished\n" {
		t.Fatalf("the drill died: %v\n%s", err, out)
	}
	if got := readLog(t, filepath.Join(dir, "max-at-smoke")); got != "60" {
		t.Errorf("maxWorkers %q when the drill checked the recovery, want 60 (the room back)", got)
	}
	// "<admitting> <serving>" when the drill waited for the alert.
	if got := strings.TrimSpace(readLog(t, filepath.Join(dir, "at-the-wait"))); got != "0 6" {
		t.Errorf("workers admitting, serving when the drill waited for SandboxdNoAdmitWorkers: %q, want \"0 6\"", got)
	}
	st := readCell(t, dir)
	if st.MaxWorkers != 60 || len(st.Patches) != 2 || st.Patches[0] != 6 {
		t.Errorf("maxWorkers %d after the drill (patches %v), want held at 6, then back to 60", st.MaxWorkers, st.Patches)
	}
	if _, err := os.Stat(filepath.Join(dir, "workers-held")); err == nil {
		t.Error("the hold's mark is still there")
	}
}

// (3) scale-full (step_scale, part 1): the fill takes more than the
// workers' free CPU, so the operator adds a worker and the step passes.
// Before: rounds of 8 1-CPU fillers made 80 CPUs in 15 minutes, short of
// six workers of 18, and no 7th worker served. The clock is a file: each
// sleep moves it on.
func TestScaleFullNeedsAnotherWorker(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.tfvars.json"), []byte(`{"ttl": "2099-01-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clock"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644); err != nil {
		t.Fatal(err)
	}
	var fns strings.Builder
	for _, fn := range []string{"kill_tree", "stop_scale_drills", "scale_back", "read_workers", "step_scale"} {
		fns.WriteString(shellFunc(t, "eks-bank.sh", fn))
	}
	fns.WriteString(shellFuncIf(t, "eks-bank.sh", "fill_plan"))
	fns.WriteString(shellFuncIf(t, "eks-bank.sh", "peak_results"))
	fns.WriteString(shellFuncIf(t, "eks-bank.sh", "peak_unfinished"))
	script := `set -euo pipefail
sd="$OUT"; dry=0; name=bank-1; ns=aerolvm-system; workers=aerolvm-workers; release=aerolvm; cname=aerolvm; HERE="$K8S"
base_workers=6; peak_workers=60; scale_minutes=60; back_minutes=20
in_scale=""; drill_pid=""; scaled_back=0
peak_drills=(ecr-storm thresholds); run_peak_list=("${peak_drills[@]}")
cell() { python3 "$CELL" "$OUT/cell.json" "$@"; }
say() { echo "$*" >> "$OUT/say"; }
result() { echo "$1 $2 $3" >> "$OUT/bank.txt"; }
now() { cat "$OUT/clock"; }
sleep() { echo $(( $(cat "$OUT/clock") + ${1%.*} )) > "$OUT/clock"; }
api_token() { :; }; cap_schedule() { :; }; nodepool() { :; }; timeline() { :; }; set_min_workers() { :; }
wait_until() { return 0; }; end_extra_machines() { :; }; x() { :; }; tfout() { echo us-east-1; }
gw_call() { cell gw "$@"; }
kr() { cell kc "$@"; }
workers_now() { cell workers; }
drills() { case "$1" in fill) cell fill "$DRILL_FILL_COUNT" "${DRILL_FILL_CPU:-1}" ;; unfill) cell unfill ;; esac; }
` + fns.String() + `
step_scale
`
	out, err := runBash(t, script, "OUT="+dir, "CELL="+fakeCell(t), "K8S="+filepath.Dir(k8sFile(t, "eks-bank.sh")), "NEW=Pending")
	if err != nil {
		t.Fatalf("the scale step died: %v\n%s\n%s", err, out, readLog(t, filepath.Join(dir, "say")))
	}
	bank := readLog(t, filepath.Join(dir, "bank.txt"))
	if !regexp.MustCompile(`(?m)^PASS scale-full .*55 of 2 CPU.*until 7 workers served`).MatchString(bank) {
		t.Errorf("bank.txt:\n%s", bank)
	}
}

// (4) At 60 workers the pull storm is sized for the workers and outlasts
// the alerts it waits for: cap + 2 cold creates a worker, each on an image
// of its own, for 15 minutes. Before: 24 creates over 12 images for 10
// minutes queued nothing (at most 2 pulls on a worker, the cap is 4), and
// SandboxdImagePullQueueBacklog and SandboxdImagePullErrors (each holds 10
// min; 10m47s and 11m20s in at 6 workers) could not fire.
func TestThresholdsStormSizedForTheWorkers(t *testing.T) {
	needTools(t, "python3")
	common := `set -euo pipefail
HERE="$K8S"; ROOT="$K8S/../.."; sd="$OUT"; ns=aerolvm-system; workers=aerolvm-workers; drill_reg=r; prom_port=1
log() { echo "$*" >> "$OUT/log"; }
say() { :; }
sleep() { :; }
now() { date +%s; }
result() { echo "$1 $2 $3" >> "$OUT/results"; }
jf() { python3 -c "import json, sys; d = json.loads(sys.argv[1]); print($2)" "$1"; }
`
	thresholds := common + `
drilled_alerts=(SandboxdImagePullErrors)
pull_cap=4
keep_forward() { :; }
kc() { for i in $(seq 1 60); do echo "w$i"; done; }
proxy() { :; }; watch_start() { :; }; watch_stop() { :; }; prom() { :; }
quiet_window() { :; }
step_pull_storm() { log "minutes=$DRILL_STORM_MINUTES cold=${DRILL_STORM_COLD:-} images=${DRILL_STORM_COLD_IMAGES:-}"; }
` + shellFunc(t, "drills-eks.sh", "step_thresholds") + `
step_thresholds
`
	storm := common + `
backoff_s=30; pull_cap=4; hold_min=1; storms=()
keep_forward() { :; }; forwarders() { :; }; watch_start() { :; }; watch_stop() { :; }; proxy() { :; }
push_images() { log "push_images $1 ${2:-}"; }
storm_start() { local n="$1"; shift; log "storm_start $n $*"; }
storm_wait() { :; }; storm_stop() { :; }; storm_fetch() { :; }; registry_log() { :; }; cleanup_run() { :; }
val() { echo 0; }; prom() { :; }; kc() { :; }; smoke() { echo 201; }
sum() { case "$1" in fired) echo '{}' ;; firedline) echo - ;; *) echo '{"by_outcome": {"ok": 24}, "max_same_path": 1, "workers": 60, "creates": 1, "min_gap_s": 31, "attempts": 1, "median_gap_s": 31}' ;; esac; }
` + shellFunc(t, "drills-lib.sh", "step_pull_storm") + `
DRILL_STORM_MINUTES=15 DRILL_STORM_COLD=360 DRILL_STORM_COLD_IMAGES=360 step_pull_storm
`
	k8s := "K8S=" + filepath.Dir(k8sFile(t, "drills-eks.sh"))
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := runBash(t, thresholds, "OUT="+dir, k8s); err != nil || readLog(t, filepath.Join(dir, "log")) != "minutes=15 cold=360 images=360\n" {
		t.Errorf("thresholds on 60 workers: %v, the storm it asked for: %q\n%s", err, readLog(t, filepath.Join(dir, "log")), out)
	}
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := runBash(t, storm, "OUT="+dir, k8s); err != nil {
		t.Fatalf("the storm died: %v\n%s", err, out)
	}
	log := readLog(t, filepath.Join(dir, "log"))
	cold := regexp.MustCompile(`(?m)^storm_start cold-\S+ --images(( r/drill/cold:\S+)+) .*--concurrency (\d+) .*--duration (\d+)$`).FindStringSubmatch(log)
	if !strings.Contains(log, "push_images ") || !regexp.MustCompile(`(?m)^push_images \S+ 360$`).MatchString(log) ||
		cold == nil || len(strings.Fields(cold[1])) != 360 || cold[3] != "360" || cold[4] != "900" {
		t.Errorf("the storm as sized: %v\n%s", cold, log)
	}
}

// (5) The run's closing line names the FAILs the drills wrote in
// drills.txt, and its answer is 1 for them: the fifth run's named only
// gvisor and scale-full. An earlier run's line in drills.txt is not this
// run's.
func TestEKSBankClosingLineNamesDrillFails(t *testing.T) {
	needTools(t, "python3", "jq")
	k8s := bankRun(t, "bank-1", "arn:aws:eks:us-east-1:111122223333:cluster/bank-1", true)
	st := filepath.Join(k8s, ".state", "bank-1")
	if err := os.MkdirAll(filepath.Join(st, "drills"), 0o755); err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{"api-token": "avm_x", "drills/drills.txt": "FAIL old-drill an earlier run's line\n"} {
		if err := os.WriteFile(filepath.Join(st, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// drills-eks.sh <name> <state-dir> <step>: a FAIL in slo-breach, a PASS
	// elsewhere, each exiting 0.
	stub := "#!/bin/sh\nif [ \"$3\" = slo-breach ]; then echo \"FAIL slo-alerts not all 4 fired\" >> \"$2/drills.txt\"; else echo \"PASS $3 ok\" >> \"$2/drills.txt\"; fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(k8s, "drills-eks.sh"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	env, _ := eksStubs(t)
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "drills")
	cmd.Env = env
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 1 || !strings.Contains(string(out), "checks that failed: slo-alerts (") || strings.Contains(string(out), "old-drill") {
		t.Errorf("exit %d, want 1 naming slo-alerts only:\n%s", cmd.ProcessState.ExitCode(), out)
	}
}

// (6a) A Ctrl-C reaches the check and the run together: the check starts
// its undo, then on_exit stops the check. An undo that has begun is left
// to finish; kill_tree killed its children before (gateways_back's Helm,
// the floor's kubectl patch). The undo here takes longer than stop_check's
// 5 s wait for the mark, so the mark, not the undo's end, is what keeps
// kill_tree away.
func TestStopCheckLeavesAnUndoThatBegan(t *testing.T) {
	extra := `
slow_undo() { log undo-start; bash -c 'sleep 6; echo undo-done >> "$OUT/log"'; }
slow_check() { check_undo=slow_undo; echo "$BASHPID" > "$OUT/check.pid"; log check-running; command sleep 20 & echo $! >> "$OUT/drill-sleeps"; wait; }
`
	r := startUndoWith(t, extra, "slow slow_check", "12 0 12", "RUN_ALL=0")
	r.waitLog(t, "check-running")
	pid, _ := strconv.Atoi(strings.TrimSpace(readLog(t, filepath.Join(r.dir, "check.pid"))))
	if pid <= 0 {
		t.Fatal("no check pid")
	}
	_ = syscall.Kill(pid, syscall.SIGINT)
	r.waitLog(t, "undo-start")
	_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGINT)
	r.end(t)
	if rest := r.after(t, "undo-start"); !strings.Contains(rest, "undo-done") {
		t.Errorf("the undo was cut short:\n%s", readLog(t, filepath.Join(r.dir, "log")))
	}
	for _, l := range strings.Fields(readLog(t, filepath.Join(r.dir, "drill-sleeps"))) {
		if p, _ := strconv.Atoi(l); p > 0 {
			_ = syscall.Kill(p, syscall.SIGKILL)
		}
	}
}

// (6b) The teardown runs as a job of its own process group, so a second
// Ctrl-C (to the run's group) reaches none of it: Terraform turns SIGINT
// back on although it starts with it ignored. The stand-in here does the
// same, and would die of the Ctrl-C.
func TestTeardownRunsInItsOwnProcessGroup(t *testing.T) {
	needTools(t, "python3")
	extra := `
step_down() {
  log down-start
  python3 -c 'import signal, sys, time
signal.signal(signal.SIGINT, signal.default_int_handler)
time.sleep(2)
open(sys.argv[1], "a").write("terraform-done\n")' "$OUT/log" || log terraform-stopped
  log down-done
}
`
	r := startUndoWith(t, extra, "scale step_scale", "12 0 12", "RUN_ALL=1", "DRILL_SLEEP=20")
	r.waitLog(t, "drills ecr-storm")
	_ = syscall.Kill(r.cmd.Process.Pid, syscall.SIGTERM)
	r.waitLog(t, "down-start")
	time.Sleep(500 * time.Millisecond)
	_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGINT)
	r.end(t)
	if rest := r.after(t, "down-start"); !strings.Contains(rest, "terraform-done") || !strings.Contains(rest, "down-done") {
		t.Errorf("a Ctrl-C reached the teardown:\n%s", rest)
	}
	if !r.sleepsGone(t) {
		t.Error("a peak drill outlived the run")
	}
}

// (6c) The way back: a worker read that fails is waited out (`read_workers
// || { sleep 30; continue; }`), not the end of the step. The code was
// right; nothing held it.
func TestScaleWayBackWaitsOutAFailedRead(t *testing.T) {
	r := startUndo(t, "scale step_scale", "12 0 12", "RUN_ALL=0", "BACK_FAIL=1")
	r.end(t)
	log, bank := readLog(t, filepath.Join(r.dir, "log")), readLog(t, filepath.Join(r.dir, "bank.txt"))
	if rest := r.after(t, "drills unfill"); !strings.Contains(rest, "workers_now failed") {
		t.Errorf("no failed read on the way back:\n%s", log)
	}
	if !strings.Contains(bank, "PASS scale-back") || strings.Contains(bank, "FAIL scale exited") || !strings.Contains(log, "after the check") {
		t.Errorf("a failed read on the way back ended the step:\n%s\n%s", bank, log)
	}
}

// EKS_BANK_DRILLS: the drills step runs only the drills named (setup always,
// first, in the drills' own order), an unknown name refuses the run before
// any call, and estimate prices only those drills.
func TestEKSBankDrillsSubset(t *testing.T) {
	needTools(t, "python3", "jq")
	// drills-eks.sh <name> <state-dir> <step>: it notes the drill and passes.
	runDrills := func(drills string) (string, string, int) {
		k8s := bankRun(t, "bank-1", "arn:aws:eks:us-east-1:111122223333:cluster/bank-1", true)
		st := filepath.Join(k8s, ".state", "bank-1")
		if err := os.WriteFile(filepath.Join(st, "api-token"), []byte("avm_x"), 0o600); err != nil {
			t.Fatal(err)
		}
		ran := filepath.Join(st, "ran")
		stub := "#!/bin/sh\necho \"$3\" >> \"" + ran + "\"\nmkdir -p \"$2\"; echo \"PASS $3 ok\" >> \"$2/drills.txt\"\n"
		if err := os.WriteFile(filepath.Join(k8s, "drills-eks.sh"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		env, _ := eksStubs(t)
		cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "drills")
		cmd.Env = append(env, "EKS_BANK_DRILLS="+drills)
		out, _ := cmd.CombinedOutput()
		return readLog(t, ran), string(out), cmd.ProcessState.ExitCode()
	}
	for _, tc := range []struct{ drills, want string }{
		{"setup,slo-breach", "setup\nslo-breach\n"},
		{"slo-breach", "setup\nslo-breach\n"},             // setup is added
		{"ecr-push, static", "setup\nstatic\necr-push\n"}, // the drills' own order
		{"ecr-storm", "setup\necr-push\n"},                // its images, pushed at 6 workers
		{"", "setup\nstatic\npull-storm\nslo-breach\nlarge-layers\necr-push\n"},
	} {
		if ran, out, code := runDrills(tc.drills); ran != tc.want || code != 0 {
			t.Errorf("EKS_BANK_DRILLS=%q: exit %d, ran %q, want %q:\n%s", tc.drills, code, ran, tc.want, out)
		}
	}

	// An unknown name: refused before any step, with no call made.
	k8s := bankRun(t, "bank-1", "arn:aws:eks:us-east-1:111122223333:cluster/bank-1", true)
	env, log := eksStubs(t)
	cmd := exec.Command("bash", filepath.Join(k8s, "eks-bank.sh"), "bank-1", "all")
	cmd.Env = append(env, "EKS_BANK_DRILLS=setup,slo-breech")
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 2 || !strings.Contains(string(out), `EKS_BANK_DRILLS: "slo-breech" is not a drill`) ||
		strings.Contains(string(out), "--- up") || strings.TrimSpace(readLog(t, log)) != "" {
		t.Errorf("an unknown drill: exit %d, calls %q:\n%s", cmd.ProcessState.ExitCode(), readLog(t, log), out)
	}

	// estimate prices the drills named, and only those.
	estimate := func(drills string) (string, float64) {
		env, log := eksStubs(t)
		cmd := exec.Command("bash", k8sFile(t, "eks-bank.sh"), "bank-1", "estimate")
		cmd.Env = append(env, "DRY_RUN=1", "EKS_BANK_DRY_DIR="+t.TempDir(), "EKS_BANK_DRILLS="+drills)
		out, err := cmd.CombinedOutput()
		if err != nil || strings.TrimSpace(readLog(t, log)) != "" {
			t.Fatalf("estimate: %v, calls %q:\n%s", err, readLog(t, log), out)
		}
		row := regexp.MustCompile(`(?m)^drills +([0-9.]+) +[0-9.]+ +\(([a-z -]+)\)$`).FindStringSubmatch(string(out))
		planned := regexp.MustCompile(`planned: \$([0-9.]+)`).FindStringSubmatch(string(out))
		if row == nil || planned == nil {
			t.Fatalf("no drills row or plan:\n%s", out)
		}
		p, _ := strconv.ParseFloat(planned[1], 64)
		return row[1] + " " + row[2], p
	}
	sub, subPlanned := estimate("setup,slo-breach")
	all, allPlanned := estimate("")
	if sub != "0.95 setup slo-breach" || all != "2.60 setup static pull-storm slo-breach large-layers ecr-push" || subPlanned >= allPlanned {
		t.Errorf("estimate: subset %q ($%.2f), all %q ($%.2f)", sub, subPlanned, all, allPlanned)
	}
}

// parseFirst runs parse_drills (with the caller's EKS_BANK_DRILLS) before
// the check, where eks-bank.sh has it; the code before it had none.
const parseFirst = `
if declare -F parse_drills >/dev/null; then parse_drills; fi
`

// (#1366 review, 1) The scale step runs only the peak drills EKS_BANK_DRILLS
// names, and writes a SKIP line for the other. Before: with
// EKS_BANK_DRILLS=setup,slo-breach it still ran ecr-storm, which pushed its
// own 200 images at the peak until the time box ended it, and thresholds
// never started; neither wrote a line.
func TestScaleStepRunsOnlyTheNamedPeakDrills(t *testing.T) {
	for _, tc := range []struct {
		drills    string
		ran, skip []string
	}{
		{"setup,slo-breach", nil, []string{"ecr-storm", "thresholds"}},
		{"slo-breach thresholds", []string{"thresholds"}, []string{"ecr-storm"}},
		{"", []string{"ecr-storm", "thresholds"}, nil}, // unset: both, as before
	} {
		// The floor back to 6 is the cell back to 6 (thresholds, which set
		// that in the harness, may not run here).
		extra := parseFirst + `set_min_workers() { log "set_min_workers $1"; [[ "$1" != 6 ]] || echo "6 0 6" > "$OUT/workers"; }
`
		r := startUndoWith(t, extra, "scale step_scale", "12 0 12", "RUN_ALL=0", "EKS_BANK_DRILLS="+tc.drills)
		r.end(t)
		log, bank := readLog(t, filepath.Join(r.dir, "log")), readLog(t, filepath.Join(r.dir, "bank.txt"))
		for _, d := range []string{"ecr-storm", "thresholds"} {
			ran := strings.Contains(log, "drills "+d+"\n")
			skipped := strings.Contains(bank, "SKIP "+d+" not in EKS_BANK_DRILLS\n")
			want := false
			for _, w := range tc.ran {
				want = want || w == d
			}
			if ran != want || skipped == want {
				t.Errorf("EKS_BANK_DRILLS=%q: %s ran %v, skipped %v (want ran %v):\n%s\n%s", tc.drills, d, ran, skipped, want, log, bank)
			}
		}
		if !strings.Contains(log, "after the check") {
			t.Errorf("EKS_BANK_DRILLS=%q: the scale step did not end:\n%s", tc.drills, log)
		}
	}
}

// (#1366 review, 1) A peak drill the time box cuts off, or that never
// starts, writes a FAIL line, so the closing line counts it. The clock is
// a file each sleep moves on; the box is 1 minute and ecr-storm outlasts it.
func TestPeakDrillsTheTimeBoxEndsAreRecorded(t *testing.T) {
	extra := `
date +%s > "$OUT/clock"
now() { cat "$OUT/clock"; }
sleep() { command sleep 0.2; echo $(( $(cat "$OUT/clock") + ${1%.*} )) > "$OUT/clock"; }
scale_minutes=1
drills() {
  log "drills $1"
  case "$1" in
    # wait $!: killed, the drill answers 143, as drills-eks.sh does.
    ecr-storm) command sleep 20 & echo $! >> "$OUT/drill-sleeps"; wait $! ;;
    unfill) echo "6 0 6" > "$OUT/workers" ;;
  esac
}
`
	r := startUndoWith(t, extra, "scale step_scale", "12 0 12", "RUN_ALL=0")
	r.end(t)
	bank := readLog(t, filepath.Join(r.dir, "bank.txt"))
	if !regexp.MustCompile(`(?m)^FAIL ecr-storm cut off by the time box after [0-9]+s$`).MatchString(bank) ||
		!strings.Contains(bank, "FAIL thresholds not started: the time box ended first\n") {
		t.Errorf("bank.txt:\n%s\n%s", bank, readLog(t, filepath.Join(r.dir, "log")))
	}
	if strings.Contains(readLog(t, filepath.Join(r.dir, "log")), "drills thresholds") || !r.sleepsGone(t) {
		t.Errorf("thresholds ran after the box, or ecr-storm outlived it:\n%s", readLog(t, filepath.Join(r.dir, "log")))
	}
}

// bankDown runs `eks-bank.sh bank-1 <steps>` on stubs that end down cleanly
// (an aws that lists nothing), with env added; it returns the output, the
// exit code and the scripts called.
func bankDown(t *testing.T, steps []string, env ...string) (string, int, string) {
	t.Helper()
	k8s := bankRun(t, "bank-1", "arn:aws:eks:us-east-1:111122223333:cluster/bank-1", true)
	calls := filepath.Join(k8s, "scripts.log")
	stub := "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> \"" + calls + "\"\nexit 0\n"
	for _, s := range []string{"cluster.sh", "cell.sh"} {
		if err := os.WriteFile(filepath.Join(k8s, s), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(k8s, ".state", "bank-1", "terraform.tfstate"), []byte(`{"resources": [{"type": "aws_vpc"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	base, _ := eksStubs(t)
	awsDir := t.TempDir()
	awsStub := "#!/bin/sh\ncase \"$*\" in *\"sts get-caller-identity\"*) echo 111122223333 ;; *\"s3api head-bucket\"*) exit 254 ;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(awsDir, "aws"), []byte(awsStub), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, e := range base {
		if strings.HasPrefix(e, "PATH=") {
			base[i] = "PATH=" + awsDir + string(os.PathListSeparator) + strings.TrimPrefix(e, "PATH=")
		}
	}
	cmd := exec.Command("bash", append([]string{filepath.Join(k8s, "eks-bank.sh"), "bank-1"}, steps...)...)
	cmd.Env = append(base, env...)
	out, _ := cmd.CombinedOutput()
	return string(out), cmd.ProcessState.ExitCode(), readLog(t, calls)
}

// (#1366 review, 2) EKS_BANK_DRILLS is read only by the steps it is for
// (up, estimate, drills, scale, all). A bad value left in the shell never
// stops down. Before: every step list exited 2 on it, down too.
func TestEKSBankDownRunsWithABadDrillsValue(t *testing.T) {
	needTools(t, "python3", "jq")
	out, code, calls := bankDown(t, []string{"down"}, "EKS_BANK_DRILLS=no-such-drill")
	if code != 0 || !strings.Contains(calls, "cell.sh bank-1 down") || !strings.Contains(out, "down: nothing of bank-1 is left") {
		t.Errorf("down with a bad EKS_BANK_DRILLS: exit %d, scripts %q:\n%s", code, calls, out)
	}
	// The steps it is for still refuse it, before any call.
	out, code, calls = bankDown(t, []string{"drills", "down"}, "EKS_BANK_DRILLS=no-such-drill")
	if code != 2 || calls != "" || !strings.Contains(out, `"no-such-drill" is not a drill`) {
		t.Errorf("drills with a bad EKS_BANK_DRILLS: exit %d, scripts %q:\n%s", code, calls, out)
	}
}

// (#1366 review, 3) A value with no drill names in it is refused like an
// unknown name; newlines separate names as commas and spaces do. Before:
// "," and " " ran setup alone, and a second line was dropped.
func TestEKSBankDrillsNeedNames(t *testing.T) {
	needTools(t, "python3", "jq")
	for _, v := range []string{",", " ", " , ", "\n"} {
		out, code, calls := bankDown(t, []string{"drills"}, "EKS_BANK_DRILLS="+v)
		if code != 2 || calls != "" || !strings.Contains(out, "EKS_BANK_DRILLS has no drill names in it") {
			t.Errorf("EKS_BANK_DRILLS=%q: exit %d, scripts %q:\n%s", v, code, calls, out)
		}
	}
	cmd := exec.Command("bash", k8sFile(t, "eks-bank.sh"), "bank-1", "estimate")
	cmd.Env = append(cleanEnviron(), "DRY_RUN=1", "EKS_BANK_DRY_DIR="+t.TempDir(), "EKS_BANK_DRILLS=setup\nslo-breach")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "(setup slo-breach)") {
		t.Errorf("names on two lines: %v\n%s", err, out)
	}
}

// (#1366 review, 4) The refusal lists the names the script takes, from the
// list it checks against: each listed name is taken, ecr-storm and
// thresholds among them. Before: a hand-typed copy of six names.
func TestEKSBankDrillsErrorNamesEveryDrill(t *testing.T) {
	needTools(t, "python3")
	run := func(drills string) (string, error) {
		cmd := exec.Command("bash", k8sFile(t, "eks-bank.sh"), "bank-1", "estimate")
		cmd.Env = append(cleanEnviron(), "DRY_RUN=1", "EKS_BANK_DRY_DIR="+t.TempDir(), "EKS_BANK_DRILLS="+drills)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, _ := run("nope")
	m := regexp.MustCompile(`"nope" is not a drill \(([a-z -]+)\)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no list of drills in the refusal:\n%s", out)
	}
	names := strings.Fields(m[1])
	if !strings.Contains(" "+m[1]+" ", " ecr-storm ") || !strings.Contains(" "+m[1]+" ", " thresholds ") {
		t.Errorf("the list leaves out the peak drills: %v", names)
	}
	for _, n := range names {
		if out, err := run(n); err != nil {
			t.Errorf("%q, listed as a drill, is refused: %v\n%s", n, err, out)
		}
	}
}

// (#1366 review, 5) The tests' environment holds none of the caller's bank
// run settings: an exported EKS_BANK_DRILLS (or ceiling, or timer) failed
// TestEKSBankEstimateGuardsUp.
func TestBankTestEnvDropsCallerSettings(t *testing.T) {
	needTools(t, "python3")
	t.Setenv("EKS_BANK_DRILLS", "no-such-drill")
	t.Setenv("EKS_BANK_CEILING", "1")
	t.Setenv("EKS_BANK_TTL", "1h")
	t.Setenv("DRILL_STORM_MINUTES", "1")
	env, log := eksStubs(t)
	for _, e := range env {
		if strings.HasPrefix(e, "EKS_BANK_") || strings.HasPrefix(e, "DRILL_") || strings.HasPrefix(e, "DRY_RUN=") {
			t.Errorf("the stubs' environment keeps the caller's %s", e)
		}
	}
	cmd := exec.Command("bash", k8sFile(t, "eks-bank.sh"), "bank-1", "estimate")
	cmd.Env = append(env, "DRY_RUN=1", "EKS_BANK_DRY_DIR="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "worst case (teardown timer at 6 h): $40.05; ceiling $45.00") || strings.TrimSpace(readLog(t, log)) != "" {
		t.Errorf("the default estimate under the caller's settings: %v\n%s", err, out)
	}
}

// (#1366 re-review, 1) The peak drills' result lines come from one place,
// peak_results, and from marks written whole. Before, the drills' subshell
// wrote its end mark, then its FAIL line: a kill between the two left no
// line (3 of 400 stress runs). And it wrote the start time through a
// redirect that empties the file first: a kill there left it empty, and
// the arithmetic on it ended the scale step (1 of 400: "FAIL scale exited
// 1", scale-back lost). Each case here is a state those kills can leave.
func TestPeakResultsFromTheMarks(t *testing.T) {
	fn := shellFuncIf(t, "eks-bank.sh", "peak_results")
	call := `peak_results "$OUT/peak" "$BOXED"`
	if fn == "" {
		// The code before it: peak_unfinished <dir>, after the subshell had
		// written its own exit lines.
		fn, call = shellFunc(t, "eks-bank.sh", "peak_unfinished"), `peak_unfinished "$OUT/peak"`
	}
	for _, tc := range []struct {
		desc, boxed string
		marks       map[string]string // file in peak/ -> contents
		want        string
	}{
		{"ended 0", "0", map[string]string{"ecr-storm.started": "100", "ecr-storm.ended": "0"}, ""},
		{"ended 3", "0", map[string]string{"ecr-storm.started": "100", "ecr-storm.ended": "3"}, "FAIL ecr-storm drills-eks.sh ecr-storm exited 3\n"},
		{"killed by the box: exit 143", "1", map[string]string{"ecr-storm.started": "100", "ecr-storm.ended": "143"}, "FAIL ecr-storm cut off by the time box after 60s\n"},
		{"killed by the box before its end mark", "1", map[string]string{"ecr-storm.started": "100"}, "FAIL ecr-storm cut off by the time box after 60s\n"},
		{"a start mark the kill left empty", "1", map[string]string{"ecr-storm.started": ""}, "FAIL ecr-storm cut off by the time box\n"},
		{"never started", "1", map[string]string{}, "FAIL ecr-storm not started: the time box ended first\n"},
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "peak"), 0o755); err != nil {
			t.Fatal(err)
		}
		for f, body := range tc.marks {
			if err := os.WriteFile(filepath.Join(dir, "peak", f), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		script := `set -euo pipefail
run_peak_list=(ecr-storm)
now() { echo 160; }
result() { echo "$1 $2 $3" >> "$OUT/bank.txt"; }
` + fn + call + "\necho finished >> \"$OUT/log\"\n"
		out, err := runBash(t, script, "OUT="+dir, "BOXED="+tc.boxed)
		if err != nil || readLog(t, filepath.Join(dir, "log")) != "finished\n" {
			t.Errorf("%s: died: %v\n%s", tc.desc, err, out)
			continue
		}
		if got := readLog(t, filepath.Join(dir, "bank.txt")); got != tc.want {
			t.Errorf("%s: recorded %q, want %q", tc.desc, got, tc.want)
		}
	}
}

// (#1366 re-review, 2) A scale fill that runs past a short time box passes
// a negative limit to the wait for the peak's workers. That is no wait at
// all now. Before: `seq 1 <negative>` counts down on macOS, so the step
// checked and slept about as long as the overrun. The clock is a file.
func TestScaleWaitAfterAFillPastTheBox(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.tfvars.json"), []byte(`{"ttl": "2099-01-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clock"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644); err != nil {
		t.Fatal(err)
	}
	var fns strings.Builder
	for _, fn := range []string{"wait_until", "kill_tree", "stop_scale_drills", "scale_back", "read_workers", "step_scale"} {
		fns.WriteString(shellFunc(t, "eks-bank.sh", fn))
	}
	fns.WriteString(shellFuncIf(t, "eks-bank.sh", "peak_results"))
	fns.WriteString(shellFuncIf(t, "eks-bank.sh", "peak_unfinished"))
	// A 10-minute box; the workers never reach the fill's target, so the
	// fill runs its whole 15 minutes, past the box.
	script := `set -euo pipefail
sd="$OUT"; dry=0; name=bank-1; ns=aerolvm-system; workers=aerolvm-workers; release=aerolvm; cname=aerolvm; HERE="$K8S"
base_workers=6; peak_workers=60; scale_minutes=10; back_minutes=20
in_scale=""; drill_pid=""; scaled_back=0
peak_drills=(ecr-storm thresholds); run_peak_list=()
say() { echo "$*" >> "$OUT/say"; }
result() { echo "$1 $2 $3" >> "$OUT/bank.txt"; }
now() { cat "$OUT/clock"; }
sleep() { echo $(( $(cat "$OUT/clock") + ${1%.*} )) > "$OUT/clock"; }
api_token() { :; }; cap_schedule() { :; }; nodepool() { :; }; timeline() { :; }; set_min_workers() { :; }
end_extra_machines() { :; }; x() { :; }; tfout() { echo us-east-1; }
fill_plan() { echo "2 1"; }
workers_now() { echo "6 0 6"; }
drills() { :; }
at_least() { echo check >> "$OUT/checks"; return 1; }
` + fns.String() + `
step_scale
echo finished >> "$OUT/log"
`
	out, err := runBash(t, script, "OUT="+dir, "K8S="+filepath.Dir(k8sFile(t, "eks-bank.sh")))
	if err != nil || readLog(t, filepath.Join(dir, "log")) != "finished\n" {
		t.Fatalf("the scale step died: %v\n%s", err, out)
	}
	if checks := strings.Count(readLog(t, filepath.Join(dir, "checks")), "check"); checks != 0 {
		t.Errorf("waited for the peak's workers %d times after the box had ended (want 0):\n%s", checks, readLog(t, filepath.Join(dir, "say")))
	}
}
