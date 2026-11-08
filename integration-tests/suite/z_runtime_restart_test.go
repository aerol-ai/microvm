//go:build integration

package suite

// T14 (plans/kubectl-style-cluster-ops.md §6.4) and the fix for what it
// found: WASM and V8-isolate sandboxes keep running across
// `systemctl restart sandboxd`, with their state, and answer exec at once
// afterwards, the way containers and VMs do. Their workers run outside
// sandboxd's cgroup (aerolvm-wasm, aerolvm-isolate-hosts, the jail's group
// cgroups) and the next sandboxd takes them over at boot.
//
// Each case probes its sandboxes before the restart, restarts sandboxd
// once, and asserts each one: still started, exec answering within seconds
// of /health, its state moved on by exactly that one exec (a counter in a
// /work file for WASM, a module global for an isolate), and its worker the
// same process. Each result is also logged as a "T14 ..." JSON block.
// They restart sandboxd, so the file sorts late.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// t14Probe is one look at a sandbox: its status, an exec that also moves its
// state (a counter), and the state read another way.
type t14Probe struct {
	At      float64 `json:"at_seconds"` // since the restart began; 0 before it
	Status  string  `json:"status"`
	Reason  string  `json:"status_reason,omitempty"`
	ExecOK  bool    `json:"exec_ok"`
	ExecOut string  `json:"exec_out,omitempty"`
	ExecErr string  `json:"exec_err,omitempty"`
	State   string  `json:"state,omitempty"`
}

// t14Result is one sandbox's whole measurement.
type t14Result struct {
	Runtime        string     `json:"runtime"`
	Variant        string     `json:"variant"`
	SandboxID      string     `json:"sandbox_id"`
	Before         t14Probe   `json:"before"`
	RestartSeconds float64    `json:"restart_seconds"` // restart until /health is 200
	After          t14Probe   `json:"after"`           // first look once healthy
	Later          []t14Probe `json:"later,omitempty"` // looks while waiting for it to come back
	ExecBackAfter  float64    `json:"exec_back_after_seconds"`
	ProcsBefore    string     `json:"procs_before"`
	ProcsAfter     string     `json:"procs_after"`
	Journal        string     `json:"journal,omitempty"`
}

// t14Subject is one sandbox under measurement: probe looks at it once.
type t14Subject struct {
	runtime, variant string
	sb               *microvm.Sandbox
	probe            func(ctx context.Context) t14Probe
	res              t14Result
}

// t14Node is the single node these cases restart.
func t14Node(t *testing.T) string {
	t.Helper()
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this restarts sandboxd")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) != 1 {
		t.Skip("T14 runs on a single-node scenario (AEROL_INTEGRATION_TARGETS with one node)")
	}
	target, ok := harness.SSHTarget(targets.Nodes[0])
	if !ok {
		t.Skip("no SSH address for the node")
	}
	return target
}

// t14Procs lists the host processes a restart can kill or keep: sandboxd,
// everything in its unit's cgroup, every WASM worker (the aerolvm-wasm
// cgroup) and every workerd, each with its cgroup.
func t14Procs(t *testing.T, target string) string {
	t.Helper()
	script := `pid=$(systemctl show -p MainPID --value sandboxd)
cg=$(systemctl show -p ControlGroup --value sandboxd)
echo "sandboxd pid=$pid cgroup=$cg"
for p in $(cat /sys/fs/cgroup$cg/cgroup.procs 2>/dev/null); do echo "unit pid=$p $(ps -o comm= -p $p) started=$(ps -o lstart= -p $p | tr -s ' ')"; done
for p in $(cat /sys/fs/cgroup/aerolvm-wasm/cgroup.procs 2>/dev/null); do echo "wasm pid=$p $(tr '\0' ' ' < /proc/$p/cmdline)"; done
for p in $(pgrep -x workerd); do echo "workerd pid=$p started=$(ps -o lstart= -p $p | tr -s ' ') cgroup=$(tr '\n' ' ' < /proc/$p/cgroup)"; done
true`
	out, err := harness.SSHRunStdin(t, target, "sudo sh -s", script)
	if err != nil {
		return "ssh failed: " + err.Error() + "\n" + out
	}
	return strings.TrimSpace(out)
}

var t14ProcLine = regexp.MustCompile(`^(wasm|workerd) pid=(\d+)`)

// t14WorkerPIDs reads the WASM worker and workerd pids out of t14Procs.
func t14WorkerPIDs(procs, kind string) []string {
	var out []string
	for _, line := range strings.Split(procs, "\n") {
		if m := t14ProcLine.FindStringSubmatch(line); m != nil && m[1] == kind {
			out = append(out, m[2])
		}
	}
	return out
}

// t14Restart restarts sandboxd and waits until /health answers 200 through
// the scenario's URL, then until the node is back (waitNodeRejoined; on one
// node that is the API serving again). It returns when the restart began
// and how long until /health answered.
func t14Restart(t *testing.T, target string) (time.Time, float64) {
	t.Helper()
	return t14RestartWith(t, target, "sudo systemctl restart sandboxd")
}

// t14RestartWith runs script on the node (a restart, or a stop, a kill and
// a start) and waits for /health.
func t14RestartWith(t *testing.T, target, script string) (time.Time, float64) {
	t.Helper()
	return t14Disrupt(t, func() {
		if out, err := harness.SSHRun(t, target, script); err != nil {
			t.Fatalf("restart sandboxd: %v\n%s", err, out)
		}
	})
}

// t14Disrupt runs disrupt (a restart, an upgrade) and waits until /health
// answers 200 through the scenario's URL. It returns when disrupt began and
// how long until /health answered.
func t14Disrupt(t *testing.T, disrupt func()) (time.Time, float64) {
	t.Helper()
	began := time.Now()
	disrupt()
	httpc := harness.HTTPClient(10 * time.Second)
	deadline := began.Add(5 * time.Minute)
	for {
		resp, err := httpc.Get(strings.TrimRight(sc.BaseURL, "/") + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				took := time.Since(began).Seconds()
				// The node is a single-node scenario's only one (t14Node).
				if err := waitNodeRejoined(t, harness.LoadIntegrationTargets().Nodes[0]); err != nil {
					t.Fatalf("after the restart: %v", err)
				}
				return began, took
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandboxd did not answer /health within 5m of the restart (last: %v)", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// t14Measure probes every subject, restarts sandboxd once with script,
// then probes each again: at once, then every 3s for up to a minute until
// its exec answers. It logs the results; the caller asserts them.
func t14Measure(t *testing.T, target, script string, subjects []*t14Subject) {
	t.Helper()
	t14MeasureWith(t, target, subjects, func() {
		if out, err := harness.SSHRun(t, target, script); err != nil {
			t.Fatalf("restart sandboxd: %v\n%s", err, out)
		}
	})
}

// t14MeasureWith is t14Measure around any disruption (an upgrade).
func t14MeasureWith(t *testing.T, target string, subjects []*t14Subject, disrupt func()) {
	t.Helper()
	ctx := context.Background()
	for _, s := range subjects {
		s.res = t14Result{Runtime: s.runtime, Variant: s.variant, SandboxID: s.sb.ID}
		s.res.Before = s.probe(ctx)
	}
	before := t14Procs(t, target)
	began, took := t14Disrupt(t, disrupt)
	after := t14Procs(t, target)
	since := func() float64 { return time.Since(began).Seconds() }
	for _, s := range subjects {
		s.res.ProcsBefore, s.res.ProcsAfter, s.res.RestartSeconds = before, after, took
		s.res.ExecBackAfter = -1
		p := s.probe(ctx)
		p.At = since()
		s.res.After = p
		if p.ExecOK {
			s.res.ExecBackAfter = p.At
		}
	}
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		waiting := false
		for _, s := range subjects {
			if s.res.ExecBackAfter >= 0 {
				continue
			}
			waiting = true
			p := s.probe(ctx)
			p.At = since()
			s.res.Later = append(s.res.Later, p)
			if p.ExecOK {
				s.res.ExecBackAfter = p.At
			}
		}
		if !waiting {
			break
		}
		time.Sleep(3 * time.Second)
	}
	for _, s := range subjects {
		jout, _ := harness.SSHRun(t, target, fmt.Sprintf("sudo journalctl -u sandboxd --since '@%d' --no-pager -o cat | grep -F %q | grep -v 'request complete' | tail -n 15", began.Unix()-1, s.sb.ID))
		s.res.Journal = strings.TrimSpace(jout)
		raw, _ := json.MarshalIndent(s.res, "", "  ")
		t.Logf("T14 %s/%s:\n%s", s.runtime, s.variant, raw)
		t.Logf("T14 SUMMARY %s/%s: before exec=%q status=%s | restart %.1fs | after status=%s exec_ok=%v exec=%q err=%q state=%q | exec back after %.1fs",
			s.runtime, s.variant, s.res.Before.ExecOut, s.res.Before.Status, took,
			s.res.After.Status, s.res.After.ExecOK, s.res.After.ExecOut, s.res.After.ExecErr, s.res.After.State, s.res.ExecBackAfter)
	}
}

// t14AssertKept fails unless s came through the restart running, answered
// exec within restart+20s, and its state moved on by exactly the one exec
// (wantOut). The first answer must be the right one: a sandbox that was
// restored or started fresh answers 1 (isolate) or needs a start (WASM).
func t14AssertKept(t *testing.T, s *t14Subject, wantOut, wantState string) {
	t.Helper()
	first := s.res.After
	if !first.ExecOK && len(s.res.Later) > 0 {
		first = s.res.Later[len(s.res.Later)-1]
	}
	switch {
	case s.res.ExecBackAfter < 0:
		t.Errorf("%s/%s %s: exec never answered after the restart: %+v", s.runtime, s.variant, s.sb.ID, first)
	case s.res.ExecBackAfter > s.res.RestartSeconds+20:
		t.Errorf("%s/%s %s: exec came back %.1fs after the restart began (restart took %.1fs)", s.runtime, s.variant, s.sb.ID, s.res.ExecBackAfter, s.res.RestartSeconds)
	case first.Status != string(models.SandboxStatusStarted):
		t.Errorf("%s/%s %s: status after the restart = %s (%s)", s.runtime, s.variant, s.sb.ID, first.Status, first.Reason)
	case first.ExecOut != wantOut:
		t.Errorf("%s/%s %s: first exec after the restart = %q, want %q (its state must carry over)", s.runtime, s.variant, s.sb.ID, first.ExecOut, wantOut)
	case wantState != "" && first.State != wantState:
		t.Errorf("%s/%s %s: state after the restart = %q, want %q", s.runtime, s.variant, s.sb.ID, first.State, wantState)
	}
}

// t14Status reads the sandbox's status and reason.
func t14Status(ctx context.Context, c *harness.Client, id string) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	sb, err := c.SDK().Get(ctx, id)
	if err != nil {
		return "get failed: " + err.Error(), ""
	}
	return string(sb.Status), sb.StatusReason
}

// wasmCounter bumps a counter file in /work, the WASM sandbox's preopened
// work dir (which the toolbox upload writes to), and prints the new value.
const wasmCounter = `import os
p = '/work/t14-count.txt'
n = int(open(p).read()) if os.path.exists(p) else 0
n += 1
open(p, 'w').write(str(n))
print(n)
`

// newWasmCounterSubject creates a WASM sandbox, uploads the counter and a
// marker, and bumps the counter to 2.
func newWasmCounterSubject(t *testing.T, c *harness.Client, variant string, opts sdktypes.CreateSandboxOptions) *t14Subject {
	t.Helper()
	ref := stagedWasmModuleRefOrDefault(t)
	opts.Name, opts.Runtime, opts.Image, opts.ModuleRef = harness.UniqueName(sc, t), "wasm", ref, ref
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	sb, err := c.SDK().Create(ctx, opts)
	cancel()
	if err != nil {
		t.Fatalf("create a %s WASM sandbox: %v", variant, err)
	}
	t.Cleanup(func() { destroyBest(c, sb.ID) })
	waitRunning(t, sb)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := sb.UploadFile(ctx, "/t14-count.py", []byte(wasmCounter)); err != nil {
		t.Fatalf("upload the counter to %s: %v", sb.ID, err)
	}
	if err := sb.UploadFile(ctx, "/t14-marker.txt", []byte("marker-"+sb.ID)); err != nil {
		t.Fatalf("upload the marker to %s: %v", sb.ID, err)
	}
	s := &t14Subject{runtime: "wasm", variant: variant, sb: sb}
	s.probe = func(ctx context.Context) t14Probe {
		var p t14Probe
		p.Status, p.Reason = t14Status(ctx, c, s.sb.ID)
		ectx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		res, err := s.sb.ExecCommand(ectx, "python /work/t14-count.py")
		switch {
		case err != nil:
			p.ExecErr = err.Error()
		case res.ExitCode != 0:
			p.ExecErr = fmt.Sprintf("exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		default:
			p.ExecOK, p.ExecOut = true, strings.TrimSpace(res.Stdout)
		}
		if b, err := s.sb.DownloadFile(ectx, "/t14-marker.txt"); err != nil {
			p.State = "marker: " + err.Error()
		} else {
			p.State = "marker: " + string(b)
		}
		return p
	}
	// Two bumps before the measurement: its own before-probe makes it 3.
	for i := 1; i <= 2; i++ {
		if p := s.probe(context.Background()); !p.ExecOK || p.ExecOut != fmt.Sprint(i) {
			t.Fatalf("wasm %s before the restart: bump %d = %+v", variant, i, p)
		}
	}
	return s
}

// UC-677 — WASM across `systemctl restart sandboxd`: an ephemeral (default)
// and a passivatable sandbox on the resident host keep running, answer exec
// at once with their counter moved on by one, keep their /work, and the
// resident host is the same process. UC-701: the same for a sandbox with
// public traffic on, which runs on its own per-sandbox worker.
func TestT14WasmAcrossSandboxdRestart(t *testing.T) {
	harness.Require(t, sc, "UC-677", "UC-701")
	target := t14Node(t)
	c := client(t)
	yes := true
	subjects := []*t14Subject{
		newWasmCounterSubject(t, c, "ephemeral (default)", sdktypes.CreateSandboxOptions{}),
		newWasmCounterSubject(t, c, "passivatable", sdktypes.CreateSandboxOptions{Durability: sdktypes.DurabilityPassivatable}),
		newWasmCounterSubject(t, c, "public traffic (per-sandbox worker)", sdktypes.CreateSandboxOptions{AllowPublicTraffic: &yes}),
	}
	t14Measure(t, target, "sudo systemctl restart sandboxd", subjects)
	for _, s := range subjects {
		if s.res.Before.ExecOut != "3" {
			t.Fatalf("wasm %s: the measurement's own before-exec read %q, want 3", s.variant, s.res.Before.ExecOut)
		}
		t14AssertKept(t, s, "4", "marker: marker-"+s.sb.ID)
		if !strings.Contains(s.res.Journal, "taken over") {
			t.Errorf("wasm %s %s: sandboxd did not log taking it over:\n%s", s.variant, s.sb.ID, s.res.Journal)
		}
	}
	// The workers themselves lived through it: every WASM worker from
	// before is still running, outside sandboxd's unit.
	before := t14WorkerPIDs(subjects[0].res.ProcsBefore, "wasm")
	after := t14WorkerPIDs(subjects[0].res.ProcsAfter, "wasm")
	if len(before) == 0 {
		t.Fatalf("no WASM worker in the aerolvm-wasm cgroup before the restart:\n%s", subjects[0].res.ProcsBefore)
	}
	for _, pid := range before {
		if !slices.Contains(after, pid) {
			t.Errorf("WASM worker pid %s did not survive the restart\nbefore:\n%s\nafter:\n%s", pid, subjects[0].res.ProcsBefore, subjects[0].res.ProcsAfter)
		}
	}
}

// UC-700 — a WASM sandbox with public traffic on runs on its own worker;
// Python runs a script file from /work there, and -c too. Before, every
// exec on such a worker opened a wasip1 listener whose fd broke Python's
// embedded files ("Fatal Python error: error evaluating path").
func TestWasmPerSandboxWorkerRunsScriptFile(t *testing.T) {
	harness.Require(t, sc, "UC-700")
	c := client(t)
	ref := stagedWasmModuleRefOrDefault(t)
	yes := true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: "wasm", Image: ref, ModuleRef: ref, AllowPublicTraffic: &yes,
	})
	cancel()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { destroyBest(c, sb.ID) })
	waitRunning(t, sb)
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := sb.UploadFile(ctx, "/uc700.py", []byte("print(6*7)\n")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	for _, cmd := range []string{"python /work/uc700.py", "python -c print(6*7)"} {
		res, err := sb.ExecCommand(ctx, cmd)
		if err != nil || res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != "42" {
			t.Fatalf("exec %q = %+v, %v", cmd, res, err)
		}
	}
}

// UC-702 — a WASM sandbox whose worker died while sandboxd was down is
// restored at boot over its kept /work: it is started, answers exec at
// once, and its counter file carries on. Before, it was marked stopped.
func TestWasmRestoredWhenItsWorkerDied(t *testing.T) {
	harness.Require(t, sc, "UC-702")
	target := t14Node(t)
	c := client(t)
	s := newWasmCounterSubject(t, c, "worker killed while sandboxd was down", sdktypes.CreateSandboxOptions{})
	// Stop sandboxd, kill every WASM worker (the sandbox's resident host is
	// one of them), start sandboxd.
	script := `set -e
sudo systemctl stop sandboxd
for p in $(cat /sys/fs/cgroup/aerolvm-wasm/cgroup.procs 2>/dev/null); do sudo kill -9 $p || true; done
sleep 1
sudo systemctl start sandboxd`
	t14Measure(t, target, script, []*t14Subject{s})
	t14AssertKept(t, s, "4", "marker: marker-"+s.sb.ID)
	if !strings.Contains(s.res.Journal, "restored over its kept work dir") {
		t.Errorf("sandboxd did not log restoring %s:\n%s", s.sb.ID, s.res.Journal)
	}
}

// isolateCounter counts fetches in a module global: it lives as long as the
// isolate that runs the sandbox.
const isolateCounter = `let n = 0;
export default { async fetch() { n++; return new Response(String(n)); } };`

// newIsolateCounterSubject creates an isolate sandbox with the counter
// bundle and fetches it to 2.
func newIsolateCounterSubject(t *testing.T, c *harness.Client, ref, variant, tenant string) *t14Subject {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: models.RuntimeIsolate, ModuleRef: ref, TenantID: tenant, MemoryMB: 128,
	})
	cancel()
	if err != nil {
		jout, _ := harness.SSHRun(t, t14Node(t), "sudo journalctl -u sandboxd --since '-3min' --no-pager -o cat | grep -iE 'isolate|workerd' | tail -n 12")
		t.Fatalf("create an isolate sandbox (%s): %v\njournal:\n%s", variant, err, jout)
	}
	t.Cleanup(func() { destroyBest(c, sb.ID) })
	deadline := time.Now().Add(90 * time.Second)
	for {
		status, reason := t14Status(context.Background(), c, sb.ID)
		if status == string(models.SandboxStatusStarted) {
			break
		}
		if status == "error" || time.Now().After(deadline) {
			t.Fatalf("isolate %s never reached started: %s (%s)", sb.ID, status, reason)
		}
		time.Sleep(2 * time.Second)
	}
	s := &t14Subject{runtime: "isolate", variant: variant, sb: sb}
	s.probe = func(ctx context.Context) t14Probe {
		var p t14Probe
		p.Status, p.Reason = t14Status(ctx, c, s.sb.ID)
		ectx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		res, err := s.sb.ExecCommand(ectx, "/")
		switch {
		case err != nil:
			p.ExecErr = err.Error()
		case res.ExitCode != 0:
			p.ExecErr = fmt.Sprintf("exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		default:
			p.ExecOK, p.ExecOut = true, strings.TrimSpace(res.Stdout)
			p.State = "in-memory counter " + p.ExecOut
		}
		return p
	}
	for i := 1; i <= 2; i++ {
		if p := s.probe(context.Background()); !p.ExecOK || p.ExecOut != fmt.Sprint(i) {
			t.Fatalf("isolate %s fetch %d before the restart = %+v", variant, i, p)
		}
	}
	return s
}

// UC-678 — V8 isolate across `systemctl restart sandboxd`: an isolate whose
// fetch handler counts calls in memory keeps running and answers 4 after
// the restart (its isolate, and so its memory, is the same one), first with
// the jail on (the default; before, no jailed isolate could even start),
// then with SB_ISOLATE_USE_JAIL=false.
func TestT14IsolateAcrossSandboxdRestart(t *testing.T) {
	harness.Require(t, sc, "UC-678")
	target := t14Node(t)
	c := client(t)
	ref := uploadBundle(t, c, "itest-t14-counter", isolateCounter)

	measure := func(variant, tenant string) {
		s := newIsolateCounterSubject(t, c, ref, variant, tenant)
		t14Measure(t, target, "sudo systemctl restart sandboxd", []*t14Subject{s})
		if s.res.Before.ExecOut != "3" {
			t.Fatalf("isolate %s: the measurement's own before-fetch read %q, want 3", variant, s.res.Before.ExecOut)
		}
		t14AssertKept(t, s, "4", "in-memory counter 4")
		if len(t14WorkerPIDs(s.res.ProcsBefore, "workerd")) == 0 {
			t.Errorf("isolate %s: no workerd before the restart:\n%s", variant, s.res.ProcsBefore)
		}
	}
	measure("jail on (default)", "itest-t14-jail-on")

	// The same with the jail off: workerd then runs in aerolvm-isolate-hosts.
	env, _ := harness.SSHRun(t, target, "sudo grep -E '^SB_ISOLATE_USE_JAIL=' /etc/sandboxd/sandboxd.env || true")
	t.Logf("T14 isolate: SB_ISOLATE_USE_JAIL lines before the switch: %q", strings.TrimSpace(env))
	if out, err := harness.SSHRun(t, target, "echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null && echo ok"); err != nil {
		t.Fatalf("turn the jail off: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := harness.SSHRun(t, target, "sudo sed -i '/^SB_ISOLATE_USE_JAIL=false$/d' /etc/sandboxd/sandboxd.env && echo ok"); err != nil {
			t.Errorf("RESTORE: put the jail back: %v\n%s", err, out)
			return
		}
		// Through t14Restart, so the next case starts on a node that is back.
		t14Restart(t, target)
	})
	t14Restart(t, target)
	if procs := t14Procs(t, target); !slices.ContainsFunc(strings.Split(procs, "\n"), func(l string) bool { return strings.HasPrefix(l, "sandboxd pid=") }) {
		t.Fatalf("sandboxd is not running after turning the jail off:\n%s", procs)
	}
	measure("jail off", "itest-t14-jail-off")
}
