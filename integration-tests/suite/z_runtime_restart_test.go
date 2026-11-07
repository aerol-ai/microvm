//go:build integration

package suite

// T14 (plans/kubectl-style-cluster-ops.md §6.4, eng/CEO task T14): what WASM
// and V8-isolate sandboxes do across `systemctl restart sandboxd`. Do they
// keep running, keep their state, and answer exec afterwards?
//
// These cases are measurements. Each one records what it saw (status, exec,
// state, host processes, times, and what sandboxd logged about the sandbox)
// as "T14 ..." log lines and a JSON summary, and passes once the
// measurement is complete. A runtime that does not survive is a finding for
// the plan, not a failure here. They restart sandboxd, so the file sorts
// late.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	StartTried     bool       `json:"start_tried"`
	AfterStart     *t14Probe  `json:"after_start,omitempty"`
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
// everything in its unit's cgroup, and every workerd with its cgroup.
func t14Procs(t *testing.T, target string) string {
	t.Helper()
	script := `pid=$(systemctl show -p MainPID --value sandboxd)
cg=$(systemctl show -p ControlGroup --value sandboxd)
echo "sandboxd pid=$pid cgroup=$cg"
for p in $(cat /sys/fs/cgroup$cg/cgroup.procs 2>/dev/null); do echo "unit pid=$p $(ps -o comm= -p $p) started=$(ps -o lstart= -p $p | tr -s ' ')"; done
for p in $(pgrep -x workerd); do echo "workerd pid=$p started=$(ps -o lstart= -p $p | tr -s ' ') cgroup=$(tr '\n' ' ' < /proc/$p/cgroup)"; done
true`
	out, err := harness.SSHRunStdin(t, target, "sudo sh -s", script)
	if err != nil {
		return "ssh failed: " + err.Error() + "\n" + out
	}
	return strings.TrimSpace(out)
}

// t14Restart restarts sandboxd and waits until /health answers 200 through
// the scenario's URL. It returns when the restart began and how long it took.
func t14Restart(t *testing.T, target string) (time.Time, float64) {
	t.Helper()
	began := time.Now()
	if out, err := harness.SSHRun(t, target, "sudo systemctl restart sandboxd"); err != nil {
		t.Fatalf("restart sandboxd: %v\n%s", err, out)
	}
	httpc := harness.HTTPClient(10 * time.Second)
	deadline := began.Add(5 * time.Minute)
	for {
		resp, err := httpc.Get(strings.TrimRight(sc.BaseURL, "/") + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return began, time.Since(began).Seconds()
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandboxd did not answer /health within 5m of the restart (last: %v)", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// t14Measure probes every subject, restarts sandboxd once, then probes each
// again: at once, then every 5s for up to 2 minutes until its exec answers,
// then, if it never did and it reads stopped, after a start. It logs and
// returns the results.
func t14Measure(t *testing.T, c *harness.Client, target string, subjects []*t14Subject) {
	t.Helper()
	ctx := context.Background()
	for _, s := range subjects {
		s.res = t14Result{Runtime: s.runtime, Variant: s.variant, SandboxID: s.sb.ID}
		s.res.Before = s.probe(ctx)
	}
	before := t14Procs(t, target)
	began, took := t14Restart(t, target)
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
	deadline := time.Now().Add(2 * time.Minute)
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
		time.Sleep(5 * time.Second)
	}
	for _, s := range subjects {
		last := s.res.After
		if n := len(s.res.Later); n > 0 {
			last = s.res.Later[n-1]
		}
		if s.res.ExecBackAfter < 0 && last.Status == string(models.SandboxStatusStopped) {
			s.res.StartTried = true
			sctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			_, err := c.SDK().Start(sctx, s.sb.ID)
			cancel()
			p := s.probe(ctx)
			p.At = since()
			if err != nil {
				p.ExecErr = "start: " + err.Error() + "; " + p.ExecErr
			}
			s.res.AfterStart = &p
		}
		jout, _ := harness.SSHRun(t, target, fmt.Sprintf("sudo journalctl -u sandboxd --since '@%d' --no-pager -o cat | grep -F %q | tail -n 15", began.Unix()-1, s.sb.ID))
		s.res.Journal = strings.TrimSpace(jout)
		raw, _ := json.MarshalIndent(s.res, "", "  ")
		t.Logf("T14 %s/%s:\n%s", s.runtime, s.variant, raw)
		t.Logf("T14 SUMMARY %s/%s: before exec=%q state=%q status=%s | restart %.1fs | after status=%s exec_ok=%v exec=%q err=%q state=%q | exec back after %.1fs | start tried=%v",
			s.runtime, s.variant, s.res.Before.ExecOut, s.res.Before.State, s.res.Before.Status, took,
			s.res.After.Status, s.res.After.ExecOK, s.res.After.ExecOut, s.res.After.ExecErr, s.res.After.State,
			s.res.ExecBackAfter, s.res.StartTried)
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

// UC-677 — T14 for WASM: an ephemeral (default) and a passivatable WASM
// sandbox, each with a counter file it bumps on every exec, across one
// `systemctl restart sandboxd`.
func TestT14WasmAcrossSandboxdRestart(t *testing.T) {
	harness.Require(t, sc, "UC-677")
	target := t14Node(t)
	c := client(t)
	ref := stagedWasmModuleRefOrDefault(t)
	var subjects []*t14Subject
	for _, durability := range []string{"", sdktypes.DurabilityPassivatable} {
		variant := durability
		if variant == "" {
			variant = "ephemeral (default)"
		}
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
			Name: harness.UniqueName(sc, t), Runtime: "wasm", Image: ref, ModuleRef: ref, Durability: durability,
		})
		waitRunning(t, sb)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if err := sb.UploadFile(ctx, "/t14-count.py", []byte(wasmCounter)); err != nil {
			cancel()
			t.Fatalf("upload the counter to %s: %v", sb.ID, err)
		}
		if err := sb.UploadFile(ctx, "/t14-marker.txt", []byte("marker-"+sb.ID)); err != nil {
			cancel()
			t.Fatalf("upload the marker to %s: %v", sb.ID, err)
		}
		cancel()
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
		// Two bumps before the probe: the probe's own exec makes it 3.
		for i := 1; i <= 2; i++ {
			if p := s.probe(context.Background()); !p.ExecOK || p.ExecOut != fmt.Sprint(i) {
				t.Fatalf("wasm %s before the restart: bump %d = %+v", variant, i, p)
			}
		}
		subjects = append(subjects, s)
	}
	// What a durable WASM create answers today, for the record.
	dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
	dsb, derr := c.SDK().Create(dctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: "wasm", Image: ref, ModuleRef: ref, Durability: sdktypes.DurabilityDurable,
	})
	dcancel()
	if derr == nil {
		destroyBest(c, dsb.ID)
		t.Logf("T14 wasm/durable: create accepted (%s)", dsb.ID)
	} else {
		t.Logf("T14 wasm/durable: create refused: %v", derr)
	}

	t14Measure(t, c, target, subjects)
	for _, s := range subjects {
		if s.res.Before.ExecOut != "3" {
			t.Fatalf("wasm %s: the measurement's own before-exec read %q, want 3", s.variant, s.res.Before.ExecOut)
		}
	}
}

// isolateCounter counts fetches in a module global: it lives as long as the
// workerd process that runs the sandbox.
const isolateCounter = `let n = 0;
export default { async fetch() { n++; return new Response(String(n)); } };`

// UC-678 — T14 for the V8 isolate: an isolate sandbox whose fetch handler
// counts calls in memory, across one `systemctl restart sandboxd`, first
// with the jail on (the default), then with SB_ISOLATE_USE_JAIL=false.
func TestT14IsolateAcrossSandboxdRestart(t *testing.T) {
	harness.Require(t, sc, "UC-678")
	target := t14Node(t)
	c := client(t)
	ref := uploadBundle(t, c, "itest-t14-counter", isolateCounter)

	// measure records one variant. A variant whose sandbox cannot even be
	// set up is a finding too (the jail is the default), so it is recorded
	// with the host's evidence instead of stopping the case; measure
	// reports whether the restart itself was measured.
	measure := func(variant, tenant string) bool {
		setupFailed := func(format string, args ...any) bool {
			msg := fmt.Sprintf(format, args...)
			procs := t14Procs(t, target)
			jout, _ := harness.SSHRun(t, target, "sudo journalctl -u sandboxd --since '-3min' --no-pager -o cat | grep -iE 'isolate|workerd' | tail -n 12")
			t.Logf("T14 isolate/%s: SETUP FAILED, no restart measured: %s\nhost:\n%s\njournal:\n%s", variant, msg, procs, strings.TrimSpace(jout))
			return false
		}
		// Not newIsolateSandbox: it stops the case on a failed create.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Name: harness.UniqueName(sc, t), Runtime: models.RuntimeIsolate, ModuleRef: ref, TenantID: tenant, MemoryMB: 128,
		})
		cancel()
		if err != nil {
			return setupFailed("create: %v", err)
		}
		t.Cleanup(func() { destroyBest(c, sb.ID) })
		deadline := time.Now().Add(90 * time.Second)
		for {
			status, reason := t14Status(context.Background(), c, sb.ID)
			if status == string(models.SandboxStatusStarted) {
				break
			}
			if status == "error" || time.Now().After(deadline) {
				return setupFailed("sandbox %s never reached started: %s (%s)", sb.ID, status, reason)
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
				return setupFailed("fetch %d before the restart = %+v", i, p)
			}
		}
		t14Measure(t, c, target, []*t14Subject{s})
		if s.res.Before.ExecOut != "3" {
			t.Fatalf("isolate %s: the measurement's own before-fetch read %q, want 3", variant, s.res.Before.ExecOut)
		}
		return true
	}

	jailOn := measure("jail on (default)", "itest-t14-jail-on")

	// The same with the jail off: workerd then runs as sandboxd's child.
	env, _ := harness.SSHRun(t, target, "grep -E '^SB_ISOLATE_USE_JAIL=' /etc/sandboxd/sandboxd.env || true")
	t.Logf("T14 isolate: SB_ISOLATE_USE_JAIL lines before the switch: %q", strings.TrimSpace(env))
	if out, err := harness.SSHRun(t, target, "echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null && echo ok"); err != nil {
		t.Fatalf("turn the jail off: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := harness.SSHRun(t, target, "sudo sed -i '/^SB_ISOLATE_USE_JAIL=false$/d' /etc/sandboxd/sandboxd.env && sudo systemctl restart sandboxd && echo ok"); err != nil {
			t.Errorf("RESTORE: put the jail back: %v\n%s", err, out)
		}
	})
	t14Restart(t, target)
	if procs := t14Procs(t, target); !slices.ContainsFunc(strings.Split(procs, "\n"), func(l string) bool { return strings.HasPrefix(l, "sandboxd pid=") }) {
		t.Fatalf("sandboxd is not running after turning the jail off:\n%s", procs)
	}
	if jailOff := measure("jail off", "itest-t14-jail-off"); !jailOn && !jailOff {
		t.Fatal("T14 isolate: neither variant could be set up, so nothing was measured")
	}
}
