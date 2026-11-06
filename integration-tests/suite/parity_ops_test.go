//go:build integration

package suite

// Live checks for plans/agent-sandbox-feature-parity.md items I1 (sandboxd
// dials toolboxd again while it refuses the connection) and O3 (the
// create-throughput benchmark tool).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// refusingToolbox makes the owner node refuse sandboxd's connections to one
// sandbox's toolboxd, the way a toolboxd that is not listening yet does: an
// OUTPUT rule answers sandboxd's SYN with a TCP reset, which the dialer sees
// as ECONNREFUSED. The rule names the sandbox's address and toolbox port
// only, so nothing else on the node is touched.
type refusingToolbox struct {
	t       *testing.T
	node    harness.IntegrationNode
	base    string // the owner's own API, through an SSH forward
	sb      *microvm.Sandbox
	ip      string
	comment string
}

const toolboxPortOnNode = 2280 // SB_TOOLBOX_PORT's default; the scenarios keep it

func newRefusingToolbox(t *testing.T, uc string) *refusingToolbox {
	t.Helper()
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Runtime: "docker"})
	waitRunning(t, sb)
	node := sandboxNode(t, c, sb)
	base := nodeBase(t, node)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := harness.NewAPIClient(base, sc.OperatorPAT).Do(ctx, http.MethodGet, "/v1/sandboxes/"+sb.ID, nil)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("GET the sandbox on its owner %s: %v %v", node.Name, err, resp)
	}
	var row struct {
		ContainerIP string `json:"container_ip"`
	}
	if err := resp.JSON(&row); err != nil || row.ContainerIP == "" {
		t.Fatalf("no container_ip on %s: %v %s", sb.ID, err, resp.Body)
	}
	rt := &refusingToolbox{t: t, node: node, base: base, sb: sb, ip: row.ContainerIP,
		comment: "aerolvm-itest-" + strings.ToLower(uc) + "-" + sb.ID}
	// Whatever happens to the test, the node keeps no rule of ours.
	t.Cleanup(func() { _, _ = harness.SSHRun(t, sshTargetOf(node), rt.deleteScript()) })
	return rt
}

func sshTargetOf(node harness.IntegrationNode) string {
	target, _ := harness.SSHTarget(node)
	return target
}

func (rt *refusingToolbox) ruleSpec() string {
	return fmt.Sprintf("OUTPUT -p tcp -d %s --dport %d -m comment --comment %s -j REJECT --reject-with tcp-reset",
		rt.ip, toolboxPortOnNode, rt.comment)
}

func (rt *refusingToolbox) deleteScript() string {
	return "while sudo iptables -D " + rt.ruleSpec() + " 2>/dev/null; do :; done; true"
}

// refuseUntilHit runs on the node: it adds the rule, waits until the rule
// has refused a connect, keeps refusing for hold, then lifts it, and
// prints the refused-connect count. ready is closed once the rule is in.
func (rt *refusingToolbox) refuseUntilHit(hold time.Duration) (ready <-chan struct{}, refused <-chan int) {
	readyCh := make(chan struct{})
	refusedCh := make(chan int, 1)
	script := fmt.Sprintf(`set -e
sudo iptables -I %s
hits=0
for i in $(seq 1 1200); do
  hits=$(sudo iptables -L OUTPUT -v -x -n | awk '/%s/ {print $1; exit}')
  [ "${hits:-0}" -gt 0 ] && break
  sleep 0.05
done
sleep %.3f
hits=$(sudo iptables -L OUTPUT -v -x -n | awk '/%s/ {print $1; exit}')
%s
echo "refused=${hits:-0}"`, strings.Replace(rt.ruleSpec(), "OUTPUT", "OUTPUT 1", 1), rt.comment, hold.Seconds(), rt.comment, rt.deleteScript())
	go func() {
		out, err := harness.SSHRun(rt.t, sshTargetOf(rt.node), script)
		n := -1
		if i := strings.LastIndex(out, "refused="); i >= 0 {
			n, _ = strconv.Atoi(strings.TrimSpace(out[i+len("refused="):]))
		}
		if err != nil {
			rt.t.Errorf("refusing script on %s: %v\n%s", rt.node.Name, err, out)
		}
		refusedCh <- n
	}()
	go func() {
		// The script's SSH call returns only at the end, so look for the
		// rule from a second session.
		check := "sudo iptables -C " + rt.ruleSpec() + " 2>/dev/null && echo present || echo absent"
		for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if out, _ := harness.SSHRun(rt.t, sshTargetOf(rt.node), check); strings.Contains(out, "present") {
				close(readyCh)
				return
			}
		}
	}()
	return readyCh, refusedCh
}

// exec runs command on the sandbox through its owner's own API (so the
// refused dial is the only thing between the call and toolboxd) and
// returns the status, the body and how long the call took.
func (rt *refusingToolbox) exec(command string) (int, []byte, time.Duration) {
	rt.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	start := time.Now()
	resp, err := harness.NewAPIClient(rt.base, sc.OperatorPAT).Do(ctx, http.MethodPost,
		"/v1/sandboxes/"+rt.sb.ID+"/toolbox/process/execute", map[string]any{"command": command})
	took := time.Since(start)
	if err != nil {
		rt.t.Fatalf("exec through %s: %v", rt.node.Name, err)
	}
	return resp.Status, resp.Body, took
}

func (rt *refusingToolbox) dialRetries(key string) float64 {
	rt.t.Helper()
	return harness.MetricValueOrZero(nodeMetrics(rt.t, rt.base), "aerolvm_toolbox_dial_retries_total", map[string]string{"key": key})
}

func waitRefused(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(90 * time.Second):
		t.Fatal("the refusing rule never showed up on the node")
	}
}

// UC-453 — I1: while the owner node refuses sandboxd's connections to the
// sandbox's toolboxd for a moment, an exec is not failed: sandboxd dials
// again, reaches toolboxd once the refusal ends, and the command runs
// exactly once.
func TestParityToolboxDialRetryLive(t *testing.T) {
	harness.Require(t, sc, "UC-453")
	rt := newRefusingToolbox(t, "UC-453")
	if st, body, _ := rt.exec("true"); st != http.StatusOK {
		t.Fatalf("exec before the refusal = %d %s", st, body)
	}
	marker := "/tmp/uc453-runs"
	// Something else on the node (a probe) can be the connect the rule
	// refuses first; then the exec meets no refusal. Try again in that case.
	for attempt := 1; attempt <= 3; attempt++ {
		connectedBefore := rt.dialRetries("connected")
		ready, refused := rt.refuseUntilHit(0)
		waitRefused(t, ready)
		st, body, took := rt.exec(fmt.Sprintf("echo %d >> %s", attempt, marker))
		hits := <-refused
		if st != http.StatusOK {
			t.Fatalf("attempt %d: exec while toolboxd refused = %d %s after %v, want 200 once the refusal ended", attempt, st, body, took)
		}
		var res struct {
			ExitCode int `json:"exit_code"`
		}
		if err := json.Unmarshal(body, &res); err != nil || res.ExitCode != 0 {
			t.Fatalf("attempt %d: exec result %s (%v)", attempt, body, err)
		}
		if hits < 1 || took < 200*time.Millisecond {
			t.Logf("attempt %d: the exec met no refusal (refused connects %d, took %v); trying again", attempt, hits, took)
			continue
		}
		if after := rt.dialRetries("connected"); after < connectedBefore+1 {
			t.Fatalf("aerolvm_toolbox_dial_retries_total{key=connected} on %s = %v, was %v: the retry was not counted", rt.node.Name, after, connectedBefore)
		}
		// Each attempt appended one line, and none was run twice.
		var want []string
		for i := 1; i <= attempt; i++ {
			want = append(want, strconv.Itoa(i))
		}
		st, body, _ = rt.exec("cat " + marker)
		var runs struct {
			Stdout string `json:"stdout"`
		}
		if err := json.Unmarshal(body, &runs); st != http.StatusOK || err != nil || runs.Stdout != strings.Join(want, "\n")+"\n" {
			t.Fatalf("runs recorded = %d %s, want exactly %v", st, body, want)
		}
		return
	}
	t.Fatal("three attempts never had the exec meet the refusal")
}

// UC-454 — I1: a toolboxd that refuses for longer than the retry window
// fails the call with 502 after the 1.4 s of retries (not at once, and not
// only once the refusal ends), and the command never runs. The refusal
// lasts 30 s and the bound is 20 s: the time is measured from the test
// runner, which can add seconds of network on its own (sandboxd logged
// 3.4 s for a call the runner timed at 11.6 s, live 2026-11-06).
func TestParityToolboxDialRetryGivesUpLive(t *testing.T) {
	harness.Require(t, sc, "UC-454")
	rt := newRefusingToolbox(t, "UC-454")
	marker := "/tmp/uc454-ran"
	refusedBefore := rt.dialRetries("refused")
	ready, refused := rt.refuseUntilHit(30 * time.Second)
	waitRefused(t, ready)
	st, body, took := rt.exec("touch " + marker)
	hits := <-refused
	if st != http.StatusBadGateway {
		t.Fatalf("exec while toolboxd refused for 30 s = %d %s after %v, want 502", st, body, took)
	}
	if hits < 4 {
		t.Fatalf("the node refused %d connects, want the first dial and 3 retries", hits)
	}
	// 0.2 + 0.4 + 0.8 s of waits, plus the 2 s a container engine waits
	// for a stop event before answering 502.
	if took < 1400*time.Millisecond || took > 20*time.Second {
		t.Fatalf("502 after %v, want after the 1.4 s retry window and well before the 30 s refusal ended", took)
	}
	if after := rt.dialRetries("refused"); after < refusedBefore+3 {
		t.Fatalf("aerolvm_toolbox_dial_retries_total{key=refused} on %s = %v, was %v; want 3 more", rt.node.Name, after, refusedBefore)
	}
	if st, body, _ := rt.exec("test -e " + marker + " && echo ran || echo never"); st != http.StatusOK || !strings.Contains(string(body), "never") {
		t.Fatalf("after the refusal: %d %s, want the command never to have run", st, body)
	}
}

// --- O3: the create-throughput benchmark tool ------------------------------

var (
	benchOnce sync.Once
	benchPath string
	benchErr  error
)

// benchBinary builds cmd/aerolvm-bench from this tree once per run, so a
// run tests the branch.
func benchBinary(t *testing.T) string {
	t.Helper()
	benchOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aerolvm-bench-itest-")
		if err != nil {
			benchErr = err
			return
		}
		benchPath = filepath.Join(dir, "aerolvm-bench")
		if out, err := exec.Command("go", "build", "-o", benchPath, "../../cmd/aerolvm-bench").CombinedOutput(); err != nil {
			benchErr = fmt.Errorf("go build ./cmd/aerolvm-bench: %v\n%s", err, out)
		}
	})
	if benchErr != nil {
		t.Fatal(benchErr)
	}
	return benchPath
}

// throughputReport is the part of aerolvm-bench's -json report the cases read.
type throughputReport struct {
	RunID            string  `json:"run_id"`
	Interrupted      bool    `json:"interrupted"`
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
	CreatesPerSecond float64 `json:"creates_per_second"`
	Creates          struct {
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"creates"`
	CreateLatencyMs struct {
		Samples int     `json:"samples"`
		P50     float64 `json:"p50"`
		P90     float64 `json:"p90"`
		P99     float64 `json:"p99"`
		Max     float64 `json:"max"`
	} `json:"create_latency_ms"`
	Errors     []json.RawMessage `json:"errors"`
	LeftBehind int               `json:"left_behind"`
}

// benchRun is one aerolvm-bench process against the scenario's API.
type benchRun struct {
	t      *testing.T
	runID  string
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func startBench(t *testing.T, uc string, args ...string) *benchRun {
	t.Helper()
	var raw [3]byte
	_, _ = rand.Read(raw[:])
	br := &benchRun{t: t, runID: strings.ToLower(uc) + "-" + hex.EncodeToString(raw[:])}
	br.cmd = exec.Command(benchBinary(t), append([]string{"-json", "-run-id", br.runID, "-image", harness.DefaultImage}, args...)...)
	br.cmd.Env = append(os.Environ(), "SB_API_URL="+sc.BaseURL, "SB_PAT_TOKEN="+sc.PAT, "SB_API_TOKEN=")
	br.cmd.Stdout, br.cmd.Stderr = &br.stdout, &br.stderr
	if err := br.cmd.Start(); err != nil {
		t.Fatalf("start aerolvm-bench: %v", err)
	}
	// Whatever the test does, nothing of this run outlives it.
	t.Cleanup(func() {
		_ = br.cmd.Process.Kill()
		_ = exec.Command(benchBinary(t), "-cleanup", br.runID).Run()
	})
	return br
}

// wait returns the exit code and the parsed report.
func (br *benchRun) wait(timeout time.Duration) (int, throughputReport) {
	br.t.Helper()
	done := make(chan error, 1)
	go func() { done <- br.cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(timeout):
		_ = br.cmd.Process.Kill()
		br.t.Fatalf("aerolvm-bench still running after %v\nstderr: %s", timeout, br.stderr.String())
	}
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		br.t.Fatalf("aerolvm-bench: %v", err)
	}
	var rep throughputReport
	if jerr := json.Unmarshal(br.stdout.Bytes(), &rep); jerr != nil {
		br.t.Fatalf("aerolvm-bench exit %d, stdout is not the JSON report: %v\nstdout: %s\nstderr: %s", code, jerr, br.stdout.String(), br.stderr.String())
	}
	return code, rep
}

// runSandboxes lists the sandboxes tagged with the run's id, through the
// SDK and not through the tool.
func (br *benchRun) runSandboxes() int {
	br.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	items, err := client(br.t).SDK().List(ctx, microvm.WithTags(map[string]string{"aerolvm-bench-run": br.runID}))
	if err != nil {
		br.t.Fatalf("list the run's sandboxes: %v", err)
	}
	return len(items)
}

func checkBenchPercentiles(t *testing.T, rep throughputReport) {
	t.Helper()
	l := rep.CreateLatencyMs
	if rep.Creates.Succeeded < 1 || l.Samples != rep.Creates.Succeeded || rep.CreatesPerSecond <= 0 || rep.ElapsedSeconds <= 0 {
		t.Fatalf("report %+v: want at least one create, a sample per create and a rate", rep)
	}
	if !(l.P50 > 0 && l.P50 <= l.P90 && l.P90 <= l.P99 && l.P99 <= l.Max) {
		t.Fatalf("create latency %+v: want 0 < p50 <= p90 <= p99 <= max", l)
	}
	// Two workers, one create each at a time, cannot beat two creates per
	// median create time by much; a rate far above that is a counting
	// bug, not a fast server.
	if pace := 2 * 1000 / l.P50; rep.CreatesPerSecond > 2*pace {
		t.Fatalf("%.2f creates per second with 2 workers at p50 %.1f ms (about %.2f expected)", rep.CreatesPerSecond, l.P50, pace)
	}
}

// UC-455 — O3: aerolvm-bench runs a few seconds at low concurrency against
// the live API, reports a create rate and sane create-time percentiles,
// and leaves none of its sandboxes behind.
func TestParityBenchReportsAndCleansUp(t *testing.T) {
	harness.Require(t, sc, "UC-455")
	br := startBench(t, "UC-455", "-concurrency", "2", "-duration", "5s")
	code, rep := br.wait(5 * time.Minute)
	if code != 0 || rep.RunID != br.runID || rep.Interrupted {
		t.Fatalf("exit %d, report %+v\nstderr: %s", code, rep, br.stderr.String())
	}
	if rep.Creates.Failed != 0 {
		t.Fatalf("%d creates failed at concurrency 2: %s", rep.Creates.Failed, rep.Errors)
	}
	checkBenchPercentiles(t, rep)
	if rep.LeftBehind != 0 {
		t.Fatalf("the tool reports %d sandboxes left behind", rep.LeftBehind)
	}
	if n := br.runSandboxes(); n != 0 {
		t.Fatalf("the API still lists %d sandboxes tagged with run %s", n, br.runID)
	}
}

// UC-456 — O3: aerolvm-bench stopped with one interrupt mid-run waits for
// the creates in flight, deletes every sandbox it made and reports the
// interrupted run; the API lists none of them afterwards.
func TestParityBenchInterruptedCleansUp(t *testing.T) {
	harness.Require(t, sc, "UC-456")
	br := startBench(t, "UC-456", "-concurrency", "2", "-duration", "10m", "-hold")
	// -hold keeps every sandbox until the end, so the interrupt has
	// several to delete.
	deadline := time.Now().Add(3 * time.Minute)
	for br.runSandboxes() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("no sandboxes of the run appeared\nstderr: %s", br.stderr.String())
		}
		time.Sleep(2 * time.Second)
	}
	if err := br.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	code, rep := br.wait(5 * time.Minute)
	if code != 0 || !rep.Interrupted || rep.LeftBehind != 0 || rep.Creates.Succeeded < 2 {
		t.Fatalf("exit %d, report %+v\nstderr: %s", code, rep, br.stderr.String())
	}
	if !strings.Contains(br.stderr.String(), "stopping") {
		t.Fatalf("stderr does not say it is stopping: %s", br.stderr.String())
	}
	if n := br.runSandboxes(); n != 0 {
		t.Fatalf("the API still lists %d sandboxes tagged with run %s after the interrupt", n, br.runID)
	}
}
