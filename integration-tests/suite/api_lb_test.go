//go:build integration

package suite

// UC-356: the health-checked load balancer in front of the ingress nodes
// (Terraform api_load_balancer = "nlb", scenario cluster-3-mixed-lb).
//
// The bank-readiness finding it answers: with DNS round-robin, an ingress
// node whose sandboxd is down but whose Caddy is up still completes the TCP
// and TLS handshakes, so every client DNS sends there gets 502 until the
// daemon is back; about 1/N of API calls fail per daemon outage.
//
// What this measures is the real balancer, nothing in the harness:
//   - it first checks that the domain resolves to the balancer's address and
//     nothing else, so no call can reach a node by round-robin;
//   - every call opens its own TCP and TLS connection with a transport of its
//     own. A kept-alive connection pinned to a healthy node would hide the
//     failure, and the suite's shared client (and any client-side model of a
//     health-checked balancer in harness transport, which skips a node whose
//     daemon a case stopped) is never used here. Against this scenario that
//     model has nothing to skip anyway: the only address DNS returns is the
//     balancer's.
//
// Node rotation is read from the balancer itself (elbv2 describe-target-health
// on the 443 target group), so "left rotation" and "back in rotation" are
// AWS's own view, not an inference from response codes.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// lbCall is one probe through the domain.
type lbCall struct {
	at     time.Time
	path   string
	status int
	err    error
}

func (c lbCall) ok() bool { return c.err == nil && c.status == http.StatusOK }

func (c lbCall) String() string {
	if c.err != nil {
		return fmt.Sprintf("%s %s: %v", c.at.Format("15:04:05.000"), c.path, c.err)
	}
	return fmt.Sprintf("%s %s: %d", c.at.Format("15:04:05.000"), c.path, c.status)
}

// lbProber calls the API through the domain on a fresh connection each time.
type lbProber struct {
	base   string
	bearer string
	client *http.Client
	n      int
}

func newLBProber(domain, bearer string) *lbProber {
	return &lbProber{
		base:   "https://" + domain,
		bearer: bearer,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				// One connection per call: the balancer picks a target per
				// connection, so only a new connection is a new choice.
				DisableKeepAlives:   true,
				DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
				// Staging certificates: availability is under test here, the
				// chain is UC-09's.
				TLSClientConfig: &tls.Config{ServerName: domain, InsecureSkipVerify: true}, //nolint:gosec
			},
		},
	}
}

// call alternates the public /health (served by the node's own sandboxd
// through Caddy: the request that answered 502 in the finding) and an
// authenticated /v1/whoami (the API with its auth path, also answered by the
// node that received it).
func (p *lbProber) call(ctx context.Context) lbCall {
	path := "/health"
	if p.n%2 == 1 {
		path = "/v1/whoami"
	}
	p.n++
	c := lbCall{at: time.Now(), path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		c.err = err
		return c
	}
	if path != "/health" {
		req.Header.Set("Authorization", "Bearer "+p.bearer)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		c.err = err
		return c
	}
	resp.Body.Close()
	c.status = resp.StatusCode
	return c
}

// run makes n calls spaced by gap and returns them.
func (p *lbProber) run(ctx context.Context, n int, gap time.Duration) []lbCall {
	out := make([]lbCall, 0, n)
	for i := 0; i < n && ctx.Err() == nil; i++ {
		out = append(out, p.call(ctx))
		time.Sleep(gap)
	}
	return out
}

func lbFailures(calls []lbCall) []lbCall {
	var bad []lbCall
	for _, c := range calls {
		if !c.ok() {
			bad = append(bad, c)
		}
	}
	return bad
}

func lbSample(calls []lbCall, n int) string {
	var parts []string
	for i, c := range calls {
		if i == n {
			parts = append(parts, fmt.Sprintf("... %d more", len(calls)-n))
			break
		}
		parts = append(parts, c.String())
	}
	return strings.Join(parts, "; ")
}

// lbTargetState is the balancer's view of one instance on one target group:
// healthy, unhealthy, initial, draining, ... The region is the ARN's.
func lbTargetState(arn, instanceID string, port int) (string, error) {
	fields := strings.Split(arn, ":")
	if len(fields) < 4 || fields[3] == "" {
		return "", fmt.Errorf("target group ARN %q has no region", arn)
	}
	out, err := exec.Command("aws", "elbv2", "describe-target-health", "--region", fields[3],
		"--target-group-arn", arn, "--targets", fmt.Sprintf("Id=%s,Port=%d", instanceID, port),
		"--query", "TargetHealthDescriptions[0].TargetHealth.State", "--output", "text").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("describe-target-health: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// lbWaitState polls until the instance's state satisfies want or the bound
// passes, and returns how long it took and the last state seen.
func lbWaitState(t *testing.T, arn, instanceID string, want func(string) bool, bound time.Duration) (time.Duration, string, bool) {
	t.Helper()
	start := time.Now()
	last := ""
	for time.Since(start) <= bound {
		state, err := lbTargetState(arn, instanceID, 443)
		if err != nil {
			last = err.Error()
		} else {
			last = state
			if want(state) {
				return time.Since(start), state, true
			}
		}
		time.Sleep(time.Second)
	}
	return time.Since(start), last, false
}

// lbVictim is an ingress-capable node the suite can reach over SSH, not the
// seed where there is another (restarting the seed is the costliest restart;
// see harness.PickRestartableNode).
func lbVictim(targets *harness.IntegrationTargets) (harness.IntegrationNode, bool) {
	var picks []harness.IntegrationNode
	for _, n := range targets.Nodes {
		role := strings.ReplaceAll(strings.TrimSpace(n.Role), " ", "")
		ingress := role == "" || role == "mixed" || strings.Contains(","+role+",", ",ingress,")
		if _, ok := harness.SSHTarget(n); ok && ingress && n.InstanceID != "" {
			picks = append(picks, n)
		}
	}
	sort.SliceStable(picks, func(i, j int) bool { return !picks[i].Seed && picks[j].Seed })
	if len(picks) == 0 {
		return harness.IntegrationNode{}, false
	}
	return picks[0], true
}

func lbEnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// UC-356 — one ingress node's daemon stops behind the balancer: the node
// leaves rotation within the health-check window, calls through the domain
// then all succeed, and the node comes back once its daemon does.
func TestAPILoadBalancerRidesOutADaemonOutage(t *testing.T) {
	harness.Require(t, sc, "UC-356")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	lb := targets.APILoadBalancer
	if lb == nil || lb.IP == "" || lb.TargetGroupARNs["443"] == "" {
		t.Fatalf("the scenario advertises api-load-balancer but integration_targets has no balancer (%+v): was it applied with api_load_balancer = \"nlb\"?", lb)
	}
	arn := lb.TargetGroupARNs["443"]
	// The window the balancer is held to: two failed probes 5 s apart, plus a
	// probe's phase and the balancer's propagation. The bank ask is 10-20 s.
	outBound := lbEnvDuration("AEROL_LB_OUT_OF_ROTATION_MAX", 20*time.Second)
	// A restarted daemon needs two passing probes; restore already waited
	// for the node to rejoin the cluster.
	backBound := lbEnvDuration("AEROL_LB_BACK_IN_ROTATION_MAX", 90*time.Second)
	// After AWS reports the node out, give every balancer node the change.
	const settle = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// 1. Every call goes through the balancer: the domain resolves to its
	// address only.
	ips, err := net.DefaultResolver.LookupHost(ctx, sc.Domain)
	if err != nil {
		t.Fatalf("resolve %s: %v", sc.Domain, err)
	}
	if len(ips) != 1 || ips[0] != lb.IP {
		t.Fatalf("%s resolves to %v, want only the balancer %s: a call could reach a node by round-robin and this case would measure DNS, not the balancer", sc.Domain, ips, lb.IP)
	}

	victim, ok := lbVictim(targets)
	if !ok {
		t.Fatal("no ingress node reachable over SSH to stop")
	}
	probe := newLBProber(sc.Domain, sc.PAT)

	// 2. Before: the victim is in rotation and every call succeeds.
	if _, state, ok := lbWaitState(t, arn, victim.InstanceID, func(s string) bool { return s == "healthy" }, 2*time.Minute); !ok {
		t.Fatalf("%s is not healthy on the balancer before the outage (last: %s)", victim.Name, state)
	}
	if bad := lbFailures(probe.run(ctx, 20, 200*time.Millisecond)); len(bad) > 0 {
		t.Fatalf("before any outage, %d of 20 calls through the balancer failed: %s", len(bad), lbSample(bad, 5))
	}

	// 3. Stop the victim's daemon, keep calling, and time how long the
	// balancer takes to drop it.
	restore := harness.KillNodeDaemon(t, victim)
	t.Cleanup(restore)
	killedAt := time.Now()
	var (
		mu     sync.Mutex
		window []lbCall
		stop   = make(chan struct{})
		done   = make(chan struct{})
	)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			c := probe.call(ctx)
			mu.Lock()
			window = append(window, c)
			mu.Unlock()
			time.Sleep(250 * time.Millisecond)
		}
	}()
	leftAfter, state, left := lbWaitState(t, arn, victim.InstanceID, func(s string) bool { return s != "healthy" }, outBound+30*time.Second)
	time.Sleep(settle)
	close(stop)
	<-done
	if !left {
		t.Fatalf("%s stayed in rotation %v after its daemon stopped (last state: %s)", victim.Name, time.Since(killedAt).Round(time.Second), state)
	}
	if leftAfter > outBound {
		t.Errorf("%s left rotation %v after its daemon stopped, over the %v bound", victim.Name, leftAfter.Round(time.Second), outBound)
	}
	windowBad := lbFailures(window)
	t.Logf("%s left rotation %v after its daemon stopped (state %s); during that window %d of %d calls failed: %s",
		victim.Name, leftAfter.Round(100*time.Millisecond), state, len(windowBad), len(window), lbSample(windowBad, 5))

	// 4. Out of rotation: no call may fail. 60 fresh connections; were the
	// stopped node still taking a third of them, all 60 would succeed with
	// probability (2/3)^60, about 3e-11.
	steady := probe.run(ctx, 60, 500*time.Millisecond)
	steadyBad := lbFailures(steady)
	if len(steadyBad) > 0 {
		t.Errorf("with %s out of rotation, %d of %d calls through the balancer failed (want none): %s", victim.Name, len(steadyBad), len(steady), lbSample(steadyBad, 5))
	}
	if state, err := lbTargetState(arn, victim.InstanceID, 443); err == nil && state == "healthy" {
		t.Errorf("%s reports healthy while its daemon is stopped: the health check does not reach sandboxd", victim.Name)
	}

	// 5. Restart the daemon: the node returns to rotation and serves.
	restore()
	backAfter, state, back := lbWaitState(t, arn, victim.InstanceID, func(s string) bool { return s == "healthy" }, backBound)
	if !back {
		t.Errorf("%s did not return to rotation within %v of rejoining the cluster (last state: %s)", victim.Name, backBound, state)
	}
	after := probe.run(ctx, 30, 250*time.Millisecond)
	afterBad := lbFailures(after)
	if len(afterBad) > 0 {
		t.Errorf("after %s returned, %d of %d calls failed: %s", victim.Name, len(afterBad), len(after), lbSample(afterBad, 5))
	}

	bankRecord(t, "api_load_balancer_daemon_outage", map[string]any{
		"victim": victim.Name, "balancer_ip": lb.IP,
		"left_rotation_ms": leftAfter.Milliseconds(), "out_of_rotation_bound_ms": outBound.Milliseconds(),
		"window_calls": len(window), "window_failures": len(windowBad),
		"steady_calls": len(steady), "steady_failures": len(steadyBad),
		"back_in_rotation_ms": backAfter.Milliseconds(), "after_calls": len(after), "after_failures": len(afterBad),
	})
	t.Logf("%s back in rotation %v after rejoining; %d/%d calls failed while out of rotation, %d/%d after", victim.Name, backAfter.Round(100*time.Millisecond), len(steadyBad), len(steady), len(afterBad), len(after))
}
