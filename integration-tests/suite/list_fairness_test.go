//go:build integration

package suite

// UC-362: one tenant's list storm does not degrade another tenant.
//
// The gap it answers (after UC-361): a node's cluster-list slots were shared
// by everyone, so one tenant polling hard enough took every slot and the
// other tenants' lists were shed with 503 alongside it. Each tenant now holds
// at most its share of a node's slots (SB_API_LIST_MAX_INFLIGHT_PER_TENANT)
// and is told 429 rate_limited past it; waiting tenants take turns.
//
// Two teams list at once, each with its own avm_ runner token and a few
// sandboxes (so each list really fans out to owner nodes, as a busy tenant's
// would): a noisy one with AEROL_FAIRNESS_NOISY clients (default 1024) and
// a quiet one with AEROL_FAIRNESS_QUIET (default 4), for
// AEROL_FAIRNESS_SECONDS (default 60). Every client is pinned to one ingress
// node, round-robin, on a connection of its own tenant, so every node serves
// both tenants at once and no load balancer or connection reuse can keep
// them apart. Neither client retries.
//
// What it asserts:
//   - the quiet tenant's lists succeed (200) at least 99% of the time and
//     their p99 is within AEROL_FAIRNESS_QUIET_P99_MS (default 2000): a quiet
//     list never waits for a slot, so its latency is the node's own under the
//     noisy load, not the gate's 500 ms queue wait or a 503;
//   - the noisy tenant is told 429 (with Retry-After) and never sees a 502,
//     another 5xx, a refusal without Retry-After, a transport error or a
//     request hung past 30 s;
//   - no sandboxd on any node restarted.
//
// The scenario must size the gate so one tenant's load fills its share
// (capability api-list-fairness): a healthy list holds its slot for
// milliseconds, so on the default 16 slots with 4 per tenant a fast cluster
// can serve 1024 clients without ever refusing one (the 1024-client UC-361
// run on main 6d4988d1 never filled the gate). cluster-3-mixed-lb runs 8
// slots with 2 per tenant. The quiet tenant's clients must fit inside its
// own share on every node, which the test checks before it starts.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fairnessTally is what one tenant's clients saw.
type fairnessTally struct {
	ok, rateLimited, overloaded, noRetryAfter, badStatus, transport, hung atomic.Int64

	mu      sync.Mutex
	okLat   []time.Duration
	samples map[string]int
}

func (f *fairnessTally) note(kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.samples == nil {
		f.samples = map[string]int{}
	}
	f.samples[kind]++
}

// failures are the answers that are never acceptable for either tenant.
func (f *fairnessTally) failures() int64 {
	return f.noRetryAfter.Load() + f.badStatus.Load() + f.transport.Load() + f.hung.Load()
}

func (f *fairnessTally) total() int64 {
	return f.ok.Load() + f.rateLimited.Load() + f.overloaded.Load() + f.failures()
}

// record files one answer to GET /v1/sandboxes.
func (f *fairnessTally) record(resp *harness.APIResponse, err error, d time.Duration) {
	switch {
	case err != nil && errors.Is(err, context.DeadlineExceeded):
		f.hung.Add(1)
		f.note("hung past 30s")
	case err != nil:
		f.transport.Add(1)
		f.note("transport: " + overloadClip(err.Error()))
	case resp.Status == http.StatusOK:
		f.ok.Add(1)
		f.mu.Lock()
		f.okLat = append(f.okLat, d)
		f.mu.Unlock()
	case resp.Status == http.StatusTooManyRequests || resp.Status == http.StatusServiceUnavailable:
		if resp.Header.Get("Retry-After") == "" {
			f.noRetryAfter.Add(1)
			f.note(fmt.Sprintf("%d without Retry-After: %s", resp.Status, overloadClip(resp.String())))
			return
		}
		if resp.Status == http.StatusTooManyRequests {
			if !strings.Contains(string(resp.Body), models.ErrorCodeRateLimited) {
				// Some other 429 (a proxy's, say): not the gate's answer.
				f.badStatus.Add(1)
				f.note("429 without code rate_limited: " + overloadClip(resp.String()))
				return
			}
			f.rateLimited.Add(1)
			return
		}
		f.overloaded.Add(1)
		f.note("503 " + overloadClip(resp.String()))
	default:
		f.badStatus.Add(1)
		f.note(fmt.Sprintf("status %d: %s", resp.Status, overloadClip(resp.String())))
	}
}

// pinnedAPIClients returns, per node, a client that presents bearer and
// dials only that node (with the real hostname for SNI), on a transport of
// its own: one tenant's requests never share a connection with another's.
func pinnedAPIClients(t *testing.T, nodes []harness.IntegrationNode, bearer string) []*harness.APIClient {
	t.Helper()
	out := make([]*harness.APIClient, 0, len(nodes))
	for _, n := range nodes {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = pinnedDial(n.PublicIP)
		tr.MaxIdleConnsPerHost = 4096
		t.Cleanup(tr.CloseIdleConnections)
		out = append(out, &harness.APIClient{Base: strings.TrimRight(sc.BaseURL, "/"), Bearer: bearer, HTTP: &http.Client{Transport: tr}})
	}
	return out
}

// UC-362 — a noisy tenant's list storm leaves a quiet tenant's lists
// unaffected; the noisy one is told 429.
func TestListFairnessQuietTenantUnaffectedByANoisyOne(t *testing.T) {
	harness.Require(t, sc, "UC-362")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) == 0 {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	for _, node := range targets.Nodes {
		harness.RequireNodeSSH(t, node)
	}
	ingress := ingressNodes(targets)
	if len(ingress) == 0 {
		t.Fatal("no ingress node with a public address to send lists to")
	}
	noisyN := benchEnvInt("AEROL_FAIRNESS_NOISY", 1024)
	quietN := benchEnvInt("AEROL_FAIRNESS_QUIET", 4)
	dur := time.Duration(benchEnvInt("AEROL_FAIRNESS_SECONDS", 60)) * time.Second
	quietP99Bound := time.Duration(benchEnvInt("AEROL_FAIRNESS_QUIET_P99_MS", 2000)) * time.Millisecond
	sandboxesEach := benchEnvInt("AEROL_FAIRNESS_SANDBOXES", 3)
	const requestBudget = 30 * time.Second

	// 1. The gate every ingress node runs. The quiet tenant must fit inside
	// its own share on each node, or its own lists would (rightly) be 429.
	quietPerNode := (quietN + len(ingress) - 1) / len(ingress)
	before := map[string]map[string]float64{}
	for _, node := range ingress {
		m, err := apiListMetrics(t, node)
		if err != nil {
			t.Fatalf("%s: read the list gate's metrics: %v", node.Name, err)
		}
		limit, share := m["aerolvm_api_list_max_inflight"], m["aerolvm_api_list_max_inflight_per_tenant"]
		if limit <= 0 || share <= 0 || share >= limit {
			t.Fatalf("%s runs no per-tenant share (SB_API_LIST_MAX_INFLIGHT=%g, per tenant %g): this build or scenario cannot show fairness", node.Name, limit, share)
		}
		if float64(quietPerNode) > share {
			t.Fatalf("%s: the quiet tenant's %d clients put %d on a node whose per-tenant share is %g, over its own share; lower AEROL_FAIRNESS_QUIET or raise SB_API_LIST_MAX_INFLIGHT_PER_TENANT", node.Name, quietN, quietPerNode, share)
		}
		before[node.Name] = m
		t.Logf("%s: list gate %g slots, %g per tenant", node.Name, limit, share)
	}

	// 2. Which run of sandboxd each node is on.
	runs := map[string]overloadDaemonRun{}
	for _, node := range targets.Nodes {
		run, err := overloadReadDaemonRun(t, node)
		if err != nil {
			t.Fatalf("%s: %v", node.Name, err)
		}
		runs[node.Name] = run
	}

	// 3. Two tenants, each with its own team token and sandboxes on the
	// cluster's owner nodes, so every list fans out.
	noisyTok := mintToken(t, "uc362-noisy", "runner", harness.TeamPayments)
	quietTok := mintToken(t, "uc362-quiet", "runner", harness.TeamCheckout)
	owners := map[string][]string{}
	for _, tenant := range []struct {
		team, secret string
	}{{harness.TeamPayments, noisyTok.Secret}, {harness.TeamCheckout, quietTok.Secret}} {
		for range sandboxesEach {
			sb := sandboxAs(t, tenant.secret)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			owner, err := client(t).OwnerNodeID(ctx, sb.ID)
			cancel()
			if err != nil {
				owner = "?"
			}
			owners[tenant.team] = append(owners[tenant.team], owner)
		}
	}
	t.Logf("sandbox owners: noisy (%s) %v, quiet (%s) %v", harness.TeamPayments, owners[harness.TeamPayments], harness.TeamCheckout, owners[harness.TeamCheckout])

	noisyClients := pinnedAPIClients(t, ingress, noisyTok.Secret)
	quietClients := pinnedAPIClients(t, ingress, quietTok.Secret)
	list := func(c *harness.APIClient) (*harness.APIResponse, time.Duration, error) {
		ctx, cancel := context.WithTimeout(context.Background(), requestBudget)
		defer cancel()
		t0 := time.Now()
		resp, err := c.Do(ctx, http.MethodGet, "/v1/sandboxes", nil)
		return resp, time.Since(t0), err
	}

	// 4. The quiet tenant's idle baseline, through every node.
	var baseline []time.Duration
	for i := range 20 {
		resp, d, err := list(quietClients[i%len(quietClients)])
		if err != nil || resp.Status != http.StatusOK {
			t.Fatalf("quiet baseline list %d: %v %s", i, err, resp.String())
		}
		baseline = append(baseline, d)
	}

	// 5. Both loads at once.
	var noisy, quiet fairnessTally
	end := time.Now().Add(dur)
	var wg sync.WaitGroup
	run := func(n int, clients []*harness.APIClient, tally *fairnessTally) {
		for i := range n {
			c := clients[i%len(clients)]
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(end) {
					resp, d, err := list(c)
					tally.record(resp, err, d)
				}
			}()
		}
	}
	run(noisyN, noisyClients, &noisy)
	run(quietN, quietClients, &quiet)
	wg.Wait()

	// 6. No sandboxd restarted, and what each node's gate counted.
	var restarted []string
	refusals := map[string]string{}
	var rateLimitedOnNodes float64
	for _, node := range targets.Nodes {
		was := runs[node.Name]
		now, err := overloadReadDaemonRun(t, node)
		if err != nil {
			t.Errorf("%s: %v", node.Name, err)
			continue
		}
		starts, watchdog, err := overloadRestartsSince(t, node, was.since)
		if err != nil {
			t.Errorf("%s: %v", node.Name, err)
			continue
		}
		if now.invocation != was.invocation || now.restarts != was.restarts || starts > 0 || watchdog > 0 {
			restarted = append(restarted, fmt.Sprintf("%s (InvocationID %s→%s, NRestarts %s→%s, %d start(s) and %d watchdog restart(s) in the journal)",
				node.Name, was.invocation, now.invocation, was.restarts, now.restarts, starts, watchdog))
		}
	}
	for _, node := range ingress {
		m, err := apiListMetrics(t, node)
		if err != nil {
			refusals[node.Name] = "?"
			continue
		}
		b := before[node.Name]
		rl := m["aerolvm_api_list_rate_limited_total"] - b["aerolvm_api_list_rate_limited_total"]
		rateLimitedOnNodes += rl
		refusals[node.Name] = fmt.Sprintf("429:%g 503:%g", rl, m["aerolvm_api_list_shed_total"]-b["aerolvm_api_list_shed_total"])
	}

	quietSum, noisySum := bankSummarize(quiet.okLat), bankSummarize(noisy.okLat)
	quietTotal := quiet.total()
	quietRate := 0.0
	if quietTotal > 0 {
		quietRate = float64(quiet.ok.Load()) / float64(quietTotal)
	}
	sort.Slice(baseline, func(i, j int) bool { return baseline[i] < baseline[j] })
	bankRecord(t, "list_fairness_v1_sandboxes", map[string]any{
		"noisy_clients": noisyN, "quiet_clients": quietN, "seconds": dur.Seconds(), "ingress_nodes": len(ingress),
		"quiet_baseline_p50_ms": baseline[len(baseline)/2].Milliseconds(),
		"quiet": map[string]any{"ok": quiet.ok.Load(), "rate_limited": quiet.rateLimited.Load(), "overloaded": quiet.overloaded.Load(),
			"failures": quiet.failures(), "success_rate": quietRate, "ok_latency": quietSum, "samples": quiet.samples},
		"noisy": map[string]any{"ok": noisy.ok.Load(), "rate_limited": noisy.rateLimited.Load(), "overloaded": noisy.overloaded.Load(),
			"failures": noisy.failures(), "ok_rps": float64(noisy.ok.Load()) / dur.Seconds(), "ok_latency": noisySum, "samples": noisy.samples},
		"refusals_by_node": refusals, "sandbox_owners": owners, "restarted": restarted,
	})
	t.Logf("quiet (%d clients): %d/%d ok (%.2f%%), p50 %.0f ms p99 %.0f ms (idle p50 %v), %d x 429, %d x 503; noisy (%d clients): %d ok (%.0f req/s), %d x 429, %d x 503; refusals by node %v",
		quietN, quiet.ok.Load(), quietTotal, 100*quietRate, quietSum.P50MS, quietSum.P99MS, baseline[len(baseline)/2],
		quiet.rateLimited.Load(), quiet.overloaded.Load(), noisyN, noisy.ok.Load(), float64(noisy.ok.Load())/dur.Seconds(),
		noisy.rateLimited.Load(), noisy.overloaded.Load(), refusals)

	if len(restarted) > 0 {
		t.Errorf("sandboxd restarted under load: %s", strings.Join(restarted, "; "))
	}
	if quietTotal == 0 || quietRate < 0.99 {
		t.Errorf("the quiet tenant's lists succeeded %.2f%% of %d (want >= 99%%): %d x 429, %d x 503, %d other failures; samples %v",
			100*quietRate, quietTotal, quiet.rateLimited.Load(), quiet.overloaded.Load(), quiet.failures(), quiet.samples)
	}
	if bound := float64(quietP99Bound.Milliseconds()); quietSum.P99MS > bound {
		t.Errorf("the quiet tenant's p99 was %.0f ms under the noisy load, over the %v bound (idle p50 %v)", quietSum.P99MS, quietP99Bound, baseline[len(baseline)/2])
	}
	if noisy.rateLimited.Load() == 0 {
		t.Errorf("the noisy tenant was never told 429: its share was never full (%d ok, %d x 503; nodes counted %g x 429). Raise AEROL_FAIRNESS_NOISY, or lower SB_API_LIST_MAX_INFLIGHT_PER_TENANT in the scenario", noisy.ok.Load(), noisy.overloaded.Load(), rateLimitedOnNodes)
	}
	if n := noisy.failures(); n > 0 {
		t.Errorf("%d noisy requests failed other than as a refusal with Retry-After (bad status %d, refusal without Retry-After %d, transport %d, hung past %v %d); samples %v",
			n, noisy.badStatus.Load(), noisy.noRetryAfter.Load(), noisy.transport.Load(), requestBudget, noisy.hung.Load(), noisy.samples)
	}
}
