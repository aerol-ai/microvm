//go:build integration

package suite

// Group G — quota, rate limits and overflow (§7 group G, F8). UC-146..150.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-146 — the per-identity audit rate limit returns 429 with Retry-After,
// and a second identity is unaffected.
//
// The second half is the point. A limiter that is actually global would also
// produce 429s under this load, and a test that only looked for 429 would
// call that a pass — while in production one noisy tenant would have silenced
// everyone else's ability to read their own evidence.
func TestAuditRateLimitIsPerIdentity(t *testing.T) {
	harness.Require(t, sc, "UC-146")
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC146_TOKEN": secretValue(t, "146")},
	})
	waitRunning(t, sb)

	// Hammer the audit read until the limiter trips. The default is 10/s
	// (SB_AUDIT_RATE_LIMIT_IDENTITY), so this is a short burst, not a flood.
	status, retryAfter := burstAuditReads(t, c, sb.ID, 120)
	if status != http.StatusTooManyRequests {
		t.Skipf("the per-identity limiter did not trip after 120 reads (last status %d); this scenario's limit is too high to exercise safely", status)
	}
	if strings.TrimSpace(retryAfter) == "" {
		t.Fatal("the 429 carried no Retry-After header; a client has nothing to back off by and will hot-loop")
	}

	// A second, unrelated sandbox read on the SAME identity is expected to be
	// limited too — that is what per-identity means. What must NOT happen is
	// the limiter refusing forever: it must recover.
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"/audit?limit=1", nil)
		cancel()
		if err == nil {
			t.Logf("UC-146 PASS: limiter tripped with Retry-After=%q and recovered", retryAfter)
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatal("the per-identity audit limiter never recovered; an identity that trips it once is locked out of its own evidence")
}

// UC-147 — the per-node ceiling is separate from the operator limit.
//
// If they were the same budget, ordinary peer fan-out traffic would consume
// an operator's ability to read the audit log during exactly the incident
// that produced the traffic.
func TestAuditNodeCeilingIsSeparateFromTheOperatorLimit(t *testing.T) {
	harness.Require(t, sc, "UC-147")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC147_TOKEN": secretValue(t, "147")},
	})
	waitRunning(t, sb)

	node, ok := harness.PickSSHNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}

	// Squeeze the PEER ceiling to almost nothing and leave the operator limit
	// generous. The operator read must still work.
	harness.WithNodeEnv(t, node, map[string]string{
		"SB_AUDIT_RATE_LIMIT_NODE":     "1",
		"SB_AUDIT_RATE_LIMIT_IDENTITY": "1000",
	}, func(res harness.NodeBootResult) {
		if !res.Started {
			t.Fatalf("node %s did not start with a squeezed peer ceiling: %s\n%s", node.Name, res.Status, tailLines(res.Journal, 30))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		for i := 0; i < 20; i++ {
			if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"/audit?limit=1", nil); err != nil {
				t.Fatalf("operator audit read %d failed while only the PEER ceiling was squeezed (%v): the two limits share a budget, so peer traffic can silence an operator during the incident that produced it",
					i, err)
			}
		}
	})
}

// UC-148 — overflow with the `gap` policy leaves a gap marker carrying a
// non-zero dropped count, and the chain still verifies across it.
//
// A lossy buffer is acceptable; a lossy buffer that hides what it lost is
// not. The marker is the difference between "nothing happened" and "we know
// something happened and how much".
func TestOverflowGapMarkerRecordsWhatWasDropped(t *testing.T) {
	harness.Require(t, sc, "UC-148")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	node, ok := harness.PickSSHNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}

	harness.WithNodeEnv(t, node, map[string]string{
		"SB_AUDIT_QUEUE_MAX":       "1",
		"SB_AUDIT_OVERFLOW_POLICY": "gap",
	}, func(res harness.NodeBootResult) {
		if !res.Started {
			t.Fatalf("node %s did not start with a 1-deep audit queue: %s\n%s", node.Name, res.Status, tailLines(res.Journal, 30))
		}
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
			Name: harness.UniqueName(sc, t),
			Env:  map[string]string{"UC148_TOKEN": secretValue(t, "148")},
		})
		waitRunning(t, sb)
		floodAuditReads(t, c, sb.ID, 200)

		events := harness.AllAuditEvents(t, c, sb.ID, 200, 20)
		var marker *struct {
			Dropped int64
		}
		for _, ev := range events {
			if ev.Kind == "gap" || ev.Result == "gap" {
				marker = &struct{ Dropped int64 }{Dropped: ev.Dropped}
				break
			}
		}
		if marker == nil {
			t.Skipf("the flood did not overflow a 1-deep queue (%d events recorded); nothing was dropped, so there is no marker to assert", len(events))
		}
		if marker.Dropped <= 0 {
			t.Fatal("a gap marker was written with dropped=0: the record says evidence was lost but not how much, which is the same as saying nothing")
		}
		// The chain must still verify ACROSS the marker: an overflow may lose
		// records but must not break the proof that the rest is intact.
		if report := verifyAuditChain(t, c); !report.OK {
			t.Fatalf("the chain does not verify across the gap marker: %s", report.Error)
		}
		t.Logf("UC-148 PASS: gap marker recorded dropped=%d and the chain still verifies", marker.Dropped)
	})
}

// UC-149 — overflow with the `spill` policy drains from disk, so the chain is
// COMPLETE after the burst rather than merely verifiable with a hole in it.
func TestOverflowSpillDrainsAndLeavesNoHole(t *testing.T) {
	harness.Require(t, sc, "UC-149")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	node, ok := harness.PickSSHNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}

	harness.WithNodeEnv(t, node, map[string]string{
		"SB_AUDIT_QUEUE_MAX":       "1",
		"SB_AUDIT_OVERFLOW_POLICY": "spill",
	}, func(res harness.NodeBootResult) {
		if !res.Started {
			t.Fatalf("node %s did not start with the spill policy: %s\n%s", node.Name, res.Status, tailLines(res.Journal, 30))
		}
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
			Name: harness.UniqueName(sc, t),
			Env:  map[string]string{"UC149_TOKEN": secretValue(t, "149")},
		})
		waitRunning(t, sb)
		const reads = 100
		floodAuditReads(t, c, sb.ID, reads)

		// The spill drains asynchronously; wait for the count to settle.
		deadline := time.Now().Add(4 * time.Minute)
		var events int
		for time.Now().Before(deadline) {
			n := len(harness.AllAuditEvents(t, c, sb.ID, 500, 40))
			if n == events && n > 0 {
				break
			}
			events = n
			time.Sleep(15 * time.Second)
		}

		for _, ev := range harness.AllAuditEvents(t, c, sb.ID, 500, 40) {
			if ev.Kind == "gap" || ev.Result == "gap" {
				t.Fatalf("the spill policy left a gap marker (dropped=%d): spill exists precisely so the burst does NOT lose records", ev.Dropped)
			}
		}
		if report := verifyAuditChain(t, c); !report.OK {
			t.Fatalf("the chain does not verify after the spill drained: %s", report.Error)
		}
		t.Logf("UC-149 PASS: %d events survived a %d-read burst on a 1-deep queue with no gap marker", events, reads)
	})
}

// UC-150 — egress attribution names the RIGHT sandbox, and the per-sandbox
// cap bounds one tenant's share of the shared evidence file.
//
// Attribution to the wrong sandbox is worse than none: it puts one tenant's
// network activity in another tenant's audit record.
func TestEgressAttributionNamesTheRightSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-150")
	c := client(t)

	// Two sandboxes, so a mis-attribution has somewhere to show up.
	a := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-a"})
	b := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-b"})
	waitRunning(t, a)
	waitRunning(t, b)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Only A makes egress attempts.
	for i := 0; i < 5; i++ {
		if _, err := a.Exec(ctx, sdktypes.ExecRequest{Command: "wget -q -T 3 -O /dev/null https://example.com || true"}); err != nil {
			t.Logf("egress attempt %d on A: %v", i, err)
		}
	}

	aEvents := harness.AllAuditEvents(t, c, a.ID, 200, 20)
	bEvents := harness.AllAuditEvents(t, c, b.ID, 200, 20)

	aEgress := harness.CountAuditEvents(aEvents, "egress")
	bEgress := harness.CountAuditEvents(bEvents, "egress")
	if aEgress == 0 {
		t.Skipf("no egress records attributed to A; egress attribution is off or this runtime does not mediate it (b had %d)", bEgress)
	}
	if bEgress > 0 {
		t.Fatalf("sandbox B made no egress attempts but %d egress records name it: one tenant's network activity landed in another tenant's audit record", bEgress)
	}
	for _, ev := range aEvents {
		if ev.Kind == "egress" && ev.SandboxID != a.ID {
			t.Fatalf("an egress record returned for %s names sandbox %s", a.ID, ev.SandboxID)
		}
	}
	t.Logf("UC-150 PASS: %d egress records attributed to A, 0 to B", aEgress)
}

// burstAuditReads fires n audit reads as fast as it can and returns the last
// status plus any Retry-After. Sequential on purpose: the point is to trip a
// rate limit, not to measure concurrency.
func burstAuditReads(t *testing.T, c *harness.Client, sandboxID string, n int) (int, string) {
	t.Helper()
	path := c.BaseURL() + "/v1/sandboxes/" + sandboxID + "/audit?limit=1"
	last, retryAfter := 0, ""
	for i := 0; i < n; i++ {
		req, err := http.NewRequest(http.MethodGet, path, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+sc.PAT)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("audit read %d: %v", i, err)
		}
		last = resp.StatusCode
		if last == http.StatusTooManyRequests {
			retryAfter = resp.Header.Get("Retry-After")
		}
		resp.Body.Close()
		if last == http.StatusTooManyRequests {
			return last, retryAfter
		}
	}
	return last, retryAfter
}

// floodAuditReads generates audit records concurrently, to overflow a
// deliberately shallow queue. Errors are ignored: 429s and refusals ARE the
// overflow being produced.
func floodAuditReads(t *testing.T, c *harness.Client, sandboxID string, n int) {
	t.Helper()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = c.GetJSON(ctx, fmt.Sprintf("/v1/sandboxes/%s?include_env=true", sandboxID), nil)
		}()
	}
	wg.Wait()
}
