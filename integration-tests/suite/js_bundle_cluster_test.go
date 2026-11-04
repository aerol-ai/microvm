//go:build integration

package suite

// Group M, UC-168 — the js-bundle cluster list fan-out.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
)

// missingPeersHeader is what pkg/api/v1/js_bundle_cluster.go sets when the
// aggregate could not reach every node.
const missingPeersHeader = "X-Aerol-Missing-JSBundle-Peers"

// UC-168 — listing js-bundles aggregates across nodes, and DECLARES a peer it
// could not reach rather than silently returning a short list.
//
// Same honesty property as UC-134. A short list here is worse than an error:
// an operator concludes a bundle was deleted and re-uploads it, or a delete
// sweep removes one it thinks is unreferenced.
func TestJSBundleListDeclaresUnreachablePeers(t *testing.T) {
	harness.Require(t, sc, "UC-168")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	name := harness.UniqueName(sc, t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var created models.JSBundle
	if err := c.PostJSON(ctx, "/v1/js-bundles", models.CreateJSBundleRequest{
		Name:   name,
		Source: `export default { async fetch() { return new Response("uc168"); } };`,
	}, &created); err != nil {
		t.Fatalf("upload bundle: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.Delete(cctx, "/v1/js-bundles/"+created.ModuleRef)
	})

	// The aggregate must contain it, and must not be declaring missing peers
	// on a healthy cluster. The leader caches the aggregate for two seconds,
	// so allow one cache window before calling the list short.
	var body string
	var headers http.Header
	listDeadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		body, headers, err = getWithHeaders(ctx, c, "/v1/js-bundles")
		if err != nil {
			t.Fatalf("list bundles: %v", err)
		}
		if strings.Contains(body, created.Digest) || time.Now().After(listDeadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !strings.Contains(body, created.Digest) {
		t.Fatalf("the cluster-wide list does not contain the bundle just uploaded (%s)", created.Digest)
	}
	if missing := strings.TrimSpace(headers.Get(missingPeersHeader)); missing != "" {
		t.Fatalf("a healthy cluster declared missing js-bundle peers %q; either a node is down before this case started or the aggregate cannot reach its peers at all", missing)
	}

	if !sc.Has(harness.CapCluster) || !harness.DisruptiveAllowed() {
		t.Log("the unreachable-peer half needs a cluster and the disruptive gate; the aggregate half above ran")
		return
	}

	// Now stop a peer and assert the response SAYS so. The peer must run
	// isolate: the aggregate asks only isolate workers, so stopping any other
	// node (the containerd worker on cluster-bank-flagship) correctly leaves
	// the list complete.
	victim, ok := isolatePeerToStop(t, c, targets)
	if !ok {
		t.Skip("no SSH-reachable non-seed node runs the isolate runtime")
	}
	requireNonSeedVictim(t, victim)
	target, _ := harness.SSHTarget(victim)
	if out, err := harness.SSHRun(t, target, "sudo systemctl stop sandboxd"); err != nil {
		t.Fatalf("stop sandboxd on %s: %v\n%s", victim.Name, err, out)
	}
	// Out of the client's rotation, as a health-checked load balancer would
	// take it out. The missing-peers header is written by the node that
	// serves the list, which still has to ask the victim and fail, so this
	// hides nothing; a client pinned to the victim's Caddy would read 502
	// for the whole poll instead. restoreNodeDaemon puts it back.
	harness.MarkNodeDown(victim.PublicIP)
	t.Cleanup(func() { restoreNodeDaemon(t, victim, target) })

	deadline := time.Now().Add(3 * time.Minute)
	// Two correct answers with the holder down: the list still names the
	// bundle (the server tier's replicated catalogue answers for a node that
	// published its inventory, so nothing is missing), or it is short and
	// says so in the header. Short and silent is the failure.
	var stopped string
	for time.Now().Before(deadline) {
		body, headers, err := getWithHeaders(ctx, c, "/v1/js-bundles")
		if err == nil && strings.TrimSpace(headers.Get(missingPeersHeader)) != "" {
			t.Logf("UC-168 PASS: the aggregate declared %q unreachable", headers.Get(missingPeersHeader))
			return
		}
		if err == nil && strings.Contains(body, created.Digest) {
			stopped = body
		} else if err == nil {
			stopped = ""
		}
		time.Sleep(10 * time.Second)
	}
	if stopped != "" {
		t.Logf("UC-168 PASS: with %s stopped the list still names its bundle %s (served from the replicated catalogue), so nothing is short", victim.Name, created.Digest)
		return
	}
	t.Fatalf("with %s stopped, the js-bundle list dropped bundle %s and never set %s: the response is silently short, so an operator would conclude a bundle was deleted",
		victim.Name, created.Digest, missingPeersHeader)
}

// isolatePeerToStop picks a non-seed, SSH-reachable node whose capacity
// advertises the isolate runtime.
func isolatePeerToStop(t *testing.T, c *harness.Client, targets *harness.IntegrationTargets) (harness.IntegrationNode, bool) {
	t.Helper()
	members, err := benchClusterMembers(c)
	if err != nil {
		t.Fatalf("read cluster members: %v", err)
	}
	for _, n := range targets.Nodes {
		if n.Seed {
			continue
		}
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		for _, m := range members.Members {
			if (m.NodeName == n.Name || strings.HasSuffix(m.NodeName, "-"+n.Name)) && nodeAdvertisesRuntime(members, m.NodeID, models.RuntimeIsolate) {
				return n, true
			}
		}
	}
	return harness.IntegrationNode{}, false
}
