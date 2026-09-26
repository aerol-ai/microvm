//go:build integration

package suite

// Group M, UC-168 — the js-bundle cluster list fan-out.

import (
	"context"
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
		_ = c.Delete(cctx, "/v1/js-bundles/"+created.Digest)
	})

	// The aggregate must contain it, and must not be declaring missing peers
	// on a healthy cluster.
	body, headers, err := getWithHeaders(ctx, c, "/v1/js-bundles")
	if err != nil {
		t.Fatalf("list bundles: %v", err)
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

	// Now stop a peer and assert the response SAYS so.
	victim, ok := pickNonSeedNode(targets)
	if !ok {
		t.Skip("no SSH-reachable non-seed node to stop")
	}
	target, _ := harness.SSHTarget(victim)
	if out, err := harness.SSHRun(t, target, "sudo systemctl stop sandboxd"); err != nil {
		t.Fatalf("stop sandboxd on %s: %v\n%s", victim.Name, err, out)
	}
	t.Cleanup(func() {
		if out, err := harness.SSHRun(t, target, "sudo systemctl start sandboxd"); err != nil {
			t.Errorf("RESTORE FAILED: sandboxd is left stopped on %s and the rest of this run is suspect: %v\n%s", victim.Name, err, out)
		}
	})

	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		_, headers, err := getWithHeaders(ctx, c, "/v1/js-bundles")
		if err == nil && strings.TrimSpace(headers.Get(missingPeersHeader)) != "" {
			t.Logf("UC-168 PASS: the aggregate declared %q unreachable", headers.Get(missingPeersHeader))
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("with %s stopped, the js-bundle list never set %s: the response is silently short, so an operator would conclude a bundle was deleted",
		victim.Name, missingPeersHeader)
}
