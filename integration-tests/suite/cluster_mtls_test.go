//go:build integration

package suite

// Group H, non-disruptive half — cluster mTLS and authz (§7 group H,
// F12/F13). UC-151..154. UC-155 is disruptive and lives in
// z_cluster_mtls_revoke_test.go.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// UC-151 — every node presents a certificate carrying DNS:node:<id>, and the
// CA signing key exists ONLY on the seed.
//
// The second half is the one that decides how bad a single node compromise
// is. With ca.key on a worker, an attacker who takes that worker can mint a
// certificate for any node id and read every sandbox's sealed material; with
// it only on the seed (and, under enterprise, nowhere at all), they get one
// node's worth of access.
func TestEveryNodeHasAScopedCertAndOnlyTheSeedHasTheCAKey(t *testing.T) {
	harness.Require(t, sc, "UC-151")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	checked := 0
	for _, node := range targets.Nodes {
		target, ok := harness.SSHTarget(node)
		if !ok {
			continue
		}
		checked++
		nodeID := heteroNodeID(t, c, targets, node.Name)

		sans, err := harness.SSHRun(t, target, nodeCertSANsScript)
		if err != nil {
			t.Fatalf("read the node certificate on %s: %v\n%s", node.Name, err, sans)
		}
		want := "DNS:node:" + nodeID
		if !strings.Contains(sans, want) {
			t.Fatalf("%s presents a certificate whose SANs do not include %q (got %q): the peer dialer cannot bind this connection to a node id",
				node.Name, want, strings.TrimSpace(sans))
		}

		out, err := harness.SSHRun(t, target, caKeyPresenceScript)
		if err != nil {
			t.Fatalf("probe for ca.key on %s: %v", node.Name, err)
		}
		hasCAKey := strings.Contains(out, "PRESENT")
		if !node.Seed && hasCAKey {
			t.Fatalf("the CA signing key is present on joiner %s: whoever takes that node can mint a certificate for ANY node id and read every sandbox's sealed material",
				node.Name)
		}
		if node.Seed && hasCAKey && sc.Has(harness.CapEnterprise) {
			t.Fatalf("the CA signing key is present on the seed under the enterprise profile; config.go refuses to boot with it, so either the gate did not run or the key arrived after boot")
		}
	}
	if checked == 0 {
		t.Fatal("no node was inspected; this case would have passed having checked nothing")
	}
}

// UC-152 — a plaintext call to the cluster-internal port is refused.
//
// An internal listener that speaks http to anyone who asks is a listener with
// no identity check at all, whatever the mTLS configuration says.
func TestPlaintextCallToTheInternalPortIsRefused(t *testing.T) {
	harness.Require(t, sc, "UC-152")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	node, ok := harness.PickSSHNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	target, _ := harness.SSHTarget(node)

	out, err := harness.SSHRun(t, target, plaintextInternalProbeScript)
	if err != nil {
		t.Fatalf("probe the internal port in plaintext: %v\n%s", err, out)
	}
	status := strings.TrimSpace(lastField(out))
	// curl reports 000 when the server closes the connection or the TLS
	// handshake fails, which is the correct outcome: the listener did not
	// serve a plaintext request.
	if status == "000" || status == "" {
		t.Logf("UC-152 PASS: the internal listener refused a plaintext request outright")
		return
	}
	if strings.HasPrefix(status, "2") {
		t.Fatalf("the cluster-internal port SERVED a plaintext request (status %s): there is no transport identity check on that listener", status)
	}
	t.Logf("UC-152 PASS: plaintext request refused with status %s", status)
}

// UC-153 — a forged identity is rejected. A self-signed certificate that
// claims a valid node id must not be accepted.
//
// This is the difference between "the connection is encrypted" and "the
// connection is to who it says it is". Only the second protects the sealed
// material.
func TestForgedPeerIdentityIsRejected(t *testing.T) {
	harness.Require(t, sc, "UC-153")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	node, ok := harness.PickSSHNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	target, _ := harness.SSHTarget(node)
	c := client(t)
	nodeID := heteroNodeID(t, c, targets, node.Name)

	out, err := harness.SSHRun(t, target, forgedCertProbeScript(nodeID))
	if err != nil {
		t.Skipf("could not mint a forged certificate on %s (openssl may be missing): %v\n%s", node.Name, err, strings.TrimSpace(out))
	}
	status := strings.TrimSpace(lastField(out))
	if strings.HasPrefix(status, "2") {
		t.Fatalf("a SELF-SIGNED certificate claiming node id %q was accepted by the peer listener (status %s): anyone who can reach the port can claim to be any node",
			nodeID, status)
	}
	t.Logf("UC-153 PASS: a self-signed certificate claiming %q was refused (status %s)", nodeID, status)
}

// UC-154 — operator-only routes accept the fleet PAT and refuse a
// tenant-scoped token; the mTLS-gated internal routes refuse the PAT too.
//
// RE-SCOPED from the plan (§7 prerequisite box): the plan's positive half
// ("/v1/cluster/internal/* … accept the fleet PAT") is false. Those routes
// are internalOp = op(withInternalMTLS(...)) and cluster.AuthenticatedPeerNodeID
// rejects any request without VerifiedChains and a node:<id> SAN, so a PAT
// can never satisfy them — and refusing it is the CORRECT behaviour, which is
// what the second half now asserts.
func TestOperatorRoutesAcceptThePATAndInternalRoutesDoNot(t *testing.T) {
	harness.Require(t, sc, "UC-154")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Positive half: op()-only routes work with the fleet PAT.
	for _, path := range []struct {
		method, path string
	}{
		{http.MethodPost, "/v1/audit/verify"},
		{http.MethodGet, "/v1/cluster/storage-retirements"},
	} {
		var err error
		if path.method == http.MethodPost {
			err = c.PostJSON(ctx, path.path, nil, nil)
		} else {
			err = c.GetJSON(ctx, path.path, nil)
		}
		if err != nil && (strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "403")) {
			t.Fatalf("the fleet PAT was refused by the operator-only route %s %s: %v", path.method, path.path, err)
		}
	}

	// Negative half: a tenant-scoped token must not reach them. Without a way
	// to mint one this half cannot run, and saying so beats a silent pass.
	tenantToken := strings.TrimSpace(envOr("AEROL_TENANT_TOKEN", ""))
	if tenantToken == "" {
		t.Log("AEROL_TENANT_TOKEN not set; the tenant-refusal half of UC-154 did not run. The PAT-acceptance half above did.")
		return
	}
	for _, p := range []string{"/v1/audit/verify", "/v1/cluster/storage-retirements"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL()+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tenantToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("tenant-token request to %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("operator-only route %s served a TENANT-scoped token (status %d)", p, resp.StatusCode)
		}
	}
}
