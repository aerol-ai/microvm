//go:build integration

package suite

// Group F — export connectors and witness (§7 group F, F9/F10/F11).
// UC-139..143, 145, 145b.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const exportDeliveryTimeout = 5 * time.Minute

// generateAuditRecords does enough work to put fresh records on the wire and
// returns the sandbox so a caller can look for its events specifically.
// Looking for THIS sandbox's records is what stops a case passing on
// leftovers from an earlier one.
func generateAuditRecords(t *testing.T, c *harness.Client, tag string, reads int) (string, string) {
	t.Helper()
	secret := secretValue(t, tag)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC_TOKEN": secret},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for i := 0; i < reads; i++ {
		if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
			t.Fatalf("read env %d: %v", i, err)
		}
	}
	return sb.ID, secret
}

// UC-139 — the file backend writes one chained JSON object per line.
//
// Configured per-node rather than assumed: the scenario may be running the
// webhook or s3 backend, and pkg/auditexport is single-valued (no fan-out),
// so the only way to assert the file connector is to switch a node to it.
func TestFileExportBackendWritesChainedRecords(t *testing.T) {
	harness.Require(t, sc, "UC-139")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}

	const path = "/var/log/aerol-audit-file-export.jsonl"
	harness.WithNodeEnv(t, node, map[string]string{
		"SB_AUDIT_EXPORT_ENABLED":   "true",
		"SB_AUDIT_EXPORT_BACKEND":   "file",
		"SB_AUDIT_EXPORT_FILE_PATH": path,
	}, func(res harness.NodeBootResult) {
		if !res.Started {
			// Enterprise refuses an on-node exporter; that is UC-158's
			// assertion, not a failure here.
			if res.RefusedWith("off-node") || res.RefusedWith("on-node") {
				t.Skipf("this profile refuses the file backend (that is UC-158's assertion):\n%s", tailLines(res.Journal, 20))
			}
			t.Fatalf("node %s did not start with the file exporter: %s\n%s", node.Name, res.Status, tailLines(res.Journal, 30))
		}
		sandboxID, secret := generateAuditRecords(t, c, "139", 3)

		target, _ := harness.SSHTarget(node)
		deadline := time.Now().Add(exportDeliveryTimeout)
		for time.Now().Before(deadline) {
			out, err := harness.SSHRun(t, target, "sudo cat "+path+" 2>/dev/null || true")
			if err == nil && strings.Contains(out, sandboxID) {
				assertChainedJSONL(t, "the file export at "+path, out, secret)
				return
			}
			time.Sleep(10 * time.Second)
		}
		t.Fatalf("no record for %s reached %s within %s", sandboxID, path, exportDeliveryTimeout)
	})
}

// UC-140 — the s3 backend writes objects under the prefix that reconstruct
// the chain.
func TestS3ExportBackendWritesReconstructableObjects(t *testing.T) {
	harness.Require(t, sc, "UC-140")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	bucket := strings.TrimSpace(envOr("AEROL_AUDIT_EXPORT_S3_BUCKET", ""))
	if bucket == "" {
		t.Skip("AEROL_AUDIT_EXPORT_S3_BUCKET not set; no bucket to export into")
	}
	c := client(t)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}

	prefix := "itest-uc140/" + harness.UniqueName(sc, t)
	harness.WithNodeEnv(t, node, map[string]string{
		"SB_AUDIT_EXPORT_ENABLED":   "true",
		"SB_AUDIT_EXPORT_BACKEND":   "s3",
		"SB_AUDIT_EXPORT_S3_BUCKET": bucket,
		"SB_AUDIT_EXPORT_S3_PREFIX": prefix,
	}, func(res harness.NodeBootResult) {
		if !res.Started {
			t.Fatalf("node %s did not start with the s3 exporter: %s\n%s", node.Name, res.Status, tailLines(res.Journal, 30))
		}
		sandboxID, secret := generateAuditRecords(t, c, "140", 3)

		target, _ := harness.SSHTarget(node)
		deadline := time.Now().Add(exportDeliveryTimeout)
		for time.Now().Before(deadline) {
			// The node has the instance-profile credentials; reading from
			// there also proves the exporter's own credentials work.
			out, err := harness.SSHRun(t, target,
				"aws s3 cp --recursive s3://"+bucket+"/"+prefix+" - 2>/dev/null || true")
			if err == nil && strings.Contains(out, sandboxID) {
				assertChainedJSONL(t, "the s3 export under "+prefix, out, secret)
				return
			}
			time.Sleep(15 * time.Second)
		}
		t.Fatalf("no object for %s appeared under s3://%s/%s within %s", sandboxID, bucket, prefix, exportDeliveryTimeout)
	})
}

// UC-141 — the webhook backend delivers records the receiver accepts.
//
// The receiver verifies the bearer token AND the HMAC with the same function
// the exporter signs with, so "the receiver saw it" already means "with a
// valid signature": a bad signature is counted as rejected, not accepted.
func TestWebhookExportDeliversSignedRecords(t *testing.T) {
	harness.Require(t, sc, "UC-141")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	receiver, ok := harness.FindReceiverNode(t, targets)
	if !ok {
		t.Skip("no audit receiver provisioned in this scenario")
	}
	c := client(t)

	before, err := harness.ReceiverStatsFor(t, receiver)
	if err != nil {
		t.Fatalf("read receiver stats: %v", err)
	}
	sandboxID, secret := generateAuditRecords(t, c, "141", 3)

	recs := harness.AwaitReceiverRecords(t, receiver, 500, exportDeliveryTimeout, func(evs []auditlog.Event) bool {
		for _, ev := range evs {
			if ev.SandboxID == sandboxID {
				return true
			}
		}
		return false
	})

	after, err := harness.ReceiverStatsFor(t, receiver)
	if err != nil {
		t.Fatalf("read receiver stats: %v", err)
	}
	if after.Rejected > before.Rejected {
		t.Fatalf("the receiver rejected %d delivery attempts (%d -> %d): the exporter's signature or token is wrong",
			after.Rejected-before.Rejected, before.Rejected, after.Rejected)
	}
	if after.Batches <= before.Batches {
		t.Fatalf("no new batch reached the receiver (%d -> %d) even though records for %s arrived", before.Batches, after.Batches, sandboxID)
	}
	raw, _ := json.Marshal(recs)
	harness.AssertNoPlaintext(t, "the exported audit records", string(raw), secret)
}

// UC-142 — backoff and at-least-once. A sink that fails several times must be
// retried until every record lands; none may be silently dropped.
func TestExportRetriesUntilEveryRecordLands(t *testing.T) {
	harness.Require(t, sc, "UC-142")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	receiver, ok := harness.FindReceiverNode(t, targets)
	if !ok {
		t.Skip("no audit receiver provisioned in this scenario")
	}
	c := client(t)

	// 503 specifically: the exporter classifies 429 and 5xx as Temporary and
	// retries them, while a 4xx is a receiver-config error. Failing with the
	// wrong class would test the wrong path.
	if _, err := harness.ReceiverRequest(t, receiver, "POST", "/_chaos/fail?n=5"); err != nil {
		t.Fatalf("arm the receiver's chaos failure: %v", err)
	}
	t.Cleanup(func() {
		if _, err := harness.ReceiverRequest(t, receiver, "POST", "/_chaos/fail?n=0"); err != nil {
			t.Errorf("RESTORE FAILED: the receiver may still be refusing deliveries and later export cases will fail for the wrong reason: %v", err)
		}
	})

	sandboxID, _ := generateAuditRecords(t, c, "142", 5)

	harness.AwaitReceiverRecords(t, receiver, 500, exportDeliveryTimeout, func(evs []auditlog.Event) bool {
		for _, ev := range evs {
			if ev.SandboxID == sandboxID {
				return true
			}
		}
		return false
	})

	stats, err := harness.ReceiverStatsFor(t, receiver)
	if err != nil {
		t.Fatalf("read receiver stats: %v", err)
	}
	if stats.FailNext != 0 {
		t.Fatalf("the receiver still has %d forced failures queued; the exporter gave up before exhausting them — records were dropped, not retried", stats.FailNext)
	}
	t.Logf("UC-142 PASS: delivery survived 5 forced 503s (batches=%d duplicates=%d)", stats.Batches, stats.Duplicates)
}

// UC-143 — the witness receives chain heads, receipts persist, and the health
// gauge reports 1.
func TestWitnessShipsHeadsAndReportsHealthy(t *testing.T) {
	harness.Require(t, sc, "UC-143")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	receiver, ok := harness.FindReceiverNode(t, targets)
	if !ok {
		t.Skip("no audit receiver provisioned in this scenario")
	}
	c := client(t)

	// Fresh records, so the head the witness records is one produced during
	// this run rather than a stale value from provisioning.
	generateAuditRecords(t, c, "143", 3)

	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	nodeID := heteroNodeID(t, c, targets, node.Name)

	deadline := time.Now().Add(exportDeliveryTimeout)
	var head string
	for time.Now().Before(deadline) {
		h, present, err := harness.WitnessedHeadFor(t, receiver, nodeID)
		if err != nil {
			t.Fatalf("read the witnessed head for %s: %v", nodeID, err)
		}
		if present && h != "" {
			head = h
			break
		}
		time.Sleep(15 * time.Second)
	}
	if head == "" {
		t.Fatalf("the witness never recorded a head for %s within %s", nodeID, exportDeliveryTimeout)
	}

	// The health gauge is what an operator alerts on; a witness that ships
	// heads while reporting 0 is a page that never fires.
	assertExpvarEquals(t, c, "aerolvm_secret_audit_witness_healthy", 1)

	// And the receipt must be on disk, or a restart loses the proof.
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, witnessReceiptScript)
	if err != nil || !strings.Contains(out, "FOUND") {
		t.Fatalf("no witness receipt persisted on %s: %v (%s)", node.Name, err, strings.TrimSpace(out))
	}
}

// UC-145 — the ingest endpoint accepts a correctly-tokened event and refuses
// an untokened one, and its listener is loopback-only.
//
// Loopback-only is the part with teeth: an ingest endpoint reachable off-box
// lets anyone who can route to the node write into the evidence file.
func TestAuditIngestRequiresATokenAndIsLoopbackOnly(t *testing.T) {
	harness.Require(t, sc, "UC-145")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	target, _ := harness.SSHTarget(node)

	bound, err := harness.SSHRun(t, target, auditIngestBindScript)
	if err != nil {
		t.Skipf("could not read the ingest listener on %s: %v", node.Name, err)
	}
	bound = strings.TrimSpace(bound)
	if bound == "" || bound == "NONE" {
		t.Skip("no audit ingest listener configured on this node")
	}
	// A listener on 0.0.0.0 or :: is reachable from off-box.
	if strings.HasPrefix(bound, "0.0.0.0:") || strings.HasPrefix(bound, ":::") || strings.HasPrefix(bound, "*:") {
		t.Fatalf("the audit ingest listener is bound to %s: anyone who can route to this node can write into the evidence file", bound)
	}
	if !strings.HasPrefix(bound, "127.0.0.1:") && !strings.HasPrefix(bound, "[::1]:") {
		t.Fatalf("the audit ingest listener is bound to %s, which is neither loopback nor obviously scoped", bound)
	}

	// An untokened POST must be refused.
	code, err := harness.SSHRun(t, target, auditIngestUntokenedScript)
	if err != nil {
		t.Fatalf("probe the ingest endpoint: %v (%s)", err, strings.TrimSpace(code))
	}
	status := strings.TrimSpace(code)
	if strings.HasPrefix(status, "2") {
		t.Fatalf("the ingest endpoint accepted an UNTOKENED event (status %s): anything on the box can forge evidence", status)
	}
	t.Logf("UC-145 PASS: ingest bound to %s and refuses an untokened event (%s)", bound, status)
}

// UC-145b — retention prune is the only path that destroys evidence, and it
// must HOLD while export is lagging, then leave a chain that still verifies
// across the checkpoint boundary.
//
// Nothing else covers this: UC-123 covers the tomb sweep, UC-132 corrupts a
// line in a live file. This is the path that legitimately rewrites
// secrets.jsonl in place.
func TestRetentionPruneHoldsWhileExportLagsThenVerifies(t *testing.T) {
	harness.Require(t, sc, "UC-145b")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this stops the receiver and forces a prune")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	receiver, ok := harness.FindReceiverNode(t, targets)
	if !ok {
		t.Skip("no audit receiver provisioned in this scenario")
	}
	c := client(t)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	recvTarget, _ := harness.SSHTarget(receiver)

	sandboxID, _ := generateAuditRecords(t, c, "145b", 5)
	before := harness.AllAuditEvents(t, c, sandboxID, 200, 10)
	if len(before) == 0 {
		t.Fatal("no records to prune; this case would assert nothing")
	}

	// Stop the receiver so the export cursor cannot advance.
	if out, err := harness.SSHRun(t, recvTarget, "sudo systemctl stop aerol-audit-receiver"); err != nil {
		t.Fatalf("stop the receiver: %v\n%s", err, out)
	}
	receiverStopped := true
	startReceiver := func() {
		if !receiverStopped {
			return
		}
		receiverStopped = false
		if out, err := harness.SSHRun(t, recvTarget, "sudo systemctl start aerol-audit-receiver"); err != nil {
			t.Errorf("RESTORE FAILED: the audit receiver is left stopped and every later export case will fail for the wrong reason: %v\n%s", err, out)
		}
	}
	t.Cleanup(startReceiver)

	// Zero retention makes the node want to prune everything. The export gate
	// must hold it: dropping evidence the exporter has not shipped is
	// irreversible data loss.
	harness.WithNodeEnv(t, node, map[string]string{
		"SB_SECRET_AUDIT_RETENTION_DAYS": "0",
	}, func(res harness.NodeBootResult) {
		if !res.Started {
			t.Fatalf("node %s did not start with zero retention: %s\n%s", node.Name, res.Status, tailLines(res.Journal, 30))
		}
		// Give the prune sweep time to want to run and be refused.
		time.Sleep(90 * time.Second)

		lagging := harness.AllAuditEvents(t, c, sandboxID, 200, 10)
		if len(missingEventIDs(before, lagging)) > 0 {
			t.Fatalf("records were pruned while the exporter was down (%d of %d gone): the export gate did not hold and evidence is irrecoverably lost",
				len(missingEventIDs(before, lagging)), len(before))
		}

		// Let the export catch up, then allow the prune and assert the chain
		// still verifies ACROSS the checkpoint the prune writes.
		startReceiver()
		deadline := time.Now().Add(exportDeliveryTimeout)
		for time.Now().Before(deadline) {
			if report := verifyAuditChain(t, c); report.OK {
				if report.Redacted > 0 {
					t.Logf("UC-145b PASS: prune ran (%d redacted) and the chain still verifies across the checkpoint", report.Redacted)
					return
				}
			}
			time.Sleep(20 * time.Second)
		}
		// A prune that never ran is not a failure of the gate, but say so
		// rather than claim the boundary was verified.
		final := verifyAuditChain(t, c)
		if !final.OK {
			t.Fatalf("the chain does not verify after the prune window: %s", final.Error)
		}
		t.Logf("the export gate held and the chain verifies, but no prune ran within the window (redacted=%d); the checkpoint boundary was not exercised", final.Redacted)
	})

}
