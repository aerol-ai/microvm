//go:build integration

package suite

// Customer key custody on AWS KMS (plans/customer-key-custody.md). UC-310
// and UC-311 on cluster-3-mixed-wrapped-kms (Terraform key_custody =
// "wrapped"): built wrapped from the start, then the customer disables the
// key. UC-312 on cluster-3-mixed-kms-switch: the two-step switch from local
// to AWS KMS with a failover in the middle of it (eng D22).

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-310 — a cluster built with wrapped custody never wrote a plaintext
// server key: not in the key file, the env files, the cred bundle the seed
// made, or the copy of it every joiner downloaded from S3.
func TestKeyCustodyKMSWrappedFromTheStart(t *testing.T) {
	harness.Require(t, sc, "UC-310")
	targets := kcTargets(t)
	nodes := kcNodes(targets)
	sawBundle := false
	for _, n := range nodes {
		out := kcSSH(t, n, `if sudo test -e `+kcKeyFile+`; then echo KEYFILE; fi
if sudo sh -c "grep -l '^SB_CREDENTIAL_ENCRYPTION_KEY=' /etc/sandboxd/*.env"; then echo ENVKEY; fi
sudo sh -c "grep -h '^SB_CREDENTIAL_KEY_CUSTODY=' /etc/sandboxd/*.env" || true
sudo test -s `+kcWrapped+` && echo WRAPPED
# The seed's own bundle, and on a joiner the copy cluster-join.sh downloaded
# from the S3 bundle object.
if sudo test -s /tmp/aerolvm-cred-bundle.tar.gz; then echo "BUNDLE:$(sudo tar -tzf /tmp/aerolvm-cred-bundle.tar.gz | tr '\n' ' ')"; fi`)
		if strings.Contains(out, "KEYFILE") || strings.Contains(out, "ENVKEY") || !strings.Contains(out, "WRAPPED") || !strings.Contains(out, "SB_CREDENTIAL_KEY_CUSTODY=wrapped") {
			t.Fatalf("%s: plaintext server key present or custody not wrapped:\n%s", n.Name, out)
		}
		if i := strings.Index(out, "BUNDLE:"); i >= 0 {
			sawBundle = true
			files := strings.Fields(out[i+len("BUNDLE:"):])
			for _, f := range files {
				if strings.TrimPrefix(f, "./") == "credential_encryption.key" {
					t.Fatalf("%s: the cred bundle holds a plaintext key: %v", n.Name, files)
				}
			}
			if !strings.Contains(out[i:], "credential_encryption.key.wrapped") {
				t.Fatalf("%s: the cred bundle has no wrapped key: %v", n.Name, files)
			}
		}
		if s := kcSSH(t, n, "sudo /usr/local/bin/sandboxd key status --check"); !strings.Contains(s, "check: every server key unwraps and matches") {
			t.Fatalf("%s: `sandboxd key status --check` failed:\n%s", n.Name, s)
		}
	}
	if !sawBundle {
		t.Log("no cred bundle left in /tmp on any node; the bundle half of the check did not run")
	}
	kcAwaitMetric(t, nodes, "aerolvm_key_custody", map[string]string{"key": "server key", "key2": "customer key store (wrapped)"}, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })
	kcHAFailover(t, targets, "", "UC310_TOKEN", secretValue(t, "310"))
}

// UC-311 — the customer disables its AWS KMS key. Every node stops within
// the bound, the full stop of §10: an exec stream open across it closes,
// /health says revoked, each node writes key_revoked, the condition of the
// SandboxdKeyRevoked alert (aerolvm_key_revoked == 1) holds, and a create
// with secrets answers 503 key_revoked. Enabling the key brings every node
// back by itself, and a sandbox sealed before the revoke fails over.
func TestKeyCustodyKMSKeyDisabled(t *testing.T) {
	harness.Require(t, sc, "UC-311")
	targets := kcTargets(t)
	nodes := kcNodes(targets)
	kcEnsureFastRecheck(t, targets)
	keyID := kcKMSKeyID(t, nodes[0])
	c := client(t)
	secret := secretValue(t, "311")
	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{"UC311_TOKEN": secret}})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	var mu sync.Mutex
	var out strings.Builder
	stream, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{
		Command: `echo ready-311; read line`,
		OnStdout: func(b []byte) {
			mu.Lock()
			out.Write(b)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("exec stream: %v", err)
	}
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(100 * time.Millisecond) {
		mu.Lock()
		ready := strings.Contains(out.String(), "ready-311")
		mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the exec stream never printed ready-311")
		}
	}
	ended := make(chan struct{})
	go func() {
		_, _ = stream.Wait()
		close(ended)
	}()

	// KMS applies a disable within seconds to minutes (eventual consistency),
	// on top of the re-check bound.
	bound := kcRevokeBound + 2*time.Minute
	enabled := true
	t.Cleanup(func() {
		if !enabled {
			harness.SetKMSKeyEnabled(t, keyID, true)
			kcAwaitMetric(t, nodes, "aerolvm_key_revoked", nil, bound, func(v float64, ok bool) bool { return !ok || v == 0 })
		}
	})
	harness.SetKMSKeyEnabled(t, keyID, false)
	enabled = false
	kcAwaitMetric(t, nodes, "aerolvm_key_revoked", nil, bound, func(v float64, ok bool) bool { return ok && v == 1 })
	for _, n := range nodes {
		if h := kcNodeHealth(t, n); !strings.Contains(h, "revoked") {
			t.Fatalf("%s: /health does not report the revoke: %s", n.Name, h)
		}
		if evs, err := harness.NodeAuditEvents(t, n, "key_revoked"); err != nil || len(evs) == 0 {
			t.Fatalf("%s wrote no key_revoked audit record (err %v)", n.Name, err)
		}
	}
	select {
	case <-ended:
	case <-time.After(time.Minute):
		t.Fatal("an exec stream open across the revoke kept running")
	}
	cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer ccancel()
	status, body, err := c.PostStatus(cctx, "/v1/sandboxes", map[string]any{
		"image": harness.DefaultImage, "env": map[string]string{"UC311": "x"},
	})
	if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(string(body), "key_revoked") {
		t.Fatalf("create with env while the key is disabled = %d %s %v, want 503 key_revoked", status, body, err)
	}

	harness.SetKMSKeyEnabled(t, keyID, true)
	enabled = true
	kcAwaitMetric(t, nodes, "aerolvm_key_revoked", nil, bound, func(v float64, ok bool) bool { return ok && v == 0 })
	for _, n := range nodes {
		if evs, err := harness.NodeAuditEvents(t, n, "key_recovered"); err != nil || len(evs) == 0 {
			t.Fatalf("%s wrote no key_recovered audit record (err %v)", n.Name, err)
		}
	}
	kcHAFailover(t, targets, sb.ID, "UC311_TOKEN", secret)
}

// UC-312 — the two-step switch from local to AWS KMS (eng D22), with a
// failover in the middle of step 2: a sandbox sealed by a node that already
// seals with AWS KMS fails over to a node that still seals locally, which
// opens the untagged AWS KMS copy with the AWS settings step 1 gave it.
// Before #811 that node had no AWS client at all and the open failed.
func TestKeyCustodyKMSSwitchFailoverMidRoll(t *testing.T) {
	harness.Require(t, sc, "UC-312")
	targets := kcTargets(t)
	nodes := kcNodes(targets)
	if kcMarked(t, nodes[0], "kms-switched") {
		t.Skip("this cluster already switched to AWS KMS (an earlier run); the switch needs a fresh cluster")
	}
	c := client(t)
	// The scenario installs with AWS KMS sealing. Step 1's state is local
	// sealing with the AWS settings kept: set it on every node.
	for _, n := range nodes {
		kcSetEnv(t, n, map[string]string{"SB_SECRET_PROVIDER": "local"})
	}
	kcRollingRestart(t, targets)
	before := secretValue(t, "312")
	sbLocal := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{"UC312_BEFORE": before}})
	waitRunning(t, sbLocal)

	// Step 2 on one joiner only.
	var flipped harness.IntegrationNode
	for _, n := range nodes {
		if !n.Seed {
			flipped = n
			break
		}
	}
	if flipped.Name == "" {
		t.Skip("no joiner to switch first")
	}
	kcSetEnv(t, flipped, map[string]string{"SB_SECRET_PROVIDER": "awskms"})
	kcRestart(t, flipped)

	// A sandbox the switched node owns, so its copies are sealed with AWS
	// KMS while both other nodes still seal locally.
	secret := secretValue(t, "312b")
	var id string
	for attempt := 1; attempt <= 8 && id == ""; attempt++ {
		sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: map[string]string{"UC312_MID": secret}})
		waitRunning(t, sb)
		if n, ok := nodeForClusterID(t, c, targets, resolvePlacementOwner(t, c, sb.ID)); ok && n.Name == flipped.Name {
			id = sb.ID
			break
		}
		dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
		_ = sb.Destroy(dctx)
		dcancel()
	}
	if id == "" {
		t.Fatalf("no sandbox landed on %s in 8 creates; placement never chose the switched node", flipped.Name)
	}
	if v := harness.MetricValueOrZero(kcMetricsOf(t, flipped), "aerolvm_key_store_calls_total", map[string]string{"key": "awskms", "key2": "wrap", "key3": "ok"}); v == 0 {
		t.Fatalf("%s sealed no copy with AWS KMS", flipped.Name)
	}
	// kcHAFailover stops the owner, the switched node: every survivor
	// still seals locally.
	kcHAFailover(t, targets, id, "UC312_MID", secret)

	// The rest of step 2.
	for _, n := range nodes {
		if n.Name != flipped.Name {
			kcSetEnv(t, n, map[string]string{"SB_SECRET_PROVIDER": "awskms"})
			kcRestart(t, n)
		}
	}
	for _, n := range nodes {
		kcMark(t, n, "kms-switched")
	}
	kcAwaitMetric(t, nodes, "aerolvm_key_rows_stale", nil, 5*time.Minute, func(v float64, ok bool) bool { return ok && v == 0 })
	kcHAFailover(t, targets, sbLocal.ID, "UC312_BEFORE", before)
	kcHAFailover(t, targets, id, "UC312_MID", secret)
}
