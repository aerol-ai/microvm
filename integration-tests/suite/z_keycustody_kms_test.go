//go:build integration

package suite

// Customer key custody on AWS KMS, built wrapped from the start
// (plans/customer-key-custody.md §3, Phase 6), UC-310, on
// cluster-3-mixed-wrapped-kms (Terraform key_custody = "wrapped").

import (
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
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
if sudo grep -l '^SB_CREDENTIAL_ENCRYPTION_KEY=' /etc/sandboxd/*.env 2>/dev/null; then echo ENVKEY; fi
sudo grep -h '^SB_CREDENTIAL_KEY_CUSTODY=' /etc/sandboxd/*.env 2>/dev/null || true
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
