//go:build integration

package suite

// Customer key custody on a single node (plans/customer-key-custody.md §3),
// UC-315, on single-node-wrapped-kms: Terraform key_custody = "wrapped"
// reaches install.sh --key-custody wrapped on the one node.

import (
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-315 — a single node installed with wrapped custody never writes a
// plaintext server key, and after a restart opens its sealed values through
// AWS KMS: a sandbox from before the restart still answers (its toolbox
// token is sealed), and a new one reads its secret.
func TestKeyCustodySingleNodeWrapped(t *testing.T) {
	harness.Require(t, sc, "UC-315")
	targets := kcTargets(t)
	node := kcSeed(t, targets)
	out := kcSSH(t, node, `if sudo test -e `+kcKeyFile+`; then echo KEYFILE; fi
if sudo sh -c "grep -l '^SB_CREDENTIAL_ENCRYPTION_KEY=' /etc/sandboxd/*.env"; then echo ENVKEY; fi
sudo sh -c "grep -h '^SB_CREDENTIAL_KEY_CUSTODY=' /etc/sandboxd/*.env" || true
sudo test -s `+kcWrapped+` && echo WRAPPED
if sudo test -s /tmp/aerolvm-cred-bundle.tar.gz; then echo "BUNDLE:$(sudo tar -tzf /tmp/aerolvm-cred-bundle.tar.gz | tr '\n' ' ')"; fi`)
	if strings.Contains(out, "KEYFILE") || strings.Contains(out, "ENVKEY") || !strings.Contains(out, "WRAPPED") || !strings.Contains(out, "SB_CREDENTIAL_KEY_CUSTODY=wrapped") {
		t.Fatalf("%s: a plaintext server key, or custody not wrapped:\n%s", node.Name, out)
	}
	if i := strings.Index(out, "BUNDLE:"); i >= 0 {
		for _, f := range strings.Fields(out[i+len("BUNDLE:"):]) {
			if strings.TrimPrefix(f, "./") == "credential_encryption.key" {
				t.Fatalf("%s: the cred bundle holds a plaintext key", node.Name)
			}
		}
	}
	if s := kcSSH(t, node, "sudo /usr/local/bin/sandboxd key status --check"); !strings.Contains(s, "check: every server key unwraps and matches") {
		t.Fatalf("%s: `sandboxd key status --check` failed:\n%s", node.Name, s)
	}
	kcAwaitMetric(t, []harness.IntegrationNode{node}, "aerolvm_key_custody", map[string]string{"key": "server key", "key2": "customer key store (wrapped)"}, time.Minute, func(v float64, ok bool) bool { return ok && v == 1 })

	c := client(t)
	secret := secretValue(t, "315")
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC315_TOKEN": secret}})
	if got := execEnvValue(t, c, sb.ID, "UC315_TOKEN", 3*time.Minute); got != secret {
		t.Fatalf("before the restart the sandbox reads %q", got)
	}
	kcRestart(t, node)
	if got := execEnvValue(t, c, sb.ID, "UC315_TOKEN", 4*time.Minute); got != secret {
		t.Fatalf("after the restart the sandbox reads %q", got)
	}
	after := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Env: map[string]string{"UC315_AFTER": "back"}})
	if got := execEnvValue(t, c, after.ID, "UC315_AFTER", 3*time.Minute); got != "back" {
		t.Fatalf("a sandbox made after the restart reads %q", got)
	}
}
