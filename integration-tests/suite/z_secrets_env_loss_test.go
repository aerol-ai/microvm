//go:build integration

package suite

// Group D, disruptive half — UC-130. Corrupts a sealed row on a real node.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-130 — a lost or corrupted sealed env fails LOUD, not empty.
//
// The failure this rules out is the quiet one: the sandbox comes up, its
// environment is empty, and the application fails somewhere far away with an
// error that names nothing about secrets. An explicit refusal is strictly
// better than a running sandbox that silently lost its credentials.
func TestCorruptedSealedEnvFailsLoud(t *testing.T) {
	harness.Require(t, sc, "UC-130")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this corrupts a sealed row on a real node")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	secret := secretValue(t, "130")

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC130_TOKEN": secret},
	})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	node, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		node, ok = harness.PickSSHNode(targets)
		if !ok {
			t.Skip("no SSH-reachable node holding the store")
		}
	}
	target, _ := harness.SSHTarget(node)

	// Corrupt the ciphertext in place. The AEAD must refuse it; it must not be
	// decrypted into an empty map.
	out, err := harness.SSHRun(t, target, corruptSealedEnvScript(sb.ID))
	if err != nil || strings.Contains(out, "NOROW") {
		t.Skipf("could not corrupt the sealed env row on %s (%v): %s", node.Name, err, strings.TrimSpace(out))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var withEnv struct {
		Env map[string]string `json:"env"`
	}
	readErr := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", &withEnv)
	if readErr == nil {
		if len(withEnv.Env) == 0 {
			t.Fatal("a corrupted sealed env decoded to an EMPTY environment with no error: the silent failure this case exists to catch")
		}
		if withEnv.Env["UC130_TOKEN"] != secret {
			t.Fatalf("a corrupted sealed env returned a DIFFERENT value (%q) instead of failing: the AEAD did not detect the tamper", withEnv.Env["UC130_TOKEN"])
		}
		t.Fatalf("the corruption did not take effect (the env still reads back correctly); this case asserted nothing")
	}
	// It failed, which is right. The error must say something about the
	// secret, not just 500.
	msg := readErr.Error()
	if !mentionsAny(msg, "decrypt", "secret", "seal", "env") {
		t.Fatalf("the read failed but the error names nothing an operator can act on: %q", msg)
	}
	t.Logf("UC-130 PASS: a corrupted sealed env failed loud: %v", readErr)
}

// mentionsAny reports whether s contains any needle, case-insensitively.
func mentionsAny(s string, needles ...string) bool {
	low := strings.ToLower(s)
	for _, n := range needles {
		if strings.Contains(low, n) {
			return true
		}
	}
	return false
}
