//go:build integration

package suite

// Phase 4 egress use cases (plans/egress-domain-filtering.md): a
// Firecracker guest gets a hostname allowlist through the egress gateway,
// reached over its own TAP device, and the policy changes while it runs.

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-204 (Phase 4) — a Firecracker guest with a hostname allowlist: the
// listed name is fetchable over HTTPS, another is refused fast, and a live
// switch to block-all shuts it.
func TestEgressFirecrackerHostnames(t *testing.T) {
	harness.Require(t, sc, "UC-204")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		Runtime:         "firecracker",
		NetworkAllowOut: []string{"pypi.org"},
	})
	waitRunning(t, sb)

	if rc, _ := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://pypi.org/simple/requests/"); rc != 0 {
		t.Fatalf("an allowed name must be fetchable from the guest (rc=%d)", rc)
	}
	if rc, secs := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://example.com/"); rc == 0 || secs >= 10 {
		t.Fatalf("a name outside the list must be refused fast (rc=%d after %ds)", rc, secs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	got, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EgressStatus != "active" {
		t.Fatalf("egress_status = %q, want active", got.EgressStatus)
	}
	setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkBlockAll: true})
	if fetches(t, sb, "https://pypi.org/simple/requests/") {
		t.Fatal("block-all must shut the guest")
	}
}
