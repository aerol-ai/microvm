//go:build integration

package suite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// refusedForNoHostFirewall handles a deployment with no host firewall (local
// mode). There a container sandbox asking for network policy must be refused
// (501 network_policy_unenforced) instead of accepted and left unfiltered.
// It asserts that refusal and reports true, so the caller ends the case: there
// is no enforcement to probe. On every other deployment it reports false.
func refusedForNoHostFirewall(t *testing.T, opts sdktypes.CreateSandboxOptions) bool {
	t.Helper()
	if !sc.Has(harness.CapNoHostFirewall) {
		return false
	}
	c := client(t)
	opts.Name = harness.UniqueName(sc, t)
	if opts.Image == "" {
		opts.Image = harness.DefaultImage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, opts)
	if err == nil {
		destroyBest(c, sb.ID)
		t.Fatalf("a node with no host firewall accepted network policy it cannot enforce (block_all=%v allow=%v deny=%v)",
			opts.NetworkBlockAll, opts.NetworkAllowOut, opts.NetworkDenyOut)
	}
	if msg := err.Error(); !strings.Contains(msg, "network_policy_unenforced") && !strings.Contains(msg, "501") {
		t.Fatalf("network policy refused on a node with no host firewall, but not as unenforced: %v", err)
	}
	t.Logf("no host firewall on this node: network policy refused, fail closed (%v)", err)
	return true
}
