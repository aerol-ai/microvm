//go:build integration

package suite

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-77 — A domain-mode deployment publishes its ingress target: the hostname
// and/or IP set that custom-domain DNS records must point at. Source classifies
// the shape so callers know whether to render a CNAME or A/AAAA hint, and a
// non-unknown source must carry a matching address.
func TestDNSIngressTarget(t *testing.T) {
	harness.Require(t, sc, "UC-77")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target, err := c.SDK().DNSTarget(ctx)
	if err != nil {
		t.Fatalf("dns target: %v", err)
	}

	switch target.Source {
	case sdktypes.IngressTargetSourceHostname:
		if target.Hostname == "" {
			t.Fatalf("source=hostname but Hostname is empty: %+v", target)
		}
	case sdktypes.IngressTargetSourceIPs:
		if len(target.IPs) == 0 {
			t.Fatalf("source=ips but IPs is empty: %+v", target)
		}
	case sdktypes.IngressTargetSourceMixed:
		if target.Hostname == "" && len(target.IPs) == 0 {
			t.Fatalf("source=mixed but neither Hostname nor IPs set: %+v", target)
		}
	case sdktypes.IngressTargetSourceUnknown:
		// Acceptable: a deployment can legitimately not yet know its target.
	default:
		t.Fatalf("unexpected ingress target source %q", target.Source)
	}
}
