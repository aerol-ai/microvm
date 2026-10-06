package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestFirstHost(t *testing.T) {
	if gw, ok := firstHost("10.88.0.0/16"); !ok || gw.String() != "10.88.0.1" {
		t.Fatalf("firstHost = %s %v", gw, ok)
	}
	for _, bad := range []string{"nope", "fd00::/8"} {
		if _, ok := firstHost(bad); ok {
			t.Fatalf("%s must not yield a gateway", bad)
		}
	}
}

// TestWireEgressGatewaySkips: off, privileged or non-worker nodes never wire
// the gateway client (nil service is never touched on those paths).
func TestWireEgressGatewaySkips(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, cfg := range []config.Config{
		{EgressFQDNEnabled: false},
		{EgressFQDNEnabled: true, ContainerPrivileged: true},
	} {
		wireEgressGateway(context.Background(), cfg, nil, nil, log)
	}
}
