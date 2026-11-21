package rootclient

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// TestEgressCallsNeedTheirFeature: against a helper that does not list the
// hostname gateway's calls (one release back), each is refused here,
// before it is sent, with an UnsupportedError naming it: the agent's
// self-test then fails and per-binary flows are refused, never admitted.
func TestEgressCallsNeedTheirFeature(t *testing.T) {
	sock := sockPath(t)
	h := &countingHelper{features: []string{rootdpb.FeatureEnsureHost}}
	serveCounting(t, sock, h)
	c := newClient(t, sock)
	for _, ec := range []struct {
		feature string
		call    func(ctx context.Context) error
	}{
		{rootdpb.FeatureBridgeProbe, func(ctx context.Context) error {
			_, err := c.BridgeProbe(ctx, rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP, 0)
			return err
		}},
		{rootdpb.FeatureMatchProcess, func(ctx context.Context) error {
			_, _, err := c.MatchProcess(ctx, 100, "10.88.0.2:40000", "192.0.2.1:443", []string{"/usr/bin/curl"})
			return err
		}},
	} {
		err := ec.call(ctxT(t))
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Feature != ec.feature || !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s = %v, want an UnsupportedError naming it", ec.feature, err)
		}
	}
	if seen := h.seen(); len(seen) != 0 {
		t.Fatalf("calls the helper does not serve were sent: %v", seen)
	}
}
