package rootclient

import (
	"context"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// The hostname egress gateway's host side (M1 PR 5b, internal/rootd
// egress.go).

// BridgeProbe runs one step of the gateway self-test's probe network on
// the helper's own bridge, in probe slot slot.
func (c *Client) BridgeProbe(ctx context.Context, op rootdpb.BridgeProbeOp, slot uint32) (*rootdpb.BridgeProbeResponse, error) {
	return call(ctx, c, rootdpb.FeatureBridgeProbe, &rootdpb.BridgeProbeRequest{Op: op, Slot: slot}, rootdpb.RootHelperClient.BridgeProbe)
}

// MatchProcess asks which of paths the process pid's sandbox holds the
// connection local→remote with (ip:port each); notFound when no process
// does.
func (c *Client) MatchProcess(ctx context.Context, pid uint32, local, remote string, paths []string) (matched []string, notFound bool, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureMatchProcess,
		&rootdpb.MatchProcessRequest{Pid: pid, Local: local, Remote: remote, Paths: paths}, rootdpb.RootHelperClient.MatchProcess)
	return resp.GetMatched(), resp.GetNotFound(), err
}
