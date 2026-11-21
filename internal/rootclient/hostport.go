package rootclient

import (
	"context"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// HostPort forwards raw-TCP host ports through the helper (M1 PR 5b,
// internal/rootd hostports.go): one port set or removed, or the node's set
// made exact. skipped is what a reconcile left out because its sandbox
// address is no longer leased.
func (c *Client) HostPort(ctx context.Context, req *rootdpb.HostPortRequest) (skipped []uint32, err error) {
	resp, err := call(ctx, c, rootdpb.FeatureHostPort, req, rootdpb.RootHelperClient.HostPort)
	return resp.GetSkipped(), err
}
