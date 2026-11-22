package rootclient

import (
	"context"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// MarkSandboxCgroup has the helper make a started container's group the
// kernel's whole out-of-memory choice (M1 PR 6; F10): memory.oom.group 1,
// and OOM score 500 on every process in it. It is PrepareSandbox with the
// cgroup part alone, sent once the container's task has started; a helper
// that does not list the part fails it here, before it is sent
// (UnsupportedError), so a sandbox never starts unmarked without a word.
// The containerd driver calls it where single mode writes the two settings
// itself (cntr.CgroupMarker).
func (c *Client) MarkSandboxCgroup(ctx context.Context, containerID string) error {
	_, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartCgroup},
		Cgroup: &rootdpb.SandboxCgroup{ContainerId: containerID}})
	return err
}
