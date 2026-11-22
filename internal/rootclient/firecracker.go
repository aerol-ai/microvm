package rootclient

import (
	"context"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// The Firecracker calls (M1 PR 9b): in privilege mode split the helper
// runs a VM through the jailer (a host of kind FIRECRACKER, hosts.go),
// makes its TAP and its filesystems.

// PrepareFirecracker has the helper make a VM's jail and move the disks
// sandboxd built in its stage folder (stage: "rootfs.ext4",
// "overlay.ext4") into the chroot. It answers the chroot and the stage
// folder.
func (c *Client) PrepareFirecracker(ctx context.Context, id string, stage ...string) (root, stageDir string, err error) {
	kind := rootdpb.HostKind_HOST_KIND_FIRECRACKER
	if err := c.requireHost(ctx, rootdpb.FeaturePrepareHost, kind); err != nil {
		return "", "", err
	}
	req := &rootdpb.PrepareHostRequest{Kind: kind, Id: id, Firecracker: &rootdpb.FirecrackerHostSpec{Stage: stage}}
	resp, err := call(ctx, c, rootdpb.FeaturePrepareHost, req, rootdpb.RootHelperClient.PrepareHost)
	return resp.GetRunDir(), resp.GetStageDir(), err
}

// EnsureTap has the helper make sure one of the TAP pool's devices is up,
// and answers the slot it worked out from the name.
func (c *Client) EnsureTap(ctx context.Context, name string) (*rootdpb.EnsureTapResponse, error) {
	if err := c.Require(ctx, rootdpb.FeatureEnsureTap); err != nil {
		return nil, err
	}
	return call(ctx, c, rootdpb.FeatureEnsureTap, &rootdpb.EnsureTapRequest{Name: name}, rootdpb.RootHelperClient.EnsureTap)
}

// RemoveTap has the helper make sure one of the pool's TAPs is gone.
func (c *Client) RemoveTap(ctx context.Context, name string) error {
	if err := c.Require(ctx, rootdpb.FeatureRemoveTap); err != nil {
		return err
	}
	_, err := call(ctx, c, rootdpb.FeatureRemoveTap, &rootdpb.RemoveTapRequest{Name: name}, rootdpb.RootHelperClient.RemoveTap)
	return err
}

// MakeFilesystem has the helper make an ext4 filesystem in a VM's disk file
// name in its stage folder: from the folder source with sizeMiB, or, with
// no source, empty in the file sandboxd made.
func (c *Client) MakeFilesystem(ctx context.Context, id, name, source string, sizeMiB uint64) error {
	if err := c.Require(ctx, rootdpb.FeatureMakeFilesystem); err != nil {
		return err
	}
	req := &rootdpb.MakeFilesystemRequest{Id: id, Name: name, Source: source, SizeMib: sizeMiB}
	_, err := call(ctx, c, rootdpb.FeatureMakeFilesystem, req, rootdpb.RootHelperClient.MakeFilesystem)
	return err
}
