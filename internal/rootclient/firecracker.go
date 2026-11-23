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

// EnsureSnapshotTap is EnsureTap for a VM restored from a snapshot (M1 PR
// 14b): the TAP's neighbor entry gets the MAC the snapshot froze, which
// the helper works out from the snapshot's guest CID. An older helper,
// whose handshake does not list the snapshot calls, would refuse the
// field: it is not sent one (UnsupportedError).
func (c *Client) EnsureSnapshotTap(ctx context.Context, name string, guestCID uint32) (*rootdpb.EnsureTapResponse, error) {
	if err := c.Require(ctx, rootdpb.FeatureShareFirecrackerFiles); err != nil {
		return nil, err
	}
	return call(ctx, c, rootdpb.FeatureEnsureTap, &rootdpb.EnsureTapRequest{Name: name, GuestCid: guestCID}, rootdpb.RootHelperClient.EnsureTap)
}

// ShareFirecrackerFiles has the helper link files sandboxd put in a VM's
// stage folder into its chroot, read-only for the jailer's user: a
// snapshot's memory and state, a template's root disk. They stay sandboxd's.
func (c *Client) ShareFirecrackerFiles(ctx context.Context, id string, names ...string) error {
	_, err := call(ctx, c, rootdpb.FeatureShareFirecrackerFiles, &rootdpb.FirecrackerFilesRequest{Id: id, Names: names},
		rootdpb.RootHelperClient.ShareFirecrackerFiles)
	return err
}

// HandOutFirecrackerFiles has the helper let sandboxd's group read files in
// a VM's chroot (a snapshot's memory and state, the VM's disks), for
// sandboxd to copy out.
func (c *Client) HandOutFirecrackerFiles(ctx context.Context, id string, names ...string) error {
	_, err := call(ctx, c, rootdpb.FeatureHandOutFirecrackerFiles, &rootdpb.FirecrackerFilesRequest{Id: id, Names: names},
		rootdpb.RootHelperClient.HandOutFirecrackerFiles)
	return err
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
