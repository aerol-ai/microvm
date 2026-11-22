package rootd

import (
	"context"
	"errors"
	"fmt"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The container's parts that read its root filesystem snapshot (M1 PR 7):
// image_user (imageuser.go) and disk_quota (quota.go). The agent names a
// container; its snapshot has the container's own key. The helper asks
// containerd for it itself, in its own namespace and under its own
// snapshotter, so a key from another namespace or snapshotter is simply
// not there; and it takes every host path from containerd's answer, never
// the agent's.

// SnapshotInfo is what the helper reads of a snapshot: its kind and its
// parent's name.
type SnapshotInfo struct {
	// Kind is "active", "view" or "committed".
	Kind string
	// Parent is the committed snapshot below it: for a container's
	// snapshot, the image's top layer, named by its chain ID.
	Parent string
}

// SnapshotReader reads the snapshots of the helper's namespace and
// snapshotter (Options.Snapshots). A snapshot that is not there answers an
// error for which errSnapshotGone holds.
type SnapshotReader interface {
	Stat(ctx context.Context, key string) (SnapshotInfo, error)
	Mounts(ctx context.Context, key string) ([]rootpolicy.Mount, error)
}

// errSnapshotGone matches a snapshot containerd does not have.
var errSnapshotGone = errors.New("no such snapshot")

// ContainerdSnapshots is containerd's snapshot service, over conn (the
// helper's own connection to containerd), in namespace, under snapshotter.
func ContainerdSnapshots(conn grpc.ClientConnInterface, namespace, snapshotter string) SnapshotReader {
	return containerdSnapshots{c: snapshotsapi.NewSnapshotsClient(conn), ns: namespace, snapshotter: snapshotter}
}

type containerdSnapshots struct {
	c           snapshotsapi.SnapshotsClient
	ns          string
	snapshotter string
}

func (s containerdSnapshots) Stat(ctx context.Context, key string) (SnapshotInfo, error) {
	resp, err := s.c.Stat(namespaces.WithNamespace(ctx, s.ns), &snapshotsapi.StatSnapshotRequest{Snapshotter: s.snapshotter, Key: key})
	if err != nil {
		return SnapshotInfo{}, snapshotErr(err)
	}
	kind := "committed"
	switch resp.GetInfo().GetKind() {
	case snapshotsapi.Kind_ACTIVE:
		kind = "active"
	case snapshotsapi.Kind_VIEW:
		kind = "view"
	case snapshotsapi.Kind_UNKNOWN:
		kind = "unknown"
	}
	return SnapshotInfo{Kind: kind, Parent: resp.GetInfo().GetParent()}, nil
}

func (s containerdSnapshots) Mounts(ctx context.Context, key string) ([]rootpolicy.Mount, error) {
	resp, err := s.c.Mounts(namespaces.WithNamespace(ctx, s.ns), &snapshotsapi.MountsRequest{Snapshotter: s.snapshotter, Key: key})
	if err != nil {
		return nil, snapshotErr(err)
	}
	var out []rootpolicy.Mount
	for _, m := range resp.GetMounts() {
		out = append(out, rootpolicy.Mount{Type: m.GetType(), Source: m.GetSource(), Target: m.GetTarget(), Options: m.GetOptions()})
	}
	return out, nil
}

// snapshotErr marks containerd's NotFound as errSnapshotGone.
func snapshotErr(err error) error {
	if status.Code(err) == codes.NotFound {
		return fmt.Errorf("%w: %w", errSnapshotGone, err)
	}
	return err
}

// activeSnapshot reads container id's snapshot: it must be an active one
// of the helper's namespace and snapshotter, the root filesystem a create
// has just prepared. The agent's own create always prepares it first, so
// one that is not there, or is an image's layer or a view, is refused.
func (c *containerCalls) activeSnapshot(ctx context.Context, id string) ([]rootpolicy.Mount, SnapshotInfo, error) {
	info, err := c.snaps.Stat(ctx, id)
	switch {
	case errors.Is(err, errSnapshotGone):
		return nil, info, &fileError{code: codes.NotFound, reason: string(rootpolicy.RuleSnapshot),
			msg: fmt.Sprintf("root helper: no snapshot %q in namespace %s under snapshotter %s", id, c.policy.Namespace, c.policy.Snapshotter)}
	case err != nil:
		return nil, info, fmt.Errorf("root helper: snapshot %s: %w", id, err)
	case info.Kind != "active":
		return nil, info, &fileError{code: codes.InvalidArgument, reason: string(rootpolicy.RuleSnapshot),
			msg: fmt.Sprintf("root helper: snapshot %q is %s, not a container's active root filesystem", id, info.Kind)}
	}
	ms, err := c.snaps.Mounts(ctx, id)
	if err != nil {
		return nil, info, fmt.Errorf("root helper: snapshot %s mounts: %w", id, err)
	}
	return ms, info, nil
}
