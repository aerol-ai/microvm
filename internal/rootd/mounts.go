package rootd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// External storage mounts (M1 PR 8; plan §3.3, "Mounts"). In privilege mode
// single sandboxd runs pkg/mounts itself, as root: mount -t nfs, and
// mount-s3, sshfs and rclone with tenant-shaped options, as root. In split
// mode the helper runs the same Manager (so adoption across restarts, the
// supervisor's one restart and the sweep stay one piece of code), made
// with mounts.Config.Tools, and the agent sends specs:
//
//   - Every spec is checked here, with the rules the agent runs before it
//     sends (rootpolicy.CheckExternalMounts): the secrets rule, the spec
//     rules and the tool allow lists, and only the credentials a tool
//     reads. The agent checks first, so a refusal here means drift or a
//     broken agent, and is reported as one (eng review D9).
//   - The helper builds every mount point, <mounts folder>/<sandbox>/<index>,
//     and every tool argument; no request names a host path. Each folder on
//     the way is its own (mounts.ensureToolFolder): never a link, never
//     another user's. The containerd gate lets a container bind only its
//     own mount points (rootpolicy.CheckMountBind).
//   - NFS shares are mounted by root with nosuid,nodev last (the NFS
//     adapter). FUSE tools run as the helper's mount user, with no-new-privs,
//     no capabilities, an environment of their own and only the FUSE
//     descriptor the helper mounted; credentials reach them through a
//     memfd or a key file of their own (pkg/mounts tools.go).
//   - The helper runs in the namespace that builds sandboxes (the runtime
//     container, or the VM's own), so a mount it makes is where runc and
//     runsc bind it from: F13's cross-namespace check, and the shared
//     process namespace it needed, have nothing left to do.
//
// Tools start in the helpers' cgroup (aerolvm-mounts), never the helper's
// own, so a helper swap, which waits for the helper's whole cgroup to
// empty, never stops one; the next helper adopts them on the agent's next
// reconcile pass (MOUNT_EXTERNAL_MODE_REESTABLISH), by each tool's marker.

// MountManager is the mount work: *mounts.Manager outside tests.
type MountManager interface {
	MountAll(ctx context.Context, sandboxID string, specs []models.MountSpec) ([]mounts.ContainerBind, error)
	Reestablish(ctx context.Context, sandboxID string, specs []models.MountSpec) error
	KeepLive(ctx context.Context, sandboxID string, specs []models.MountSpec) (mounts.KeepReport, error)
	HostBindsFor(sandboxID string) []mounts.ContainerBind
	UnmountAll(sandboxID string) error
	Discard(sandboxID string) bool
	Sweep(keep map[string]struct{})
	Close()
}

// ReasonMountFolder: a folder a mount point sits in is not the helper's
// own (a link, or another user's), so nothing was mounted through it.
const ReasonMountFolder = "mount_folder"

// Mount calls running at once, and waiting for a turn. A mount waits for
// its tool up to SB_MOUNT_WAIT_TIMEOUT, so a turn can be long; past the
// queue a call is answered ResourceExhausted at once (503 at the API).
const (
	maxMountCalls   = 32
	maxMountWaiting = 512
)

// mountCalls serves the mount calls; nil when this helper serves none.
type mountCalls struct {
	mgr   MountManager
	locks *keyedLocks
	limit *callLimit
	log   *slog.Logger
}

var mountFeatures = []string{rootdpb.FeatureMountExternal, rootdpb.FeatureUnmountExternal, rootdpb.FeatureSweepExternalMounts}

// newMountCalls opens the helper's mount manager, from its own config.
// Without one (no mount user on this node) the helper serves no mount
// call, and the agent refuses mounts by name.
func newMountCalls(cfg Config, opts Options, locks *keyedLocks, log *slog.Logger) (*mountCalls, error) {
	mgr := opts.Mounts
	if mgr == nil {
		if cfg.Mounts == nil {
			return nil, nil
		}
		m := cfg.Mounts
		real, err := mounts.New(log, mounts.Config{
			RootDir:     m.Root,
			CredDir:     m.CredDir,
			WaitTimeout: m.WaitTimeout,
			CgroupRoot:  m.CgroupRoot,
			Tools:       &mounts.ToolUser{UID: m.UID, GID: m.GID, CacheDir: m.CacheDir},
		})
		if err != nil {
			return nil, fmt.Errorf("root helper: external mounts: %w", err)
		}
		mgr = real
	}
	return &mountCalls{mgr: mgr, locks: locks, log: log, limit: newCallLimit(maxMountCalls, maxMountWaiting)}, nil
}

func (c *mountCalls) close() {
	if c != nil {
		c.mgr.Close()
	}
}

// mountKey is a sandbox's mounts' lock key (D11).
func mountKey(id string) string { return "mounts/" + id }

func (c *mountCalls) mountExternal(ctx context.Context, req *rootdpb.MountExternalRequest) (*rootdpb.MountExternalResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	id := req.GetSandboxId()
	if err := rootpolicy.CheckMountSandboxID(id); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	mode := req.GetMode()
	if mode != rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE && mode != rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_REESTABLISH &&
		mode != rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_KEEP_LIVE {
		return nil, badRequest("root helper: mount mode %v is not one the helper does", mode)
	}
	specs := specsOf(req.GetMounts())
	if err := rootpolicy.CheckExternalMounts(specs, mode == rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_KEEP_LIVE); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	release, err := c.limit.enter(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	unlock, err := c.locks.lock(ctx, mountKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	start := time.Now()
	resp := &rootdpb.MountExternalResponse{}
	switch mode {
	case rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE:
		var binds []mounts.ContainerBind
		if binds, err = c.mgr.MountAll(ctx, id, specs); err == nil {
			resp.Binds = bindsOf(binds)
		}
	case rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_REESTABLISH:
		if err = c.mgr.Reestablish(ctx, id, specs); err == nil {
			resp.Binds = bindsOf(c.mgr.HostBindsFor(id))
		}
	default:
		var report mounts.KeepReport
		if report, err = c.mgr.KeepLive(ctx, id, specs); err == nil {
			resp.Kept, resp.Gone, resp.Already = indexes(report.Kept), indexes(report.Gone), report.Already
			resp.Binds = bindsOf(c.mgr.HostBindsFor(id))
		}
	}
	if err != nil {
		return nil, c.mountFailure(ctx, id, err)
	}
	c.log.Info("root helper: external mounts serve", "sandbox_id", id, "mode", mode.String(), "mounts", len(specs),
		"took_ms", time.Since(start).Milliseconds())
	return resp, nil
}

// mountFailure is a failed mount's answer. None is the helper's own
// failure: a tool that is not installed is the node's setup, a sandbox
// whose mounts already serve is the agent's to resolve, and anything else
// is the storage's answer (a bucket, a key, a server), which the tool's
// own output names. Each gets its own code, which the agent turns back
// into single mode's errors (pkg/mounts), so the API answers as before.
func (c *mountCalls) mountFailure(ctx context.Context, id string, err error) error {
	switch {
	case ctx.Err() != nil:
		return ctxError(ctx)
	case errors.Is(err, mounts.ErrMountsEstablished):
		return &fileError{code: codes.AlreadyExists, msg: err.Error()}
	case errors.Is(err, mounts.ErrMountToolUnavailable):
		return &fileError{code: codes.FailedPrecondition, msg: err.Error()}
	case errors.Is(err, mounts.ErrToolFolder):
		return &fileError{code: codes.PermissionDenied, reason: ReasonMountFolder, msg: err.Error()}
	}
	c.log.Warn("root helper: external mount failed", "sandbox_id", id, "error", err)
	return &fileError{code: codes.Unknown, msg: err.Error()}
}

func (c *mountCalls) unmountExternal(ctx context.Context, req *rootdpb.UnmountExternalRequest) (*rootdpb.UnmountExternalResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	id := req.GetSandboxId()
	if err := rootpolicy.CheckMountSandboxID(id); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	unlock, err := c.locks.lock(ctx, mountKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if req.GetDiscard() {
		return &rootdpb.UnmountExternalResponse{Had: c.mgr.Discard(id)}, nil
	}
	if err := c.mgr.UnmountAll(id); err != nil {
		return nil, fmt.Errorf("root helper: unmount sandbox %s: %w", id, err)
	}
	return &rootdpb.UnmountExternalResponse{}, nil
}

func (c *mountCalls) sweep(req *rootdpb.SweepExternalMountsRequest) (*rootdpb.SweepExternalMountsResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	keep := make(map[string]struct{}, len(req.GetKeep()))
	for _, id := range req.GetKeep() {
		if err := rootpolicy.CheckMountSandboxID(id); err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
		keep[id] = struct{}{}
	}
	c.mgr.Sweep(keep)
	return &rootdpb.SweepExternalMountsResponse{}, nil
}

// specsOf is the request's mounts as the Manager takes them.
func specsOf(in []*rootdpb.ExternalMount) []models.MountSpec {
	out := make([]models.MountSpec, 0, len(in))
	for _, m := range in {
		out = append(out, models.MountSpec{
			Type:        models.MountType(m.GetType()),
			Target:      m.GetTarget(),
			Source:      m.GetSource(),
			Options:     m.GetOptions(),
			Credentials: m.GetCredentials(),
			ReadOnly:    m.GetReadOnly(),
		})
	}
	return out
}

func bindsOf(in []mounts.ContainerBind) []*rootdpb.MountBind {
	out := make([]*rootdpb.MountBind, 0, len(in))
	for _, b := range in {
		out = append(out, &rootdpb.MountBind{HostPath: b.HostPath, Target: b.ContainerPath, ReadOnly: b.ReadOnly})
	}
	return out
}

func indexes(in []int) []uint32 {
	out := make([]uint32, 0, len(in))
	for _, i := range in {
		out = append(out, uint32(i))
	}
	slices.Sort(out)
	return out
}
