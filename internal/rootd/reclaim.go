package rootd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// Platform volume reclaim on NFS (M1 PR 8). sandboxd's reclaim janitor
// deletes a deleted volume's files: in privilege mode single it mounts the
// volume's folder as root and empties it (pkg/volumes). In split mode the
// helper does that part, with the export and mount options of its own
// settings (SB_PLATFORM_VOLUMES_NFS_SERVER, _EXPORT, _OPTIONS), a scratch
// folder of its own, nosuid, nodev and noexec always, and an emptying that
// never crosses into another mount or follows a link
// (mounts.EmptyOnDevice). The agent sends the volume's stored source, and
// the helper refuses any that is not one volume's folder of that export
// (rootpolicy.CheckReclaimSource). An S3 reclaim needs no root: the agent
// still runs it.

// ReclaimConfig is the helper's own NFS platform volume backend; nil when
// the node's platform volumes are not on NFS.
type ReclaimConfig struct {
	Export rootpolicy.NFSExport
	// Options are the operator's NFS mount options, which the helper
	// checks against the NFS allow list at start; nosuid, nodev and noexec
	// end them.
	Options string
	// ScratchDir is where a volume's folder is mounted for the time it
	// takes to empty it: the helper's own, root's alone.
	ScratchDir string
}

// reclaimForced end every reclaim mount's options: nothing on the export
// runs, or acts as a device or a set-uid file, while root empties it.
const reclaimForced = "nosuid,nodev,noexec"

// reclaimRun runs mount and umount; tests replace it.
var reclaimRun volumes.Runner = volumes.ExecRunner

type reclaimCalls struct {
	cfg   ReclaimConfig
	r     *volumes.Reclaimer
	locks *keyedLocks
	log   *slog.Logger
}

func newReclaimCalls(cfg Config, locks *keyedLocks, log *slog.Logger) (*reclaimCalls, error) {
	rc := cfg.Reclaim
	if rc == nil {
		return nil, nil
	}
	if err := os.MkdirAll(rc.ScratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("root helper: volume reclaim folder: %w", err)
	}
	if err := os.Chmod(rc.ScratchDir, 0o700); err != nil {
		return nil, fmt.Errorf("root helper: volume reclaim folder: %w", err)
	}
	opts := reclaimForced
	if o := strings.Trim(strings.TrimSpace(rc.Options), ","); o != "" {
		opts = o + "," + reclaimForced
	}
	r := volumes.NewReclaimer(volumes.Backend{Kind: volumes.BackendNFS, NFSServer: rc.Export.Server,
		NFSExport: rc.Export.Export, NFSOptions: opts}, rc.ScratchDir, reclaimRun).WithEmpty(mounts.EmptyOnDevice)
	return &reclaimCalls{cfg: *rc, r: r, locks: locks, log: log}, nil
}

func (c *reclaimCalls) reclaim(ctx context.Context, req *rootdpb.ReclaimVolumeRequest) (*rootdpb.ReclaimVolumeResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	src := req.GetSource()
	if err := rootpolicy.CheckReclaimSource(c.cfg.Export, src); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	unlock, err := c.locks.lock(ctx, "reclaim/"+src)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := c.r.Reclaim(ctx, volumes.BackendNFS, src); err != nil {
		return nil, fmt.Errorf("root helper: %w", err)
	}
	c.log.Info("root helper: platform volume reclaimed", "source", src)
	return &rootdpb.ReclaimVolumeResponse{}, nil
}
