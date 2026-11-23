package containerd

import (
	"context"
	"errors"
	"fmt"
	"io"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/runscwrap"
)

// gVisor checkpoint moves in privilege mode split (M1 PR 13). In single
// mode the driver runs runsc checkpoint itself, as root, and keeps both
// sides' checkpoints under its own run dir (gvisor_move.go). In split mode
// it can do neither: runsc's state is root's, and runsc reads a staged
// checkpoint as root, so it must sit where the agent cannot change it. The
// root helper does both in its own moves folder (internal/rootd moves.go);
// the driver names a sandbox by its ID and passes the bundle's bytes
// through, as single mode does with its own folder:
//
//   - a move's stop: CheckpointMove, after the same checks as single mode
//     (a running gVisor sandbox, not from the warm pool);
//   - the export and the import: ExportMove and ImportMove, in the move
//     bundle format both modes send, so a split node and a single node
//     move sandboxes to each other;
//   - the restore's create: StagedMove answers where the checkpoint is,
//     for the spec's RestoreAnnotation, and the helper's restore runsc
//     config names aerolvm-runsc (split_create.go, runscConfigFor);
//   - the drops: DropMove, where single mode removes its folders.
//
// The helper serves these only with SB_GVISOR_CHECKPOINT_MOVES on in its
// own settings; the daemon wires them only when sandboxd's is on too.

// MoveHelper is the root helper's gVisor move calls as the driver uses
// them (*rootclient.Client).
type MoveHelper interface {
	CheckpointMove(ctx context.Context, sandboxID string) error
	ExportMove(ctx context.Context, sandboxID string, w io.Writer) error
	ImportMove(ctx context.Context, sandboxID string, r io.Reader) (string, error)
	StagedMove(ctx context.Context, sandboxID string) (string, error)
	DropMove(ctx context.Context, sandboxID string, sides ...rootdpb.MoveSide) error
}

// SetMoveHelper has the driver take gVisor moves' checkpoints through the
// root helper: privilege mode split with SB_GVISOR_CHECKPOINT_MOVES on.
func (d *Driver) SetMoveHelper(m MoveHelper) {
	d.moves = m
}

// errSplitNoMoves: a split node whose driver has no move calls wired
// (SB_GVISOR_CHECKPOINT_MOVES off) asked to move a sandbox.
var errSplitNoMoves = errors.New("containerd: privilege mode split takes gVisor checkpoints through the root helper's move calls, " +
	"which this node does not use (SB_GVISOR_CHECKPOINT_MOVES)")

// moveHelper is the driver's move calls in split mode, or errSplitNoMoves.
func (d *Driver) moveHelper() (MoveHelper, error) {
	if d.moves == nil {
		return nil, errSplitNoMoves
	}
	return d.moves, nil
}

// errNotStaged: a restore's create with no checkpoint staged here.
func errNotStaged(sandboxID string) error {
	return fmt.Errorf("containerd runtime: no gVisor checkpoint is staged for %s", sandboxID)
}

// restoreSpec is a restore's spec option: RestoreAnnotation naming the
// checkpoint staged for sandboxID, under the driver's run dir in single
// mode, in the helper's moves folder in split.
func (d *Driver) restoreSpec(ctx context.Context, sandboxID string) (oci.SpecOpts, error) {
	if d.helper == nil {
		if !d.staged(sandboxID) {
			return nil, errNotStaged(sandboxID)
		}
		return d.restoreSpecOpt(sandboxID)
	}
	m, err := d.moveHelper()
	if err != nil {
		return nil, err
	}
	dir, err := m.StagedMove(ctx, sandboxID)
	if err != nil {
		return nil, fmt.Errorf("root helper: staged checkpoint of %s: %w", sandboxID, err)
	}
	if dir == "" {
		return nil, errNotStaged(sandboxID)
	}
	return oci.WithAnnotations(map[string]string{runscwrap.RestoreAnnotation: dir}), nil
}

// splitStaleCheckpoint drops, on a split start, the checkpoint the helper
// saved for a gVisor container before it ran here again. Only gVisor
// containers have one, and the record LoadContainer just read says which
// runtime runs it, with no trip through the gate.
func (d *Driver) splitStaleCheckpoint(ctx context.Context, c cntr.Container) {
	if d.moves == nil || c == nil {
		return
	}
	if info, err := c.Info(ctx, cntr.WithoutRefreshedMetadata); err == nil && info.Runtime.Name == runscShimName {
		d.splitDropMove(ctx, c.ID(), rootdpb.MoveSide_MOVE_SIDE_OUT)
	}
}

// splitDropMove has the helper drop a sandbox's checkpoints on sides, best
// effort: the helper's sweep takes what a failed drop leaves. A no-op with
// no move calls wired.
func (d *Driver) splitDropMove(ctx context.Context, sandboxID string, sides ...rootdpb.MoveSide) {
	if d.moves == nil || validateSandboxID(sandboxID) != nil {
		return
	}
	if err := d.moves.DropMove(ctx, sandboxID, sides...); err != nil && d.logger != nil {
		d.logger.Warn("containerd: the root helper did not drop a move's checkpoint; its sweep removes it later",
			"sandbox_id", sandboxID, "error", err)
	}
}
