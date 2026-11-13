package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Snapshot moves, the worker's half (plans/kubernetes-v2-architecture.md
// §10.5; the leader's half and the order of steps are in
// internal/cluster/snapshot_move.go). A Firecracker sandbox moves with its
// memory: the source stops it, which writes its snapshot, and the target
// pulls a bundle, the sandbox's row and that snapshot, sealed with the
// cluster's key for this target and this incarnation. The row carries what
// the restored VM still holds: its toolbox token, so the target can adopt
// the guest it resumes.
//
// A gVisor sandbox moves the same way (C21) where SB_GVISOR_CHECKPOINT_MOVES
// is on: the source's stop saves it with runsc checkpoint first, and the
// target, which has no container to start, keeps the bundle's row in memory
// until the swap and then rebuilds the sandbox as a failover recreate does,
// from the placement, with the row's identity and the runtime restoring the
// checkpoint instead of booting (startCheckpointMoved).

// snapshotMover is a runtime that can carry a stopped sandbox's memory to
// another worker: the Firecracker driver, and the containerd driver for
// gVisor sandboxes.
type snapshotMover interface {
	ExportSandboxSnapshot(ctx context.Context, sandboxID string, w io.Writer) error
	ImportSandboxSnapshot(ctx context.Context, sandboxID string, r io.Reader) error
	DropImportedSnapshot(ctx context.Context, sandboxID string) error
}

const (
	moveBundleVersion = 1
	// statusReasonMovedIn is an imported row's reason until its start.
	statusReasonMovedIn = "moved"
	// moveInFenceTTL holds an imported row from the stale-ownership sweep:
	// the placement names the source until the swap, moments later.
	moveInFenceTTL = 30 * time.Minute
	// maxMoveRow bounds the row at the head of a bundle.
	maxMoveRow = 1 << 20
)

var (
	// ErrMoveNotForThisNode: a bundle asked for by a node the move does not
	// name, or for a sandbox no move released.
	ErrMoveNotForThisNode = errors.New("no snapshot move of this sandbox names this node")
	// ErrNotSnapshotMovable: a sandbox a snapshot move does not take.
	ErrNotSnapshotMovable = errors.New("only a Firecracker sandbox, or a gVisor one where checkpoint moves are on, without external-storage mounts moves with its memory")
)

// moveRow is the row a bundle carries: the API's view of the sandbox and
// the fields it does not show.
type moveRow struct {
	Version             int            `json:"version"`
	Sandbox             models.Sandbox `json:"sandbox"`
	ToolboxToken        string         `json:"toolbox_token"`
	CreateRequestDigest string         `json:"create_request_digest,omitempty"`
	AuditIncarnationID  string         `json:"audit_incarnation_id,omitempty"`
	TokensNotBefore     int64          `json:"tokens_not_before,omitempty"`
	OwnerRef            string         `json:"owner_ref,omitempty"`
}

// moveTargets is, per sandbox released for a snapshot move, the only node
// that may pull its bundle.
type moveTargets struct {
	mu     sync.Mutex
	target map[string]string
}

func (m *moveTargets) set(id, target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.target == nil {
		m.target = make(map[string]string)
	}
	m.target[id] = target
}

func (m *moveTargets) get(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.target[id]
}

func (m *moveTargets) clear(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.target, id)
}

// checkpointRows holds, per gVisor sandbox imported here, the row its
// bundle carried, until its start after the swap or a drop. It is not
// stored: until the swap this node does not own the sandbox, and a restart
// in between ends the move (the leader then sees the start fail).
type checkpointRows struct {
	mu   sync.Mutex
	rows map[string]moveRow
}

func (c *checkpointRows) put(id string, row moveRow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rows == nil {
		c.rows = make(map[string]moveRow)
	}
	c.rows[id] = row
}

func (c *checkpointRows) take(id string) (moveRow, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	row, ok := c.rows[id]
	delete(c.rows, id)
	return row, ok
}

// dropImportEverywhere drops id's import from every runtime that takes
// one, for an import that failed before its row named the runtime.
func (s *Service) dropImportEverywhere(id string) {
	for _, rt := range []any{s.firecracker, s.docker} {
		if m, ok := rt.(snapshotMover); ok {
			_ = m.DropImportedSnapshot(context.Background(), id)
		}
	}
}

// isCheckpointMovable reports whether sb is a gVisor sandbox this worker
// moves with its memory.
func (s *Service) isCheckpointMovable(sb *models.Sandbox) bool {
	return sb != nil && s.cfg.GvisorCheckpointMoves && sb.Runtime == models.RuntimeGvisor
}

// snapshotMoverFor is the runtime that moves sb with its memory.
func (s *Service) snapshotMoverFor(sb *models.Sandbox) (snapshotMover, error) {
	var rt any
	switch {
	case s.isFirecrackerSandbox(sb):
		if s.firecracker != nil {
			rt = s.firecracker
		}
	case s.isCheckpointMovable(sb):
		// The containerd driver; the Docker engine moves no gVisor
		// sandbox this way.
		if r, err := s.runtimeForSandbox(sb); err == nil {
			rt = r
		}
	}
	if m, ok := rt.(snapshotMover); ok {
		return m, nil
	}
	return nil, ErrNotSnapshotMovable
}

// ReleaseForSnapshotMove stops and fences id, as ReleaseForMove does, and
// names target as the only node that may pull its bundle.
func (s *Service) ReleaseForSnapshotMove(ctx context.Context, id, target string) string {
	id, target = strings.TrimSpace(id), strings.TrimSpace(target)
	sb, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return MoveGone
	}
	if err != nil {
		return "error: " + err.Error()
	}
	if _, err := s.snapshotMoverFor(sb); err != nil {
		return "error: " + err.Error()
	}
	// External-storage mounts are not re-attached on the target (as for C21).
	raw, err := s.store.GetMounts(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "error: " + err.Error()
	}
	if len(raw) > 0 && string(raw) != "null" && string(raw) != "[]" {
		return "error: " + ErrNotSnapshotMovable.Error()
	}
	if s.isCheckpointMovable(sb) {
		// Only a running gVisor sandbox has memory to save, unless an
		// earlier release saved it and still holds it.
		if sb.Status != models.SandboxStatusStarted && !s.moveFenced(id) {
			return "error: a stopped gVisor sandbox has no memory to move"
		}
		ctx = runtime.WithCheckpoint(ctx)
	}
	s.moveTargets.set(id, target)
	out := s.stopOne(ctx, id, true)
	if out != MoveReleased {
		s.moveTargets.clear(id)
	}
	return out
}

// ExportMove writes id's bundle, sealed for peer, to w. Only the target the
// release named may have it, and only while the sandbox is released here.
func (s *Service) ExportMove(ctx context.Context, id, peer string, w io.Writer) error {
	id = strings.TrimSpace(id)
	target := s.moveTargets.get(id)
	if target == "" || target != strings.TrimSpace(peer) || !s.moveFenced(id) {
		return ErrMoveNotForThisNode
	}
	defer s.moveTargets.clear(id)
	inc, err := s.ownedIncarnation(ctx, id)
	if err != nil {
		return err
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	sb, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if sb.Status != models.SandboxStatusStopped {
		return fmt.Errorf("export %s: %w", id, ErrNotSnapshotMovable)
	}
	mover, err := s.snapshotMoverFor(sb)
	if err != nil {
		return fmt.Errorf("export %s: %w", id, err)
	}
	sw, err := secrets.NewSealWriter(w, s.cipher, cluster.MoveBundleAAD(id, inc, target))
	if err != nil {
		return err
	}
	if err := writeMoveRow(sw, moveRow{
		Version: moveBundleVersion, Sandbox: *sb, ToolboxToken: sb.ToolboxToken,
		CreateRequestDigest: sb.CreateRequestDigest, AuditIncarnationID: sb.AuditIncarnationID,
		TokensNotBefore: sb.TokensNotBefore, OwnerRef: sb.OwnerRef,
	}); err != nil {
		return err
	}
	if err := mover.ExportSandboxSnapshot(ctx, id, sw); err != nil {
		return err
	}
	return sw.Close()
}

// ownedIncarnation is id's placement incarnation while this node owns it,
// read from the leader: a worker's own view lags a reassign, and the target
// asks just after one (StartMoved; p5-move-7 refused its own sandbox).
func (s *Service) ownedIncarnation(ctx context.Context, id string) (string, error) {
	c := s.Cluster()
	if c == nil {
		return "", errors.New("snapshot moves need cluster mode")
	}
	got, err := c.AuthoritativePlacementsByIDs(ctx, []string{id})
	if err != nil {
		return "", fmt.Errorf("%s: read its placement: %w", id, err)
	}
	p, ok := got[id]
	if !ok || strings.TrimSpace(p.OwnerNodeID) != c.SelfNodeID() {
		return "", fmt.Errorf("%s: this node does not own it", id)
	}
	return strings.TrimSpace(p.IncarnationID), nil
}

func writeMoveRow(w io.Writer, row moveRow) error {
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func readMoveRow(r io.Reader) (moveRow, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return moveRow{}, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > maxMoveRow {
		return moveRow{}, errors.New("bad row length")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(r, raw); err != nil {
		return moveRow{}, err
	}
	var row moveRow
	if err := json.Unmarshal(raw, &row); err != nil {
		return moveRow{}, err
	}
	return row, nil
}

// ImportMove pulls id's bundle from source and puts the sandbox in place
// here, stopped, held from the stale-ownership sweep until the placement
// names this node. Nothing stays behind when it fails.
func (s *Service) ImportMove(ctx context.Context, id, source string) (err error) {
	id, source = strings.TrimSpace(id), strings.TrimSpace(source)
	c := s.Cluster()
	if c == nil {
		return errors.New("snapshot moves need cluster mode")
	}
	p, ok := c.PlacementOf(id)
	if !ok || strings.TrimSpace(p.OwnerNodeID) != source {
		return fmt.Errorf("import %s: the placement does not name %s", id, source)
	}
	if _, gerr := s.store.Get(ctx, id); gerr == nil {
		if !s.movesIn.held(id, time.Now()) {
			return fmt.Errorf("import %s: this node already has it", id)
		}
		// What an earlier import left: start again.
		if derr := s.DropMove(ctx, id); derr != nil {
			return derr
		}
	}
	s.movesIn.set(id, time.Now().Add(moveInFenceTTL))
	placed := false
	var mover snapshotMover
	defer func() {
		if err != nil {
			if placed {
				_ = s.store.Delete(context.Background(), id)
			}
			if mover != nil {
				_ = mover.DropImportedSnapshot(context.Background(), id)
			} else {
				// Failed before the row named its runtime.
				s.dropImportEverywhere(id)
			}
			s.movesIn.clear(id)
		}
	}()

	pr, pw := io.Pipe()
	defer pr.Close()
	go func() { pw.CloseWithError(cluster.FetchMoveBundle(ctx, c, source, id, pw)) }()
	or, err := secrets.NewOpenReader(pr, s.cipher, cluster.MoveBundleAAD(id, strings.TrimSpace(p.IncarnationID), c.SelfNodeID()))
	if err != nil {
		return err
	}
	row, err := readMoveRow(or)
	if err != nil {
		return fmt.Errorf("import %s: row: %w", id, err)
	}
	if row.Version != moveBundleVersion || row.Sandbox.ID != id {
		return fmt.Errorf("import %s: the bundle is not this sandbox's", id)
	}
	if mover, err = s.snapshotMoverFor(&row.Sandbox); err != nil {
		return fmt.Errorf("import %s: %w", id, err)
	}
	if err := mover.ImportSandboxSnapshot(ctx, id, or); err != nil {
		return err
	}
	// The last chunk proves the stream whole.
	if _, err := io.Copy(io.Discard, or); err != nil {
		return fmt.Errorf("import %s: %w", id, err)
	}
	if s.isCheckpointMovable(&row.Sandbox) {
		// Rebuilt after the swap (startCheckpointMoved): no row until then.
		s.movedRows.put(id, row)
		s.prefetchMovedImage(mover, id, row.Sandbox.Image)
		return nil
	}
	sb := row.Sandbox
	sb.ToolboxToken = row.ToolboxToken
	sb.CreateRequestDigest = row.CreateRequestDigest
	sb.AuditIncarnationID = row.AuditIncarnationID
	sb.TokensNotBefore = row.TokensNotBefore
	sb.OwnerRef = row.OwnerRef
	sb.Status = models.SandboxStatusStopped
	sb.StatusReason = statusReasonMovedIn
	sb.ContainerID, sb.ContainerIP = "", ""
	sb.UpdatedAt = time.Now().UTC()
	if err := s.store.Create(ctx, &sb); err != nil {
		return fmt.Errorf("import %s: %w", id, err)
	}
	placed = true
	return nil
}

// DropMove undoes ImportMove: the move did not happen. A sandbox the
// placement already names this node's is kept.
func (s *Service) DropMove(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if c := s.Cluster(); c != nil {
		if p, ok := c.PlacementOf(id); ok && strings.TrimSpace(p.OwnerNodeID) == c.SelfNodeID() {
			return fmt.Errorf("drop %s: it moved here", id)
		}
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	s.movesIn.clear(id)
	if row, ok := s.movedRows.take(id); ok {
		mover, err := s.snapshotMoverFor(&row.Sandbox)
		if err != nil {
			return err
		}
		return mover.DropImportedSnapshot(ctx, id)
	}
	sb, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		// Nothing imported, or a failed import already dropped it.
		return nil
	}
	if err != nil {
		return err
	}
	mover, err := s.snapshotMoverFor(sb)
	if err != nil {
		return err
	}
	if err := s.store.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return mover.DropImportedSnapshot(ctx, id)
}

// StartMoved starts id, which moved here, from its memory.
func (s *Service) StartMoved(ctx context.Context, id string, rc *cluster.MoveRecreate) error {
	id = strings.TrimSpace(id)
	if _, err := s.ownedIncarnation(ctx, id); err != nil {
		return err
	}
	s.movesIn.clear(id)
	if row, ok := s.movedRows.take(id); ok {
		return s.startCheckpointMoved(ctx, id, row, rc)
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = s.startSandboxLocked(ctx, id, startForRestart)
	return err
}

// movedIdentityKey carries a moved gVisor sandbox's source row into its
// recreate here.
type movedIdentityKey struct{}

func contextWithMovedIdentity(ctx context.Context, row moveRow) context.Context {
	return context.WithValue(ctx, movedIdentityKey{}, &row)
}

// movedIdentityFrom is the source row of a sandbox this create rebuilds
// after a move with its memory, or nil.
func movedIdentityFrom(ctx context.Context) *moveRow {
	if ctx == nil {
		return nil
	}
	row, _ := ctx.Value(movedIdentityKey{}).(*moveRow)
	return row
}

// startCheckpointMoved rebuilds a gVisor sandbox that moved here, once the
// leader has confirmed the placement names this node (StartMoved): the
// failover recreate's path (lease, ownership check, secrets, ports) from
// rc, the leader's read of the placement, with the source row's identity
// and the runtime restoring the staged checkpoint. If the restore fails,
// the sandbox starts from its image instead, with the same identity, as it
// would have without C21.
func (s *Service) startCheckpointMoved(ctx context.Context, id string, row moveRow, rc *cluster.MoveRecreate) error {
	mover, err := s.snapshotMoverFor(&row.Sandbox)
	if err != nil {
		return err
	}
	if rc == nil {
		_ = mover.DropImportedSnapshot(context.Background(), id)
		return fmt.Errorf("start %s: the leader sent no spec to rebuild it from", id)
	}
	spec, secrets, ports := rc.Spec, rc.Secrets, rc.Ports
	ownerSince := rc.OwnerSinceUnixNano
	mctx := contextWithMovedIdentity(ctx, row)
	_, err = s.RecreateSandboxReport(runtime.WithRestore(mctx), id, spec, secrets, ports, ownerSince)
	if err == nil {
		return nil
	}
	_ = mover.DropImportedSnapshot(context.Background(), id)
	if _, gerr := s.store.Get(ctx, id); !errors.Is(gerr, store.ErrNotFound) {
		// It exists here: the rest of the recreate (its ports) failed,
		// not the restore.
		return err
	}
	s.logger.Warn("cluster: a moved gVisor sandbox did not restore; starting it from its image", "sandbox_id", id, "err", err)
	if _, cerr := s.RecreateSandboxReport(mctx, id, spec, secrets, ports, ownerSince); cerr != nil {
		return fmt.Errorf("start %s: restore: %v; from its image: %w", id, err, cerr)
	}
	return nil
}

// prefetchMovedImage starts pulling a moved sandbox's image here, so its
// rebuild after the swap finds it: the rebuild waits on the same pull, and
// the move's budget is not spent on it. Best effort: a private image needs
// the create's credentials, which the rebuild has.
func (s *Service) prefetchMovedImage(mover snapshotMover, id, image string) {
	p, ok := mover.(imagePreparer)
	if !ok || strings.TrimSpace(image) == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), checkpointPrefetchTimeout)
		defer cancel()
		if err := p.PrepareImage(ctx, image); err != nil && s.logger != nil {
			s.logger.Info("cluster: a moved sandbox's image was not pulled ahead; its rebuild pulls it", "sandbox_id", id, "err", err)
		}
	}()
}

// checkpointPrefetchTimeout bounds prefetchMovedImage's pull.
const checkpointPrefetchTimeout = 5 * time.Minute

// recordMovedIn is recordFailoverReason for a sandbox a move restored here.
func (s *Service) recordMovedIn(ctx context.Context, id string) {
	if err := s.store.SetStatusReason(ctx, id, statusReasonMovedIn, nil); err != nil && s.logger != nil {
		s.logger.Warn("cluster: record moved status reason failed", "sandbox_id", id, "err", err)
	}
	recordSandboxStart(startKindMoved)
	s.beginSystemActionReason(ctx, id, systemActionMoveRestored, statusReasonMovedIn)(nil)
}
