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

// snapshotMover is a runtime that can carry a stopped sandbox's snapshot to
// another worker (the Firecracker driver).
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
	ErrNotSnapshotMovable = errors.New("only a Firecracker sandbox without external-storage mounts moves by snapshot")
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

func (s *Service) snapshotMover() (snapshotMover, error) {
	if s.firecracker == nil {
		return nil, ErrNotSnapshotMovable
	}
	m, ok := s.firecracker.(snapshotMover)
	if !ok {
		return nil, ErrNotSnapshotMovable
	}
	return m, nil
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
	if !s.isFirecrackerSandbox(sb) {
		return "error: " + ErrNotSnapshotMovable.Error()
	}
	// External-storage mounts are not re-attached on the target (as for C21).
	raw, err := s.store.GetMounts(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "error: " + err.Error()
	}
	if len(raw) > 0 && string(raw) != "null" && string(raw) != "[]" {
		return "error: " + ErrNotSnapshotMovable.Error()
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
	if !s.isFirecrackerSandbox(sb) || sb.Status != models.SandboxStatusStopped {
		return fmt.Errorf("export %s: %w", id, ErrNotSnapshotMovable)
	}
	mover, err := s.snapshotMover()
	if err != nil {
		return err
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
	mover, err := s.snapshotMover()
	if err != nil {
		return err
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
	defer func() {
		if err != nil {
			if placed {
				_ = s.store.Delete(context.Background(), id)
			}
			_ = mover.DropImportedSnapshot(context.Background(), id)
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
	if row.Version != moveBundleVersion || row.Sandbox.ID != id || !s.isFirecrackerSandbox(&row.Sandbox) {
		return fmt.Errorf("import %s: the bundle is not this sandbox's", id)
	}
	if err := mover.ImportSandboxSnapshot(ctx, id, or); err != nil {
		return err
	}
	// The last chunk proves the stream whole.
	if _, err := io.Copy(io.Discard, or); err != nil {
		return fmt.Errorf("import %s: %w", id, err)
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
	mover, err := s.snapshotMover()
	if err != nil {
		return err
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.store.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	s.movesIn.clear(id)
	return mover.DropImportedSnapshot(ctx, id)
}

// StartMoved starts id, which moved here, from its memory.
func (s *Service) StartMoved(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if _, err := s.ownedIncarnation(ctx, id); err != nil {
		return err
	}
	s.movesIn.clear(id)
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = s.startSandboxLocked(ctx, id, startForRestart)
	return err
}
