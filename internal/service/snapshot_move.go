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
// target, which has no container to start, stores the bundle's row (sealed,
// in moved_in_rows) until the swap and then rebuilds the sandbox as a
// failover recreate does, from the placement, with the row's identity and
// the runtime restoring the checkpoint instead of booting
// (startCheckpointMoved).
//
// What the target took in is durable from the moment it acknowledges the
// import (review N4): a Firecracker sandbox's stopped row, or a gVisor
// sandbox's stored row with the leader's recreate inputs. The import also
// arms a move-in check on this agent (checkMovedIn), and an agent restart
// arms it again at boot (resumeMovedIn): it starts the sandbox once the
// placement names this node, or drops the import once the move's time is
// up, so a leader that dies after the swap, or whose drop fails, leaves
// nothing stopped or staged for good. Before, the gVisor row lived only in
// memory, and a restart between the import and the start lost the sandbox
// while the leader still counted it as moved.

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
	// maxMoveRow bounds the row at the head of a bundle.
	maxMoveRow = 1 << 20
)

// defaultMoveInFenceTTL holds an imported row from the stale-ownership
// sweep: the placement names the source until the swap, moments later.
// Past it, the move-in check (checkMovedIn) drops an import whose move
// never happened. A Service's own is moveTimings.inFence.
const defaultMoveInFenceTTL = 30 * time.Minute

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

// take claims id's bundle for peer: true, and the target gone, only when
// peer is the target the release named. One lock for the check and the
// claim, so two pulls never both pass.
func (m *moveTargets) take(id, peer string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.target[id]; t == "" || t != peer {
		return false
	}
	delete(m.target, id)
	return true
}

// movedInRecord is what a gVisor checkpoint move's target stores from its
// import until the start after the swap: the row the bundle carried and the
// leader's recreate inputs (nil from a leader from before them), so a
// restarted agent can rebuild the sandbox itself (resumeMovedIn).
type movedInRecord struct {
	Row      moveRow               `json:"row"`
	Recreate *cluster.MoveRecreate `json:"recreate,omitempty"`
}

// movedInAAD binds a stored record to its sandbox.
func movedInAAD(id string) []byte { return []byte("aerolvm-moved-in-v1|" + id) }

// putMovedIn stores id's record, sealed: the row holds the toolbox token.
func (s *Service) putMovedIn(ctx context.Context, id string, rec movedInRecord) error {
	if s.cipher == nil {
		return errors.New("no cluster key to seal the moved row with")
	}
	raw, err := json.Marshal(rec)
	var sealed []byte
	if err == nil {
		sealed, err = s.cipher.EncryptWithAAD(raw, movedInAAD(id))
	}
	if err == nil {
		err = s.store.PutMovedInRow(ctx, id, sealed, time.Now())
	}
	return err
}

// loadMovedIn is id's stored record. ok is false when there is none; a
// record that does not open is an error.
func (s *Service) loadMovedIn(ctx context.Context, id string) (rec movedInRecord, importedAt time.Time, ok bool, err error) {
	stored, err := s.store.GetMovedInRow(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return movedInRecord{}, time.Time{}, false, nil
	}
	if err != nil {
		return movedInRecord{}, time.Time{}, false, err
	}
	if s.cipher == nil {
		return movedInRecord{}, stored.ImportedAt, true, errors.New("no cluster key to open the moved row with")
	}
	raw, err := s.cipher.DecryptWithAAD(stored.Sealed, movedInAAD(id))
	if err == nil {
		err = json.Unmarshal(raw, &rec)
	}
	if err != nil {
		return movedInRecord{}, stored.ImportedAt, true, fmt.Errorf("moved row of %s: %w", id, err)
	}
	return rec, stored.ImportedAt, true, nil
}

// awaitingMovedStart reports whether sb is a Firecracker row a move
// imported here that has not started yet: stopped as moved in, or in error
// after a start that failed (it keeps the reason).
func awaitingMovedStart(sb *models.Sandbox) bool {
	return sb != nil && sb.StatusReason == statusReasonMovedIn &&
		(sb.Status == models.SandboxStatusStopped || sb.Status == models.SandboxStatusError)
}

// movedInHeld reports whether sb, a row a snapshot move imported here, is
// held from the stale-ownership sweep: the placement names its source until
// the swap. This process's hold, or for a process that restarted since,
// the row's own (stopped, moved in, within the move's time).
func (s *Service) movedInHeld(sb *models.Sandbox, now time.Time) bool {
	if s.movesIn.held(sb.ID, now) {
		return true
	}
	return awaitingMovedStart(sb) &&
		now.Before(sb.UpdatedAt.Add(s.moveTimings.inFence()))
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
// names target as the only node that may pull its bundle. lifetime is the
// incarnation the leader chose to move, as for ReleaseForMove (R10).
func (s *Service) ReleaseForSnapshotMove(ctx context.Context, id, target, lifetime string) string {
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
	out := s.stopOne(ctx, id, lifetime, true)
	if out != MoveReleased {
		s.moveTargets.clear(id)
	}
	return out
}

// ExportMove writes id's bundle, sealed for peer, to w. Only the target the
// release named may have it, and only while the sandbox is released here.
func (s *Service) ExportMove(ctx context.Context, id, peer string, w io.Writer) error {
	id = strings.TrimSpace(id)
	target := strings.TrimSpace(peer)
	// A bundle goes out once, so the target is claimed here, before a byte
	// is written. Cleared at the end instead, the importer could finish
	// reading before the export returned, and a second pull right after it
	// still found the target and got the bundle again.
	if !s.moveFenced(id) || !s.moveTargets.take(id, target) {
		return ErrMoveNotForThisNode
	}
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
// names this node, durably before it answers: a gVisor sandbox's row is
// stored with rc, the leader's recreate inputs (N4). Nothing stays behind
// when it fails.
func (s *Service) ImportMove(ctx context.Context, id, source string, rc *cluster.MoveRecreate) (err error) {
	id, source = strings.TrimSpace(id), strings.TrimSpace(source)
	c := s.Cluster()
	if c == nil {
		return errors.New("snapshot moves need cluster mode")
	}
	p, ok := c.PlacementOf(id)
	if !ok || strings.TrimSpace(p.OwnerNodeID) != source {
		return fmt.Errorf("import %s: the placement does not name %s", id, source)
	}
	if sb, gerr := s.store.Get(ctx, id); gerr == nil {
		if !s.movedInHeld(sb, time.Now()) {
			return fmt.Errorf("import %s: this node already has it", id)
		}
		// What an earlier import left: start again.
		if derr := s.DropMove(ctx, id); derr != nil {
			return derr
		}
	}
	if _, gerr := s.store.GetMovedInRow(ctx, id); gerr == nil {
		// An earlier import of this move, never started: start again.
		if derr := s.DropMove(ctx, id); derr != nil {
			return derr
		}
	}
	s.movesIn.set(id, time.Now().Add(s.moveTimings.inFence()))
	placed := false
	var mover snapshotMover
	defer func() {
		if err == nil {
			// The leader's start, or its drop, may never come: it can die
			// after the swap, and its drop is best effort. This agent then
			// finishes the move itself, without waiting for a restart.
			s.armMovedInCheck(ctx, id, s.moveTimings.retry())
			return
		}
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
		// Rebuilt after the swap (startCheckpointMoved): no sandbox row
		// until then, so its bundle's row is stored before this answers.
		// The leader swaps on that answer; a restart after it finds the row
		// and finishes the move (resumeMovedIn).
		if err := s.putMovedIn(ctx, id, movedInRecord{Row: row, Recreate: rc}); err != nil {
			return fmt.Errorf("import %s: keep its row: %w", id, err)
		}
		s.prefetchMovedImage(mover, id, row.Sandbox.Image)
		return nil
	}
	sb := stoppedMovedRow(row, statusReasonMovedIn)
	if err := s.store.Create(ctx, &sb); err != nil {
		return fmt.Errorf("import %s: %w", id, err)
	}
	placed = true
	return nil
}

// stoppedMovedRow is the local row of a sandbox a bundle's row describes,
// stopped with reason, and with the identity the row carries.
func stoppedMovedRow(row moveRow, reason string) models.Sandbox {
	sb := row.Sandbox
	sb.ToolboxToken = row.ToolboxToken
	sb.CreateRequestDigest = row.CreateRequestDigest
	sb.AuditIncarnationID = row.AuditIncarnationID
	sb.TokensNotBefore = row.TokensNotBefore
	sb.OwnerRef = row.OwnerRef
	sb.Status = models.SandboxStatusStopped
	sb.StatusReason = reason
	sb.ContainerID, sb.ContainerIP = "", ""
	sb.UpdatedAt = time.Now().UTC()
	return sb
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
	return s.dropImport(ctx, id, "")
}

// dropImport drops id's import. With lifetime set, it is an import of that
// lifetime beside a placement of another (checkMovedInOnce): a Firecracker
// row goes only while it is still that import, stopped as moved in, so a
// row of the current lifetime is never touched.
func (s *Service) dropImport(ctx context.Context, id, lifetime string) error {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	s.movesIn.clear(id)
	rec, _, stored, err := s.loadMovedIn(ctx, id)
	if stored {
		// The staged checkpoint goes first: a record left behind by a drop
		// that failed is dropped again next time.
		if err != nil {
			// A record that does not open names no runtime.
			s.dropImportEverywhere(id)
		} else if mover, merr := s.snapshotMoverFor(&rec.Row.Sandbox); merr != nil {
			return merr
		} else if derr := mover.DropImportedSnapshot(ctx, id); derr != nil {
			return derr
		}
		return s.store.DeleteMovedInRow(ctx, id)
	}
	if err != nil {
		return err
	}
	sb, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		// Nothing imported, or a failed import already dropped it.
		return nil
	}
	if err != nil {
		return err
	}
	if lifetime != "" && (sb.AuditIncarnationID != lifetime || !awaitingMovedStart(sb)) {
		return nil
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

// StartMoved starts id, which moved here, from its memory. rc is the
// leader's recreate inputs for a gVisor rebuild; nil uses the ones stored
// at the import. Retryable: a gVisor sandbox's stored row goes only once it
// started, and a Firecracker sandbox's row stays stopped here on a failure.
func (s *Service) StartMoved(ctx context.Context, id string, rc *cluster.MoveRecreate) error {
	id = strings.TrimSpace(id)
	if _, err := s.ownedIncarnation(ctx, id); err != nil {
		return err
	}
	s.movesIn.clear(id)
	rec, _, stored, err := s.loadMovedIn(ctx, id)
	if err != nil {
		return err
	}
	if stored {
		if rc == nil {
			rc = rec.Recreate
		}
		if err := s.startCheckpointMoved(ctx, id, rec.Row, rc); err != nil {
			return err
		}
		// A row left behind is harmless: a later start (the move-in
		// check's, or the next agent start's) finds the sandbox already
		// here, and removes it then.
		_ = s.store.DeleteMovedInRow(ctx, id)
		return nil
	}
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = s.startSandboxLocked(ctx, id, startForRestart)
	return err
}

// resumeMovedIn finishes, at an agent's start, the moves it took in before
// a restart (N4): each stored gVisor row and each Firecracker row still
// stopped as moved in gets its move-in check again (checkMovedIn), and is
// held from the stale-ownership sweep until the move's time is up.
func (s *Service) resumeMovedIn(ctx context.Context) {
	if s.Cluster() == nil {
		return
	}
	pending := map[string]time.Time{}
	stored, err := s.store.ListMovedInRows(ctx)
	if err != nil && s.logger != nil {
		s.logger.Warn("cluster: cannot list the moves taken in before this start", "error", err)
	}
	for _, r := range stored {
		pending[r.SandboxID] = r.ImportedAt
	}
	if rows, err := s.store.List(ctx); err == nil {
		for _, sb := range rows {
			if awaitingMovedStart(sb) {
				pending[sb.ID] = sb.UpdatedAt
			}
		}
	}
	now := time.Now()
	for id, at := range pending {
		if until := at.Add(s.moveTimings.inFence()); now.Before(until) {
			s.movesIn.set(id, until)
		}
		s.armMovedInCheck(ctx, id, 0)
	}
}

// moveInChecks is, per sandbox imported here, the generation of its live
// move-in check. Arming one retires the one before, so a sandbox has at
// most one, and a re-import never loses its check.
type moveInChecks struct {
	mu   sync.Mutex
	gen  map[string]uint64
	next uint64
}

func (m *moveInChecks) arm(id string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen == nil {
		m.gen = make(map[string]uint64)
	}
	m.next++
	m.gen[id] = m.next
	return m.next
}

// live reports whether g is still id's check.
func (m *moveInChecks) live(id string, g uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gen[id] == g
}

// done retires id's check g, unless a later one replaced it.
func (m *moveInChecks) done(id string, g uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen[id] == g {
		delete(m.gen, id)
	}
}

// moveInCheck is one sandbox's move-in check: the sandbox, and the
// generation it was armed as.
type moveInCheck struct {
	id  string
	gen uint64
}

// armMovedInCheck runs id's move-in check after d, in place of any before.
func (s *Service) armMovedInCheck(ctx context.Context, id string, d time.Duration) {
	s.scheduleMovedInCheck(context.WithoutCancel(ctx), moveInCheck{id: id, gen: s.moveInChecks.arm(id)}, d)
}

func (s *Service) scheduleMovedInCheck(ctx context.Context, ck moveInCheck, d time.Duration) {
	s.moveTimers.after(d, func() { s.checkMovedIn(ctx, ck) })
}

// movedInState is what a move-in check reads of an import here.
type movedInState struct {
	// pending: a stored gVisor row, or a Firecracker row still stopped as
	// moved in.
	pending bool
	// until is when the move's time is up.
	until time.Time
	// lifetime is the imported row's incarnation.
	lifetime string
	// unreadable: a stored row that does not open.
	unreadable bool
}

// movedInPending reads id's import from the store, at every check, so a
// check sees a re-import, and a start or a drop by anyone.
func (s *Service) movedInPending(ctx context.Context, id string) (movedInState, error) {
	ttl := s.moveTimings.inFence()
	rec, importedAt, stored, err := s.loadMovedIn(ctx, id)
	if stored {
		return movedInState{pending: true, until: importedAt.Add(ttl), lifetime: rec.Row.AuditIncarnationID, unreadable: err != nil}, nil
	}
	var sb *models.Sandbox
	if err == nil {
		sb, err = s.store.Get(ctx, id)
	}
	if errors.Is(err, store.ErrNotFound) {
		return movedInState{}, nil
	}
	if err != nil {
		return movedInState{}, err
	}
	pending := awaitingMovedStart(sb)
	return movedInState{pending: pending, until: sb.UpdatedAt.Add(ttl), lifetime: sb.AuditIncarnationID}, nil
}

// checkMovedIn is one step of a move-in check (N4). The import arms it on
// a live agent, and resumeMovedIn after a restart: the leader may die after
// the swap and before its start, and a new leader does not start a sandbox
// whose placement already names this node; its drop of a move that did not
// happen is best effort. Once the placement names this node, the check
// starts the sandbox (StartMoved is idempotent, so racing the leader's own
// start is safe). Past the move's time, with the placement elsewhere, it
// drops the import. Otherwise, or on any error, it looks again a retry
// later. It ends once the import is no longer pending, or a later check
// replaced it, and it is bounded (checkMovedInOnce, giveUpMovedIn).
//
// Only the move that produced an import can hand this node its placement,
// so the check does not tie its start to that move's handoff. A snapshot
// move takes only a sandbox with no failover-recreate policy
// (placementWantsSnapshotMove), and every other path that reassigns a
// placement to a new node takes only one with that policy: the dead-owner
// eviction, orphan recovery and the stuck-placement handoff, as the
// decommission's recreate move does. A WASM migrate moves only WASM. An
// orphaned sandbox with no recreate policy goes back only to the node it
// was orphaned from (opClaimOrphan): the source, not this target. A later
// snapshot move of the same sandbox to this node drops the earlier import
// before it takes the new one (ImportMove). What is left is a placement of
// another lifetime with the same id, placed here after a delete (a keyed
// create gets its id back): the check compares the incarnation, and drops
// an import of another lifetime instead of starting it.
func (s *Service) checkMovedIn(ctx context.Context, ck moveInCheck) {
	if !s.moveInChecks.live(ck.id, ck.gen) {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, moveInCheckTimeout)
	defer cancel()
	if err := s.checkMovedInOnce(rctx, ck); err != nil {
		if s.logger != nil && !errors.Is(err, errMoveInWaiting) {
			s.logger.Warn("cluster: a move taken in here is not finished; checking again", "sandbox_id", ck.id, "err", err)
		}
		s.scheduleMovedInCheck(ctx, ck, s.moveTimings.retry())
		return
	}
	s.moveInChecks.done(ck.id, ck.gen)
}

// errMoveInWaiting: the placement still names the source, within the
// move's time.
var errMoveInWaiting = errors.New("the placement still names the move's source")

// checkMovedInOnce is checkMovedIn's step: nil once the import is started,
// dropped, given up on, or no longer pending. It is bounded: a start that
// can never work (a stored row that does not open, or one with no recreate
// inputs, from a leader older than its target) is given up on at once, one
// that keeps failing once the move's time is up, and a drop that keeps
// failing once that time has passed again.
func (s *Service) checkMovedInOnce(ctx context.Context, ck moveInCheck) error {
	id := ck.id
	st, err := s.movedInPending(ctx, id)
	c := s.Cluster()
	if err != nil || !st.pending || c == nil {
		return err
	}
	if st.unreadable {
		return s.giveUpMovedIn(ctx, id, errors.New("its stored row does not open"))
	}
	got, err := c.AuthoritativePlacementsByIDs(ctx, []string{id})
	if err != nil {
		return fmt.Errorf("read its placement: %w", err)
	}
	p, ok := got[id]
	switch {
	case ok && strings.TrimSpace(p.OwnerNodeID) == c.SelfNodeID() && !sameIncarnation(st.lifetime, p.IncarnationID):
		// Another lifetime with this id: never start this import as it.
		err = s.dropImport(ctx, id, st.lifetime)
	case ok && strings.TrimSpace(p.OwnerNodeID) == c.SelfNodeID():
		if err := s.StartMoved(ctx, id, nil); err != nil {
			if errors.Is(err, errMoveNoSpec) || !time.Now().Before(st.until) {
				return s.giveUpMovedIn(ctx, id, err)
			}
			return fmt.Errorf("start: %w", err)
		}
		if s.logger != nil {
			s.logger.Info("cluster: started a sandbox moved here; the leader's start did not come", "sandbox_id", id)
		}
		return nil
	case time.Now().Before(st.until):
		return errMoveInWaiting
	default:
		// The move never happened: its time is up and the placement still
		// names another node. The source starts its own copy (its fence
		// lapsed long ago); this one goes.
		err = s.DropMove(ctx, id)
	}
	if err != nil && time.Now().After(st.until.Add(s.moveTimings.inFence())) {
		if s.logger != nil {
			s.logger.Error("cluster: a move taken in here could not be dropped; giving up until the agent restarts", "sandbox_id", id, "err", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("drop: %w", err)
	}
	return nil
}

// sameIncarnation reports whether an import of lifetime belongs to a
// placement of incarnation; an unknown one on either side matches, as for
// a row from before incarnations.
func sameIncarnation(lifetime, incarnation string) bool {
	lifetime, incarnation = strings.TrimSpace(lifetime), strings.TrimSpace(incarnation)
	return lifetime == "" || incarnation == "" || lifetime == incarnation
}

// statusReasonMoveStartFailed is the reason a moved sandbox's row carries
// when the move-in check gave up on starting it.
const statusReasonMoveStartFailed = "move_start_failed"

// errMoveNoSpec: a moved gVisor sandbox's start has no recreate inputs,
// from the leader or stored with its import.
var errMoveNoSpec = errors.New("the leader sent no spec to rebuild it from")

// giveUpMovedIn ends a move-in check that cannot start its import, with one
// log line and a status a user can see: the sandbox's row stays stopped (or
// in error, with the start's error) with reason move_start_failed. A
// Firecracker sandbox keeps its row and its staged memory, so a user's
// start can try again. A gVisor sandbox gets
// a stopped row from its stored one; with nothing to rebuild it from, its
// staged checkpoint goes, and deleting the sandbox is what is left. A
// stored row that does not open goes with its checkpoint, from every
// runtime: nothing names the sandbox.
func (s *Service) giveUpMovedIn(ctx context.Context, id string, cause error) error {
	unlock, err := s.lifecycleLocks.lockCtx(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	s.movesIn.clear(id)
	rec, _, stored, lerr := s.loadMovedIn(ctx, id)
	switch {
	case stored && lerr != nil:
		s.dropImportEverywhere(id)
	case stored:
		if _, gerr := s.store.Get(ctx, id); errors.Is(gerr, store.ErrNotFound) {
			sb := stoppedMovedRow(rec.Row, statusReasonMoveStartFailed)
			err = s.store.Create(ctx, &sb)
		}
		if mover, merr := s.snapshotMoverFor(&rec.Row.Sandbox); merr == nil && err == nil {
			_ = mover.DropImportedSnapshot(ctx, id)
		}
	default:
		// Under the lock, so a start cannot slip in: only a row still
		// awaiting its start gets the reason.
		var sb *models.Sandbox
		if sb, err = s.store.Get(ctx, id); err == nil && awaitingMovedStart(sb) {
			err = s.store.SetStatusReason(ctx, id, statusReasonMoveStartFailed, nil)
		}
	}
	if err == nil && stored {
		err = s.store.DeleteMovedInRow(ctx, id)
	}
	if err != nil {
		return err
	}
	if s.logger != nil {
		s.logger.Error("cluster: a sandbox moved here could not be started; it is left stopped", "sandbox_id", id, "status_reason", statusReasonMoveStartFailed, "err", cause)
	}
	return nil
}

// moveInCheckTimeout bounds one checkMovedIn step: a read and a start that
// may rebuild the sandbox from its checkpoint.
const moveInCheckTimeout = 5 * time.Minute

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
		return fmt.Errorf("start %s: %w", id, errMoveNoSpec)
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
