package service

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Server-key rotation (plans/customer-key-custody.md §13, eng D26). The
// operator stages, promotes and retires ring keys with `sandboxd key
// rotate`, which only edits the server-key file; this node takes each step
// at its next re-read of that file. While the ring holds more than one key
// the same loop reseals every sealed column onto the current key: local
// AES work only, since the ring is already in memory.

// Secret-audit kinds of a rotation step, written by each node when it takes
// the step: a new Kind value, no new field (§8).
const (
	KindKeyRotationStaged   = "key_rotation_staged"
	KindKeyRotationPromoted = "key_rotation_promoted"
	KindKeyRotationRetired  = "key_rotation_retired"
)

// keyRingStateName remembers the ring this node last took, next to the
// audit log, so a step taken while the daemon was down is still recorded.
const keyRingStateName = "key-ring.last"

// rowsUnopenable is the aerolvm_server_key_rows key of a value no ring key
// opens.
const rowsUnopenable = "unopenable"

var (
	// serverKeyRingGauge is aerolvm_server_key_ring{key=id,key2=state}: a
	// promote waits for the staged key to show on every member.
	serverKeyRingGauge = expvar.NewMap("aerolvm_server_key_ring")
	// serverKeyRowsGauge is aerolvm_server_key_rows{key=id}: a retire waits
	// for the old key to reach 0 on every member. Empty while the ring
	// holds one key.
	serverKeyRowsGauge = expvar.NewMap("aerolvm_server_key_rows")
	keyRowsResealed    = expvar.NewInt("aerolvm_server_key_rows_resealed_total")
)

var keyRingMu sync.Mutex

// serverKeyRing reads this node's ring from disk without unwrapping: the
// wrapped file's entries, custody=file's ring file, or the legacy key alone
// when neither has a ring.
func (s *Service) serverKeyRing() ([]secrets.RingEntry, error) {
	if s.cfg.CredentialKeyCustody == secrets.CustodyWrapped {
		f, err := secrets.ReadWrappedKeyFile(s.cfg.CredentialKeyWrappedPath)
		if err != nil {
			return nil, err
		}
		return f.Entries(), nil
	}
	f, err := secrets.ReadKeyRingFile(s.cfg.KeyRingPath())
	if errors.Is(err, fs.ErrNotExist) {
		return []secrets.RingEntry{{ID: 0, State: secrets.RingStateCurrent}}, nil
	}
	if err != nil {
		return nil, err
	}
	return f.Ring, nil
}

// reloadKeyRingFile is custody=file's re-read: a ring file staged, promoted
// or retired by `sandboxd key rotate` reaches the Cipher here.
func (s *Service) reloadKeyRingFile() {
	f, err := secrets.ReadKeyRingFile(s.cfg.KeyRingPath())
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err == nil {
		err = s.cipher.SetRing(f.RingKeys())
	}
	if err != nil {
		s.logger.Error("key custody: server-key ring not taken; the node keeps its current ring", "path", s.cfg.KeyRingPath(), "error", err)
		return
	}
	s.noteServerKeyRing(f.Ring)
}

// applyWrappedRing is the wrapped re-check's ring step: keys new to this
// node are unwrapped, the rest are kept as they are.
func (s *Service) applyWrappedRing(ctx context.Context, f secrets.WrappedKeyFile) {
	keys, err := secrets.UnwrapRing(ctx, s.keyStoreWrapper, f, s.cipher.HoldsKey)
	if err == nil {
		err = s.cipher.SetRing(keys)
	}
	if err != nil {
		s.logger.Error("key custody: server-key ring not taken; the node keeps its current ring", "path", s.cfg.CredentialKeyWrappedPath, "error", err)
		return
	}
	s.noteServerKeyRing(f.Entries())
}

// noteServerKeyRing publishes the ring gauge and records each rotation step
// since the last ring this node took. The state is written only once every
// record is durable, so a failed record is retried on the next re-read.
func (s *Service) noteServerKeyRing(entries []secrets.RingEntry) {
	inner := map[string]*expvar.Map{}
	for _, e := range entries {
		id := strconv.FormatUint(uint64(e.ID), 10)
		if inner[id] == nil {
			inner[id] = new(expvar.Map).Init()
		}
		one := new(expvar.Int)
		one.Set(1)
		inner[id].Set(e.State, one)
	}
	serverKeyRingGauge.Init()
	for id, m := range inner {
		serverKeyRingGauge.Set(id, m)
	}

	keyRingMu.Lock()
	defer keyRingMu.Unlock()
	dataDir := secretAuditDataDir(s.cfg.DBPath)
	if dataDir == "" {
		return
	}
	path := filepath.Join(dataDir, "audit", keyRingStateName)
	now := secrets.RingSummary(entries)
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.logger.Warn("key custody: last recorded ring unreadable", "path", path, "error", err)
	}
	prevSummary := strings.TrimSpace(string(raw))
	if prevSummary == now {
		return
	}
	if prevSummary != "" {
		prev := secrets.ParseRingSummary(prevSummary)
		var from uint32
		for id, state := range prev {
			if state == secrets.RingStateCurrent {
				from = id
			}
		}
		// A copy can carry several steps at once (staged and promoted
		// between two re-reads): each is recorded, in order.
		type step struct{ kind, reason string }
		var steps []step
		for _, e := range entries {
			if prev[e.ID] == "" && e.State != secrets.RingStateRetired {
				steps = append(steps, step{KindKeyRotationStaged, fmt.Sprintf("key=%d", e.ID)})
			}
			if e.State == secrets.RingStateCurrent && prev[e.ID] != secrets.RingStateCurrent {
				steps = append(steps, step{KindKeyRotationPromoted, fmt.Sprintf("from=%d to=%d", from, e.ID)})
			}
			if e.State == secrets.RingStateRetired && prev[e.ID] != secrets.RingStateRetired {
				steps = append(steps, step{KindKeyRotationRetired, fmt.Sprintf("key=%d", e.ID)})
			}
		}
		for _, st := range steps {
			if !s.emitDurableKeyEvent(st.kind, st.reason) {
				s.logger.Warn("key custody: rotation step not recorded; the next re-read retries", "kind", st.kind)
				return
			}
			s.logger.Warn("key custody: server-key rotation step taken", "step", st.kind, "detail", st.reason)
		}
	}
	werr := os.MkdirAll(filepath.Dir(path), 0o700)
	if werr == nil {
		werr = os.WriteFile(path, []byte(now+"\n"), 0o600)
	}
	if werr != nil {
		s.logger.Warn("key custody: could not remember the ring", "path", path, "error", werr)
	}
}

// emitDurableKeyEvent writes a key-custody record and reports whether it is
// durable (true with no sink: there is nothing to retry into).
func (s *Service) emitDurableKeyEvent(kind, reason string) bool {
	sink := s.secretAuditSink()
	if sink == nil {
		return true
	}
	actor := s.auditActor()
	ev := SecretAuditEvent{
		Time: time.Now().UTC(), Actor: actor, NodeID: actor,
		Result: secretAuditResultSuccess, Reason: reason, Kind: kind,
	}
	ensureSecretAuditEventID(&ev)
	if durable, ok := sink.(DurableSecretAuditSink); ok {
		return durable.EmitDurable(ev) == nil
	}
	sink.Emit(ev)
	return true
}

// ResealServerKeyRows moves every value sealed under the server key onto
// its current ring key (§13 step 3) and returns how many values each key
// opens afterwards. Each write is a compare-and-swap on the bytes read, so
// a concurrent write wins and its value is counted under the key it was
// read on until the next pass looks again: the count never reaches 0 early.
// With one key in the ring there is nothing to move and nothing is read.
func (s *Service) ResealServerKeyRows(ctx context.Context) (map[string]int, error) {
	if s == nil || s.cipher == nil || s.KeyRevoked() || !s.cipher.Rotating() {
		serverKeyRowsGauge.Init()
		return nil, nil
	}
	current := strconv.FormatUint(uint64(s.cipher.CurrentKeyID()), 10)
	counts := map[string]int{}
	resealed := 0
	count := func(from uint32, moved bool) {
		if moved {
			counts[current]++
			resealed++
			return
		}
		counts[strconv.FormatUint(uint64(from), 10)]++
	}
	err := s.resealPass(ctx, count, func() { counts[rowsUnopenable]++ })
	serverKeyRowsGauge.Init()
	for id, n := range counts {
		v := new(expvar.Int)
		v.Set(int64(n))
		serverKeyRowsGauge.Set(id, v)
	}
	keyRowsResealed.Add(int64(resealed))
	if resealed > 0 {
		s.logger.Info("key custody: values resealed onto the current server key", "resealed", resealed, "rows", counts)
	}
	return counts, err
}

func (s *Service) resealPass(ctx context.Context, count func(from uint32, moved bool), unopenable func()) error {
	if s.store != nil {
		for _, col := range store.SealedColumns {
			if err := s.resealColumn(ctx, col, count, unopenable); err != nil {
				return err
			}
		}
	}
	if err := s.resealEgressCA(count, unopenable); err != nil {
		return err
	}
	if s.store != nil {
		return s.resealLocalClusterSecrets(ctx, count)
	}
	return nil
}

func (s *Service) resealColumn(ctx context.Context, col store.SealedColumn, count func(uint32, bool), unopenable func()) error {
	after := ""
	for {
		rows, err := s.store.ListSealedRows(ctx, col, after, keySweepPage)
		if err != nil {
			return err
		}
		var batch []store.ResealedRow
		var froms []uint32
		for _, row := range rows {
			out, from, changed, err := s.cipher.Reseal(row.Sealed, row.AAD)
			switch {
			case errors.Is(err, secrets.ErrKeyRevoked):
				return err
			case err != nil:
				unopenable()
			case !changed:
				count(from, false)
			default:
				batch = append(batch, store.ResealedRow{SandboxID: row.SandboxID, Old: row.Sealed, New: out})
				froms = append(froms, from)
			}
		}
		written, err := s.store.ResealSealedRows(ctx, col, batch)
		if err != nil {
			return err
		}
		for i := range batch {
			count(froms[i], written[i])
		}
		if len(rows) < keySweepPage {
			return nil
		}
		after = rows[len(rows)-1].SandboxID
	}
}

// resealEgressCA reseals the node's egress inspection CA key under the
// lock that creates it, so a create and a reseal never interleave.
func (s *Service) resealEgressCA(count func(uint32, bool), unopenable func()) error {
	s.egressCAMu.Lock()
	defer s.egressCAMu.Unlock()
	path := filepath.Join(s.egressCADir(), "ca.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("egress inspection CA: %w", err)
	}
	var rec egressCARecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("egress inspection CA: %w", err)
	}
	out, from, changed, err := s.cipher.Reseal(rec.SealedKey, nil)
	switch {
	case errors.Is(err, secrets.ErrKeyRevoked):
		return err
	case err != nil:
		unopenable()
		return nil
	case !changed:
		count(from, false)
		return nil
	}
	rec.SealedKey = out
	next, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, next, 0o600); err != nil {
		count(from, false)
		return err
	}
	count(from, true)
	return nil
}

// resealLocalClusterSecrets moves this node's local cluster-secret copies
// onto the current key. Each node reseals its own copies; an older copy
// arriving from a peer never replaces a newer one with the same content
// (eng D20), and a new generation sealed by a peer before it took the
// promote is moved by a later pass.
func (s *Service) resealLocalClusterSecrets(ctx context.Context, count func(uint32, bool)) error {
	after := ""
	for {
		rows, err := s.store.ListClusterSecretsBatch(ctx, after, keySweepPage)
		if err != nil {
			return err
		}
		for _, row := range rows {
			out, from, changed, err := secrets.ResealLocalEnvelope(row.SealedPayload, s.cipher)
			switch {
			case errors.Is(err, secrets.ErrKeyRevoked):
				return err
			case err != nil:
				// A key-store row or an unreadable envelope: not this
				// key's to move.
				continue
			case !changed:
				count(from, false)
				continue
			}
			unlock := lockSecretSandboxOps(row.SandboxID)
			ok, werr := s.store.RewrapClusterSecret(ctx, row.Ref, row.SealGeneration, row.SealedPayload, out)
			unlock()
			if werr != nil {
				s.logger.Warn("key custody: resealed cluster secret not stored", "ref", row.Ref, "error", werr)
			}
			count(from, ok && werr == nil)
		}
		if len(rows) < keySweepPage {
			return nil
		}
		after = rows[len(rows)-1].Ref
	}
}

func (s *Service) resealTick(ctx context.Context) {
	if _, err := s.ResealServerKeyRows(ctx); err != nil {
		s.logger.Warn("key custody: reseal pass stopped early; the next re-read retries", "error", err)
	}
}
