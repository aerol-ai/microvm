package service

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"golang.org/x/sys/unix"
)

const (
	secretAuditResultSuccess = "success"
	secretAuditResultFailure = "failure"
	secretAuditResultGap     = "gap"

	secretAuditReasonOK              = "ok"
	secretAuditReasonNotFound        = "not_found"
	secretAuditReasonRecipientDenied = "recipient_denied"
	secretAuditReasonVersionMismatch = "version_mismatch"
	secretAuditReasonDecryptFailed   = "decrypt_failed"
	secretAuditReasonError           = "error"
	secretAuditReasonOverflow        = "overflow"

	// secretAuditKindSecretOpen is an explicit stored kind. Missing Kind is not
	// reinterpreted. secretAuditKindEgress is host-mediated destination
	// attribution (wasm NetMediator / isolate proxy) — never claim guest-side
	// secret use from these records.
	secretAuditKindSecretOpen          = "secret_open"
	secretAuditKindEgress              = "egress"
	secretAuditKindGap                 = "gap"
	secretAuditKindRetentionCheckpoint = "retention_checkpoint"

	defaultSecretAuditBuffer = 1024
	// enterpriseSecretAuditBuffer reduces spill likelihood under burst open
	// rates; Emit stays non-blocking and overflows to secrets.spill.jsonl.
	enterpriseSecretAuditBuffer = 8192
	// Bound the power-loss window for the local audit fallback. Enterprise
	// deployments must also configure an external durable/WORM witness.
	secretAuditSyncInterval = time.Second
	secretAuditFileName     = "secrets.jsonl"
	secretAuditSpillName    = "secrets.spill.jsonl"
	secretAuditSpillWorking = "secrets.spill.jsonl.working"
	// secretAuditLockName is a stable sidecar flock target. Retention and
	// wasm workers lock this path *before* opening secrets.jsonl so a rename
	// during prune cannot leave writers appending to an unlinked inode.
	secretAuditLockName = "secrets.jsonl.lock"
)

var (
	auditEventsDroppedTotal  = expvar.NewInt("aerolvm_audit_events_dropped_total")
	auditSpillMalformedTotal = expvar.NewInt("aerolvm_audit_spill_malformed_total")
	auditTipWriteFailTotal   = expvar.NewInt("aerolvm_audit_tip_write_fail_total")
	secretAuditSinkHealthy   = expvar.NewInt("aerolvm_secret_audit_sink_healthy")
)

// SecretAuditEvent is one audit record (secret-open by default, or host-mediated
// egress). Never carry plaintext, credentials, PII, or wrapped error strings
// (those may embed caller input). Destination must never include credentials.
type SecretAuditEvent = auditlog.Event

// SecretAuditSink receives secret-read events. Emit must be non-blocking.
// A nil sink is a no-op and must not panic.
type SecretAuditSink interface {
	Emit(SecretAuditEvent)
}

// DurableSecretAuditSink accepts an event only after its bytes have reached
// durable storage. Security-boundary ingest endpoints use this interface so a
// 202 response never means merely "queued in process memory".
type DurableSecretAuditSink interface {
	SecretAuditSink
	EmitDurable(SecretAuditEvent) error
}

type noopSecretAuditSink struct{}

func (noopSecretAuditSink) Emit(SecretAuditEvent) {}

// unavailableSecretAuditSink keeps a failed writer loud after non-strict boot:
// every event that could not be persisted is counted, and the health gauge
// remains zero. This avoids the previous permanent, silent noop fallback.
type unavailableSecretAuditSink struct{}

func (unavailableSecretAuditSink) Emit(SecretAuditEvent) {
	auditEventsDroppedTotal.Add(1)
}

type auditWriteReq struct {
	ev          SecretAuditEvent
	durable     chan error // when non-nil, report the fsynced event result
	sync        chan error // when non-nil, writer fsyncs after draining prior work
	pruneCutoff time.Time  // when non-zero, rewrite file dropping older events
	pruneDone   chan error
}

// fileAuditSink appends JSON Lines under {DataDir}/audit/secrets.jsonl via a
// single writer goroutine. Emit is always non-blocking: a full buffer either
// drops (open-source) or enqueues onto spillCh (enterprise) for the writer to
// durable-append — Emit never fsyncs. Gap markers are recorded only when
// evidence cannot be persisted (drop path or failed spill accept). The writer
// drains spill before channel work so spilled events land ahead of later
// in-memory sends.
//
// sendMu serializes producers against Close so Emit/Sync/Prune never send on a
// closed channel (check-then-send race under -race / daemon shutdown).
type fileAuditSink struct {
	ch         chan auditWriteReq
	spillCh    chan SecretAuditEvent // enterprise overflow; drained by writer
	pendingGap atomic.Int64          // coalesced drop count awaiting a gap marker write
	closed     atomic.Bool
	// spillEnabled (enterprise): buffer-full Emit enqueues to spillCh instead
	// of dropping. Gap only if spillCh cannot accept quickly.
	spillEnabled bool
	// sendMu serializes channel send vs Close. Spill file I/O runs on the
	// writer goroutine so Emit never holds sendMu across disk waits.
	sendMu           sync.Mutex
	spillMu          sync.Mutex
	gapMu            sync.Mutex
	done             chan struct{}
	path             string
	lockPath         string
	gapPath          string
	tipPath          string
	spillPath        string
	spillWorkingPath string
	witnessTipPath   string // optional; prune reads WitnessedThrough from here
	file             *os.File
	chainMu          sync.Mutex
	chainHead        string
	chainEvent       string
	writePoison      error // append outcome became ambiguous; refuse later writes
	// writeHook, when set (tests), runs before each file write and may block.
	writeHook func()
	// afterPrune, when set (Service), ships a new witness tip after prune
	// inserts a retention_checkpoint (retained event bytes are unchanged).
	afterPrune func()
}

func newFileAuditSink(auditDir string, buffer int) (*fileAuditSink, error) {
	return newFileAuditSinkOpts(auditDir, buffer, false)
}

func newFileAuditSinkOpts(auditDir string, buffer int, spillEnabled bool) (*fileAuditSink, error) {
	if buffer <= 0 {
		buffer = defaultSecretAuditBuffer
	}
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return nil, fmt.Errorf("secret audit mkdir: %w", err)
	}
	path := filepath.Join(auditDir, secretAuditFileName)
	lockPath := filepath.Join(auditDir, secretAuditLockName)
	gapPath := filepath.Join(auditDir, "secrets.gap")
	tipPath := filepath.Join(auditDir, "secrets.tip")
	spillPath := filepath.Join(auditDir, secretAuditSpillName)
	spillWorkingPath := filepath.Join(auditDir, secretAuditSpillWorking)
	// Acquire the stable sidecar lock before opening the data file so retention
	// rename cannot race a concurrent open+append onto an unlinked inode.
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("secret audit lock open: %w", err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("secret audit lock: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
	_ = lockFile.Close()
	if err != nil {
		return nil, fmt.Errorf("secret audit open: %w", err)
	}
	// Tip file is the fast-path for append linking under lock; verification
	// paths must call RecomputeChainHead instead of trusting this sidecar.
	head, tipEvent := loadChainTip(path, tipPath)
	pending := loadGapCount(gapPath)
	s := &fileAuditSink{
		ch:               make(chan auditWriteReq, buffer),
		spillCh:          make(chan SecretAuditEvent, buffer),
		done:             make(chan struct{}),
		path:             path,
		lockPath:         lockPath,
		gapPath:          gapPath,
		tipPath:          tipPath,
		spillPath:        spillPath,
		spillWorkingPath: spillWorkingPath,
		witnessTipPath:   filepath.Join(auditDir, secretAuditWitnessTipFile),
		file:             f,
		spillEnabled:     spillEnabled,
		chainHead:        head,
		chainEvent:       tipEvent,
	}
	if pending > 0 {
		s.pendingGap.Store(pending)
	}
	go s.loop()
	return s, nil
}

func (s *fileAuditSink) Emit(ev SecretAuditEvent) {
	if s == nil {
		return
	}
	s.sendMu.Lock()
	if s.closed.Load() {
		s.sendMu.Unlock()
		return
	}
	req := auditWriteReq{ev: ev}
	select {
	case s.ch <- req:
		s.sendMu.Unlock()
	default:
		spill := s.spillEnabled
		s.sendMu.Unlock()
		// Never fsync on the Emit path. Prefer a non-blocking spillCh handoff;
		// the writer durable-appends. If spillCh is also full, record a gap.
		if spill {
			s.sendMu.Lock()
			if s.closed.Load() {
				s.sendMu.Unlock()
				return
			}
			select {
			case s.spillCh <- ev:
				s.sendMu.Unlock()
				return
			default:
				s.sendMu.Unlock()
			}
			auditEventsDroppedTotal.Add(1)
			s.pendingGap.Add(1)
			return
		}
		auditEventsDroppedTotal.Add(1)
		s.pendingGap.Add(1)
	}
}

func (s *fileAuditSink) EmitDurable(ev SecretAuditEvent) error {
	if s == nil {
		return errors.New("secret audit sink unavailable")
	}
	done := make(chan error, 1)
	s.sendMu.Lock()
	if s.closed.Load() {
		s.sendMu.Unlock()
		return errors.New("secret audit sink closed")
	}
	s.ch <- auditWriteReq{ev: ev, durable: done}
	s.sendMu.Unlock()
	return <-done
}

// Sync blocks until every previously accepted event (and any pending gap
// marker) has been written and fsynced. No-op on a nil or closed sink.
func (s *fileAuditSink) Sync() error {
	if s == nil {
		return nil
	}
	done := make(chan error, 1)
	s.sendMu.Lock()
	if s.closed.Load() {
		s.sendMu.Unlock()
		return nil
	}
	// Sync must not drop — wait for buffer space while still holding sendMu so
	// Close cannot close(ch) mid-send.
	s.ch <- auditWriteReq{sync: done}
	s.sendMu.Unlock()
	return <-done
}

// Close stops the writer and closes the file. Safe to call once.
// Callers must stop retention (and await it) before Close so Prune cannot race.
func (s *fileAuditSink) Close() {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.sendMu.Lock()
	close(s.ch)
	close(s.spillCh)
	s.sendMu.Unlock()
	<-s.done
}

func (s *fileAuditSink) loop() {
	defer close(s.done)
	defer func() { _ = s.file.Close() }()
	ticker := time.NewTicker(secretAuditSyncInterval)
	defer ticker.Stop()
	flushGap := func() {
		if n := s.pendingGap.Load(); n > 0 {
			if err := s.writeEventInternal(SecretAuditEvent{
				Time:    time.Now().UTC(),
				Result:  secretAuditResultGap,
				Reason:  secretAuditReasonOverflow,
				Kind:    secretAuditKindGap,
				Dropped: n,
			}, false); err != nil {
				return
			}
			// Preserve drops added concurrently while the marker was written.
			for {
				current := s.pendingGap.Load()
				remove := n
				if current < remove {
					remove = current
				}
				if s.pendingGap.CompareAndSwap(current, current-remove) {
					remaining := current - remove
					s.persistGapState(remaining)
					break
				}
			}
		}
	}
	for {
		// Spill file first — durable overflow keeps chronological precedence.
		if s.drainSpill() {
			continue
		}
		select {
		case ev, ok := <-s.spillCh:
			if !ok {
				s.spillCh = nil
				continue
			}
			if err := s.appendSpill(ev); err != nil {
				auditEventsDroppedTotal.Add(1)
				n := s.pendingGap.Add(1)
				s.persistGapState(n)
			}
		case next, ok := <-s.ch:
			if !ok {
				// Drain remaining spill queue then spill file on shutdown.
				if s.spillCh != nil {
					for ev := range s.spillCh {
						if err := s.appendSpill(ev); err != nil {
							auditEventsDroppedTotal.Add(1)
							n := s.pendingGap.Add(1)
							s.persistGapState(n)
						}
					}
					s.spillCh = nil
				}
				for s.drainSpill() {
				}
				flushGap()
				_ = s.syncFile()
				return
			}
			flushGap()
			if next.pruneDone != nil {
				next.pruneDone <- s.pruneLocked(next.pruneCutoff)
				continue
			}
			flushSpill := func() {
				if s.spillCh != nil {
					for {
						select {
						case ev, ok := <-s.spillCh:
							if !ok {
								s.spillCh = nil
							} else if err := s.appendSpill(ev); err != nil {
								auditEventsDroppedTotal.Add(1)
								n := s.pendingGap.Add(1)
								s.persistGapState(n)
							}
							continue
						default:
						}
						break
					}
				}
				for s.drainSpill() {
				}
			}
			if next.sync != nil {
				// Sync must observe spilled events: flush spillCh → spill file → JSONL.
				flushSpill()
				flushGap()
				next.sync <- s.syncFile()
				continue
			}
			// Drain the currently queued event burst and group-commit it. Control
			// requests split batches so Sync/Prune retain their ordering contract.
			queued := []auditWriteReq{next}
			for n := len(s.ch); n > 0; n-- {
				queued = append(queued, <-s.ch)
			}
			for len(queued) > 0 {
				if queued[0].sync != nil || queued[0].pruneDone != nil {
					control := queued[0]
					queued = queued[1:]
					if control.sync != nil {
						flushSpill()
						flushGap()
						control.sync <- s.syncFile()
					} else {
						control.pruneDone <- s.pruneLocked(control.pruneCutoff)
					}
					continue
				}
				end := 0
				durable := false
				for end < len(queued) && queued[end].sync == nil && queued[end].pruneDone == nil {
					durable = durable || queued[end].durable != nil
					end++
				}
				events := make([]SecretAuditEvent, end)
				for i := range end {
					events[i] = queued[i].ev
				}
				err := s.writeEventBatch(events, durable, true)
				for i := range end {
					if queued[i].durable != nil {
						queued[i].durable <- err
					}
				}
				queued = queued[end:]
			}
		case <-ticker.C:
			flushGap()
			_ = s.syncFile()
		}
	}
}

// appendSpill durable-appends one event under the audit flock when the
// in-memory channel is full. Used by enterprise Emit so request paths never
// block and evidence is not silently discarded. fsync bounds the loss window.
func (s *fileAuditSink) appendSpill(ev SecretAuditEvent) error {
	if s == nil || s.spillPath == "" {
		return errors.New("secret audit spill path unset")
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ensureSecretAuditEventID(&ev)
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.spillMu.Lock()
	defer s.spillMu.Unlock()
	return s.withAuditFileLock(func() error {
		f, err := os.OpenFile(s.spillPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(line); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	})
}

// drainSpill moves one immutable spill segment into the authoritative JSONL.
// It streams and group-commits the segment in bounded batches, then removes the
// segment only after every batch is durable. A crash may replay a batch (event
// IDs make that detectable/idempotent downstream), but cannot lose evidence.
func (s *fileAuditSink) drainSpill() bool {
	if s == nil || s.spillPath == "" {
		return false
	}
	s.spillMu.Lock()
	defer s.spillMu.Unlock()

	working := s.spillWorkingPath
	if working == "" {
		working = s.spillPath + ".working"
	}
	var hasWork bool
	err := s.withAuditFileLock(func() error {
		// Resume an interrupted drain before accepting a fresh spill rename.
		if st, err := os.Stat(working); err == nil && st.Size() > 0 {
			hasWork = true
			return nil
		}
		st, err := os.Stat(s.spillPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if st.Size() == 0 {
			_ = os.Remove(s.spillPath)
			return nil
		}
		if err := os.Rename(s.spillPath, working); err != nil {
			return err
		}
		hasWork = true
		return nil
	})
	if err != nil || !hasWork {
		return false
	}

	offsetPath := working + ".off"
	start := loadSpillOffset(offsetPath)
	f, err := os.Open(working)
	if err != nil {
		return false
	}
	defer f.Close()
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return false
		}
	}
	br := bufio.NewReaderSize(f, 64*1024)
	var consumed int64
	batch := make([]SecretAuditEvent, 0, 256)
	flush := func() bool {
		if len(batch) == 0 {
			return true
		}
		if err := s.writeEventBatch(batch, true, false); err != nil {
			return false
		}
		if err := persistSpillOffset(offsetPath, start+consumed); err != nil {
			return false
		}
		batch = batch[:0]
		return true
	}
	for {
		line, readErr := br.ReadBytes('\n')
		if len(line) > 0 {
			consumed += int64(len(line))
			text := strings.TrimSpace(string(line))
			if text != "" {
				var ev SecretAuditEvent
				if json.Unmarshal([]byte(text), &ev) != nil {
					auditSpillMalformedTotal.Add(1)
					sum := sha256.Sum256([]byte(text))
					ev = SecretAuditEvent{
						Time: time.Unix(1_000_000_000+int64(sum[0]), 0).UTC(), EventID: "ae-spill-malformed-" + hex.EncodeToString(sum[:8]),
						Result: secretAuditResultGap, Reason: secretAuditReasonOverflow, Kind: secretAuditKindGap, Dropped: 1,
					}
				}
				batch = append(batch, ev)
				if len(batch) == cap(batch) && !flush() {
					return false
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return false
		}
	}
	if !flush() {
		return false
	}
	if err := s.withAuditFileLock(func() error {
		_ = os.Remove(offsetPath)
		return os.Remove(working)
	}); err != nil {
		return false
	}
	return true
}

func (s *fileAuditSink) syncFile() error {
	err := s.withAuditFileLock(func() error {
		if err := s.file.Sync(); err != nil {
			return err
		}
		head, eventID := s.chainTip()
		return persistChainTipErr(s.tipPath, head, eventID)
	})
	if err != nil {
		secretAuditSinkHealthy.Set(0)
	}
	return err
}

// Prune drops events (and gap markers) older than cutoff. Serialized on the
// writer goroutine so it cannot race appends.
func (s *fileAuditSink) Prune(cutoff time.Time) error {
	if s == nil {
		return nil
	}
	done := make(chan error, 1)
	s.sendMu.Lock()
	if s.closed.Load() {
		s.sendMu.Unlock()
		return nil
	}
	s.ch <- auditWriteReq{pruneCutoff: cutoff, pruneDone: done}
	s.sendMu.Unlock()
	return <-done
}

func (s *fileAuditSink) withAuditFileLock(fn func() error) error {
	lockPath := s.lockPath
	if lockPath == "" {
		lockPath = s.path + ".lock"
	}
	// The sidecar is only a flock target and never stores data.
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(lf.Fd()), unix.LOCK_UN) }()
	return fn()
}

func (s *fileAuditSink) pruneLocked(cutoff time.Time) error {
	if cutoff.IsZero() {
		return nil
	}
	err := s.withAuditFileLock(func() error {
		// Pass 1: discover whether anything expires and the last dropped hash.
		// Retained event bytes are never rewritten (EventHash stays immutable).
		src, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		scanner := bufio.NewScanner(src)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		var lastDroppedHash string
		witnessedThrough := ""
		witnessCandidate := ""
		if tip, tipErr := readWitnessTip(s.witnessTipPath); tipErr == nil {
			witnessCandidate = strings.TrimSpace(tip.HeadHex)
		}
		droppedLines := 0
		droppingPrefix := true
		chainPrev := auditlog.GenesisPrevHash
		allowChainBreak := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var ev SecretAuditEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				_ = src.Close()
				return fmt.Errorf("secret audit retention encountered malformed event: %w", err)
			}
			storedPrev := strings.TrimSpace(ev.PrevHash)
			if storedPrev == "" {
				storedPrev = chainPrev
			}
			if ev.EventHash == "" || ev.EventHash != auditlog.HashEvent(storedPrev, ev) {
				_ = src.Close()
				return fmt.Errorf("secret audit retention encountered invalid event hash")
			}
			if ev.Kind == secretAuditKindRetentionCheckpoint {
				allowChainBreak = true
			} else {
				if storedPrev != chainPrev && !allowChainBreak {
					_ = src.Close()
					return fmt.Errorf("secret audit retention encountered broken hash chain")
				}
				allowChainBreak = false
			}
			chainPrev = ev.EventHash
			if droppingPrefix && !ev.Time.IsZero() && ev.Time.Before(cutoff) {
				droppedLines++
				if ev.EventHash != "" {
					lastDroppedHash = ev.EventHash
					if ev.EventHash == witnessCandidate {
						witnessedThrough = witnessCandidate
					}
				}
				continue
			}
			droppingPrefix = false
		}
		if err := scanner.Err(); err != nil {
			_ = src.Close()
			return err
		}
		if droppedLines == 0 {
			_ = src.Close()
			return nil
		}
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			_ = src.Close()
			return err
		}

		// Carry the exact witnessed ancestor when it falls anywhere in the
		// dropped prefix. Requiring it to equal the last dropped event would make
		// a legitimately lagging witness unverifiable after retention.
		cp := SecretAuditEvent{
			// Anchor the checkpoint at the retained boundary. Using prune wall
			// time here would pin it at the head for an entire retention window
			// and prevent daily prefix reclamation.
			Time:             cutoff.UTC(),
			Result:           secretAuditResultSuccess,
			Reason:           "prune",
			Kind:             secretAuditKindRetentionCheckpoint,
			PrevHash:         lastDroppedHash,
			WitnessedThrough: witnessedThrough,
		}
		if cp.PrevHash == "" {
			cp.PrevHash = auditlog.GenesisPrevHash
		}
		ensureSecretAuditEventID(&cp)
		auditlog.LinkEvent(cp.PrevHash, &cp)

		tmp := s.path + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			_ = src.Close()
			return err
		}
		removeTmp := true
		defer func() {
			if removeTmp {
				_ = os.Remove(tmp)
			}
		}()
		writer := bufio.NewWriterSize(f, 64*1024)
		line, err := json.Marshal(cp)
		if err != nil {
			_ = f.Close()
			_ = src.Close()
			return err
		}
		if _, err := writer.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			_ = src.Close()
			return err
		}
		lastKeptHash := cp.EventHash
		lastKeptEventID := cp.EventID

		// Pass 2: stream kept lines through unchanged (no rehash).
		scanner = bufio.NewScanner(src)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		remainingDrops := droppedLines
		for scanner.Scan() {
			raw := strings.TrimSpace(scanner.Text())
			if raw == "" {
				continue
			}
			if remainingDrops > 0 {
				remainingDrops--
				continue
			}
			var ev SecretAuditEvent
			if err := json.Unmarshal([]byte(raw), &ev); err != nil {
				_ = f.Close()
				_ = src.Close()
				return fmt.Errorf("secret audit retention event changed between passes: %w", err)
			}
			if _, err := writer.WriteString(raw); err != nil {
				_ = f.Close()
				_ = src.Close()
				return err
			}
			if _, err := writer.Write([]byte{'\n'}); err != nil {
				_ = f.Close()
				_ = src.Close()
				return err
			}
			if ev.EventHash != "" {
				lastKeptHash = ev.EventHash
				lastKeptEventID = ev.EventID
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			_ = src.Close()
			return err
		}
		_ = src.Close()

		if err := writer.Flush(); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmp, s.path); err != nil {
			return err
		}
		removeTmp = false
		if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
			_ = dir.Sync()
			_ = dir.Close()
		}
		_ = s.file.Close()
		nf, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		s.file = nf
		s.chainMu.Lock()
		s.chainHead = lastKeptHash
		s.chainEvent = lastKeptEventID
		s.chainMu.Unlock()
		persistChainTip(s.tipPath, lastKeptHash, lastKeptEventID)
		return nil
	})
	if err != nil {
		return err
	}
	if s.afterPrune != nil {
		s.afterPrune()
	}
	return nil
}

func ensureSecretAuditEventID(ev *SecretAuditEvent) {
	auditlog.EnsureEventID(ev)
}

func (s *fileAuditSink) writeEvent(ev SecretAuditEvent) error {
	return s.writeEventInternal(ev, true)
}

func (s *fileAuditSink) writeEventInternal(ev SecretAuditEvent, accountFailure bool) error {
	return s.writeEventBatch([]SecretAuditEvent{ev}, true, accountFailure)
}

// writeEventBatch links and appends a batch under one flock and, when durable,
// one fsync. This preserves the hash chain while avoiding one disk barrier per
// concurrent enterprise request.
func (s *fileAuditSink) writeEventBatch(events []SecretAuditEvent, durable, accountFailure bool) error {
	if len(events) == 0 {
		return nil
	}
	for range events {
		if s.writeHook != nil {
			s.writeHook()
		}
	}
	lineErr := s.withAuditFileLock(func() error {
		s.chainMu.Lock()
		poisoned := s.writePoison
		s.chainMu.Unlock()
		if poisoned != nil {
			return fmt.Errorf("secret audit writer poisoned: %w", poisoned)
		}
		// Prefer in-memory tip under flock; fall back to sidecar/file scan.
		prev := s.chainHead
		if prev == "" {
			prev, _ = loadChainTip(s.path, s.tipPath)
		}
		if prev == "" {
			prev = auditlog.GenesisPrevHash
		}
		var encoded []byte
		for i := range events {
			ev := &events[i]
			if ev.Time.IsZero() {
				ev.Time = time.Now().UTC()
			}
			ensureSecretAuditEventID(ev)
			auditlog.LinkEvent(prev, ev)
			line, err := json.Marshal(ev)
			if err != nil {
				return err
			}
			encoded = append(encoded, line...)
			encoded = append(encoded, '\n')
			prev = ev.EventHash
		}
		before, err := s.file.Stat()
		if err != nil {
			return err
		}
		rollback := func(writeErr error) error {
			if truncateErr := s.file.Truncate(before.Size()); truncateErr != nil {
				s.chainMu.Lock()
				s.writePoison = fmt.Errorf("rollback append after %v: %w", writeErr, truncateErr)
				s.chainMu.Unlock()
				return s.writePoison
			}
			if syncErr := s.file.Sync(); syncErr != nil {
				s.chainMu.Lock()
				s.writePoison = fmt.Errorf("sync rollback after %v: %w", writeErr, syncErr)
				s.chainMu.Unlock()
				return s.writePoison
			}
			return writeErr
		}
		if _, err := s.file.Write(encoded); err != nil {
			return rollback(err)
		}
		if durable {
			if err := s.file.Sync(); err != nil {
				return rollback(err)
			}
		}
		last := events[len(events)-1]
		s.chainMu.Lock()
		s.chainHead = last.EventHash
		s.chainEvent = last.EventID
		s.chainMu.Unlock()
		if durable {
			if tipErr := persistChainTipErr(s.tipPath, last.EventHash, last.EventID); tipErr != nil {
				auditTipWriteFailTotal.Add(1)
			}
		}
		return nil
	})
	if lineErr != nil {
		secretAuditSinkHealthy.Set(0)
		if accountFailure {
			auditEventsDroppedTotal.Add(int64(len(events)))
			n := s.pendingGap.Add(int64(len(events)))
			s.persistGapState(n)
		}
		return lineErr
	}
	secretAuditSinkHealthy.Set(1)
	return nil
}

func (s *fileAuditSink) chainTip() (head, eventID string) {
	if s == nil {
		return "", ""
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.chainHead, s.chainEvent
}

// loadChainTip loads the fast-path tip for append linking under lock.
// Prefer tipPath when present; otherwise scan the last EventHash without
// verifying hashes. Verification / witness paths must use RecomputeChainHead.
func loadChainTip(path, tipPath string) (head, eventID string) {
	if tipPath != "" {
		if raw, err := os.ReadFile(tipPath); err == nil {
			parts := strings.SplitN(strings.TrimSpace(string(raw)), "\n", 2)
			if len(parts) >= 1 && parts[0] != "" {
				head = parts[0]
				if len(parts) == 2 {
					eventID = parts[1]
				}
				return head, eventID
			}
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return auditlog.GenesisPrevHash, ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	head = auditlog.GenesisPrevHash
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev SecretAuditEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if ev.EventHash != "" {
			head = ev.EventHash
			eventID = ev.EventID
		}
	}
	return head, eventID
}

// RecomputeChainHead scans secrets.jsonl and verifies every EventHash against
// HashEvent(PrevHash, ev) with PrevHash linkage. Does not trust secrets.tip.
// Returns the verified tip head and its event ID (genesis/"0" when empty).
func RecomputeChainHead(path string) (head, eventID string, err error) {
	head, eventID, _, err = recomputeChain(path)
	return head, eventID, err
}

// recomputeChain is the full verify path: returns ordered EventHashes so a
// witnessed head can be checked for ancestry without trusting the tip sidecar.
//
// Retention: prune drops a prefix and inserts an immutable retention_checkpoint
// whose PrevHash is the last dropped EventHash. Witness verification uses
// checkpoint.WitnessedThrough (when set) plus the remaining chain. Kept event
// bytes are verified as stored (no rewrite); a single discontinuity is allowed
// immediately after a retention_checkpoint.
func recomputeChain(path string) (head, eventID string, hashes []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return auditlog.GenesisPrevHash, "", nil, nil
		}
		return "", "", nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	prev := auditlog.GenesisPrevHash
	head = auditlog.GenesisPrevHash
	lineNo := 0
	allowBreak := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lineNo++
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return "", "", nil, fmt.Errorf("secret audit chain line %d: malformed json: %w", lineNo, err)
		}
		storedPrev := strings.TrimSpace(ev.PrevHash)
		if storedPrev == "" {
			storedPrev = prev
		}
		wantHash := auditlog.HashEvent(storedPrev, ev)
		if ev.EventHash == "" || ev.EventHash != wantHash {
			return "", "", nil, fmt.Errorf("secret audit chain line %d: event_hash mismatch (got %q want %q)", lineNo, ev.EventHash, wantHash)
		}
		if strings.TrimSpace(ev.Kind) == secretAuditKindRetentionCheckpoint {
			// Checkpoint bridges deleted prefix; do not require genesis continuity.
			head = ev.EventHash
			eventID = ev.EventID
			hashes = append(hashes, ev.EventHash)
			prev = ev.EventHash
			allowBreak = true
			continue
		}
		if storedPrev != prev {
			if !allowBreak {
				return "", "", nil, fmt.Errorf("secret audit chain line %d: prev_hash mismatch (got %q want %q)", lineNo, storedPrev, prev)
			}
			// First kept event after a retention_checkpoint may still point at
			// a deleted predecessor — that discontinuity is expected.
		}
		allowBreak = false
		head = ev.EventHash
		eventID = ev.EventID
		hashes = append(hashes, ev.EventHash)
		prev = ev.EventHash
	}
	if err := sc.Err(); err != nil {
		return "", "", nil, err
	}
	return head, eventID, hashes, nil
}

func persistChainTip(path, head, eventID string) {
	_ = persistChainTipErr(path, head, eventID)
}

func persistChainTipErr(path, head, eventID string) error {
	if path == "" || head == "" {
		return nil
	}
	return writeFileAtomicDurable(path, []byte(head+"\n"+eventID+"\n"), 0o600)
}

func loadGapCount(path string) int64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func persistGapCount(path string, n int64) {
	if path == "" {
		return
	}
	_ = writeFileAtomicDurable(path, []byte(strconv.FormatInt(n, 10)+"\n"), 0o600)
}

func loadSpillOffset(path string) int64 {
	if path == "" {
		return 0
	}
	return loadGapCount(path)
}

func persistSpillOffset(path string, offset int64) error {
	if path == "" || offset < 0 {
		return errors.New("audit spill offset path or value is invalid")
	}
	return writeFileAtomicDurable(path, []byte(strconv.FormatInt(offset, 10)+"\n"), 0o600)
}

func clearGapCount(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
}

func (s *fileAuditSink) persistGapState(n int64) {
	if s == nil {
		return
	}
	s.gapMu.Lock()
	defer s.gapMu.Unlock()
	if n <= 0 {
		clearGapCount(s.gapPath)
		return
	}
	persistGapCount(s.gapPath, n)
}

func writeFileAtomicDurable(path string, data []byte, perm os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("durable sidecar path is empty")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	remove := true
	defer func() {
		_ = tmp.Close()
		if remove {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	remove = false
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Service) ensureSecretAuditSink() {
	if s == nil {
		return
	}
	s.secretAuditOnce.Do(func() {
		if s.secretAudit != nil {
			return
		}
		dataDir := secretAuditDataDir(s.cfg.DBPath)
		if dataDir == "" {
			s.secretAuditInitErr = errors.New("secret audit requires a non-empty DBPath")
			secretAuditSinkHealthy.Set(0)
			s.secretAudit = unavailableSecretAuditSink{}
			return
		}
		buf := defaultSecretAuditBuffer
		spill := false
		if s.cfg.EnterpriseMode {
			buf = enterpriseSecretAuditBuffer
			// Enterprise Emit must never block the request path: overflow goes
			// to secrets.spill.jsonl under flock; gap only if spill write fails.
			spill = true
		}
		sink, err := newFileAuditSinkOpts(filepath.Join(dataDir, "audit"), buf, spill)
		if err != nil {
			s.secretAuditInitErr = err
			secretAuditSinkHealthy.Set(0)
			if s.logger != nil {
				s.logger.Error("secret audit sink unavailable", "err", err)
			}
			s.secretAudit = unavailableSecretAuditSink{}
			return
		}
		secretAuditSinkHealthy.Set(1)
		s.secretAudit = sink
		s.secretAuditFile = sink
		// Prune rotates the hash chain — ship the new tip to the external
		// witness immediately so LastWitnessedHead tracks the re-linked head.
		sink.afterPrune = func() {
			_ = s.shipSecretAuditHead(context.Background())
		}
		s.startSecretAuditPruneTicker()
	})
}

// ValidateSecretAuditSink applies the boot policy after New has attempted to
// open the writer. Strict mode is the production default; the explicit false
// value remains useful to tests and emergency recovery, while metrics and drop
// accounting still make the degraded state visible. When an external witness
// is already installed, also runs ValidateSecretAuditWitness.
func (s *Service) ValidateSecretAuditSink() error {
	if s == nil {
		return nil
	}
	s.ensureSecretAuditSink()
	if s.secretAuditFile != nil {
		if err := s.secretAuditFile.Sync(); err != nil {
			s.secretAuditInitErr = fmt.Errorf("sync secret audit sink: %w", err)
		}
	}
	if s.secretAuditInitErr != nil && s.cfg.SecretAuditStrictBoot {
		return fmt.Errorf("initialize secret audit sink: %w", s.secretAuditInitErr)
	}
	if err := s.ValidateSecretAuditWitness(); err != nil {
		return err
	}
	return nil
}

// startSecretAuditPruneTicker runs retention once at start and once per day.
// Stopped by CloseSecretAuditSink — which awaits this goroutine before closing
// the writer channel.
func (s *Service) startSecretAuditPruneTicker() {
	if s == nil || s.secretAuditFile == nil {
		return
	}
	if s.secretAuditPruneStop != nil {
		return
	}
	stop := make(chan struct{})
	s.secretAuditPruneStop = stop
	s.secretAuditPruneDone.Add(1)
	go func() {
		defer s.secretAuditPruneDone.Done()
		_ = s.PruneSecretAudit(nil)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = s.PruneSecretAudit(nil)
			}
		}
	}()
}

func secretAuditDataDir(dbPath string) string {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return ""
	}
	return filepath.Dir(dbPath)
}

func (s *Service) secretAuditSink() SecretAuditSink {
	if s == nil {
		return nil
	}
	s.ensureSecretAuditSink()
	return s.secretAudit
}

func (s *Service) auditActor() string {
	if s == nil {
		return ""
	}
	if c := s.Cluster(); c != nil {
		return c.SelfNodeID()
	}
	return ""
}

// CloseSecretAuditSink flushes and stops the file writer. Idempotent.
// Stops retention first and awaits it so Prune cannot race Close's channel close.
func (s *Service) CloseSecretAuditSink() {
	if s == nil {
		return
	}
	s.stopSecretAuditWitnessLoop()
	s.stopSecretAuditExportLoop()
	if stop := s.secretAuditPruneStop; stop != nil {
		select {
		case <-stop:
		default:
			close(stop)
		}
		s.secretAuditPruneStop = nil
		s.secretAuditPruneDone.Wait()
	}
	if f := s.secretAuditFile; f != nil {
		f.Close()
	}
}

// beginSecretAudit records decrypt latency/error metrics and emits one audit
// event when the returned closure runs. Never blocks on audit I/O.
// correlationID may be empty — a fresh id is generated.
func beginSecretAudit(sink SecretAuditSink, sandboxID, ref, actor, correlationID string) func(error) {
	return beginSecretAuditInc(sink, sandboxID, ref, actor, correlationID, "")
}

func beginSecretAuditInc(sink SecretAuditSink, sandboxID, ref, actor, correlationID, incarnationID string) func(error) {
	metricDone := beginClusterSecretOpen()
	return func(err error) {
		metricDone(err)
		emitSecretAudit(sink, sandboxID, ref, actor, correlationID, incarnationID, err)
	}
}

func emitSecretAudit(sink SecretAuditSink, sandboxID, ref, actor, correlationID, incarnationID string, err error) {
	if sink == nil {
		return
	}
	if strings.TrimSpace(correlationID) == "" {
		correlationID = newSecretAuditCorrelationID()
	}
	ev := SecretAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         actor,
		SandboxID:     sandboxID,
		Ref:           ref,
		Result:        secretAuditResultSuccess,
		Reason:        secretAuditReasonOK,
		CorrelationID: correlationID,
		NodeID:        actor,
		IncarnationID: strings.TrimSpace(incarnationID),
		// Kind left empty (= secret_open) for back-compat with older readers.
	}
	if err != nil {
		ev.Result = secretAuditResultFailure
		ev.Reason = classifySecretAuditReason(err)
	}
	sink.Emit(ev)
}

// emitEgressAudit records a host-mediated egress destination for sandboxID.
// Async via the sink; nil sink / disabled attribution is a no-op (no panic).
// Bytes stay on the netstats totals path — per-destination bytes are not claimed.
func (s *Service) emitEgressAudit(sandboxID, network, destination string) {
	if s == nil || !s.cfg.EgressAttributionEnabled {
		return
	}
	sandboxID = strings.TrimSpace(sandboxID)
	destination = strings.TrimSpace(destination)
	if sandboxID == "" || destination == "" {
		return
	}
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	actor := s.auditActor()
	sink.Emit(SecretAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         actor,
		SandboxID:     sandboxID,
		Result:        secretAuditResultSuccess,
		Reason:        secretAuditReasonOK,
		NodeID:        actor,
		Kind:          secretAuditKindEgress,
		Destination:   destination,
		Network:       strings.TrimSpace(network),
		IncarnationID: s.secretIncarnationForSeal(sandboxID),
	})
}

// EgressAuditObserver returns a non-blocking callback for wasm/isolate mediators.
// Safe to install when attribution is disabled (returns a no-op).
func (s *Service) EgressAuditObserver() func(sandboxID, network, destination string) {
	if s == nil || !s.cfg.EgressAttributionEnabled {
		return func(string, string, string) {}
	}
	return func(sandboxID, network, destination string) {
		s.emitEgressAudit(sandboxID, network, destination)
	}
}

func newSecretAuditCorrelationID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%d-%x", time.Now().UnixNano(), b[:])
}

type secretAuditCorrelationKey struct{}

// ContextWithSecretAuditCorrelation attaches correlationID for audited loads
// (include_env, etc.). Empty id is a no-op.
func ContextWithSecretAuditCorrelation(ctx context.Context, correlationID string) context.Context {
	correlationID = strings.TrimSpace(correlationID)
	if ctx == nil || correlationID == "" {
		return ctx
	}
	return context.WithValue(ctx, secretAuditCorrelationKey{}, correlationID)
}

func correlationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(secretAuditCorrelationKey{}).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func classifySecretAuditReason(err error) string {
	if err == nil {
		return secretAuditReasonOK
	}
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		return secretAuditReasonNotFound
	case errors.Is(err, secrets.ErrRecipientDenied):
		return secretAuditReasonRecipientDenied
	case errors.Is(err, secrets.ErrVersionMismatch):
		return secretAuditReasonVersionMismatch
	case errors.Is(err, secrets.ErrDecryptFailed):
		return secretAuditReasonDecryptFailed
	}
	// Cipher.Decrypt and local seal paths may not wrap sentinels yet.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"):
		return secretAuditReasonNotFound
	case strings.Contains(msg, "not allowed to open"):
		return secretAuditReasonRecipientDenied
	case strings.Contains(msg, "version mismatch"):
		return secretAuditReasonVersionMismatch
	case strings.Contains(msg, "decrypt"), strings.Contains(msg, "sealed blob"), strings.Contains(msg, "cipher"):
		return secretAuditReasonDecryptFailed
	default:
		return secretAuditReasonError
	}
}

// sandboxIDFromSecretRef extracts the sandbox id from
// cluster-secret://sandbox/{id}/vN or .../i/{inc}/vN. Returns "" when the ref
// is not that shape.
func sandboxIDFromSecretRef(ref string) string {
	parsed, err := secrets.ParseRef(ref)
	if err != nil {
		return ""
	}
	return parsed.SandboxID
}

func registryAuditRef(sandboxID string) string {
	return "registry:" + strings.TrimSpace(sandboxID)
}

func mountsAuditRef(sandboxID string) string {
	return "mounts:" + strings.TrimSpace(sandboxID)
}

func envAuditRef(sandboxID string) string {
	return "env:" + strings.TrimSpace(sandboxID)
}

// memSecretAuditSink captures events for tests.
type memSecretAuditSink struct {
	mu     sync.Mutex
	events []SecretAuditEvent
}

func (m *memSecretAuditSink) Emit(ev SecretAuditEvent) {
	if m == nil {
		return
	}
	ensureSecretAuditEventID(&ev)
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	m.mu.Lock()
	m.events = append(m.events, ev)
	m.mu.Unlock()
}

func (m *memSecretAuditSink) Events() []SecretAuditEvent {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SecretAuditEvent, len(m.events))
	copy(out, m.events)
	return out
}
