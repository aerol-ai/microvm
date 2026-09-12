package service

import (
	"bufio"
	"bytes"
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
	// secretAuditReasonRateLimited marks the coalesced egress record that
	// stands for Dropped connections the sandbox's evidence budget refused
	// (see secret_audit_quota.go).
	secretAuditReasonRateLimited = "rate_limited"
	// secretAuditReasonTornTail marks a gap the sink chained at boot after
	// cutting an unterminated, unparseable tail that a crash left mid-append.
	secretAuditReasonTornTail = "torn_tail"

	// secretAuditKindSecretOpen is an explicit stored kind. Missing Kind is not
	// reinterpreted. secretAuditKindEgress is host-mediated destination
	// attribution (wasm NetMediator / isolate proxy) — never claim guest-side
	// secret use from these records.
	secretAuditKindSecretOpen          = "secret_open"
	secretAuditKindEgress              = "egress"
	secretAuditKindGap                 = "gap"
	secretAuditKindRetentionCheckpoint = "retention_checkpoint"
	// secretAuditKindRetentionRedacted is what retention leaves of an expired
	// record it cannot cut out of the chain: its two link hashes and nothing
	// that says who opened what. See redactSecretAuditEvent.
	secretAuditKindRetentionRedacted = "retention_redacted"

	defaultSecretAuditBuffer = 1024
	// enterpriseSecretAuditBuffer reduces spill likelihood under burst open
	// rates; Emit stays non-blocking and overflows to secrets.spill.jsonl.
	enterpriseSecretAuditBuffer = 8192
	// Bound the power-loss window for the local audit fallback. Enterprise
	// deployments must also configure an external durable/WORM witness.
	secretAuditSyncInterval = time.Second
	// secretAuditCrashBufferDays is what the local JSONL keeps when
	// SB_SECRET_AUDIT_RETENTION_DAYS=0: enough to survive a crash before the
	// export tailer catches up, and nothing that could be read as "forever".
	secretAuditCrashBufferDays = 1
	secretAuditFileName        = "secrets.jsonl"
	secretAuditSpillName       = auditlog.SpillFileName
	secretAuditSpillWorking    = "secrets.spill.jsonl.working"
	// secretAuditLockName is a stable sidecar flock target. Retention and
	// wasm workers lock this path *before* opening secrets.jsonl so a rename
	// during prune cannot leave writers appending to an unlinked inode.
	secretAuditLockName = auditlog.LockFileName
	// secretAuditTornName is the durable intent record for a boot-time tail
	// repair. Written before the truncate and removed after the gap marker is
	// chained, so a crash between the two cannot lose the record that evidence
	// was lost.
	secretAuditTornName = "secrets.torn"
	// secretAuditVerifiedName records how far the writer has verified and
	// fsynced the chain (offset, last record, head). In checkpoint boot mode
	// the next open verifies only what follows it, synchronously, and proves
	// the prefix again in the background.
	secretAuditVerifiedName = "secrets.verified"

	// Boot verification modes (SB_SECRET_AUDIT_BOOT_VERIFY).
	secretAuditBootVerifyFull       = "full"
	secretAuditBootVerifyCheckpoint = "checkpoint"
	// secretAuditMaxLineBytes bounds one JSONL record during chain scans; audit
	// lines are metadata-only, so anything larger is corruption, not evidence.
	secretAuditMaxLineBytes = 1024 * 1024
)

var (
	auditEventsDroppedTotal  = expvar.NewInt("aerolvm_audit_events_dropped_total")
	auditSpillMalformedTotal = expvar.NewInt("aerolvm_audit_spill_malformed_total")
	auditTipWriteFailTotal   = expvar.NewInt("aerolvm_audit_tip_write_fail_total")
	secretAuditSinkHealthy   = expvar.NewInt("aerolvm_secret_audit_sink_healthy")
	// Boot-time torn-tail repairs. Each one is also a gap marker in the chain
	// and a log line; the counters exist so the alert fires without log access.
	auditTornTailRepairsTotal = expvar.NewInt("aerolvm_audit_torn_tail_repairs_total")
	auditTornTailBytesTotal   = expvar.NewInt("aerolvm_audit_torn_tail_bytes_total")
	// Retention: records dropped with the prefix, and records behind a newer
	// one that were reduced to hash-only stubs instead (out-of-order arrival
	// via the spill drain or worker ingest). Both are expired records leaving
	// the log; the split says how much of the file is stubs.
	auditRetentionDroppedTotal  = expvar.NewInt("aerolvm_audit_retention_dropped_total")
	auditRetentionRedactedTotal = expvar.NewInt("aerolvm_audit_retention_redacted_total")
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

// unavailableSecretAuditSink keeps a failed writer loud after non-strict boot:
// every event that could not be persisted is counted, and the health gauge
// remains zero. This avoids the previous permanent, silent noop fallback.
type unavailableSecretAuditSink struct{}

func (unavailableSecretAuditSink) Emit(SecretAuditEvent) {
	auditEventsDroppedTotal.Add(1)
}

type auditWriteReq struct {
	ev                    SecretAuditEvent
	durable               chan error // when non-nil, report the fsynced event result
	sync                  chan error // when non-nil, writer fsyncs after draining prior work
	pruneCutoff           time.Time  // when non-zero, rewrite file dropping older events
	pruneExportCursorPath string     // require cursor to cover the locked file generation/size
	pruneWitnessedHead    string     // require the locked chain tip to equal this witnessed head
	pruneDone             chan error
}

var errSecretAuditPruneGuardChanged = errors.New("secret audit advanced beyond the verified retention guard")

// fileAuditSink appends JSON Lines under {DataDir}/audit/secrets.jsonl via a
// single writer goroutine. Emit is always non-blocking: a full buffer either
// drops (open-source) or enqueues onto spillCh (enterprise) for the writer to
// durable-append — Emit never fsyncs. Gap markers are recorded only when
// evidence cannot be persisted (drop path or failed spill accept). The writer
// drains one spill segment before channel work so spilled events land ahead of
// later in-memory sends without allowing a continuously replenished spill file
// to starve durable requests indefinitely.
//
// sendMu guards the channels against Close so Emit/Sync/Prune never send on a
// closed channel (check-then-send race under -race / daemon shutdown). It is
// an RWMutex held on the read side by every sender, so senders never exclude
// one another: Sync, EmitDurable and Prune legitimately wait for a slot while
// the writer is busy (retention on a large file holds it for a long time), and
// that wait must not stall Emit — a StartSandbox secret open would otherwise
// sit behind a blocked witness ship or worker ingest for the whole prune.
// Close takes the write side, which waits for in-flight sends and then closes.
type fileAuditSink struct {
	ch         chan auditWriteReq
	spillCh    chan SecretAuditEvent // enterprise overflow; drained by writer
	pendingGap atomic.Int64          // coalesced drop count awaiting a gap marker write
	closed     atomic.Bool
	// spillEnabled (enterprise): buffer-full Emit enqueues to spillCh instead
	// of dropping. Gap only if spillCh cannot accept quickly.
	spillEnabled bool
	// sendMu: read side for senders, write side for Close (see the type
	// comment). Spill file I/O runs on the writer goroutine so Emit never
	// holds it across disk waits either.
	sendMu           sync.RWMutex
	spillMu          sync.Mutex
	gapMu            sync.Mutex
	done             chan struct{}
	path             string
	lockPath         string
	gapPath          string
	tipPath          string
	spillPath        string
	spillWorkingPath string
	tornPath         string
	verifiedPath     string
	witnessTipPath   string // optional; prune reads WitnessedThrough from here
	file             *os.File
	// bootVerify is the boot mode; bootScan is what open verified (with the
	// witness tip probed) so boot-time witness validation needs no second
	// pass; bootTrusted is how many prefix bytes open accepted from the
	// verified checkpoint instead of re-reading (0 = the whole file was read).
	bootVerify  string
	bootScan    secretAuditChainScan
	bootTrusted int64
	// bootRepair is set when this open truncated a torn tail and chained the
	// corresponding gap marker; the Service logs it once at sink init.
	bootRepair *secretAuditTornTailRepair
	chainMu    sync.Mutex
	chainHead  string
	chainEvent string
	// lastLineOffset is where the record carrying chainHead starts; the
	// verified checkpoint pins it so boot can re-read that one record.
	lastLineOffset int64
	writePoison    error // append outcome became ambiguous; refuse later writes
	// writeHook, when set (tests), runs before each file write and may block.
	writeHook func()
	// afterPrune, when set (Service), ships a new witness tip after prune
	// inserts a retention_checkpoint (retained event bytes are unchanged).
	afterPrune func()
	// afterAppend, when set (Service), receives every appended batch with
	// its file offsets, after the flock is released, on the writer goroutine.
	// The per-sandbox read index is built from it.
	afterAppend func([]secretAuditIndexedLine)
	// onPruneShift, when set (Service), runs inside the retention flock right
	// after the rewritten file is in place, so the read index can re-base
	// before anyone can open the new file.
	onPruneShift func(secretAuditPruneShift)
	// egressQuota is the per-sandbox egress evidence budget, applied on the
	// writer goroutine at every funnel a record can take. nil = unbounded.
	egressQuota *egressAuditQuota
}

// fileAuditSinkOptions configures newFileAuditSinkFrom. Zero values keep the
// built-in defaults; EgressRate 0 leaves egress evidence unbudgeted.
type fileAuditSinkOptions struct {
	buffer       int
	spillEnabled bool
	bootVerify   string
	// EgressRate / EgressBurst are the per-sandbox egress token bucket
	// (records per second, burst). EgressMarkerDelay is how long a refused
	// count accumulates before its coalesced record is written.
	egressRate        float64
	egressBurst       int
	egressMarkerDelay time.Duration
}

func newFileAuditSink(auditDir string, buffer int) (*fileAuditSink, error) {
	return newFileAuditSinkOpts(auditDir, buffer, false)
}

func newFileAuditSinkOpts(auditDir string, buffer int, spillEnabled bool) (*fileAuditSink, error) {
	return newFileAuditSinkWith(auditDir, buffer, spillEnabled, secretAuditBootVerifyFull)
}

// newFileAuditSinkWith opens the sink with an explicit boot verification
// mode: "full" re-verifies every record before the writer opens; "checkpoint"
// verifies from the last fsynced checkpoint and leaves the prefix to the
// Service's background pass.
func newFileAuditSinkWith(auditDir string, buffer int, spillEnabled bool, bootVerify string) (*fileAuditSink, error) {
	return newFileAuditSinkFrom(auditDir, fileAuditSinkOptions{buffer: buffer, spillEnabled: spillEnabled, bootVerify: bootVerify})
}

func newFileAuditSinkFrom(auditDir string, opts fileAuditSinkOptions) (*fileAuditSink, error) {
	buffer, spillEnabled, bootVerify := opts.buffer, opts.spillEnabled, opts.bootVerify
	if buffer <= 0 {
		buffer = defaultSecretAuditBuffer
	}
	if bootVerify != secretAuditBootVerifyCheckpoint {
		bootVerify = secretAuditBootVerifyFull
	}
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return nil, fmt.Errorf("secret audit mkdir: %w", err)
	}
	s := &fileAuditSink{
		ch:               make(chan auditWriteReq, buffer),
		spillCh:          make(chan SecretAuditEvent, buffer),
		done:             make(chan struct{}),
		path:             filepath.Join(auditDir, secretAuditFileName),
		lockPath:         filepath.Join(auditDir, auditlog.LockFileName),
		gapPath:          filepath.Join(auditDir, "secrets.gap"),
		tipPath:          filepath.Join(auditDir, "secrets.tip"),
		spillPath:        filepath.Join(auditDir, auditlog.SpillFileName),
		spillWorkingPath: filepath.Join(auditDir, secretAuditSpillWorking),
		tornPath:         filepath.Join(auditDir, secretAuditTornName),
		verifiedPath:     filepath.Join(auditDir, secretAuditVerifiedName),
		witnessTipPath:   filepath.Join(auditDir, secretAuditWitnessTipFile),
		spillEnabled:     spillEnabled,
		bootVerify:       bootVerify,
		egressQuota:      newEgressAuditQuota(opts.egressRate, opts.egressBurst, opts.egressMarkerDelay),
	}
	// Probe the sidecar lock read-write once: withAuditFileLock opens it
	// read-only (a directory or unwritable path would pass), and a lock the
	// daemon cannot own must fail here, not on the first append.
	lockProbe, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("secret audit lock open: %w", err)
	}
	_ = lockProbe.Close()
	// Hold the stable sidecar lock across verify, repair, and open so retention
	// rename cannot race a concurrent open+append onto an unlinked inode, and so
	// no reader can snapshot a tail this open is about to cut.
	if err := s.withAuditFileLock(s.openLocked); err != nil {
		return nil, err
	}
	go s.loop()
	return s, nil
}

// openLocked verifies the chain, repairs what a crash mid-append can leave,
// opens the append handle, and chains the repair marker before any new event.
//
// Appends are one write per batch and fsynced on a ticker, so an unclean
// shutdown can leave a strict byte-prefix of the last batch on disk. Refusing
// to open on that tail would turn every OOM-kill or power loss into a node
// that cannot boot under strict mode, while the tail itself proves nothing was
// tampered with: every complete line before it still verifies. Cut it, keep
// the verified prefix as the chain head, and record the loss in-stream.
//
// Anything else — malformed JSON that *was* fully written, or a valid record
// whose hash does not link — is corruption or tampering and still fails closed.
func (s *fileAuditSink) openLocked() error {
	// Probe for the last witnessed head in the same pass so boot-time witness
	// validation does not read the file a second time.
	var probe []string
	if tip, err := readWitnessTip(s.witnessTipPath); err == nil && strings.TrimSpace(tip.HeadHex) != "" {
		probe = []string{strings.TrimSpace(tip.HeadHex)}
	}
	scan, trusted, err := s.bootScanLocked(probe)
	if err != nil {
		return fmt.Errorf("verify secret audit chain: %w", err)
	}
	s.bootScan = scan
	s.bootTrusted = trusted
	pendingRepair := loadTornTailRepair(s.tornPath)
	if scan.tornBytes > 0 {
		rec := secretAuditTornTailRepair{Offset: scan.validEnd, Bytes: scan.tornBytes, Dropped: 1}
		switch {
		case pendingRepair == nil:
		case pendingRepair.Offset == scan.validEnd:
			// The same tear: an earlier open recorded it but did not finish
			// (the truncate failed, or it crashed while writing the marker).
			// Keep the first accounting so one loss is never reported twice.
			rec.Dropped = pendingRepair.Dropped
			rec.Bytes = max(rec.Bytes, pendingRepair.Bytes)
		default:
			// A marker was still owed at another offset and a new tear
			// appeared after it: both losses are real.
			rec.Bytes += pendingRepair.Bytes
			rec.Dropped += pendingRepair.Dropped
		}
		// Durable intent before the destructive write: if the marker append
		// below fails, the next open still owes the stream this gap.
		if err := persistTornTailRepair(s.tornPath, rec); err != nil {
			return fmt.Errorf("record secret audit torn-tail repair: %w", err)
		}
		pendingRepair = &rec
	}
	if scan.tornBytes > 0 || scan.missingNewline {
		if err := repairSecretAuditTail(s.path, scan); err != nil {
			return fmt.Errorf("repair secret audit tail: %w", err)
		}
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("secret audit open: %w", err)
	}
	s.file = f
	// Never continue from the sidecar tip: it can lag or lead the file after a
	// crash, and either forks the chain. The verified scan is authoritative.
	s.chainHead = scan.head
	s.chainEvent = scan.eventID
	s.lastLineOffset = scan.lastLineStart
	if pending := loadGapCount(s.gapPath); pending > 0 {
		s.pendingGap.Store(pending)
	}
	if pendingRepair == nil {
		// Whatever open verified is what the next boot may start from.
		s.persistVerifiedLocked()
		return nil
	}
	// Dropped is a floor: exactly one partial record was visible on disk, but
	// events still in the page cache at the crash left no trace at all.
	marker := SecretAuditEvent{
		Time:    time.Now().UTC(),
		Result:  secretAuditResultGap,
		Reason:  secretAuditReasonTornTail,
		Kind:    secretAuditKindGap,
		Dropped: pendingRepair.Dropped,
	}
	if _, err := s.appendBatchLocked([]SecretAuditEvent{marker}, true); err != nil {
		_ = f.Close()
		s.file = nil
		return fmt.Errorf("record secret audit torn-tail gap marker: %w", err)
	}
	_ = os.Remove(s.tornPath)
	s.bootScan.head, s.bootScan.eventID = s.chainHead, s.chainEvent
	s.persistVerifiedLocked()
	s.bootRepair = pendingRepair
	auditTornTailRepairsTotal.Add(1)
	auditTornTailBytesTotal.Add(pendingRepair.Bytes)
	return nil
}

// bootScanLocked verifies the file for open. In checkpoint mode a valid
// secrets.verified sidecar lets it start from the last fsynced record and
// read only what came after — O(bytes since the last sync) instead of
// O(retained volume) — returning how many prefix bytes it trusted. Anything
// wrong with the sidecar (missing, stale, pointing past EOF, or naming a
// record the file no longer holds) falls back to reading everything.
func (s *fileAuditSink) bootScanLocked(probe []string) (secretAuditChainScan, int64, error) {
	if s.bootVerify == secretAuditBootVerifyCheckpoint {
		if cp := loadVerifiedCheckpoint(s.verifiedPath); cp != nil {
			scan, ok, err := scanSecretAuditChainFromCheckpoint(s.path, cp, probe)
			if err != nil {
				return scan, 0, err
			}
			if ok {
				return scan, cp.Offset, nil
			}
		}
	}
	scan, err := scanSecretAuditChainWith(s.path, secretAuditScanOptions{probe: probe})
	return scan, 0, err
}

// secretAuditVerifiedCheckpoint is the secrets.verified sidecar: the writer
// records it after every fsync, so it always names a record that is durable
// and was appended by a chain the writer had verified.
type secretAuditVerifiedCheckpoint struct {
	Offset     int64  `json:"offset"`      // bytes verified and fsynced
	LineOffset int64  `json:"line_offset"` // start of the record carrying Head
	Head       string `json:"head"`
	EventID    string `json:"event_id"`
}

func loadVerifiedCheckpoint(path string) *secretAuditVerifiedCheckpoint {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cp secretAuditVerifiedCheckpoint
	if json.Unmarshal(raw, &cp) != nil || cp.Offset <= 0 || cp.LineOffset < 0 || cp.LineOffset >= cp.Offset ||
		cp.Offset-cp.LineOffset > secretAuditMaxLineBytes || strings.TrimSpace(cp.Head) == "" {
		return nil
	}
	return &cp
}

// persistVerifiedLocked records the writer's current durable head. Called
// under the audit flock right after a successful fsync, and after retention
// rewrote the file. Best effort: a missing sidecar only costs the next boot
// a full read.
func (s *fileAuditSink) persistVerifiedLocked() {
	if s == nil || s.verifiedPath == "" || s.file == nil {
		return
	}
	st, err := s.file.Stat()
	if err != nil {
		return
	}
	s.chainMu.Lock()
	cp := secretAuditVerifiedCheckpoint{Offset: st.Size(), LineOffset: s.lastLineOffset, Head: s.chainHead, EventID: s.chainEvent}
	s.chainMu.Unlock()
	if cp.Offset <= 0 || cp.Head == "" || cp.Head == auditlog.GenesisPrevHash || cp.LineOffset >= cp.Offset {
		_ = os.Remove(s.verifiedPath)
		return
	}
	raw, err := json.Marshal(cp)
	if err != nil {
		return
	}
	_ = writeFileAtomicDurable(s.verifiedPath, append(raw, '\n'), 0o600)
}

// scanSecretAuditChainFromCheckpoint re-reads only the checkpoint's own
// record (it must still be there, byte-for-byte hashing to Head, and end on
// a newline) and then verifies everything after it, continuing the chain
// from that head. ok=false means the checkpoint does not describe this file
// and the caller must read it all.
func scanSecretAuditChainFromCheckpoint(path string, cp *secretAuditVerifiedCheckpoint, probe []string) (secretAuditChainScan, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return secretAuditChainScan{head: auditlog.GenesisPrevHash}, false, nil
		}
		return secretAuditChainScan{}, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return secretAuditChainScan{}, false, err
	}
	if st.Size() < cp.Offset {
		return secretAuditChainScan{}, false, nil
	}
	buf := make([]byte, cp.Offset-cp.LineOffset)
	if _, err := f.ReadAt(buf, cp.LineOffset); err != nil {
		return secretAuditChainScan{}, false, nil
	}
	if buf[len(buf)-1] != '\n' {
		return secretAuditChainScan{}, false, nil
	}
	var ev SecretAuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf), &ev); err != nil || ev.EventHash != cp.Head || verifySecretAuditRecord(ev) != nil {
		return secretAuditChainScan{}, false, nil
	}
	verifier := newSecretAuditChainVerifier()
	verifier.prev = cp.Head
	verifier.started = true
	verifier.allowBreak = ev.Kind == secretAuditKindRetentionCheckpoint
	scan, err := scanSecretAuditChainReader(io.NewSectionReader(f, cp.Offset, st.Size()-cp.Offset), secretAuditScanOptions{
		base:            cp.Offset,
		verifier:        &verifier,
		startEventID:    cp.EventID,
		startLineOffset: cp.LineOffset,
		probe:           probe,
	})
	if err != nil {
		return scan, true, err
	}
	for _, h := range probe {
		if h == cp.Head {
			scan.markFound(h)
		}
	}
	if ev.Kind == secretAuditKindRetentionCheckpoint && strings.TrimSpace(ev.WitnessedThrough) != "" && scan.witnessedThrough == "" {
		scan.witnessedThrough = strings.TrimSpace(ev.WitnessedThrough)
	}
	return scan, true, nil
}

// repairSecretAuditTail makes the file end exactly on a newline-terminated,
// verified line. Caller holds the audit flock. The two cases are exclusive: a
// torn tail is cut back to validEnd; a complete final record that only lost
// its terminator gets one, or the next append would be glued onto it.
func repairSecretAuditTail(path string, scan secretAuditChainScan) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if scan.tornBytes > 0 {
		if err := f.Truncate(scan.validEnd); err != nil {
			_ = f.Close()
			return err
		}
	}
	if scan.missingNewline {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := f.Write([]byte{'\n'}); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// secretAuditTornTailRepair is the durable intent record behind secrets.torn.
type secretAuditTornTailRepair struct {
	Offset  int64 `json:"offset"`
	Bytes   int64 `json:"bytes"`
	Dropped int64 `json:"dropped"`
}

// loadTornTailRepair returns the pending repair, or nil when none is owed. A
// sidecar that exists but cannot be parsed still owes at least one marker —
// only this process writes it, so garbage there is not a reason to forget.
func loadTornTailRepair(path string) *secretAuditTornTailRepair {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var rec secretAuditTornTailRepair
	if json.Unmarshal(raw, &rec) != nil || rec.Dropped <= 0 {
		return &secretAuditTornTailRepair{Dropped: 1}
	}
	return &rec
}

func persistTornTailRepair(path string, rec secretAuditTornTailRepair) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return writeFileAtomicDurable(path, append(raw, '\n'), 0o600)
}

func (s *fileAuditSink) Emit(ev SecretAuditEvent) {
	if s == nil || s.closed.Load() {
		// Checked before the lock: once Close has begun it holds or awaits
		// the write side, and a request-path Emit must not queue behind it.
		return
	}
	s.sendMu.RLock()
	if s.closed.Load() {
		s.sendMu.RUnlock()
		return
	}
	req := auditWriteReq{ev: ev}
	select {
	case s.ch <- req:
		s.sendMu.RUnlock()
		return
	default:
	}
	// Never fsync on the Emit path. Prefer a non-blocking spillCh handoff;
	// the writer durable-appends. If spillCh is also full, record a gap.
	if s.spillEnabled {
		select {
		case s.spillCh <- ev:
			s.sendMu.RUnlock()
			return
		default:
		}
	}
	s.sendMu.RUnlock()
	auditEventsDroppedTotal.Add(1)
	s.pendingGap.Add(1)
}

func (s *fileAuditSink) EmitDurable(ev SecretAuditEvent) error {
	if s == nil {
		return errors.New("secret audit sink unavailable")
	}
	done := make(chan error, 1)
	s.sendMu.RLock()
	if s.closed.Load() {
		s.sendMu.RUnlock()
		return errors.New("secret audit sink closed")
	}
	// Durable means waiting for a slot when the writer is busy. The read side
	// keeps Close from closing the channel mid-send without excluding Emit.
	s.ch <- auditWriteReq{ev: ev, durable: done}
	s.sendMu.RUnlock()
	return <-done
}

// Sync blocks until every previously accepted event (and any pending gap
// marker) has been written and fsynced. No-op on a nil or closed sink.
func (s *fileAuditSink) Sync() error {
	if s == nil {
		return nil
	}
	done := make(chan error, 1)
	s.sendMu.RLock()
	if s.closed.Load() {
		s.sendMu.RUnlock()
		return nil
	}
	// Sync must not drop — wait for buffer space on the read side so Close
	// cannot close(ch) mid-send and Emit is not held up meanwhile.
	s.ch <- auditWriteReq{sync: done}
	s.sendMu.RUnlock()
	return <-done
}

// Close stops the writer and closes the file. Safe to call once.
// Callers must stop retention (and await it) before Close so Prune cannot race.
//
// closed flips first so new Emits return without touching the lock; the write
// side then waits for senders already inside (a Sync or EmitDurable waiting
// for a slot completes once the writer drains, which it keeps doing until the
// channel is closed here) and only then closes the channels.
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
		// Then service at least one channel/ticker operation before another
		// segment so a hot worker spill cannot starve EmitDurable or Sync.
		_ = s.drainSpill()
		select {
		case ev, ok := <-s.spillCh:
			if !ok {
				s.spillCh = nil
				continue
			}
			s.spillQueued(ev)
		case next, ok := <-s.ch:
			if !ok {
				// Drain remaining spill queue then spill file on shutdown.
				for s.spillCh != nil {
					ev, ok := <-s.spillCh
					if !ok {
						s.spillCh = nil
						break
					}
					s.spillQueued(ev)
				}
				for s.drainSpill() {
				}
				s.flushEgressQuotaMarkers(true)
				flushGap()
				_ = s.syncFile()
				return
			}
			flushGap()
			if next.pruneDone != nil {
				next.pruneDone <- s.pruneLocked(next.pruneCutoff, next.pruneExportCursorPath, next.pruneWitnessedHead)
				continue
			}
			flushSpill := func() {
				for s.spillCh != nil {
					select {
					case ev, ok := <-s.spillCh:
						if !ok {
							s.spillCh = nil
						} else {
							s.spillQueued(ev)
						}
						continue
					default:
					}
					break
				}
				for s.drainSpill() {
				}
			}
			if next.sync != nil {
				// Sync must observe spilled events: flush spillCh → spill file → JSONL.
				flushSpill()
				s.flushEgressQuotaMarkers(false)
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
						s.flushEgressQuotaMarkers(false)
						flushGap()
						control.sync <- s.syncFile()
					} else {
						control.pruneDone <- s.pruneLocked(control.pruneCutoff, control.pruneExportCursorPath, control.pruneWitnessedHead)
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
				// The budget decides here, at the funnel, so a record refused
				// on one path cannot re-enter on another; a durable caller
				// learns the refusal instead of a write result.
				kept, suppressed := s.egressQuota.admit(events)
				var err error
				if len(kept) > 0 {
					err = s.writeEventBatch(kept, durable, true)
				}
				for i := range end {
					if queued[i].durable == nil {
						continue
					}
					if suppressed != nil && suppressed[i] {
						queued[i].durable <- errAuditRateLimited
					} else {
						queued[i].durable <- err
					}
				}
				queued = queued[end:]
			}
		case <-ticker.C:
			s.flushEgressQuotaMarkers(false)
			flushGap()
			_ = s.syncFile()
		}
	}
}

// flushEgressQuotaMarkers writes the coalesced records owed by sandboxes the
// budget refused (all of them when force is set, for shutdown). Writer
// goroutine only.
func (s *fileAuditSink) flushEgressQuotaMarkers(force bool) {
	markers := s.egressQuota.owedMarkers(force)
	if len(markers) == 0 {
		return
	}
	_ = s.writeEventBatch(markers, false, true)
}

// appendSpill durable-appends a batch under the audit flock when the
// in-memory channel is full. Used by enterprise Emit so request paths never
// block and evidence is not silently discarded. One fsync per batch bounds
// the loss window without paying a disk barrier per event. The writer is
// auditlog.SpillFile, shared with the WASM worker subprocesses that spill
// into the same file.
func (s *fileAuditSink) appendSpill(events ...SecretAuditEvent) error {
	if s == nil || s.spillPath == "" {
		return errors.New("secret audit spill path unset")
	}
	s.spillMu.Lock()
	defer s.spillMu.Unlock()
	return auditlog.SpillFile{Path: s.spillPath, LockPath: s.lockPath}.Append(events)
}

// spillBatchMax bounds one group-committed spill append so a saturated
// overflow queue cannot starve the writer's other work (durable requests,
// sync, prune) behind one huge write.
const spillBatchMax = 256

// spillQueued group-commits first plus whatever else is already queued on
// spillCh (up to spillBatchMax). Drops are accounted per event, as one
// coalesced gap.
func (s *fileAuditSink) spillQueued(first SecretAuditEvent) {
	batch := append(make([]SecretAuditEvent, 0, spillBatchMax), first)
	for len(batch) < spillBatchMax {
		select {
		case ev, ok := <-s.spillCh:
			if !ok {
				s.spillCh = nil
			} else {
				batch = append(batch, ev)
				continue
			}
		default:
		}
		break
	}
	if err := s.appendSpill(batch...); err != nil {
		auditEventsDroppedTotal.Add(int64(len(batch)))
		n := s.pendingGap.Add(int64(len(batch)))
		s.persistGapState(n)
	}
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
		// Worker-spilled records take the same budget as everything else:
		// the spill file is a path into the log, not around the quota.
		kept, _ := s.egressQuota.admit(batch)
		if len(kept) > 0 {
			if err := s.writeEventBatch(kept, true, false); err != nil {
				return false
			}
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
		if err := persistChainTipErr(s.tipPath, head, eventID); err != nil {
			return err
		}
		s.persistVerifiedLocked()
		return nil
	})
	if err != nil {
		secretAuditSinkHealthy.Set(0)
	}
	return err
}

// Prune removes events (and gap markers) older than cutoff wherever they sit
// in the file: the expired prefix is dropped, expired records behind a fresh
// one become hash-only stubs (see pruneLocked). Serialized on the
// writer goroutine so it cannot race appends.
func (s *fileAuditSink) Prune(cutoff time.Time) error {
	return s.pruneWithGuards(cutoff, "", "")
}

// pruneWithGuards atomically rechecks off-node export and witness watermarks
// against the exact writer-serialized file that will be rewritten. The
// service performs network I/O before enqueueing this request; these guards
// close the append-between-check-and-prune window without blocking audit writes
// on an external service.
func (s *fileAuditSink) pruneWithGuards(cutoff time.Time, exportCursorPath, witnessedHead string) error {
	if s == nil {
		return nil
	}
	done := make(chan error, 1)
	s.sendMu.RLock()
	if s.closed.Load() {
		s.sendMu.RUnlock()
		return nil
	}
	s.ch <- auditWriteReq{
		pruneCutoff:           cutoff,
		pruneExportCursorPath: strings.TrimSpace(exportCursorPath),
		pruneWitnessedHead:    strings.TrimSpace(witnessedHead),
		pruneDone:             done,
	}
	s.sendMu.RUnlock()
	return <-done
}

func (s *fileAuditSink) withAuditFileLock(fn func() error) error {
	lockPath := s.lockPath
	if lockPath == "" {
		lockPath = s.path + ".lock"
	}
	// The sidecar is only a flock target and never stores data.
	return auditlog.WithFileLock(lockPath, fn)
}

func (s *fileAuditSink) pruneLocked(cutoff time.Time, exportCursorPath, witnessedHead string) error {
	if cutoff.IsZero() {
		return nil
	}
	pruned := false
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
		if exportCursorPath != "" {
			generation, generationErr := auditFileGeneration(src)
			if generationErr != nil {
				_ = src.Close()
				return generationErr
			}
			stat, statErr := src.Stat()
			if statErr != nil {
				_ = src.Close()
				return statErr
			}
			cursor := loadAuditExportCursor(exportCursorPath)
			if stat.Size() > 0 && (cursor.Generation != generation || cursor.Offset < stat.Size()) {
				_ = src.Close()
				return errSecretAuditPruneGuardChanged
			}
		}
		scanner := bufio.NewScanner(src)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		var lastDroppedHash string
		witnessedThrough := ""
		witnessCandidate := ""
		if tip, tipErr := readWitnessTip(s.witnessTipPath); tipErr == nil {
			witnessCandidate = strings.TrimSpace(tip.HeadHex)
		}
		// Pass 1 decides what the rewrite will do. Retention is by time, not
		// by position: the expired head of the file is dropped (the chain can
		// lose a prefix and keep verifying from a checkpoint), and expired
		// records that sit behind a newer one — the spill drain and worker
		// ingest land older events after newer ones — cannot be cut out of
		// the chain, so pass 2 reduces them to hash-only stubs: the payload
		// goes, the link stays. Stopping at the first fresh record would keep
		// those for as long as the record in front of them lives.
		droppedLines := 0   // lines pass 2 skips, the leading checkpoint included
		droppedRecords := 0 // expired records among them
		redactRecords := 0  // expired records behind a fresh one
		droppingPrefix := true
		var priorCheckpoint *SecretAuditEvent
		verifier := newSecretAuditChainVerifier()
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
			if err := verifier.Add(ev); err != nil {
				_ = src.Close()
				return fmt.Errorf("secret audit retention encountered invalid chain: %w", err)
			}
			if ev.Kind == secretAuditKindRetentionCheckpoint {
				// The leading checkpoint (the verifier guarantees it is first)
				// is re-minted by every rewrite — it is the file's generation
				// marker and the new one carries its ancestry — but it never
				// causes a rewrite by itself: a daily rewrite of an unchanged
				// file would restart the exporter for nothing.
				cp := ev
				priorCheckpoint = &cp
				droppedLines++
				continue
			}
			expired := secretAuditExpired(ev, cutoff)
			if droppingPrefix && expired {
				droppedLines++
				droppedRecords++
				if ev.EventHash != "" {
					lastDroppedHash = ev.EventHash
					if ev.EventHash == witnessCandidate {
						witnessedThrough = witnessCandidate
					}
				}
				continue
			}
			droppingPrefix = false
			if expired && ev.Kind != secretAuditKindRetentionRedacted {
				redactRecords++
			}
		}
		if err := scanner.Err(); err != nil {
			_ = src.Close()
			return err
		}
		if witnessedHead != "" && verifier.prev != witnessedHead {
			_ = src.Close()
			return errSecretAuditPruneGuardChanged
		}
		if droppedRecords == 0 && redactRecords == 0 {
			_ = src.Close()
			return nil
		}
		if priorCheckpoint != nil {
			// Nothing dropped this time: the new checkpoint stands where the
			// old one did, naming the same dropped ancestor. And a witness that
			// is still parked on a head the first prune dropped must stay
			// verifiable through the second: carry WitnessedThrough forward
			// unless this prune dropped the witnessed head itself.
			if lastDroppedHash == "" {
				lastDroppedHash = strings.TrimSpace(priorCheckpoint.PrevHash)
			}
			if witnessedThrough == "" {
				witnessedThrough = strings.TrimSpace(priorCheckpoint.WitnessedThrough)
			}
		}
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			_ = src.Close()
			return err
		}

		// Carry the exact witnessed ancestor when it falls anywhere in the
		// dropped prefix. Requiring it to equal the last dropped event would make
		// a legitimately lagging witness unverifiable after retention.
		cp := SecretAuditEvent{
			// Anchor the checkpoint at the retained boundary: it records where
			// retention stands. Its time never decides anything — the leading
			// checkpoint is re-minted by every rewrite and triggers none.
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

		// Pass 2: stream kept lines through unchanged (no rehash), tracking
		// exact byte positions so the read index can be re-based by one
		// constant instead of rebuilt: every kept line moves by
		// checkpointLen - floor as long as it is copied byte-for-byte. An
		// expired record behind a fresh one is written as its stub instead;
		// the stub is shorter, so what follows moves by a different delta and
		// the index rebuilds (once, on a day retention actually redacted).
		shift := secretAuditPruneShift{
			generation:     auditGenerationOfLine(line),
			checkpointLen:  int64(len(line)) + 1,
			checkpointHash: cp.EventHash,
			exact:          true,
		}
		br := bufio.NewReaderSize(src, 64*1024)
		remainingDrops := droppedLines
		redacted := 0
		var srcPos int64
		dstPos := shift.checkpointLen
		lastKeptLineOffset := int64(0) // the checkpoint line, until a record is kept
		floorSet := false
		for {
			rawLine, consumed, _, tooLong, err := readSecretAuditLine(br)
			if err != nil {
				_ = f.Close()
				_ = src.Close()
				return err
			}
			if consumed == 0 {
				break
			}
			lineStart := srcPos
			srcPos += consumed
			if tooLong {
				_ = f.Close()
				_ = src.Close()
				return fmt.Errorf("secret audit retention encountered a record over %d bytes", secretAuditMaxLineBytes)
			}
			raw := bytes.TrimSpace(rawLine)
			if len(raw) == 0 {
				if floorSet {
					shift.exact = false // a dropped blank line moves what follows
				}
				continue
			}
			if remainingDrops > 0 {
				remainingDrops--
				continue
			}
			if !floorSet {
				shift.floor = lineStart
				floorSet = true
			}
			if int64(len(raw))+1 != consumed {
				shift.exact = false // re-normalized whitespace changes the line's length
			}
			var ev SecretAuditEvent
			if err := json.Unmarshal(raw, &ev); err != nil {
				_ = f.Close()
				_ = src.Close()
				return fmt.Errorf("secret audit retention event changed between passes: %w", err)
			}
			if secretAuditExpired(ev, cutoff) && ev.Kind != secretAuditKindRetentionRedacted {
				stub, err := json.Marshal(redactSecretAuditEvent(ev))
				if err != nil {
					_ = f.Close()
					_ = src.Close()
					return err
				}
				raw = stub
				redacted++
				shift.exact = false
			}
			if _, err := writer.Write(raw); err != nil {
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
				lastKeptLineOffset = dstPos
			}
			dstPos += int64(len(raw)) + 1
		}
		if !floorSet {
			shift.floor = srcPos // nothing kept: every indexed offset is below the floor
		}
		shift.delta = shift.checkpointLen - shift.floor
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
		s.lastLineOffset = lastKeptLineOffset
		s.chainMu.Unlock()
		persistChainTip(s.tipPath, lastKeptHash, lastKeptEventID)
		// The rewritten file is fsynced; its offsets are new, so re-pin the
		// verified checkpoint now rather than leave a stale one for boot to
		// reject.
		s.persistVerifiedLocked()
		if s.onPruneShift != nil {
			s.onPruneShift(shift)
		}
		auditRetentionDroppedTotal.Add(int64(droppedRecords))
		auditRetentionRedactedTotal.Add(int64(redacted))
		pruned = true
		return nil
	})
	if err != nil {
		return err
	}
	if pruned && s.afterPrune != nil {
		// Witness I/O is external and may consume its full timeout. Retention is
		// serialized on the audit writer, so never perform that network call on
		// the writer goroutine and starve event/spill draining.
		go s.afterPrune()
	}
	return nil
}

// secretAuditExpired reports whether retention has passed a record. A record
// without a time is kept: nothing proves it is old, and since the write path
// stamps every record one can only come from a file edited by hand.
func secretAuditExpired(ev SecretAuditEvent, cutoff time.Time) bool {
	return !ev.Time.IsZero() && ev.Time.Before(cutoff)
}

// redactSecretAuditEvent is what retention leaves of an expired record that
// sits behind a newer one and so cannot be cut out of the chain: the two link
// hashes, the time and id (so a later prune reclaims it with the prefix and
// an operator can place it), and nothing that says who opened what.
// EventHash is the original — it is what the successor's prev_hash names —
// so the chain still verifies through the stub; the verifier links a stub by
// its stored hashes because the payload that produced them is gone, and
// refuses one that still carries any other field.
func redactSecretAuditEvent(ev SecretAuditEvent) SecretAuditEvent {
	return SecretAuditEvent{
		Time:      ev.Time,
		EventID:   ev.EventID,
		Result:    secretAuditResultSuccess,
		Reason:    "prune",
		Kind:      secretAuditKindRetentionRedacted,
		PrevHash:  ev.PrevHash,
		EventHash: ev.EventHash,
	}
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
	var lines []secretAuditIndexedLine
	lineErr := s.withAuditFileLock(func() error {
		var err error
		lines, err = s.appendBatchLocked(events, durable)
		return err
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
	if s.afterAppend != nil && len(lines) > 0 {
		s.afterAppend(lines)
	}
	return nil
}

// appendBatchLocked links, appends, and (when durable) fsyncs one batch,
// returning where each record landed. Caller holds the audit flock. Shared by
// the writer goroutine and the boot repair path, which already holds the lock
// and must not re-acquire it.
func (s *fileAuditSink) appendBatchLocked(events []SecretAuditEvent, durable bool) ([]secretAuditIndexedLine, error) {
	s.chainMu.Lock()
	poisoned := s.writePoison
	s.chainMu.Unlock()
	if poisoned != nil {
		return nil, fmt.Errorf("secret audit writer poisoned: %w", poisoned)
	}
	// Prefer the verified in-memory tip under flock. If it is ever absent,
	// recompute from authoritative evidence and propagate corruption instead
	// of silently restarting from genesis.
	prev := s.chainHead
	if prev == "" {
		var err error
		prev, _, err = RecomputeChainHead(s.path)
		if err != nil {
			return nil, fmt.Errorf("recompute secret audit chain head: %w", err)
		}
	}
	if prev == "" {
		prev = auditlog.GenesisPrevHash
	}
	var encoded []byte
	lines := make([]secretAuditIndexedLine, 0, len(events))
	for i := range events {
		ev := &events[i]
		if ev.Time.IsZero() {
			ev.Time = time.Now().UTC()
		}
		ensureSecretAuditEventID(ev)
		auditlog.LinkEvent(prev, ev)
		line, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, line...)
		encoded = append(encoded, '\n')
		lines = append(lines, secretAuditIndexedLine{length: int64(len(line)) + 1, raw: line, ev: *ev})
		prev = ev.EventHash
	}
	before, err := s.file.Stat()
	if err != nil {
		return nil, err
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
		return nil, rollback(err)
	}
	if durable {
		if err := s.file.Sync(); err != nil {
			return nil, rollback(err)
		}
	}
	offset := before.Size()
	for i := range lines {
		lines[i].offset = offset
		offset += lines[i].length
	}
	last := events[len(events)-1]
	s.chainMu.Lock()
	s.chainHead = last.EventHash
	s.chainEvent = last.EventID
	s.lastLineOffset = lines[len(lines)-1].offset
	s.chainMu.Unlock()
	if durable {
		if tipErr := persistChainTipErr(s.tipPath, last.EventHash, last.EventID); tipErr != nil {
			auditTipWriteFailTotal.Add(1)
		}
	}
	return lines, nil
}

// bootScanCurrent reports whether the open-time pass still describes the
// chain: nothing has been appended and retention has not rewritten it. The
// boot witness check may then reuse it instead of reading the file again.
func (s *fileAuditSink) bootScanCurrent() bool {
	if s == nil {
		return false
	}
	head, _ := s.chainTip()
	return head == s.bootScan.head
}

func (s *fileAuditSink) chainTip() (head, eventID string) {
	if s == nil {
		return "", ""
	}
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.chainHead, s.chainEvent
}

// RecomputeChainHead scans secrets.jsonl and verifies every EventHash against
// HashEvent(PrevHash, ev) with PrevHash linkage. Does not trust secrets.tip.
// Returns the verified tip head and its event ID (genesis/"0" when empty).
func RecomputeChainHead(path string) (head, eventID string, err error) {
	scan, err := strictSecretAuditChainScan(path, secretAuditScanOptions{})
	if err != nil {
		return "", "", err
	}
	return scan.head, scan.eventID, nil
}

type secretAuditChainVerifier struct {
	prev       string
	allowBreak bool
	started    bool
}

func newSecretAuditChainVerifier() secretAuditChainVerifier {
	return secretAuditChainVerifier{prev: auditlog.GenesisPrevHash}
}

// Add validates one immutable event in stream order. The only permitted link
// discontinuity is the first retained event after a retention checkpoint,
// whose predecessor was deliberately removed. Missing hash fields are never
// interpreted as a legacy format: this audit format is intentionally one-way.
func (v *secretAuditChainVerifier) Add(ev SecretAuditEvent) error {
	if v == nil {
		return errors.New("secret audit chain verifier unavailable")
	}
	storedPrev := strings.TrimSpace(ev.PrevHash)
	if storedPrev == "" {
		return errors.New("prev_hash is missing")
	}
	if ev.EventHash == "" {
		return errors.New("event_hash is missing")
	}
	if ev.Kind == secretAuditKindRetentionRedacted {
		// Retention kept only this record's links. Its payload is gone, so
		// event_hash cannot be recomputed; the stub is verified by position
		// instead: prev_hash must be the chain so far and event_hash is what
		// the next record must name. A stub can therefore stand only where a
		// record stood — none can be inserted or removed — but its content is
		// no longer provable, which is why one that still carries a payload
		// is rejected rather than trusted.
		if redactSecretAuditEvent(ev) != ev {
			return errors.New("retention stub carries payload")
		}
		if storedPrev != v.prev && !v.allowBreak {
			return fmt.Errorf("prev_hash mismatch (got %q want %q)", storedPrev, v.prev)
		}
		v.prev = ev.EventHash
		v.allowBreak = false
		v.started = true
		return nil
	}
	if ev.EventHash != auditlog.HashEvent(storedPrev, ev) {
		return errors.New("event_hash mismatch")
	}
	if ev.Kind == secretAuditKindRetentionCheckpoint {
		if v.started {
			return errors.New("retention checkpoint must be the first event")
		}
		v.prev = ev.EventHash
		v.allowBreak = true
		v.started = true
		return nil
	}
	if storedPrev != v.prev && !v.allowBreak {
		return fmt.Errorf("prev_hash mismatch (got %q want %q)", storedPrev, v.prev)
	}
	v.prev = ev.EventHash
	v.allowBreak = false
	v.started = true
	return nil
}

// recomputeChain is the full verify path with an ancestry probe: instead of
// materializing every EventHash (a multi-GB slice on a busy node), the
// caller names the hashes it needs to locate and the scan reports which of
// them it passed, plus the newest retention checkpoint's WitnessedThrough.
//
// Retention: prune drops a prefix and inserts an immutable retention_checkpoint
// whose PrevHash is the last dropped EventHash, and reduces expired records
// that sit behind a fresh one to retention_redacted stubs that keep only their
// link hashes. Witness verification uses checkpoint.WitnessedThrough (when
// set) plus the remaining chain. Kept event bytes are verified as stored (no
// rewrite); a single discontinuity is allowed immediately after a
// retention_checkpoint, and a stub is linked by its stored hashes.
func recomputeChain(path string, probe ...string) (secretAuditChainScan, error) {
	return strictSecretAuditChainScan(path, secretAuditScanOptions{probe: probe})
}

// strictSecretAuditChainScan is the read-side contract: a torn tail is an
// error here. Only the sink constructor may repair one — every other caller
// (writer tip fallback, witness verify, tests) must refuse a tail it cannot
// verify rather than quietly trim evidence.
func strictSecretAuditChainScan(path string, opts secretAuditScanOptions) (secretAuditChainScan, error) {
	scan, err := scanSecretAuditChainWith(path, opts)
	if err != nil {
		return scan, err
	}
	if scan.tornBytes > 0 {
		return scan, fmt.Errorf("secret audit chain has an unterminated %d-byte tail at offset %d that is not valid json", scan.tornBytes, scan.validEnd)
	}
	return scan, nil
}

// secretAuditScanOptions parameterize one pass. A nil verifier starts at
// genesis; a primed one continues a chain from base (checkpoint boot).
type secretAuditScanOptions struct {
	base            int64
	verifier        *secretAuditChainVerifier
	startEventID    string
	startLineOffset int64
	// probe lists hashes whose presence the scan should report (witness
	// ancestry) — O(len(probe)) memory instead of O(records).
	probe []string
}

// secretAuditFullScans counts passes that start at byte zero. Boot must add
// exactly one in full mode and none in checkpoint mode (the background pass
// adds its own); tests assert that.
var secretAuditFullScans atomic.Int64

// secretAuditChainScan is one verified pass over secrets.jsonl.
type secretAuditChainScan struct {
	head    string
	eventID string
	// lastLineStart is the offset of the record carrying head.
	lastLineStart int64
	// found reports which probed hashes the pass saw.
	found map[string]bool
	// witnessedThrough is the newest retention checkpoint's WitnessedThrough.
	witnessedThrough string
	// validEnd is the byte offset just past the last complete, verified line.
	validEnd int64
	// tornBytes is the length of an unterminated, unparseable tail after
	// validEnd — what a crash leaves when it interrupts one append write. The
	// writer emits line+'\n' in a single write, so a crash leaves a strict
	// byte-prefix, and no proper prefix of a JSON object is itself valid JSON;
	// that is what makes this the only defect safe to classify as a tear.
	tornBytes int64
	// missingNewline reports a complete, verified final record without its
	// terminator (the write stopped exactly between '}' and '\n').
	missingNewline bool
	// records counts verified records (blank lines excluded).
	records int64
	// redacted counts retention stubs among them: records whose payload
	// retention removed in place. The node never produces one inside the
	// retention window.
	redacted int64
}

// scanSecretAuditChain walks the file once, verifying every record against
// its predecessor. Blank lines are tolerated but never alter the chain.
func scanSecretAuditChain(path string) (secretAuditChainScan, error) {
	return scanSecretAuditChainWith(path, secretAuditScanOptions{})
}

func scanSecretAuditChainWith(path string, opts secretAuditScanOptions) (secretAuditChainScan, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return secretAuditChainScan{head: auditlog.GenesisPrevHash}, nil
		}
		return secretAuditChainScan{head: auditlog.GenesisPrevHash}, err
	}
	defer f.Close()
	return scanSecretAuditChainReader(f, opts)
}

func (scan *secretAuditChainScan) markFound(hash string) {
	if scan.found == nil {
		scan.found = map[string]bool{}
	}
	scan.found[hash] = true
}

// scanSecretAuditChainReader is scanSecretAuditChain over an already-bounded
// reader (a size snapshot taken under the flock) so a verification can run
// while the writer keeps appending. Memory is O(1) in the number of records.
func scanSecretAuditChainReader(r io.Reader, opts secretAuditScanOptions) (secretAuditChainScan, error) {
	scan := secretAuditChainScan{head: auditlog.GenesisPrevHash, validEnd: opts.base, lastLineStart: opts.startLineOffset}
	br := bufio.NewReaderSize(r, 64*1024)
	verifier := newSecretAuditChainVerifier()
	if opts.verifier != nil {
		verifier = *opts.verifier
		scan.head = verifier.prev
		scan.eventID = opts.startEventID
	}
	if opts.base == 0 {
		secretAuditFullScans.Add(1)
	}
	probe := make(map[string]struct{}, len(opts.probe))
	for _, h := range opts.probe {
		if h != "" {
			probe[h] = struct{}{}
		}
	}
	offset := opts.base
	lineNo := 0
	for {
		line, consumed, terminated, tooLong, err := readSecretAuditLine(br)
		if err != nil {
			return scan, err
		}
		if consumed == 0 {
			return scan, nil
		}
		offset += consumed
		if tooLong {
			if !terminated {
				scan.tornBytes = offset - scan.validEnd
				return scan, nil
			}
			return scan, fmt.Errorf("secret audit chain line %d exceeds %d bytes", lineNo+1, secretAuditMaxLineBytes)
		}
		text := bytes.TrimSpace(line)
		if len(text) == 0 {
			// Whitespace is harmless in either position: a terminated blank line
			// is kept, and unterminated trailing whitespace is left for the
			// next append to follow (TrimSpace on read absorbs it).
			if terminated {
				scan.validEnd = offset
			}
			continue
		}
		lineNo++
		var ev SecretAuditEvent
		if err := json.Unmarshal(text, &ev); err != nil {
			if !terminated {
				scan.tornBytes = offset - scan.validEnd
				return scan, nil
			}
			return scan, fmt.Errorf("secret audit chain line %d: malformed json: %w", lineNo, err)
		}
		// A parseable record that does not link is never a tear (see
		// tornBytes) — fail regardless of whether its terminator is present.
		if err := verifier.Add(ev); err != nil {
			return scan, fmt.Errorf("secret audit chain line %d: %w", lineNo, err)
		}
		scan.head = ev.EventHash
		scan.eventID = ev.EventID
		scan.records++
		if ev.Kind == secretAuditKindRetentionRedacted {
			scan.redacted++
		}
		scan.lastLineStart = offset - consumed
		if _, want := probe[ev.EventHash]; want {
			scan.markFound(ev.EventHash)
		}
		if ev.Kind == secretAuditKindRetentionCheckpoint && strings.TrimSpace(ev.WitnessedThrough) != "" {
			scan.witnessedThrough = strings.TrimSpace(ev.WitnessedThrough)
		}
		scan.validEnd = offset
		if !terminated {
			scan.missingNewline = true
			return scan, nil
		}
	}
}

// readSecretAuditLine returns one line (terminator included when present)
// and the bytes consumed. A line past secretAuditMaxLineBytes is counted but
// not retained so a NUL-filled or runaway tail cannot balloon the scan.
func readSecretAuditLine(br *bufio.Reader) (line []byte, consumed int64, terminated, tooLong bool, err error) {
	for {
		chunk, readErr := br.ReadSlice('\n')
		consumed += int64(len(chunk))
		if !tooLong {
			if int64(len(line))+int64(len(chunk)) > secretAuditMaxLineBytes {
				tooLong = true
				line = nil
			} else {
				line = append(line, chunk...)
			}
		}
		switch {
		case readErr == nil:
			return line, consumed, true, tooLong, nil
		case errors.Is(readErr, bufio.ErrBufferFull):
			continue
		case errors.Is(readErr, io.EOF):
			return line, consumed, false, tooLong, nil
		default:
			return nil, consumed, false, tooLong, readErr
		}
	}
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
		// Operator overrides (SB_AUDIT_QUEUE_MAX / SB_AUDIT_OVERFLOW_POLICY):
		// the buffered-backend knobs, same as kube-apiserver's audit buffer.
		if s.cfg.AuditQueueMax > 0 {
			buf = s.cfg.AuditQueueMax
		}
		switch s.cfg.AuditOverflowPolicy {
		case "gap":
			spill = false
		case "spill":
			spill = true
		}
		sink, err := newFileAuditSinkFrom(filepath.Join(dataDir, "audit"), fileAuditSinkOptions{
			buffer: buf, spillEnabled: spill, bootVerify: s.cfg.SecretAuditBootVerify,
			egressRate: s.cfg.AuditEgressSandboxRate, egressBurst: s.cfg.AuditEgressSandboxBurst,
		})
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
		if r := sink.bootRepair; r != nil && s.logger != nil {
			s.logger.Warn("secret audit torn tail repaired at boot; gap marker chained",
				"offset", r.Offset, "bytes_cut", r.Bytes, "dropped_at_least", r.Dropped, "path", sink.path)
		}
		if sink.bootTrusted > 0 {
			// Checkpoint boot: the prefix was accepted on the writer's own
			// checkpoint. Prove it now, off the boot path.
			if s.logger != nil {
				s.logger.Info("secret audit chain verified from checkpoint; full verification continues in background",
					"trusted_bytes", sink.bootTrusted, "path", sink.path)
			}
			s.startSecretAuditBootVerify()
		}
		// Prune rotates the hash chain — ship the new tip to the external
		// witness immediately so LastWitnessedHead tracks the re-linked head.
		sink.afterPrune = func() {
			_ = s.shipSecretAuditHead(context.Background())
		}
		if s.store != nil && s.cfg.AuditIndexEnabled {
			idx := newSecretAuditIndexer(s.store, sink, s.logger)
			sink.afterAppend = idx.onAppended
			sink.onPruneShift = idx.onPruned
			s.secretAuditIndex = idx
			idx.start()
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
		_ = s.PruneSecretAudit(context.Background())
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = s.PruneSecretAudit(context.Background())
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

// startSecretAuditBootVerify proves, off the boot path, the prefix a
// checkpoint boot accepted on the writer's word. It is the same full pass
// an operator can request (VerifySecretAuditChain); the difference is what
// a failure means here: the node is already running, so instead of refusing
// to start it withholds local audit reads, disables the index, and raises
// the critical alert. Evidence keeps being appended — the break is at a
// known offset and everything after it still links.
func (s *Service) startSecretAuditBootVerify() {
	if s == nil || s.secretAuditFile == nil {
		return
	}
	s.secretAuditBootVerify.Add(1)
	go func() {
		defer s.secretAuditBootVerify.Done()
		report, err := s.VerifySecretAuditChain(context.Background())
		switch {
		case err != nil:
			// Could not run (busy, sink gone): leave it to the operator
			// endpoint and the daily retention pass; do not claim either way.
			if s.logger != nil {
				s.logger.Warn("secret audit background verification did not run", "err", err)
			}
		case report.OK:
			if s.logger != nil {
				s.logger.Info("secret audit chain fully verified after checkpoint boot",
					"records", report.Records, "bytes", report.Bytes, "duration_ms", report.DurationMS)
			}
		default:
			s.secretAuditChainBroken.Store(true)
			if s.secretAuditIndex != nil {
				s.secretAuditIndex.markBroken(errors.New(report.Error))
			} else {
				secretAuditIndexChainBreaks.Add(1)
			}
			if s.logger != nil {
				s.logger.Error("secret audit chain failed full verification after checkpoint boot; local audit reads withheld until repaired",
					"error", report.Error, "records", report.Records, "bytes", report.Bytes)
			}
		}
	}()
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
	// After the writer: its final drain may still hand batches to the index.
	s.secretAuditIndex.Close()
	s.secretAuditBootVerify.Wait()
}

// beginSecretAudit records decrypt latency/error metrics and emits one audit
// event when the returned closure runs. Never blocks on audit I/O.
// correlationID may be empty — a fresh id is generated.
func beginSecretAudit(sink SecretAuditSink, sandboxID, ref, actor, correlationID string) func(error) {
	return beginSecretAuditInc(sink, sandboxID, ref, actor, correlationID, "")
}

func beginSecretAuditInc(sink SecretAuditSink, sandboxID, ref, actor, correlationID, incarnationID string) func(error) {
	return beginSecretAuditOwned(sink, sandboxID, ref, actor, correlationID, incarnationID, "")
}

// beginSecretAuditOwned stamps the tenant owner so the record authorizes and
// describes itself without a Raft lookup (plans/audit-export-connectors.md).
func beginSecretAuditOwned(sink SecretAuditSink, sandboxID, ref, actor, correlationID, incarnationID, ownerRef string) func(error) {
	metricDone := beginClusterSecretOpen()
	return func(err error) {
		metricDone(err)
		emitSecretAuditOwned(sink, sandboxID, ref, actor, correlationID, incarnationID, ownerRef, err)
	}
}

func emitSecretAudit(sink SecretAuditSink, sandboxID, ref, actor, correlationID, incarnationID string, err error) {
	emitSecretAuditOwned(sink, sandboxID, ref, actor, correlationID, incarnationID, "", err)
}

func emitSecretAuditOwned(sink SecretAuditSink, sandboxID, ref, actor, correlationID, incarnationID, ownerRef string, err error) {
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
		OwnerRef:      strings.TrimSpace(ownerRef),
		Kind:          secretAuditKindSecretOpen,
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
	incarnationID, ownerRef := s.auditIdentityFor(sandboxID)
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
		IncarnationID: incarnationID,
		OwnerRef:      ownerRef,
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
