package service

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"os"
	"path/filepath"
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

	// secretAuditKindSecretOpen is the default event kind (empty Kind is treated
	// the same for back-compat). secretAuditKindEgress is host-mediated
	// destination attribution (wasm NetMediator / isolate proxy) — never claim
	// guest-side secret use from these records.
	secretAuditKindSecretOpen = "secret_open"
	secretAuditKindEgress     = "egress"
	secretAuditKindGap        = "gap"

	defaultSecretAuditBuffer = 1024
	// Bound the power-loss window for the local audit fallback. Enterprise
	// deployments should still ship the stream to an external durable/WORM sink.
	secretAuditSyncInterval = time.Second
	secretAuditFileName     = "secrets.jsonl"
	// secretAuditLockName is a stable sidecar flock target. Retention and
	// wasm workers lock this path *before* opening secrets.jsonl so a rename
	// during prune cannot leave writers appending to an unlinked inode.
	secretAuditLockName = "secrets.jsonl.lock"
)

var (
	auditEventsDroppedTotal = expvar.NewInt("aerolvm_audit_events_dropped_total")
	secretAuditSinkHealthy  = expvar.NewInt("aerolvm_secret_audit_sink_healthy")
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
	sync        chan error // when non-nil, writer fsyncs after draining prior work
	pruneCutoff time.Time  // when non-zero, rewrite file dropping older events
	pruneDone   chan error
}

// fileAuditSink appends JSON Lines under {DataDir}/audit/secrets.jsonl via a
// single writer goroutine. Emit is non-blocking: a full buffer drops the event,
// increments aerolvm_audit_events_dropped_total, and records a gap marker.
//
// sendMu serializes producers against Close so Emit/Sync/Prune never send on a
// closed channel (check-then-send race under -race / daemon shutdown).
type fileAuditSink struct {
	ch         chan auditWriteReq
	pendingGap atomic.Bool
	closed     atomic.Bool
	sendMu     sync.Mutex
	done       chan struct{}
	path       string
	lockPath   string
	file       *os.File
	// writeHook, when set (tests), runs before each file write and may block.
	writeHook func()
}

func newFileAuditSink(auditDir string, buffer int) (*fileAuditSink, error) {
	if buffer <= 0 {
		buffer = defaultSecretAuditBuffer
	}
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return nil, fmt.Errorf("secret audit mkdir: %w", err)
	}
	path := filepath.Join(auditDir, secretAuditFileName)
	lockPath := filepath.Join(auditDir, secretAuditLockName)
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
	s := &fileAuditSink{
		ch:       make(chan auditWriteReq, buffer),
		done:     make(chan struct{}),
		path:     path,
		lockPath: lockPath,
		file:     f,
	}
	go s.loop()
	return s, nil
}

func (s *fileAuditSink) Emit(ev SecretAuditEvent) {
	if s == nil {
		return
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed.Load() {
		return
	}
	select {
	case s.ch <- auditWriteReq{ev: ev}:
	default:
		auditEventsDroppedTotal.Add(1)
		s.pendingGap.Store(true)
	}
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
	s.sendMu.Unlock()
	<-s.done
}

func (s *fileAuditSink) loop() {
	defer close(s.done)
	defer func() { _ = s.file.Close() }()
	ticker := time.NewTicker(secretAuditSyncInterval)
	defer ticker.Stop()
	for {
		var req auditWriteReq
		select {
		case next, ok := <-s.ch:
			if !ok {
				if s.pendingGap.Swap(false) {
					s.writeEvent(SecretAuditEvent{
						Time:   time.Now().UTC(),
						Result: secretAuditResultGap,
						Reason: secretAuditReasonOverflow,
						Kind:   secretAuditKindGap,
					})
				}
				_ = s.syncFile()
				return
			}
			req = next
		case <-ticker.C:
			_ = s.syncFile()
			continue
		}
		if s.pendingGap.Swap(false) {
			s.writeEvent(SecretAuditEvent{
				Time:   time.Now().UTC(),
				Result: secretAuditResultGap,
				Reason: secretAuditReasonOverflow,
				Kind:   secretAuditKindGap,
			})
		}
		if req.pruneDone != nil {
			req.pruneDone <- s.pruneLocked(req.pruneCutoff)
			continue
		}
		if req.sync != nil {
			req.sync <- s.syncFile()
			continue
		}
		s.writeEvent(req.ev)
	}
}

func (s *fileAuditSink) syncFile() error {
	err := s.withAuditFileLock(s.file.Sync)
	if err != nil {
		secretAuditSinkHealthy.Set(0)
		auditEventsDroppedTotal.Add(1)
		s.pendingGap.Store(true)
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
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
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
	return s.withAuditFileLock(func() error {
		src, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		defer src.Close()

		tmp := s.path + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		removeTmp := true
		defer func() {
			if removeTmp {
				_ = os.Remove(tmp)
			}
		}()
		writer := bufio.NewWriterSize(f, 64*1024)
		scanner := bufio.NewScanner(src)
		// Events contain metadata only. Bounding the line size prevents a corrupt
		// file from turning retention into unbounded memory use while the streaming
		// rewrite keeps total memory constant regardless of the audit-file size.
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var ev SecretAuditEvent
			if err := json.Unmarshal([]byte(line), &ev); err == nil && !ev.Time.IsZero() && ev.Time.Before(cutoff) {
				continue
			}
			// Preserve malformed lines rather than silently dropping evidence.
			if _, err := writer.WriteString(line + "\n"); err != nil {
				_ = f.Close()
				return err
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return err
		}
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
		// Persist the directory entry as well as the temporary file contents so a
		// crash cannot acknowledge a prune and then resurrect the pre-prune name.
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
		return nil
	})
}

func ensureSecretAuditEventID(ev *SecretAuditEvent) {
	auditlog.EnsureEventID(ev)
}

func (s *fileAuditSink) writeEvent(ev SecretAuditEvent) {
	if s.writeHook != nil {
		s.writeHook()
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ensureSecretAuditEventID(&ev)
	line, err := json.Marshal(ev)
	if err != nil {
		secretAuditSinkHealthy.Set(0)
		auditEventsDroppedTotal.Add(1)
		s.pendingGap.Store(true)
		return
	}
	line = append(line, '\n')
	if err := s.withAuditFileLock(func() error {
		_, werr := s.file.Write(line)
		return werr
	}); err != nil {
		secretAuditSinkHealthy.Set(0)
		auditEventsDroppedTotal.Add(1)
		s.pendingGap.Store(true)
		return
	}
	secretAuditSinkHealthy.Set(1)
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
		sink, err := newFileAuditSink(filepath.Join(dataDir, "audit"), defaultSecretAuditBuffer)
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
		s.startSecretAuditPruneTicker()
	})
}

// ValidateSecretAuditSink applies the boot policy after New has attempted to
// open the writer. Strict mode is the production default; the explicit false
// value remains useful to tests and emergency recovery, while metrics and drop
// accounting still make the degraded state visible.
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
	metricDone := beginClusterSecretOpen()
	return func(err error) {
		metricDone(err)
		emitSecretAudit(sink, sandboxID, ref, actor, correlationID, err)
	}
}

func emitSecretAudit(sink SecretAuditSink, sandboxID, ref, actor, correlationID string, err error) {
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
		Time:        time.Now().UTC(),
		Actor:       actor,
		SandboxID:   sandboxID,
		Result:      secretAuditResultSuccess,
		Reason:      secretAuditReasonOK,
		NodeID:      actor,
		Kind:        secretAuditKindEgress,
		Destination: destination,
		Network:     strings.TrimSpace(network),
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
// cluster-secret://sandbox/{id}/vN. Returns "" when the ref is not that shape.
func sandboxIDFromSecretRef(ref string) string {
	const prefix = "cluster-secret://sandbox/"
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, prefix) {
		return ""
	}
	rest := ref[len(prefix):]
	if i := strings.LastIndex(rest, "/v"); i > 0 {
		return rest[:i]
	}
	return ""
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
