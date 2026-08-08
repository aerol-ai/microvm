package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

	defaultSecretAuditBuffer = 1024
	secretAuditFileName      = "secrets.jsonl"
)

var auditEventsDroppedTotal = expvar.NewInt("aerolvm_audit_events_dropped_total")

// SecretAuditEvent is one audit record (secret-open by default, or host-mediated
// egress). Never carry plaintext, credentials, PII, or wrapped error strings
// (those may embed caller input). Destination must never include credentials.
type SecretAuditEvent struct {
	Time          time.Time `json:"time"`
	Actor         string    `json:"actor,omitempty"`
	SandboxID     string    `json:"sandbox_id,omitempty"`
	Ref           string    `json:"ref,omitempty"`
	Result        string    `json:"result"`
	Reason        string    `json:"reason,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	// NodeID is the node that wrote the event (same as Actor when set).
	NodeID string `json:"node_id,omitempty"`
	// Kind is "secret_open" (default/empty for back-compat) or "egress".
	Kind string `json:"kind,omitempty"`
	// Destination is host or host:port for Kind=egress. Never credentials.
	Destination string `json:"destination,omitempty"`
	// Network is tcp/udp when known (egress only).
	Network  string `json:"network,omitempty"`
	BytesIn  int64  `json:"bytes_in,omitempty"`
	BytesOut int64  `json:"bytes_out,omitempty"`
}

// SecretAuditSink receives secret-read events. Emit must be non-blocking.
// A nil sink is a no-op and must not panic.
type SecretAuditSink interface {
	Emit(SecretAuditEvent)
}

type noopSecretAuditSink struct{}

func (noopSecretAuditSink) Emit(SecretAuditEvent) {}

type auditWriteReq struct {
	ev          SecretAuditEvent
	sync        chan struct{} // when non-nil, writer closes after draining prior work
	pruneCutoff time.Time     // when non-zero, rewrite file dropping older events
	pruneDone   chan error
}

// fileAuditSink appends JSON Lines under {DataDir}/audit/secrets.jsonl via a
// single writer goroutine. Emit is non-blocking: a full buffer drops the event,
// increments aerolvm_audit_events_dropped_total, and records a gap marker.
type fileAuditSink struct {
	ch         chan auditWriteReq
	pendingGap atomic.Bool
	closed     atomic.Bool
	done       chan struct{}
	path       string
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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("secret audit open: %w", err)
	}
	s := &fileAuditSink{
		ch:   make(chan auditWriteReq, buffer),
		done: make(chan struct{}),
		path: path,
		file: f,
	}
	go s.loop()
	return s, nil
}

func (s *fileAuditSink) Emit(ev SecretAuditEvent) {
	if s == nil || s.closed.Load() {
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
// marker) has been written. No-op on a nil or closed sink.
func (s *fileAuditSink) Sync() {
	if s == nil || s.closed.Load() {
		return
	}
	done := make(chan struct{})
	req := auditWriteReq{sync: done}
	// Sync must not drop — wait for buffer space.
	s.ch <- req
	<-done
}

// Close stops the writer and closes the file. Safe to call once.
func (s *fileAuditSink) Close() {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return
	}
	close(s.ch)
	<-s.done
}

func (s *fileAuditSink) loop() {
	defer close(s.done)
	defer func() { _ = s.file.Close() }()
	for req := range s.ch {
		if s.pendingGap.Swap(false) {
			s.writeEvent(SecretAuditEvent{
				Time:   time.Now().UTC(),
				Result: secretAuditResultGap,
				Reason: secretAuditReasonOverflow,
			})
		}
		if req.pruneDone != nil {
			req.pruneDone <- s.pruneLocked(req.pruneCutoff)
			continue
		}
		if req.sync != nil {
			close(req.sync)
			continue
		}
		s.writeEvent(req.ev)
	}
	if s.pendingGap.Swap(false) {
		s.writeEvent(SecretAuditEvent{
			Time:   time.Now().UTC(),
			Result: secretAuditResultGap,
			Reason: secretAuditReasonOverflow,
		})
	}
}

// Prune drops events (and gap markers) older than cutoff. Serialized on the
// writer goroutine so it cannot race appends.
func (s *fileAuditSink) Prune(cutoff time.Time) error {
	if s == nil || s.closed.Load() {
		return nil
	}
	done := make(chan error, 1)
	s.ch <- auditWriteReq{pruneCutoff: cutoff, pruneDone: done}
	return <-done
}

func (s *fileAuditSink) pruneLocked(cutoff time.Time) error {
	if cutoff.IsZero() {
		return nil
	}
	// Exclusive flock coordinates with wasm worker direct-appends so a write
	// cannot land on the pre-rename inode and be discarded (P1 audit race).
	src, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer src.Close()
	if err := unix.Flock(int(src.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(src.Fd()), unix.LOCK_UN) }()

	raw, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	var kept [][]byte
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Preserve unparseable lines rather than silently dropping evidence.
			kept = append(kept, []byte(line))
			continue
		}
		if !ev.Time.IsZero() && ev.Time.Before(cutoff) {
			continue
		}
		kept = append(kept, []byte(line))
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, line := range kept {
		if _, err := f.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = s.file.Close()
	nf, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.file = nf
	return nil
}

func (s *fileAuditSink) writeEvent(ev SecretAuditEvent) {
	if s.writeHook != nil {
		s.writeHook()
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = s.file.Write(line)
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
			s.secretAudit = noopSecretAuditSink{}
			return
		}
		sink, err := newFileAuditSink(filepath.Join(dataDir, "audit"), defaultSecretAuditBuffer)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("secret audit sink disabled", "err", err)
			}
			s.secretAudit = noopSecretAuditSink{}
			return
		}
		s.secretAudit = sink
		s.secretAuditFile = sink
		s.startSecretAuditPruneTicker()
	})
}

// startSecretAuditPruneTicker runs retention once at start and once per day.
// Stopped by CloseSecretAuditSink.
func (s *Service) startSecretAuditPruneTicker() {
	if s == nil || s.secretAuditFile == nil {
		return
	}
	if s.secretAuditPruneStop != nil {
		return
	}
	stop := make(chan struct{})
	s.secretAuditPruneStop = stop
	go func() {
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
