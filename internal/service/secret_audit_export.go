package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const (
	secretAuditExportInterval   = time.Second
	secretAuditExportBatchMax   = 4096
	secretAuditExportDrainLimit = 256
	secretAuditExportOffset     = "export_offset"
)

type auditExportCursor struct {
	Generation string `json:"generation"`
	Offset     int64  `json:"offset"`
	Head       string `json:"head"`
	AllowBreak bool   `json:"allow_break,omitempty"`
}

var (
	secretAuditExportOK       = expvar.NewInt("aerolvm_secret_audit_export_ok")
	secretAuditExportFailures = expvar.NewInt("aerolvm_secret_audit_export_failures_total")
	// secretAuditExportLagBytes is how far the durable cursor trails the file.
	// A failing backend never drops evidence — it lags — and this is the gauge
	// the alert watches. Retention refuses to rotate unexported bytes.
	secretAuditExportLagBytes = expvar.NewInt("aerolvm_audit_export_lag_bytes")
)

// backendExporter adapts an auditexport.Backend to the control-plane seam so
// an env-configured connector and a managed build's injected exporter share
// one tailer. The receiver never controls the local cursor: the submitted
// offset is returned deterministically.
type backendExporter struct {
	backend auditexport.Backend
}

func (e backendExporter) ExportEvents(ctx context.Context, batch controlplane.AuditEventBatch) (string, error) {
	if e.backend == nil {
		return batch.Offset, nil
	}
	err := e.backend.Export(ctx, auditexport.Batch{
		NodeID: batch.NodeID, BatchID: batch.BatchID, Offset: batch.Offset,
		Events: batch.Events, ShippedAt: batch.ShippedAt,
	})
	return batch.Offset, err
}

func auditExportBatchID(nodeID, offset string, events []json.RawMessage) string {
	h := sha256.New()
	_, _ = h.Write([]byte(strings.TrimSpace(nodeID)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(offset)))
	for _, event := range events {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(event)
	}
	return fmt.Sprintf("%s:%s:%x", strings.TrimSpace(nodeID), strings.TrimSpace(offset), h.Sum(nil)[:16])
}

// SetAuditExporter installs the off-node audit batch exporter.
func (s *Service) SetAuditExporter(ex controlplane.AuditExporter) {
	if s == nil {
		return
	}
	s.auditExportMu.Lock()
	s.auditExporter = ex
	s.auditExportMu.Unlock()
	s.startSecretAuditExportLoop()
}

func (s *Service) getAuditExporter() controlplane.AuditExporter {
	if s == nil {
		return nil
	}
	s.auditExportMu.Lock()
	defer s.auditExportMu.Unlock()
	return s.auditExporter
}

func (s *Service) startSecretAuditExportLoop() {
	if s == nil {
		return
	}
	ex := s.getAuditExporter()
	if ex == nil || !(controlplane.Provider{AuditExporter: ex}).HasAuditExporter() {
		return
	}
	s.ensureSecretAuditSink()
	if s.secretAuditFile == nil {
		return
	}
	s.secretAuditExportOnce.Do(func() {
		stop := make(chan struct{})
		s.secretAuditExportStop = stop
		s.secretAuditExportDone.Add(1)
		interval := s.cfg.AuditExportFlushInterval
		if interval <= 0 {
			interval = secretAuditExportInterval
		}
		go func() {
			defer s.secretAuditExportDone.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			_ = s.drainSecretAuditExport(context.Background())
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					_ = s.drainSecretAuditExport(context.Background())
				}
			}
		}()
	})
}

func (s *Service) stopSecretAuditExportLoop() {
	if s == nil || s.secretAuditExportStop == nil {
		return
	}
	select {
	case <-s.secretAuditExportStop:
	default:
		close(s.secretAuditExportStop)
	}
	s.secretAuditExportDone.Wait()
	s.secretAuditExportStop = nil
}

func (s *Service) exportSecretAuditBatch(ctx context.Context) error {
	_, err := s.exportSecretAuditBatchOnce(ctx)
	return err
}

// drainSecretAuditExport sends consecutive batches until the current file is
// caught up. The cap prevents a permanently hot producer from monopolizing a
// goroutine; the one-second scheduler resumes immediately on the next tick.
func (s *Service) drainSecretAuditExport(ctx context.Context) error {
	for range secretAuditExportDrainLimit {
		n, err := s.exportSecretAuditBatchOnce(ctx)
		if err != nil {
			return err
		}
		if n < s.auditExportBatchMax() {
			return nil
		}
	}
	return nil
}

func (s *Service) auditExportBatchMax() int {
	if s != nil && s.cfg.AuditExportBatchMax > 0 {
		return s.cfg.AuditExportBatchMax
	}
	return secretAuditExportBatchMax
}

func (s *Service) exportSecretAuditBatchOnce(ctx context.Context) (int, error) {
	if s == nil || s.secretAuditFile == nil {
		return 0, nil
	}
	ex := s.getAuditExporter()
	if ex == nil || !(controlplane.Provider{AuditExporter: ex}).HasAuditExporter() {
		return 0, nil
	}
	s.auditExportRunMu.Lock()
	defer s.auditExportRunMu.Unlock()
	// Backoff after a failure: skip ticks until the delay elapses so 2,000
	// nodes that lost the same receiver do not hammer it every second.
	if !s.auditExportNotBefore.IsZero() && time.Now().Before(s.auditExportNotBefore) {
		return 0, nil
	}
	offsetPath := filepath.Join(filepath.Dir(s.secretAuditFile.path), secretAuditExportOffset)
	cursor := loadAuditExportCursor(offsetPath)
	batchMax := s.auditExportBatchMax()
	var (
		generation         string
		offset             int64
		fileSize           int64
		bytesRead          int64
		events             []json.RawMessage
		verifiedHead       string
		verifiedAllowBreak bool
	)
	// Snapshot a complete batch under the same flock used by append and prune.
	// The network call happens after unlock, so slow receivers never stall the
	// writer. A concurrent prune can then cause only a safe duplicate: its new
	// generation will force the following export back to byte zero.
	err := s.secretAuditFile.withAuditFileLock(func() error {
		f, err := os.Open(s.secretAuditFile.path)
		if err != nil {
			return err
		}
		defer f.Close()
		generation, err = auditFileGeneration(f)
		if err != nil {
			return err
		}
		offset = cursor.Offset
		if cursor.Generation != generation {
			offset = 0
		}
		if st, statErr := f.Stat(); statErr != nil {
			return statErr
		} else if fileSize = st.Size(); offset > fileSize {
			offset = 0
		}
		if offset > 0 {
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				return err
			}
		}
		verifier := newSecretAuditChainVerifier()
		if offset > 0 {
			verifier.prev = cursor.Head
			verifier.allowBreak = cursor.AllowBreak
			verifier.started = true
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			lineBytes := int64(len(sc.Bytes()) + 1) // audit writer always appends newline
			bytesRead += lineBytes
			if len(line) == 0 {
				continue
			}
			var ev SecretAuditEvent
			if err := json.Unmarshal(line, &ev); err != nil {
				return fmt.Errorf("audit export encountered malformed JSONL: %w", err)
			}
			if err := verifier.Add(ev); err != nil {
				return fmt.Errorf("audit export encountered invalid hash chain: %w", err)
			}
			events = append(events, append(json.RawMessage(nil), line...))
			if len(events) >= batchMax {
				break
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
		verifiedHead = verifier.prev
		verifiedAllowBreak = verifier.allowBreak
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		secretAuditExportFailures.Add(1)
		return 0, err
	}
	if len(events) == 0 {
		secretAuditExportOK.Set(1)
		secretAuditExportLagBytes.Set(0)
		return 0, nil
	}
	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	shipCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	offsetText := strconv.FormatInt(offset, 10)
	_, err = ex.ExportEvents(shipCtx, controlplane.AuditEventBatch{
		NodeID:    nodeID,
		Offset:    offsetText,
		BatchID:   auditExportBatchID(nodeID, offsetText, events),
		Events:    events,
		ShippedAt: time.Now().UTC(),
	})
	if err != nil {
		secretAuditExportOK.Set(0)
		secretAuditExportFailures.Add(1)
		secretAuditExportLagBytes.Set(fileSize - offset)
		s.auditExportBackoff.Base = s.cfg.AuditExportFlushInterval
		s.auditExportBackoff.Max = s.cfg.AuditExportMaxBackoff
		delay := s.auditExportBackoff.Next()
		s.auditExportNotBefore = time.Now().Add(delay)
		if s.logger != nil {
			s.logger.Warn("secret audit export failed; backing off", "err", err, "retry_in", delay, "attempt", s.auditExportBackoff.Attempts())
		}
		return 0, err
	}
	s.auditExportBackoff.Reset()
	s.auditExportNotBefore = time.Time{}
	newOffset := offset + bytesRead
	// The receiver acknowledges the batch but never controls our local byte
	// cursor; trusting a remote offset could skip unexported evidence.
	if err := persistAuditExportCursor(offsetPath, auditExportCursor{
		Generation: generation, Offset: newOffset, Head: verifiedHead, AllowBreak: verifiedAllowBreak,
	}); err != nil {
		secretAuditExportFailures.Add(1)
		return 0, err
	}
	secretAuditExportOK.Set(1)
	secretAuditExportLagBytes.Set(fileSize - newOffset)
	return len(events), nil
}

// secretAuditFullyExported reports whether the locally persisted exporter
// cursor covers the complete current generation. Retention must never rotate
// the file before this is true or the unexported prefix becomes unrecoverable.
func (s *Service) secretAuditFullyExported() (bool, error) {
	if s == nil || s.secretAuditFile == nil {
		return true, nil
	}
	offsetPath := filepath.Join(filepath.Dir(s.secretAuditFile.path), secretAuditExportOffset)
	cursor := loadAuditExportCursor(offsetPath)
	var generation string
	var size int64
	err := s.secretAuditFile.withAuditFileLock(func() error {
		f, err := os.Open(s.secretAuditFile.path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		defer f.Close()
		generation, err = auditFileGeneration(f)
		if err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			return err
		}
		size = st.Size()
		return nil
	})
	if err != nil {
		return false, err
	}
	if size == 0 {
		return true, nil
	}
	return cursor.Generation == generation && cursor.Offset >= size, nil
}

func auditFileGeneration(f *os.File) (string, error) {
	if f == nil {
		return "", errors.New("audit export file unavailable")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	first := []byte(nil)
	for sc.Scan() {
		if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
			first = append(first, line...)
			break
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if len(first) == 0 {
		return secretAuditEmptyGeneration, nil
	}
	return auditGenerationOfLine(first), nil
}

// auditGenerationOfLine is the generation a file whose first record is line
// would report: the identity that export cursors and the read index pin
// their offsets to, and that retention's checkpoint line changes.
func auditGenerationOfLine(line []byte) string {
	sum := sha256.Sum256(bytes.TrimSpace(line))
	return fmt.Sprintf("%x", sum[:16])
}

func loadAuditExportCursor(path string) auditExportCursor {
	var cursor auditExportCursor
	raw, err := os.ReadFile(path)
	if err != nil {
		return cursor
	}
	if json.Unmarshal(raw, &cursor) != nil || cursor.Offset < 0 || strings.TrimSpace(cursor.Generation) == "" ||
		(cursor.Offset > 0 && strings.TrimSpace(cursor.Head) == "") {
		return auditExportCursor{}
	}
	return cursor
}

func persistAuditExportCursor(path string, cursor auditExportCursor) error {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	return writeFileAtomicDurable(path, append(raw, '\n'), 0o600)
}

// ConfigureAuditExporter builds the connector named by SB_AUDIT_EXPORT_BACKEND
// (plans/audit-export-connectors.md) and installs it behind the shared tailer.
// A noop backend installs nothing: the open-source default keeps evidence on
// local disk and says so. Configuration errors fail boot; a backend that
// cannot reach its receiver does not — it lags, visibly.
func (s *Service) ConfigureAuditExporter() error {
	if s == nil {
		return nil
	}
	cfg := s.cfg.AuditExportConfig()
	if !s.cfg.AuditExportEnabled() {
		return nil
	}
	backend, err := auditexport.Open(cfg)
	if err != nil {
		return err
	}
	if auditexport.IsNoop(backend) {
		return nil
	}
	s.auditExportMu.Lock()
	s.auditBackend = backend
	s.auditExportMu.Unlock()
	if s.logger != nil {
		s.logger.Info("audit export connector configured", "backend", backend.Name())
	}
	s.SetAuditExporter(backendExporter{backend: backend})
	return nil
}

// ConfigureHTTPAuditExporter is the pre-connector entry point; it now resolves
// SB_SECRET_AUDIT_EXPORT_URL to the webhook backend. Kept for callers that
// predate ConfigureAuditExporter; configuration errors are logged, not fatal.
func (s *Service) ConfigureHTTPAuditExporter() {
	if s == nil {
		return
	}
	if err := s.ConfigureAuditExporter(); err != nil && s.logger != nil {
		s.logger.Error("audit export connector configuration failed", "err", err)
	}
}

// AuditExportHealthy reports the configured connector's last observed
// outcome; nil when none is configured.
func (s *Service) AuditExportHealthy(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.auditExportMu.Lock()
	b := s.auditBackend
	s.auditExportMu.Unlock()
	if b == nil {
		return nil
	}
	return b.Healthy(ctx)
}
