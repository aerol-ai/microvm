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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
}

var (
	secretAuditExportOK       = expvar.NewInt("aerolvm_secret_audit_export_ok")
	secretAuditExportFailures = expvar.NewInt("aerolvm_secret_audit_export_failures_total")
)

// httpAuditBatchExporter POSTs JSONL segments to SB_SECRET_AUDIT_EXPORT_URL.
type httpAuditBatchExporter struct {
	url         string
	bearerToken string
	client      *http.Client
}

func newHTTPAuditBatchExporter(url, bearerToken string) *httpAuditBatchExporter {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil
	}
	return &httpAuditBatchExporter{
		url:         url,
		bearerToken: strings.TrimSpace(bearerToken),
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (e *httpAuditBatchExporter) ExportEvents(ctx context.Context, batch controlplane.AuditEventBatch) (string, error) {
	if e == nil || e.url == "" {
		return batch.Offset, nil
	}
	var buf bytes.Buffer
	for _, raw := range batch.Events {
		buf.Write(raw)
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("X-Aerol-Audit-Offset", batch.Offset)
	req.Header.Set("X-Aerol-Node-ID", batch.NodeID)
	batchID := strings.TrimSpace(batch.BatchID)
	if batchID == "" {
		batchID = auditExportBatchID(batch.NodeID, batch.Offset, batch.Events)
	}
	req.Header.Set("Idempotency-Key", batchID)
	req.Header.Set("X-Aerol-Audit-Batch-ID", batchID)
	if e.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.bearerToken)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("audit export status %d", resp.StatusCode)
	}
	// The receiver acknowledges only success or failure. It never controls the
	// local evidence cursor, so return the submitted offset deterministically.
	return batch.Offset, nil
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
		go func() {
			defer s.secretAuditExportDone.Done()
			ticker := time.NewTicker(secretAuditExportInterval)
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
		if n < secretAuditExportBatchMax {
			return nil
		}
	}
	return nil
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
	offsetPath := filepath.Join(filepath.Dir(s.secretAuditFile.path), secretAuditExportOffset)
	cursor := loadAuditExportCursor(offsetPath)
	var (
		generation string
		offset     int64
		bytesRead  int64
		events     []json.RawMessage
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
		} else if offset > st.Size() {
			offset = 0
		}
		if offset > 0 {
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				return err
			}
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
			if !json.Valid(line) {
				return errors.New("audit export encountered malformed JSONL")
			}
			events = append(events, append(json.RawMessage(nil), line...))
			if len(events) >= secretAuditExportBatchMax {
				break
			}
		}
		return sc.Err()
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
		if s.logger != nil {
			s.logger.Warn("secret audit export failed", "err", err)
		}
		return 0, err
	}
	newOffset := offset + bytesRead
	// The receiver acknowledges the batch but never controls our local byte
	// cursor; trusting a remote offset could skip unexported evidence.
	if err := persistAuditExportCursor(offsetPath, auditExportCursor{Generation: generation, Offset: newOffset}); err != nil {
		secretAuditExportFailures.Add(1)
		return 0, err
	}
	secretAuditExportOK.Set(1)
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
		return "empty", nil
	}
	sum := sha256.Sum256(first)
	return fmt.Sprintf("%x", sum[:16]), nil
}

func loadAuditExportCursor(path string) auditExportCursor {
	var cursor auditExportCursor
	raw, err := os.ReadFile(path)
	if err != nil {
		return cursor
	}
	if json.Unmarshal(raw, &cursor) != nil || cursor.Offset < 0 || strings.TrimSpace(cursor.Generation) == "" {
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

// ConfigureHTTPAuditExporter wires SB_SECRET_AUDIT_EXPORT_URL when set.
func (s *Service) ConfigureHTTPAuditExporter() {
	if s == nil {
		return
	}
	url := strings.TrimSpace(s.cfg.SecretAuditExportURL)
	if url == "" {
		return
	}
	s.SetAuditExporter(newHTTPAuditBatchExporter(url, s.cfg.SecretAuditExportBearerToken))
}
