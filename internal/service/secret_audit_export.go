package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const (
	secretAuditExportInterval = 30 * time.Second
	secretAuditExportBatchMax = 256
	secretAuditExportOffset   = "export_offset"
)

var (
	secretAuditExportOK       = expvar.NewInt("aerolvm_secret_audit_export_ok")
	secretAuditExportFailures = expvar.NewInt("aerolvm_secret_audit_export_failures_total")
)

// httpAuditBatchExporter POSTs JSONL segments to SB_SECRET_AUDIT_EXPORT_URL.
type httpAuditBatchExporter struct {
	url    string
	client *http.Client
}

func newHTTPAuditBatchExporter(url string) *httpAuditBatchExporter {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil
	}
	return &httpAuditBatchExporter{
		url:    url,
		client: &http.Client{Timeout: 15 * time.Second},
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
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("audit export status %d", resp.StatusCode)
	}
	next := strings.TrimSpace(resp.Header.Get("X-Aerol-Audit-Next-Offset"))
	if next == "" {
		next = batch.Offset
	}
	return next, nil
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
			_ = s.exportSecretAuditBatch(context.Background())
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					_ = s.exportSecretAuditBatch(context.Background())
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
	if s == nil || s.secretAuditFile == nil {
		return nil
	}
	ex := s.getAuditExporter()
	if ex == nil || !(controlplane.Provider{AuditExporter: ex}).HasAuditExporter() {
		return nil
	}
	offsetPath := filepath.Join(filepath.Dir(s.secretAuditFile.path), secretAuditExportOffset)
	offset := loadExportOffset(offsetPath)
	f, err := os.Open(s.secretAuditFile.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		secretAuditExportFailures.Add(1)
		return err
	}
	defer f.Close()
	if offset > 0 {
		if _, err := f.Seek(offset, 0); err != nil {
			secretAuditExportFailures.Add(1)
			return err
		}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var events []json.RawMessage
	var bytesRead int64
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lineBytes := int64(len(sc.Bytes()) + 1) // + newline
		bytesRead += lineBytes
		if line == "" {
			continue
		}
		events = append(events, json.RawMessage(line))
		if len(events) >= secretAuditExportBatchMax {
			break
		}
	}
	if err := sc.Err(); err != nil {
		secretAuditExportFailures.Add(1)
		return err
	}
	if len(events) == 0 {
		secretAuditExportOK.Set(1)
		return nil
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
	next, err := ex.ExportEvents(shipCtx, controlplane.AuditEventBatch{
		NodeID:    nodeID,
		Offset:    strconv.FormatInt(offset, 10),
		Events:    events,
		ShippedAt: time.Now().UTC(),
	})
	if err != nil {
		secretAuditExportOK.Set(0)
		secretAuditExportFailures.Add(1)
		if s.logger != nil {
			s.logger.Warn("secret audit export failed", "err", err)
		}
		return err
	}
	newOffset := offset + bytesRead
	if n, err := strconv.ParseInt(strings.TrimSpace(next), 10, 64); err == nil && n > offset {
		newOffset = n
	}
	if err := os.WriteFile(offsetPath, []byte(strconv.FormatInt(newOffset, 10)+"\n"), 0o600); err != nil {
		secretAuditExportFailures.Add(1)
		return err
	}
	secretAuditExportOK.Set(1)
	return nil
}

func loadExportOffset(path string) int64 {
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

// ConfigureHTTPAuditExporter wires SB_SECRET_AUDIT_EXPORT_URL when set.
func (s *Service) ConfigureHTTPAuditExporter() {
	if s == nil {
		return
	}
	url := strings.TrimSpace(s.cfg.SecretAuditExportURL)
	if url == "" {
		return
	}
	s.SetAuditExporter(newHTTPAuditBatchExporter(url))
}
