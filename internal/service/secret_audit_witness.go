package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const (
	defaultSecretAuditWitnessInterval = 30 * time.Second
	secretAuditWitnessReceiptFile     = "witness_receipts.jsonl"
)

type witnessReceiptRecord struct {
	HeadHex    string    `json:"head_hex"`
	EventID    string    `json:"event_id"`
	NodeID     string    `json:"node_id"`
	ReceiptID  string    `json:"receipt_id"`
	RecordedAt time.Time `json:"recorded_at"`
	ShippedAt  time.Time `json:"shipped_at"`
}

// SetWitness installs the control-plane audit witness used to ship hash-chain
// heads off-node. Open-source builds leave this nil/noop.
func (s *Service) SetWitness(w controlplane.Witness) {
	if s == nil {
		return
	}
	s.auditWitnessMu.Lock()
	s.auditWitness = w
	s.auditWitnessMu.Unlock()
	s.ensureSecretAuditSink()
	s.startSecretAuditWitnessLoop()
}

func (s *Service) witness() controlplane.Witness {
	if s == nil {
		return nil
	}
	s.auditWitnessMu.Lock()
	defer s.auditWitnessMu.Unlock()
	return s.auditWitness
}

func (s *Service) startSecretAuditWitnessLoop() {
	if s == nil || s.secretAuditFile == nil {
		return
	}
	w := s.witness()
	if w == nil || !(controlplane.Provider{Witness: w}).HasExternalWitness() {
		return
	}

	s.secretAuditWitnessOnce.Do(func() {
		stop := make(chan struct{})
		s.secretAuditWitnessStop = stop
		s.secretAuditWitnessDone.Add(1)
		interval := s.cfg.SecretAuditWitnessInterval
		if interval <= 0 {
			interval = defaultSecretAuditWitnessInterval
		}
		go func() {
			defer s.secretAuditWitnessDone.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			_ = s.shipSecretAuditHead(context.Background())
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					_ = s.shipSecretAuditHead(context.Background())
				}
			}
		}()
	})
}

func (s *Service) stopSecretAuditWitnessLoop() {
	if s == nil || s.secretAuditWitnessStop == nil {
		return
	}
	select {
	case <-s.secretAuditWitnessStop:
	default:
		close(s.secretAuditWitnessStop)
	}
	s.secretAuditWitnessDone.Wait()
	s.secretAuditWitnessStop = nil
}

func (s *Service) shipSecretAuditHead(ctx context.Context) error {
	if s == nil || s.secretAuditFile == nil {
		return nil
	}
	w := s.witness()
	if w == nil || !(controlplane.Provider{Witness: w}).HasExternalWitness() {
		return nil
	}
	head, eventID := s.secretAuditFile.chainTip()
	if head == "" || head == "0" {
		return nil
	}
	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	receipt, err := w.WitnessHeads(ctx, []controlplane.AuditHead{{
		NodeID:   nodeID,
		HeadHex:  head,
		EventID:  eventID,
		Observed: time.Now().UTC(),
	}})
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("secret audit witness ship failed", "err", err)
		}
		return err
	}
	rec := witnessReceiptRecord{
		HeadHex:    head,
		EventID:    eventID,
		NodeID:     nodeID,
		ReceiptID:  receipt.ReceiptID,
		RecordedAt: receipt.RecordedAt,
		ShippedAt:  time.Now().UTC(),
	}
	if rec.RecordedAt.IsZero() {
		rec.RecordedAt = rec.ShippedAt
	}
	return appendWitnessReceipt(s.secretAuditWitnessPath(), rec)
}

func (s *Service) secretAuditWitnessPath() string {
	if s == nil || s.secretAuditFile == nil {
		return ""
	}
	return filepath.Join(filepath.Dir(s.secretAuditFile.path), secretAuditWitnessReceiptFile)
}

// VerifySecretAuditWitness recomputes the local chain tip and compares it to
// the last persisted witness receipt. A mismatch means the local log was
// altered after that head was witnessed.
func (s *Service) VerifySecretAuditWitness() (ok bool, localHead, witnessedHead string, err error) {
	if s == nil || s.secretAuditFile == nil {
		return true, "", "", nil
	}
	localHead, _ = s.secretAuditFile.chainTip()
	witnessedHead, err = lastWitnessedHead(s.secretAuditWitnessPath())
	if err != nil {
		return false, localHead, "", err
	}
	if witnessedHead == "" {
		return true, localHead, "", nil
	}
	return localHead == witnessedHead, localHead, witnessedHead, nil
}

func appendWitnessReceipt(path string, rec witnessReceiptRecord) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

func lastWitnessedHead(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var last string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec witnessReceiptRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.HeadHex != "" {
			last = rec.HeadHex
		}
	}
	return last, nil
}
