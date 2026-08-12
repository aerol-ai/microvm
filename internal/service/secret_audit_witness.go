package service

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const (
	defaultSecretAuditWitnessInterval = 30 * time.Second
	secretAuditWitnessShipTimeout     = 10 * time.Second
	secretAuditWitnessReceiptFile     = "witness_receipts.jsonl"
	secretAuditWitnessTipFile         = "witness_tip.json"
	secretAuditWitnessReceiptKeep     = 32
)

var (
	secretAuditWitnessHealthy  = expvar.NewInt("aerolvm_secret_audit_witness_healthy")
	secretAuditWitnessFailures = expvar.NewInt("aerolvm_secret_audit_witness_failures_total")
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
	s.auditWitnessShipMu.Lock()
	defer s.auditWitnessShipMu.Unlock()
	w := s.witness()
	if w == nil || !(controlplane.Provider{Witness: w}).HasExternalWitness() {
		return nil
	}
	// Prefer recomputed tip for shipping so a stale secrets.tip cannot claim
	// a head that is not in the verified chain.
	head, eventID, err := RecomputeChainHead(s.secretAuditFile.path)
	if err != nil {
		secretAuditWitnessHealthy.Set(0)
		secretAuditWitnessFailures.Add(1)
		if s.logger != nil {
			s.logger.Warn("secret audit witness ship: chain recompute failed", "err", err)
		}
		return err
	}
	if head == "" || head == auditlog.GenesisPrevHash {
		return nil
	}
	lastLocal, _ := lastWitnessedHead(s.secretAuditWitnessPath())
	if tip, _ := readWitnessTip(s.secretAuditWitnessTipPath()); tip.HeadHex != "" {
		lastLocal = tip.HeadHex
	}
	if lastLocal == head {
		// Unchanged tip — skip WitnessHeads and receipt growth.
		secretAuditWitnessHealthy.Set(1)
		return nil
	}
	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	shipCtx, cancel := context.WithTimeout(ctx, secretAuditWitnessShipTimeout)
	defer cancel()
	receipt, err := w.WitnessHeads(shipCtx, []controlplane.AuditHead{{
		NodeID:   nodeID,
		HeadHex:  head,
		EventID:  eventID,
		Observed: time.Now().UTC(),
	}})
	if err != nil {
		secretAuditWitnessHealthy.Set(0)
		secretAuditWitnessFailures.Add(1)
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
	if err := persistWitnessReceipt(s.secretAuditWitnessPath(), s.secretAuditWitnessTipPath(), rec); err != nil {
		secretAuditWitnessHealthy.Set(0)
		secretAuditWitnessFailures.Add(1)
		return err
	}
	secretAuditWitnessHealthy.Set(1)
	return nil
}

func (s *Service) secretAuditWitnessPath() string {
	if s == nil || s.secretAuditFile == nil {
		return ""
	}
	return filepath.Join(filepath.Dir(s.secretAuditFile.path), secretAuditWitnessReceiptFile)
}

func (s *Service) secretAuditWitnessTipPath() string {
	if s == nil || s.secretAuditFile == nil {
		return ""
	}
	return filepath.Join(filepath.Dir(s.secretAuditFile.path), secretAuditWitnessTipFile)
}

// VerifySecretAuditWitness recomputes the local hash chain (never trusting
// secrets.tip) and checks that an external witness head is an ancestor of the
// verified tip. Local tip may be ahead of the last ship — that is success.
func (s *Service) VerifySecretAuditWitness() (ok bool, localHead, witnessedHead string, err error) {
	if s == nil || s.secretAuditFile == nil {
		return true, "", "", nil
	}
	localHead, _, hashes, err := recomputeChain(s.secretAuditFile.path)
	if err != nil {
		secretAuditWitnessHealthy.Set(0)
		return false, "", "", err
	}
	w := s.witness()
	hasExternal := w != nil && (controlplane.Provider{Witness: w}).HasExternalWitness()
	if !hasExternal {
		return true, localHead, "", nil
	}

	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	ctx, cancel := context.WithTimeout(context.Background(), secretAuditWitnessShipTimeout)
	defer cancel()
	remoteHead, remoteOK, err := w.LastWitnessedHead(ctx, nodeID)
	if err != nil {
		secretAuditWitnessHealthy.Set(0)
		secretAuditWitnessFailures.Add(1)
		return false, localHead, "", err
	}

	// Empty chain has nothing to witness yet.
	if localHead == "" || localHead == auditlog.GenesisPrevHash || len(hashes) == 0 {
		return true, localHead, "", nil
	}

	localReceipt, err := lastWitnessedHead(s.secretAuditWitnessPath())
	if err != nil {
		return false, localHead, "", err
	}
	if tip, tipErr := readWitnessTip(s.secretAuditWitnessTipPath()); tipErr == nil && tip.HeadHex != "" {
		localReceipt = tip.HeadHex
	}
	// Missing local receipts is failure when an external witness is required —
	// never treat "no receipt file" as success.
	if localReceipt == "" {
		secretAuditWitnessHealthy.Set(0)
		return false, localHead, "", nil
	}
	if !remoteOK || remoteHead == "" {
		secretAuditWitnessHealthy.Set(0)
		return false, localHead, "", nil
	}
	witnessedHead = remoteHead

	// Witnessed head must match a local receipt OR appear as some EventHash in
	// the verified chain. Ancestry (not tip equality) is the success criterion:
	// local tip may be ahead of the last ship.
	receiptOK := localReceipt == witnessedHead
	inChain := false
	for _, h := range hashes {
		if h == witnessedHead {
			inChain = true
			break
		}
	}
	if !receiptOK && !inChain {
		secretAuditWitnessHealthy.Set(0)
		return false, localHead, witnessedHead, nil
	}
	if !inChain {
		secretAuditWitnessHealthy.Set(0)
		return false, localHead, witnessedHead, nil
	}
	secretAuditWitnessHealthy.Set(1)
	return true, localHead, witnessedHead, nil
}

// ValidateSecretAuditWitness fails closed when a real external witness is
// installed and the local chain does not contain a witnessed ancestor head.
// No-op when only the noop witness is present (daemon enforces
// SB_SECRET_AUDIT_EXTERNAL_WITNESS ⇒ non-noop Witness separately).
func (s *Service) ValidateSecretAuditWitness() error {
	if s == nil {
		return nil
	}
	w := s.witness()
	hasExternal := w != nil && (controlplane.Provider{Witness: w}).HasExternalWitness()
	if !hasExternal {
		return nil
	}
	if s.secretAuditFile == nil {
		s.ensureSecretAuditSink()
	}
	ok, local, witnessed, err := s.VerifySecretAuditWitness()
	if err != nil {
		return fmt.Errorf("verify secret audit witness: %w", err)
	}
	if !ok {
		return fmt.Errorf("secret audit witness mismatch: local_head=%q witnessed_head=%q", local, witnessed)
	}
	return nil
}

// persistWitnessReceipt overwrites witness_tip.json and rewrites the receipts
// JSONL keeping only the last N records so ship cadence cannot grow unbounded.
func persistWitnessReceipt(receiptPath, tipPath string, rec witnessReceiptRecord) error {
	if tipPath != "" {
		if err := os.MkdirAll(filepath.Dir(tipPath), 0o700); err != nil {
			return err
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := os.WriteFile(tipPath, append(raw, '\n'), 0o600); err != nil {
			return err
		}
	}
	if receiptPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(receiptPath), 0o700); err != nil {
		return err
	}
	prev, _ := loadWitnessReceipts(receiptPath)
	prev = append(prev, rec)
	if len(prev) > secretAuditWitnessReceiptKeep {
		prev = prev[len(prev)-secretAuditWitnessReceiptKeep:]
	}
	tmp := receiptPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, r := range prev {
		line, err := json.Marshal(r)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, receiptPath)
}

func appendWitnessReceipt(path string, rec witnessReceiptRecord) error {
	tip := ""
	if path != "" {
		tip = filepath.Join(filepath.Dir(path), secretAuditWitnessTipFile)
	}
	return persistWitnessReceipt(path, tip, rec)
}

func loadWitnessReceipts(path string) ([]witnessReceiptRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []witnessReceiptRecord
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
			out = append(out, rec)
		}
	}
	return out, nil
}

func lastWitnessedHead(path string) (string, error) {
	recs, err := loadWitnessReceipts(path)
	if err != nil {
		return "", err
	}
	if len(recs) == 0 {
		return "", nil
	}
	return recs[len(recs)-1].HeadHex, nil
}

func readWitnessTip(path string) (witnessReceiptRecord, error) {
	var zero witnessReceiptRecord
	if path == "" {
		return zero, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, nil
		}
		return zero, err
	}
	var rec witnessReceiptRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return zero, err
	}
	return rec, nil
}
