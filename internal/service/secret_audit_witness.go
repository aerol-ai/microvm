package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// secretAuditBootWitnessProvisional counts boots that accepted a
	// witnessed head on the local receipt because it lay in the checkpoint's
	// trusted prefix; the background pass settles it.
	secretAuditBootWitnessProvisional = expvar.NewInt("aerolvm_secret_audit_boot_witness_provisional_total")
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
	// Sync drains accepted in-memory and spill events, fsyncs the JSONL, and
	// leaves chainTip at the verified writer head. This is O(1) after the flush;
	// rescanning the full retention file every witness interval does not scale.
	if err := s.secretAuditFile.Sync(); err != nil {
		secretAuditWitnessHealthy.Set(0)
		secretAuditWitnessFailures.Add(1)
		if s.logger != nil {
			s.logger.Warn("secret audit witness ship: sync failed", "err", err)
		}
		return err
	}
	head, eventID := s.secretAuditFile.chainTip()
	if head == "" || head == auditlog.GenesisPrevHash {
		return nil
	}
	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	lastLocal, _ := lastWitnessedHead(s.secretAuditWitnessPath())
	if tip, _ := readWitnessTip(s.secretAuditWitnessTipPath()); tip.HeadHex != "" {
		lastLocal = tip.HeadHex
	}
	if lastLocal == head {
		// A local receipt is not proof that the external store still has the
		// acknowledgment. Confirm it; if missing/behind, re-submit the same
		// idempotent head instead of suppressing witness repair forever.
		verifyCtx := ctx
		if verifyCtx == nil {
			verifyCtx = context.Background()
		}
		checkCtx, cancel := context.WithTimeout(verifyCtx, secretAuditWitnessShipTimeout)
		remoteHead, remoteOK, verifyErr := w.LastWitnessedHead(checkCtx, nodeID)
		cancel()
		if verifyErr == nil && remoteOK && strings.TrimSpace(remoteHead) == head {
			secretAuditWitnessHealthy.Set(1)
			return nil
		}
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
//
// One pass, O(1) memory: the witnessed head is fetched first and the scan
// probes for it (and records the newest retention checkpoint's
// WitnessedThrough) instead of materializing every hash in the file.
func (s *Service) VerifySecretAuditWitness() (ok bool, localHead, witnessedHead string, err error) {
	if s == nil || s.secretAuditFile == nil {
		return true, "", "", nil
	}
	w := s.witness()
	hasExternal := w != nil && (controlplane.Provider{Witness: w}).HasExternalWitness()
	if !hasExternal {
		scan, scanErr := s.verifiedSecretAuditScan()
		if scanErr != nil {
			secretAuditWitnessHealthy.Set(0)
			return false, "", "", scanErr
		}
		return true, scan.head, "", nil
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
		return false, "", "", err
	}
	remoteHead = strings.TrimSpace(remoteHead)
	scan, err := s.verifiedSecretAuditScan(remoteHead)
	if err != nil {
		secretAuditWitnessHealthy.Set(0)
		return false, "", "", err
	}
	localHead = scan.head
	// Empty chain has nothing to witness yet — unless something remembers a
	// chain that is now gone, in which case this is complete erasure and the
	// success return below would certify the tamper as healthy.
	if localHead == "" || localHead == auditlog.GenesisPrevHash || scan.records == 0 {
		if s.emptyLocalChainIsErasure(remoteHead, remoteOK) {
			secretAuditWitnessHealthy.Set(0)
			secretAuditWitnessFailures.Add(1)
			return false, localHead, remoteHead, nil
		}
		return true, localHead, "", nil
	}
	localReceipt, err := s.localWitnessReceiptHead()
	if err != nil {
		return false, localHead, "", err
	}
	return s.judgeWitnessAncestry(localHead, localReceipt, remoteHead, remoteOK, scan.found[remoteHead], scan.witnessedThrough)
}

// verifiedSecretAuditScan is one strict pass under the audit flock, probing
// for the given hashes.
func (s *Service) verifiedSecretAuditScan(probe ...string) (secretAuditChainScan, error) {
	var scan secretAuditChainScan
	err := s.secretAuditFile.withAuditFileLock(func() error {
		var scanErr error
		scan, scanErr = recomputeChain(s.secretAuditFile.path, probe...)
		return scanErr
	})
	return scan, err
}

// localWitnessReceiptHead is the head this node last recorded as shipped:
// the tip sidecar when present, else the newest receipt line.
func (s *Service) localWitnessReceiptHead() (string, error) {
	localReceipt, err := lastWitnessedHead(s.secretAuditWitnessPath())
	if err != nil {
		return "", err
	}
	if tip, tipErr := readWitnessTip(s.secretAuditWitnessTipPath()); tipErr == nil && tip.HeadHex != "" {
		localReceipt = tip.HeadHex
	}
	return strings.TrimSpace(localReceipt), nil
}

// emptyLocalChainIsErasure reports whether an empty local chain contradicts
// evidence that this node once had one. An empty chain is normal exactly once
// — before the first audited event — and after that it is the signature of
// the cheapest tamper there is: delete the log. Two independent witnesses to
// a prior chain exist, and either one is enough:
//
//   - the external witness still holds a head for this node;
//   - a local receipt records a head this node shipped.
//
// Returning true means verification must fail. It cannot be recovered by
// waiting: an operator who really did rebuild this node from scratch has to
// clear the node's witnessed head (and the stale local receipt) deliberately,
// which is the point — evidence loss is an event someone signs off on.
func (s *Service) emptyLocalChainIsErasure(remoteHead string, remoteOK bool) bool {
	if remoteOK {
		if h := strings.TrimSpace(remoteHead); h != "" && h != auditlog.GenesisPrevHash {
			return true
		}
	}
	localReceipt, err := s.localWitnessReceiptHead()
	if err != nil {
		// An unreadable receipt file is not proof of erasure, but it is not
		// proof of health either; fail closed.
		return true
	}
	return localReceipt != "" && localReceipt != auditlog.GenesisPrevHash
}

// judgeWitnessAncestry applies the witness contract once the facts are in
// hand. Missing local receipts is failure when an external witness is
// required — never treat "no receipt file" as success. The witnessed head
// must be in the verified chain (or be the WitnessedThrough a retention
// checkpoint carried forward): ancestry, not tip equality, is the success
// criterion, since the local tip may be ahead of the last ship.
func (s *Service) judgeWitnessAncestry(localHead, localReceipt, remoteHead string, remoteOK, inChain bool, retentionThrough string) (bool, string, string, error) {
	if localReceipt == "" || !remoteOK || remoteHead == "" {
		secretAuditWitnessHealthy.Set(0)
		return false, localHead, "", nil
	}
	if !inChain && retentionThrough != "" && retentionThrough == remoteHead {
		inChain = true
	}
	if !inChain {
		secretAuditWitnessHealthy.Set(0)
		return false, localHead, remoteHead, nil
	}
	secretAuditWitnessHealthy.Set(1)
	return true, localHead, remoteHead, nil
}

// verifySecretAuditWitnessAtBoot answers the boot-time check from the pass
// the sink already made when it opened. That pass probed for the locally
// recorded witness tip, so when the external witness agrees with that tip
// (the normal case) nothing is read again. In checkpoint mode a tip that
// lies in the trusted prefix is accepted on the strength of the local
// receipt; the background full pass proves the chain behind it. Anything
// else falls back to one full probing pass.
func (s *Service) verifySecretAuditWitnessAtBoot(w controlplane.Witness) (ok bool, localHead, witnessedHead string, err error) {
	f := s.secretAuditFile
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
		return false, "", "", err
	}
	remoteHead = strings.TrimSpace(remoteHead)
	localHead, _ = f.chainTip()
	if localHead == "" || localHead == auditlog.GenesisPrevHash || (f.bootScan.records == 0 && f.bootTrusted == 0) {
		// Same erasure rule as VerifySecretAuditWitness: booting with no
		// chain while the witness (or a local receipt) still remembers one is
		// the thing strict boot exists to catch.
		if s.emptyLocalChainIsErasure(remoteHead, remoteOK) {
			secretAuditWitnessHealthy.Set(0)
			secretAuditWitnessFailures.Add(1)
			return false, localHead, remoteHead, nil
		}
		return true, localHead, "", nil
	}
	localReceipt, err := s.localWitnessReceiptHead()
	if err != nil {
		return false, localHead, "", err
	}
	if remoteHead != "" && remoteHead == localReceipt {
		inChain := f.bootScan.found[remoteHead] || remoteHead == localHead
		if !inChain && f.bootTrusted > 0 {
			// The head was shipped by this node from a chain it had
			// verified; it precedes the checkpoint this boot trusted.
			inChain = true
			secretAuditBootWitnessProvisional.Add(1)
		}
		return s.judgeWitnessAncestry(localHead, localReceipt, remoteHead, remoteOK, inChain, f.bootScan.witnessedThrough)
	}
	// The witness holds a head this node did not record as its latest ship
	// (a receipt write lost to a crash, or an older ack): locate it.
	return s.VerifySecretAuditWitness()
}

// requireCurrentSecretAuditWitness gates retention on an exact current-head
// acknowledgment. An older witnessed ancestor is sufficient for ordinary
// integrity verification, but not for deleting a later prefix that was never
// independently anchored.
func (s *Service) requireCurrentSecretAuditWitness(ctx context.Context) (string, error) {
	if s == nil || s.secretAuditFile == nil {
		return "", errors.New("secret audit file is unavailable")
	}
	w := s.witness()
	if w == nil || !(controlplane.Provider{Witness: w}).HasExternalWitness() {
		return "", errors.New("external secret audit witness is unavailable")
	}
	if err := s.shipSecretAuditHead(ctx); err != nil {
		return "", err
	}
	head, _ := s.secretAuditFile.chainTip()
	if head == "" || head == auditlog.GenesisPrevHash {
		return head, nil
	}
	nodeID := ""
	if c := s.Cluster(); c != nil {
		nodeID = c.SelfNodeID()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	checkCtx, cancel := context.WithTimeout(ctx, secretAuditWitnessShipTimeout)
	defer cancel()
	remoteHead, ok, err := w.LastWitnessedHead(checkCtx, nodeID)
	if err != nil {
		return "", err
	}
	if !ok || strings.TrimSpace(remoteHead) != head {
		return "", fmt.Errorf("current secret audit head is not witnessed (local=%q remote=%q)", head, strings.TrimSpace(remoteHead))
	}
	return head, nil
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
	var (
		ok               bool
		local, witnessed string
		err              error
	)
	if f := s.secretAuditFile; f != nil && f.bootScanCurrent() {
		ok, local, witnessed, err = s.verifySecretAuditWitnessAtBoot(w)
	} else {
		ok, local, witnessed, err = s.VerifySecretAuditWitness()
	}
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
		if err := writeFileAtomicDurable(tipPath, append(raw, '\n'), 0o600); err != nil {
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
	var buf bytes.Buffer
	for _, r := range prev {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := buf.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return writeFileAtomicDurable(receiptPath, buf.Bytes(), 0o600)
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
