package service

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const (
	defaultSecretAuditLimit = 100
	maxSecretAuditLimit     = 1000
	// secretAuditFanoutDeadline bounds the whole peer fan-out (not per peer).
	secretAuditFanoutDeadline = 5 * time.Second
	secretAuditFanoutParallel = 16
)

var (
	// ErrSecretAuditIndexIncomplete refuses an unbounded all-worker scan when
	// Raft cannot identify the nodes that owned the sandbox's evidence.
	ErrSecretAuditIndexIncomplete = errors.New("secret audit node index is unavailable or truncated")
	secretAuditFanoutSlots        = make(chan struct{}, 32)
	// Public rate limits are per ingress. This worker-side bound also covers
	// requests amplified through many ingress nodes over the internal
	// endpoint. A read that cannot get a slot within secretAuditQueryAdmitWait
	// fails fast with ErrSecretAuditBusy (429) instead of queueing until its
	// deadline; with the index a slot is held for milliseconds, so hitting
	// this means the node is saturated, not that the queue is deep.
	secretAuditLocalQuerySlots = make(chan struct{}, 8)
)

// SecretAuditQuery pages local/cluster secret-audit history for one sandbox.
type SecretAuditQuery struct {
	Limit  int    // default 100, max 1000
	Cursor string // exclusive lower bound time (RFC3339Nano), or empty = from start
	// Kind filters by event kind ("egress", "secret_open"). Empty = all kinds.
	Kind string
	// IncarnationID scopes history to one placement lifetime. When empty and
	// the sandbox still has a live placement, ListSecretAuditLocal defaults
	// it from Placement.IncarnationID.
	IncarnationID string
}

// SecretAuditCoverage reports which members answered a fan-out read.
// Partial is true when Missing is non-empty — never silently truncate history.
type SecretAuditCoverage struct {
	Answered []string `json:"answered"`
	Missing  []string `json:"missing"`
	Partial  bool     `json:"partial"`
}

// SecretAuditPage is the GET /v1/sandboxes/{id}/audit response body.
type SecretAuditPage struct {
	Events     []SecretAuditEvent  `json:"events"`
	Coverage   SecretAuditCoverage `json:"coverage"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

// PruneSecretAudit drops audit state older than
// SB_SECRET_AUDIT_RETENTION_DAYS. The JSONL rewrite is skipped when the file
// sink is unavailable, but retained post-delete ACL metadata is still pruned.
//
// Zero retention means "retain nothing beyond the crash buffer": post-delete
// ACL rows go at the next sweep and the JSONL keeps one day for the export
// tailer to catch up. It never means forever.
func (s *Service) PruneSecretAudit(ctx context.Context) error {
	if s == nil {
		return nil
	}
	// Normalize before any exporter/witness work. Enterprise witness validation
	// uses the context before the SQLite ACL-prune phase below, so doing this only
	// immediately before the store call leaves the periodic nil-context caller
	// able to panic in context.WithTimeout.
	if ctx == nil {
		ctx = context.Background()
	}
	days := s.cfg.SecretAuditRetentionDays
	if days < 0 {
		return nil
	}
	s.ensureSecretAuditSink()
	f := s.secretAuditFile
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -days)
	aclCutoff := cutoff
	if days == 0 {
		cutoff = now.AddDate(0, 0, -secretAuditCrashBufferDays)
		aclCutoff = now
	}
	if f != nil {
		exporter := s.getAuditExporter()
		hasExporter := exporter != nil && (controlplane.Provider{AuditExporter: exporter}).HasAuditExporter()
		exportCursorPath := ""
		if s.cfg.EnterpriseMode || strings.TrimSpace(s.cfg.SecretAuditExportURL) != "" || hasExporter {
			exportCursorPath = filepath.Join(filepath.Dir(f.path), secretAuditExportOffset)
		}
		witnessedHead := ""
		if s.cfg.SecretAuditExternalWitness {
			var err error
			witnessedHead, err = s.requireCurrentSecretAuditWitness(ctx)
			if err != nil {
				// Never rotate evidence that has not been independently anchored.
				// The daily ticker retries; manual callers receive the exact failure.
				return fmt.Errorf("verify audit witness before prune: %w", err)
			}
		}
		if err := f.pruneWithGuards(cutoff, exportCursorPath, witnessedHead); err != nil {
			if errors.Is(err, errSecretAuditPruneGuardChanged) {
				// An event landed after the external checks. Retain the file and let
				// the export/witness loops advance before the next prune attempt.
				return nil
			}
			return err
		}
	}
	if s.store == nil {
		return nil
	}
	_, err := s.store.PruneSandboxAuditACL(ctx, aclCutoff)
	return err
}

// ListSecretAuditLocal answers one page of sandboxID's history from the
// authoritative local JSONL. With the read index ready the cost is O(page):
// the index names the lines the page needs and only those are read and
// verified. Without it (index disabled, rebuilding, or disagreeing with the
// file) the page comes from a scan of the file, which is correct but
// O(retained events) — the metrics below say which path served.
//
// Integrity on this path is per returned record (its hash must match its
// own content and prev_hash); whole-chain verification is the job of boot,
// retention, and VerifySecretAuditChain, not of every page read.
func (s *Service) ListSecretAuditLocal(ctx context.Context, sandboxID string, opts SecretAuditQuery) (events []SecretAuditEvent, nextCursor string, err error) {
	if s == nil {
		return nil, "", nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, "", nil
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	release, err := acquireSecretAuditQuerySlot(ctx)
	if err != nil {
		return nil, "", err
	}
	defer release()
	incarnationID := strings.TrimSpace(opts.IncarnationID)
	if incarnationID == "" {
		incarnationID = s.secretIncarnationForSeal(sandboxID)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultSecretAuditLimit
	}
	if limit > maxSecretAuditLimit {
		limit = maxSecretAuditLimit
	}
	q := secretAuditPageQuery{sandboxID: sandboxID, incarnationID: incarnationID, kind: strings.TrimSpace(opts.Kind), limit: limit}
	if c := strings.TrimSpace(opts.Cursor); c != "" {
		q.after, q.afterKey, err = parseSecretAuditCursor(c)
		if err != nil {
			return nil, "", fmt.Errorf("invalid cursor: %w", err)
		}
	}

	s.ensureSecretAuditSink()
	path := s.secretAuditPath()
	if path == "" {
		return nil, "", nil
	}
	if s.secretAuditChainBroken.Load() || (s.secretAuditIndex != nil && s.secretAuditIndex.broken.Load()) {
		// Per-record checks cannot tell a forged-but-self-consistent record
		// from a genuine one; the chain can, and either the indexer or the
		// boot-time background pass saw it break. Refuse to serve evidence
		// from a log that no longer verifies, as strict boot would.
		return nil, "", ErrSecretAuditChainBroken
	}
	for attempt := 0; ; attempt++ {
		f, snap, err := s.openSecretAuditSnapshot(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, "", nil
			}
			return nil, "", err
		}
		page := newSecretAuditPageCollector(limit)
		scanFrom := int64(0)
		served := "scan"
		if idx := s.secretAuditIndex; idx.isReady() {
			meta, chunks, ok, err := idx.lookup(ctx, store.SecretAuditIndexKey{SandboxID: sandboxID, IncarnationID: incarnationID}, q.indexMinTime())
			if err != nil {
				_ = f.Close()
				return nil, "", err
			}
			switch {
			case ok && meta.Generation == snap.generation && meta.IndexedThrough <= snap.size:
				err := readIndexedSecretAudit(ctx, f, chunks, q, page)
				if errors.Is(err, errSecretAuditIndexCorrupt) {
					// The file is the evidence; the index is only a map of
					// it. Serve this page from the file and rebuild the map.
					idx.reportCorrupt(err)
					page = newSecretAuditPageCollector(limit)
				} else if err != nil {
					_ = f.Close()
					return nil, "", err
				} else {
					scanFrom = meta.IndexedThrough
					served = "index"
				}
			case ok && meta.Generation != snap.generation && attempt == 0:
				// Retention replaced the file between our open and the index
				// read. Reopen once; the new generation and its index agree.
				_ = f.Close()
				continue
			}
		}
		if served == "index" {
			secretAuditQueryIndexedTotal.Add(1)
		} else {
			secretAuditQueryScanFallbackTotal.Add(1)
		}
		err = scanSecretAuditRange(ctx, f, scanFrom, snap.size, q, page)
		_ = f.Close()
		if err != nil {
			return nil, "", err
		}
		events, nextCursor = page.result()
		return events, nextCursor, nil
	}
}

var (
	secretAuditQueryIndexedTotal      = expvar.NewInt("aerolvm_audit_query_indexed_total")
	secretAuditQueryScanFallbackTotal = expvar.NewInt("aerolvm_audit_query_scan_fallback_total")
	secretAuditQueryBusyTotal         = expvar.NewInt("aerolvm_audit_query_busy_total")
	secretAuditChainVerifyOK          = expvar.NewInt("aerolvm_audit_chain_verify_ok")
	secretAuditChainVerifiedUnix      = expvar.NewInt("aerolvm_audit_chain_verified_unix")

	// ErrSecretAuditBusy is returned when this node's audit read slots are
	// all taken for longer than secretAuditQueryAdmitWait. It maps to 429 +
	// Retry-After: the caller should back off, not wait out its deadline in
	// a queue that would only answer with a 504.
	ErrSecretAuditBusy = errors.New("secret audit read capacity is exhausted on this node; retry shortly")

	// ErrSecretAuditChainBroken is returned for every local read once the
	// indexer has seen the hash chain fail to link. It clears only with a
	// restart, which re-verifies the whole file (and refuses to boot on it
	// under strict mode).
	ErrSecretAuditChainBroken = errors.New("local secret audit chain failed verification; evidence on this node is not served until it is repaired")

	errSecretAuditIndexCorrupt = errors.New("secret audit index does not describe the file")
)

// secretAuditQueryAdmitWait is how long a read waits for a slot before
// failing fast. Pages are O(page) with the index, so a slot frees in
// milliseconds; waiting longer means the node is genuinely saturated.
const secretAuditQueryAdmitWait = 50 * time.Millisecond

func acquireSecretAuditQuerySlot(ctx context.Context) (func(), error) {
	release := func() { <-secretAuditLocalQuerySlots }
	select {
	case secretAuditLocalQuerySlots <- struct{}{}:
		return release, nil
	default:
	}
	timer := time.NewTimer(secretAuditQueryAdmitWait)
	defer timer.Stop()
	select {
	case secretAuditLocalQuerySlots <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		secretAuditQueryBusyTotal.Add(1)
		return nil, ErrSecretAuditBusy
	}
}

// secretAuditPageQuery is one page request after normalization.
type secretAuditPageQuery struct {
	sandboxID     string
	incarnationID string
	kind          string
	after         time.Time
	afterKey      string
	limit         int
}

// indexMinTime is the oldest chunk max_time that can still contribute.
func (q secretAuditPageQuery) indexMinTime() int64 {
	if q.after.IsZero() {
		return math.MinInt64
	}
	return q.after.UnixNano()
}

func (q secretAuditPageQuery) matches(ev SecretAuditEvent) bool {
	return secretAuditEventMatches(ev, q.sandboxID, q.incarnationID, q.kind, q.after, q.afterKey)
}

// secretAuditPageCollector retains the first page plus one look-ahead row.
// The file can hold millions of fleet events; query memory scales with the
// requested page, never with retention volume or one noisy sandbox.
type secretAuditPageCollector struct {
	limit      int
	candidates secretAuditEventMaxHeap
}

func newSecretAuditPageCollector(limit int) *secretAuditPageCollector {
	c := &secretAuditPageCollector{limit: limit, candidates: make(secretAuditEventMaxHeap, 0, limit+1)}
	heap.Init(&c.candidates)
	return c
}

func (c *secretAuditPageCollector) keep(ev SecretAuditEvent) {
	if len(c.candidates) < c.limit+1 {
		heap.Push(&c.candidates, ev)
		return
	}
	if secretAuditEventLess(ev, c.candidates[0]) {
		c.candidates[0] = ev
		heap.Fix(&c.candidates, 0)
	}
}

// bound is the newest event a full collector would still accept; anything
// at or after it in (time, key) order cannot make the page.
func (c *secretAuditPageCollector) bound() (SecretAuditEvent, bool) {
	if len(c.candidates) < c.limit+1 {
		return SecretAuditEvent{}, false
	}
	return c.candidates[0], true
}

func (c *secretAuditPageCollector) result() ([]SecretAuditEvent, string) {
	matched := append([]SecretAuditEvent(nil), c.candidates...)
	sort.SliceStable(matched, func(i, j int) bool {
		return secretAuditEventLess(matched[i], matched[j])
	})
	hasMore := len(matched) > c.limit
	if hasMore {
		matched = matched[:c.limit]
	}
	if hasMore && len(matched) > 0 {
		return matched, formatSecretAuditCursor(matched[len(matched)-1])
	}
	return matched, ""
}

// verifySecretAuditRecord checks one record against its own hash. It proves
// the bytes returned are the bytes the writer chained, not that the chain
// as a whole is intact — that is what the full verification paths are for.
func verifySecretAuditRecord(ev SecretAuditEvent) error {
	prev := strings.TrimSpace(ev.PrevHash)
	if prev == "" {
		return errors.New("prev_hash is missing")
	}
	if ev.EventHash == "" {
		return errors.New("event_hash is missing")
	}
	if ev.Kind == secretAuditKindRetentionRedacted {
		// A retention stub has no payload to hash; it is sound when it
		// carries nothing but its links (the chain scan checks the linking).
		if redactSecretAuditEvent(ev) != ev {
			return errors.New("retention stub carries payload")
		}
		return nil
	}
	if ev.EventHash != auditlog.HashEvent(prev, ev) {
		return errors.New("event_hash mismatch")
	}
	return nil
}

// readIndexedSecretAudit reads only the records the index says the page
// needs. Selection is by time first (the index carries it), then the exact
// (time, key) contract is applied to the records themselves; ties at the
// page boundary are read in full so a same-nanosecond burst can never split
// a page incorrectly.
func readIndexedSecretAudit(ctx context.Context, f *os.File, chunks []store.SecretAuditIndexChunk, q secretAuditPageQuery, page *secretAuditPageCollector) error {
	kindFilter := secretAuditIndexKindFilter(q.kind)
	hasCursor := !q.after.IsZero()
	afterNano := q.after.UnixNano()
	want := q.limit + 1
	var (
		boundary []auditIndexCand // records at the cursor's exact time: decided by key
		heapc    = make(auditIndexCandHeap, 0, want)
	)
	// Bounded max-heap of the want smallest (time, offset).
	push := func(c auditIndexCand) {
		if len(heapc) < want {
			heap.Push(&heapc, c)
			return
		}
		if auditIndexCandLess(c, heapc[0]) {
			heapc[0] = c
			heap.Fix(&heapc, 0)
		}
	}
	decoded := make([][]auditlog.IndexEntry, len(chunks))
	for ci, chunk := range chunks {
		entries, err := chunk.Decode()
		if err != nil {
			return fmt.Errorf("%w: chunk %q/%q seq %d: %v", errSecretAuditIndexCorrupt, chunk.SandboxID, chunk.IncarnationID, chunk.Seq, err)
		}
		decoded[ci] = entries
		for _, e := range entries {
			if kindFilter != auditlog.IndexKindOther && e.Kind != auditlog.IndexKindOther && e.Kind != auditlog.IndexKindGap && e.Kind != kindFilter {
				continue
			}
			if hasCursor {
				if e.TimeNano < afterNano {
					continue
				}
				if e.TimeNano == afterNano {
					boundary = append(boundary, auditIndexCand{e.TimeNano, e.Offset, e.Length})
					continue
				}
			}
			push(auditIndexCand{e.TimeNano, e.Offset, e.Length})
		}
	}
	toRead := append(boundary, heapc...)
	if len(heapc) == want {
		// Everything at the boundary time must be read: (time, offset) order
		// is only a proxy for (time, key), and the page must not depend on
		// where a same-time record happened to land in the file.
		edge := heapc[0].time
		seen := make(map[int64]struct{}, len(heapc))
		for _, c := range heapc {
			seen[c.offset] = struct{}{}
		}
		for _, entries := range decoded {
			for _, e := range entries {
				if e.TimeNano != edge {
					continue
				}
				if _, dup := seen[e.Offset]; dup {
					continue
				}
				seen[e.Offset] = struct{}{}
				toRead = append(toRead, auditIndexCand{e.TimeNano, e.Offset, e.Length})
			}
		}
	}
	var buf []byte
	for n, c := range toRead {
		if n%64 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if c.length <= 0 || c.length > secretAuditMaxLineBytes {
			return fmt.Errorf("%w: entry at offset %d has length %d", errSecretAuditIndexCorrupt, c.offset, c.length)
		}
		if int64(cap(buf)) < c.length {
			buf = make([]byte, c.length)
		}
		buf = buf[:c.length]
		if _, err := f.ReadAt(buf, c.offset); err != nil {
			return fmt.Errorf("%w: entry at offset %d: %v", errSecretAuditIndexCorrupt, c.offset, err)
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal(bytes.TrimSpace(buf), &ev); err != nil {
			return fmt.Errorf("%w: entry at offset %d is not a record: %v", errSecretAuditIndexCorrupt, c.offset, err)
		}
		isGap := ev.Result == secretAuditResultGap || ev.Kind == secretAuditKindGap
		if !isGap && ev.SandboxID != q.sandboxID {
			return fmt.Errorf("%w: entry at offset %d belongs to another sandbox", errSecretAuditIndexCorrupt, c.offset)
		}
		if err := verifySecretAuditRecord(ev); err != nil {
			return fmt.Errorf("secret audit record at offset %d failed integrity verification: %w", c.offset, err)
		}
		if q.matches(ev) {
			page.keep(ev)
		}
	}
	return nil
}

// auditIndexCand is one index entry under consideration for a page.
type auditIndexCand struct {
	time, offset, length int64
}

func auditIndexCandLess(a, b auditIndexCand) bool {
	if a.time != b.time {
		return a.time < b.time
	}
	return a.offset < b.offset
}

// auditIndexCandHeap keeps the greatest candidate at index zero so a page
// can be selected in O(entries log page).
type auditIndexCandHeap []auditIndexCand

func (h auditIndexCandHeap) Len() int           { return len(h) }
func (h auditIndexCandHeap) Less(i, j int) bool { return auditIndexCandLess(h[j], h[i]) }
func (h auditIndexCandHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *auditIndexCandHeap) Push(x any)        { *h = append(*h, x.(auditIndexCand)) }
func (h *auditIndexCandHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// scanSecretAuditRange streams [from, to) of the file into the page. It is
// the whole answer when the index cannot serve and the unindexed tail
// otherwise. Records that cannot belong to the page are skipped on a byte
// match before they are parsed.
func scanSecretAuditRange(ctx context.Context, f *os.File, from, to int64, q secretAuditPageQuery, page *secretAuditPageCollector) error {
	if from >= to {
		return nil
	}
	idJSON, err := json.Marshal(q.sandboxID)
	if err != nil {
		return err
	}
	needle := append([]byte(`"sandbox_id":`), idJSON...)
	gapResult := []byte(`"result":"gap"`)
	gapKind := []byte(`"kind":"gap"`)
	br := bufio.NewReaderSize(io.NewSectionReader(f, from, to-from), 64*1024)
	offset := from
	const cancelCheckEvery = 256
	for n := 0; ; n++ {
		if n%cancelCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		line, consumed, _, tooLong, err := readSecretAuditLine(br)
		if err != nil {
			return err
		}
		if consumed == 0 {
			return nil
		}
		start := offset
		offset += consumed
		if tooLong {
			return fmt.Errorf("secret audit record at offset %d exceeds %d bytes", start, secretAuditMaxLineBytes)
		}
		text := bytes.TrimSpace(line)
		if len(text) == 0 {
			continue
		}
		if !bytes.Contains(text, needle) && !bytes.Contains(text, gapResult) && !bytes.Contains(text, gapKind) {
			continue
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal(text, &ev); err != nil {
			return fmt.Errorf("secret audit record at offset %d is malformed: %w", start, err)
		}
		if !q.matches(ev) {
			continue
		}
		if bound, full := page.bound(); full && !secretAuditEventLess(ev, bound) {
			continue // cannot make the page; skip the hash work
		}
		if err := verifySecretAuditRecord(ev); err != nil {
			return fmt.Errorf("secret audit record at offset %d failed integrity verification: %w", start, err)
		}
		page.keep(ev)
	}
}

// secretAuditSnapshot is one file identity captured under the flock.
type secretAuditSnapshot struct {
	size       int64
	generation string
	writerTip  string
}

// openSecretAuditSnapshot captures a complete append boundary under the same
// flock used by the writer and retention. The descriptor remains valid across
// a later retention rename; limiting the reader prevents a concurrent append
// from exposing a partial final JSON line, and the generation lets the caller
// tell which file's offsets it is holding.
func (s *Service) openSecretAuditSnapshot(path string) (*os.File, secretAuditSnapshot, error) {
	var (
		f    *os.File
		snap secretAuditSnapshot
	)
	open := func() error {
		var err error
		f, snap.generation, snap.size, err = openSecretAuditGeneration(path)
		if err != nil {
			return err
		}
		if s != nil && s.secretAuditFile != nil {
			snap.writerTip, _ = s.secretAuditFile.chainTip()
		}
		return nil
	}
	if s != nil && s.secretAuditFile != nil {
		if err := s.secretAuditFile.withAuditFileLock(open); err != nil {
			return nil, snap, err
		}
		return f, snap, nil
	}
	if err := open(); err != nil {
		return nil, snap, err
	}
	return f, snap, nil
}

// SecretAuditVerification is the report of one on-demand full-chain
// verification of the local audit log.
type SecretAuditVerification struct {
	OK         bool   `json:"ok"`
	Generation string `json:"generation,omitempty"`
	Head       string `json:"head"`
	EventID    string `json:"event_id,omitempty"`
	Records    int64  `json:"records"`
	// Redacted counts retention stubs among the records: expired records
	// whose payload retention removed in place because a newer record stood
	// in front of them. The node never produces one inside the retention
	// window, so a stub younger than SB_SECRET_AUDIT_RETENTION_DAYS is
	// evidence of a hand-edited file.
	Redacted int64 `json:"redacted"`
	Bytes    int64 `json:"bytes"`
	// WriterTipMatches reports whether the verified head equals the tip the
	// writer held at the snapshot, i.e. the file and the process agree.
	WriterTipMatches bool   `json:"writer_tip_matches"`
	IndexReady       bool   `json:"index_ready"`
	IndexLagBytes    int64  `json:"index_lag_bytes"`
	DurationMS       int64  `json:"duration_ms"`
	Error            string `json:"error,omitempty"`
}

var secretAuditVerifyMu sync.Mutex

// VerifySecretAuditChain re-verifies every record of the local audit log
// against its hash chain, on demand. It is O(file) by design and runs one at
// a time per node (a second caller gets ErrSecretAuditBusy). Page reads no
// longer do this work; boot, retention, and this call are where the whole
// chain is proven.
func (s *Service) VerifySecretAuditChain(ctx context.Context) (SecretAuditVerification, error) {
	if s == nil {
		return SecretAuditVerification{}, errors.New("service unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !secretAuditVerifyMu.TryLock() {
		secretAuditQueryBusyTotal.Add(1)
		return SecretAuditVerification{}, ErrSecretAuditBusy
	}
	defer secretAuditVerifyMu.Unlock()
	s.ensureSecretAuditSink()
	path := s.secretAuditPath()
	if path == "" {
		return SecretAuditVerification{}, errors.New("secret audit sink is not configured")
	}
	started := time.Now()
	report := SecretAuditVerification{Head: auditlog.GenesisPrevHash}
	if idx := s.secretAuditIndex; idx.isReady() {
		report.IndexReady = true
		report.IndexLagBytes = secretAuditIndexLagBytes.Value()
	}
	f, snap, err := s.openSecretAuditSnapshot(path)
	if err != nil {
		if os.IsNotExist(err) {
			report.OK = true
			report.WriterTipMatches = snap.writerTip == "" || snap.writerTip == auditlog.GenesisPrevHash
			report.DurationMS = time.Since(started).Milliseconds()
			return report, nil
		}
		return report, err
	}
	defer f.Close()
	report.Generation = snap.generation
	report.Bytes = snap.size
	scan, err := scanSecretAuditChainReader(io.LimitReader(f, snap.size), secretAuditScanOptions{})
	if err == nil && scan.tornBytes > 0 {
		err = fmt.Errorf("unterminated %d-byte tail at offset %d is not valid json", scan.tornBytes, scan.validEnd)
	}
	report.Head = scan.head
	report.EventID = scan.eventID
	report.Records = scan.records
	report.Redacted = scan.redacted
	report.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		report.Error = err.Error()
		secretAuditChainVerifyOK.Set(0)
		secretAuditChainVerifiedUnix.Set(time.Now().Unix())
		return report, nil
	}
	report.WriterTipMatches = snap.writerTip == "" || snap.writerTip == scan.head
	report.OK = report.WriterTipMatches
	if !report.OK {
		report.Error = "verified head does not match the writer's tip"
	}
	if report.OK {
		secretAuditChainVerifyOK.Set(1)
	} else {
		secretAuditChainVerifyOK.Set(0)
	}
	secretAuditChainVerifiedUnix.Set(time.Now().Unix())
	return report, nil
}

// ListSecretAudit returns local events merged with a live fan-out to reachable
// peers. Coverage.Missing lists peers that timed out or failed — never silent.
//
// Scale bounds:
//   - target the bounded Raft-retained owner history when complete
//   - fail explicitly when history is absent/truncated; never scan all workers
//   - skip pure ingress roles (they do not host sandboxes)
//   - bounded parallel peer fetches under a short global deadline
func (s *Service) ListSecretAudit(ctx context.Context, sandboxID string, opts SecretAuditQuery) (SecretAuditPage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(opts.IncarnationID) == "" {
		opts.IncarnationID = s.secretIncarnationForSeal(sandboxID)
	}
	local, nextLocal, err := s.ListSecretAuditLocal(ctx, sandboxID, opts)
	if err != nil {
		return SecretAuditPage{}, err
	}
	after, afterKey, _ := parseSecretAuditCursor(opts.Cursor) // local validation succeeded

	selfID := ""
	var members []cluster.Member
	prefer := map[string]struct{}{}
	preferKnown := false
	if c := s.Cluster(); c != nil {
		selfID = c.SelfNodeID()
		members = c.Members()
		if p, ok := c.PlacementOf(sandboxID); ok {
			if !p.AuditNodesTruncated {
				addPreferredAuditNode(prefer, p.OwnerNodeID)
				addPreferredAuditNode(prefer, p.OrphanedOwnerNodeID)
				for _, id := range p.AuditNodeIDs {
					addPreferredAuditNode(prefer, id)
				}
				preferKnown = len(prefer) > 0
			}
		} else if acl, exists, aclErr := c.AuditACLForSandbox(ctx, sandboxID, opts.IncarnationID); aclErr == nil && exists && !acl.AuditNodesTruncated {
			for _, id := range acl.AuditNodeIDs {
				addPreferredAuditNode(prefer, id)
			}
			preferKnown = len(prefer) > 0
		}
	}
	if len(members) > 1 && !preferKnown {
		return SecretAuditPage{}, ErrSecretAuditIndexIncomplete
	}

	coverage := SecretAuditCoverage{Answered: []string{}}
	if selfID != "" {
		coverage.Answered = append(coverage.Answered, selfID)
	} else {
		coverage.Answered = append(coverage.Answered, "local")
	}

	merged := append([]SecretAuditEvent(nil), local...)
	fetcher := s.auditPeerFetcher()
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultSecretAuditLimit
	}
	if limit > maxSecretAuditLimit {
		limit = maxSecretAuditLimit
	}

	type peerJob struct {
		nodeID string
	}
	var jobs []peerJob
	deadPrefer := map[string]struct{}{}
	for id := range prefer {
		deadPrefer[id] = struct{}{}
	}
	for _, m := range members {
		if !m.Alive {
			continue
		}
		if m.NodeID == selfID {
			delete(deadPrefer, m.NodeID)
			continue
		}
		if strings.TrimSpace(m.InternalURL) == "" {
			continue
		}
		role := strings.TrimSpace(m.Role)
		if role == config.NodeRoleIngress {
			continue // ingress never hosts sandboxes / local audit rows
		}
		if preferKnown {
			if _, ok := prefer[m.NodeID]; !ok {
				continue
			}
		}
		delete(deadPrefer, m.NodeID)
		jobs = append(jobs, peerJob{nodeID: m.NodeID})
	}
	for id := range deadPrefer {
		if id == selfID {
			continue
		}
		coverage.Missing = append(coverage.Missing, id)
	}

	if fetcher == nil {
		for _, j := range jobs {
			coverage.Missing = append(coverage.Missing, j.nodeID)
		}
	} else if len(jobs) > 0 {
		fanCtx, cancel := context.WithTimeout(ctx, secretAuditFanoutDeadline)
		defer cancel()
		type peerResult struct {
			nodeID string
			page   cluster.AuditPeerPage
			err    error
		}
		workers := min(secretAuditFanoutParallel, len(jobs))
		jobCh := make(chan peerJob)
		results := make(chan peerResult, workers)
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobCh {
					select {
					case secretAuditFanoutSlots <- struct{}{}:
					case <-fanCtx.Done():
						results <- peerResult{nodeID: j.nodeID, err: fanCtx.Err()}
						continue
					}
					page, fetchErr := fetcher.FetchSandboxAuditFromPeer(fanCtx, j.nodeID, sandboxID, limit, opts.Cursor, opts.Kind, opts.IncarnationID)
					<-secretAuditFanoutSlots
					results <- peerResult{nodeID: j.nodeID, page: page, err: fetchErr}
				}
			}()
		}
		go func() {
			defer close(jobCh)
			for _, j := range jobs {
				select {
				case jobCh <- j:
				case <-fanCtx.Done():
					return
				}
			}
		}()
		go func() {
			wg.Wait()
			close(results)
		}()
		accounted := make(map[string]struct{}, len(jobs))
		for r := range results {
			accounted[r.nodeID] = struct{}{}
			if r.err != nil {
				coverage.Missing = append(coverage.Missing, r.nodeID)
				continue
			}
			coverage.Answered = append(coverage.Answered, r.nodeID)
			for _, dto := range r.page.Events {
				ev := secretAuditEventFromDTO(dto)
				if !secretAuditEventMatches(ev, sandboxID, opts.IncarnationID, opts.Kind, after, afterKey) {
					continue
				}
				merged = append(merged, ev)
			}
		}
		// The global deadline may expire while jobs are still queued. Account for
		// every unscheduled node explicitly so bounding goroutines can never turn
		// into silent partial coverage.
		for _, j := range jobs {
			if _, ok := accounted[j.nodeID]; !ok {
				coverage.Missing = append(coverage.Missing, j.nodeID)
			}
		}
	}

	coverage.Partial = len(coverage.Missing) > 0
	merged = dedupeSecretAuditEvents(merged)
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].Time.Equal(merged[j].Time) {
			return secretAuditEventCursorKey(merged[i]) < secretAuditEventCursorKey(merged[j])
		}
		return merged[i].Time.Before(merged[j].Time)
	})
	nextCursor := nextLocal
	if len(merged) > limit {
		merged = merged[:limit]
	}
	if len(merged) == limit {
		nextCursor = formatSecretAuditCursor(merged[len(merged)-1])
	}
	return SecretAuditPage{Events: merged, Coverage: coverage, NextCursor: nextCursor}, nil
}

func addPreferredAuditNode(prefer map[string]struct{}, nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID != "" {
		prefer[nodeID] = struct{}{}
	}
}

func (s *Service) secretAuditPath() string {
	if s == nil {
		return ""
	}
	if s.secretAuditFile != nil && s.secretAuditFile.path != "" {
		return s.secretAuditFile.path
	}
	dataDir := secretAuditDataDir(s.cfg.DBPath)
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, "audit", secretAuditFileName)
}

func (s *Service) auditPeerFetcher() cluster.AuditPeerFetcher {
	if s == nil {
		return nil
	}
	if s.testAuditFetcher != nil {
		return s.testAuditFetcher
	}
	c := s.Cluster()
	if c == nil {
		return nil
	}
	if f, ok := c.(cluster.AuditPeerFetcher); ok {
		return f
	}
	return nil
}

func secretAuditEventFromDTO(dto cluster.AuditEventDTO) SecretAuditEvent {
	// Both public types are aliases of auditlog.Event. Keep this assignment
	// direct so adding a field to the shared DTO cannot silently omit it here.
	return dto
}

// secretAuditKindMatches reports whether storedKind satisfies a query filter.
// Empty filter matches everything. Gap markers always match so kind-filtered
// pages cannot hide silent drops. Stored rows must carry an explicit kind; the
// audit format has no compatibility interpretation for missing fields.
func secretAuditKindMatches(storedKind, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	storedKind = strings.TrimSpace(storedKind)
	if storedKind == secretAuditKindGap {
		return true
	}
	return storedKind == filter
}

// secretAuditEventMatches re-applies the complete query contract to both
// local JSONL rows and peer responses. Peer mTLS authenticates the node, but a
// stale or faulty peer must not be able to inject another sandbox lifetime into
// the merged evidence page.
func secretAuditEventMatches(ev SecretAuditEvent, sandboxID, incarnationID, kind string, after time.Time, afterKey string) bool {
	if ev.Kind == secretAuditKindRetentionCheckpoint || ev.Kind == secretAuditKindRetentionRedacted {
		return false // chain structure left by retention, never evidence
	}
	isGap := ev.Result == secretAuditResultGap || ev.Kind == secretAuditKindGap
	if !isGap && ev.SandboxID != sandboxID {
		return false
	}
	if !isGap && incarnationID != "" && strings.TrimSpace(ev.IncarnationID) != strings.TrimSpace(incarnationID) {
		return false
	}
	if !isGap && !secretAuditKindMatches(ev.Kind, kind) {
		return false
	}
	if after.IsZero() {
		return true
	}
	if ev.Time.Before(after) {
		return false
	}
	return !ev.Time.Equal(after) || (afterKey != "" && secretAuditEventCursorKey(ev) > afterKey)
}

const secretAuditCursorSep = "\x1f"

func secretAuditEventCursorKey(ev SecretAuditEvent) string {
	return strings.Join([]string{
		ev.EventID,
		ev.SandboxID,
		ev.Kind,
		ev.Result,
		ev.Reason,
		ev.Actor,
		ev.CorrelationID,
		ev.Ref,
		ev.Destination,
		ev.NodeID,
		ev.Network,
		fmt.Sprintf("%d", ev.BytesIn),
		fmt.Sprintf("%d", ev.BytesOut),
	}, secretAuditCursorSep)
}

func secretAuditEventLess(a, b SecretAuditEvent) bool {
	if a.Time.Equal(b.Time) {
		return secretAuditEventCursorKey(a) < secretAuditEventCursorKey(b)
	}
	return a.Time.Before(b.Time)
}

// secretAuditEventMaxHeap keeps the greatest retained event at index zero so
// streaming queries can discard later rows while using O(page size) memory.
type secretAuditEventMaxHeap []SecretAuditEvent

func (h secretAuditEventMaxHeap) Len() int { return len(h) }
func (h secretAuditEventMaxHeap) Less(i, j int) bool {
	return secretAuditEventLess(h[j], h[i])
}
func (h secretAuditEventMaxHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *secretAuditEventMaxHeap) Push(x any) {
	*h = append(*h, x.(SecretAuditEvent))
}
func (h *secretAuditEventMaxHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func formatSecretAuditCursor(ev SecretAuditEvent) string {
	return ev.Time.UTC().Format(time.RFC3339Nano) + secretAuditCursorSep + secretAuditEventCursorKey(ev)
}

func parseSecretAuditCursor(raw string) (time.Time, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, "", nil
	}
	if i := strings.Index(raw, secretAuditCursorSep); i >= 0 {
		ts, err := time.Parse(time.RFC3339Nano, raw[:i])
		if err != nil {
			return time.Time{}, "", err
		}
		return ts, raw[i+len(secretAuditCursorSep):], nil
	}
	return time.Time{}, "", errors.New("audit cursor is missing its event key")
}

func dedupeSecretAuditEvents(events []SecretAuditEvent) []SecretAuditEvent {
	if len(events) == 0 {
		return events
	}
	seen := make(map[string]struct{}, len(events))
	out := make([]SecretAuditEvent, 0, len(events))
	for _, ev := range events {
		k := ev.Time.UTC().Format(time.RFC3339Nano) + secretAuditCursorSep + secretAuditEventCursorKey(ev)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, ev)
	}
	return out
}
