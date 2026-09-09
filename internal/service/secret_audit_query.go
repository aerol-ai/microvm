package service

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
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
	// requests amplified through many ingress nodes over the internal endpoint.
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
	if days <= 0 {
		return nil
	}
	s.ensureSecretAuditSink()
	f := s.secretAuditFile
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
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
	_, err := s.store.PruneSandboxAuditACL(ctx, cutoff)
	return err
}

// ListSecretAuditLocal scans the authoritative local JSONL for sandboxID.
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
	select {
	case secretAuditLocalQuerySlots <- struct{}{}:
		defer func() { <-secretAuditLocalQuerySlots }()
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
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
	var after time.Time
	var afterKey string
	if c := strings.TrimSpace(opts.Cursor); c != "" {
		after, afterKey, err = parseSecretAuditCursor(c)
		if err != nil {
			return nil, "", fmt.Errorf("invalid cursor: %w", err)
		}
	}

	s.ensureSecretAuditSink()
	path := s.secretAuditPath()
	if path == "" {
		return nil, "", nil
	}
	f, snapshotSize, err := s.openSecretAuditSnapshot(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	defer f.Close()

	// Retain only the first page plus one look-ahead row. The file can contain
	// millions of fleet events; query memory must scale with the requested page,
	// not with retention volume or one noisy sandbox.
	candidates := make(secretAuditEventMaxHeap, 0, limit+1)
	heap.Init(&candidates)
	keepCandidate := func(ev SecretAuditEvent) {
		if len(candidates) < limit+1 {
			heap.Push(&candidates, ev)
			return
		}
		if secretAuditEventLess(ev, candidates[0]) {
			candidates[0] = ev
			heap.Fix(&candidates, 0)
		}
	}
	verifier := newSecretAuditChainVerifier()
	sc := bufio.NewScanner(io.LimitReader(f, snapshotSize))
	// Audit lines are small (metadata only); 1MiB is ample.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	const cancelCheckEvery = 256
	linesSeen := 0
	for sc.Scan() {
		linesSeen++
		if linesSeen%cancelCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, "", err
			}
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, "", fmt.Errorf("secret audit line %d is malformed: %w", linesSeen, err)
		}
		if err := verifier.Add(ev); err != nil {
			return nil, "", fmt.Errorf("secret audit line %d failed integrity verification: %w", linesSeen, err)
		}
		if !secretAuditEventMatches(ev, sandboxID, incarnationID, opts.Kind, after, afterKey) {
			continue
		}
		keepCandidate(ev)
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	matched := append([]SecretAuditEvent(nil), candidates...)
	sort.SliceStable(matched, func(i, j int) bool {
		return secretAuditEventLess(matched[i], matched[j])
	})
	hasMore := len(matched) > limit
	if len(matched) > limit {
		matched = matched[:limit]
	}
	if hasMore && len(matched) > 0 {
		last := matched[len(matched)-1]
		nextCursor = formatSecretAuditCursor(last)
	}
	return matched, nextCursor, nil
}

// openSecretAuditSnapshot captures a complete append boundary under the same
// flock used by the writer and retention. The descriptor remains valid across
// a later retention rename; limiting the reader prevents a concurrent append
// from exposing a partial final JSON line to integrity verification.
func (s *Service) openSecretAuditSnapshot(path string) (*os.File, int64, error) {
	var (
		f    *os.File
		size int64
	)
	open := func() error {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			f = nil
			return err
		}
		size = st.Size()
		return nil
	}
	if s != nil && s.secretAuditFile != nil {
		if err := s.secretAuditFile.withAuditFileLock(open); err != nil {
			return nil, 0, err
		}
		return f, size, nil
	}
	if err := open(); err != nil {
		return nil, 0, err
	}
	return f, size, nil
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
