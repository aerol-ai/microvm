package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

const (
	defaultSecretAuditLimit = 100
	maxSecretAuditLimit     = 1000
	// secretAuditFanoutDeadline bounds the whole peer fan-out (not per peer).
	secretAuditFanoutDeadline = 5 * time.Second
	secretAuditFanoutParallel = 16
)

// SecretAuditQuery pages local/cluster secret-audit history for one sandbox.
type SecretAuditQuery struct {
	Limit  int    // default 100, max 1000
	Cursor string // exclusive lower bound time (RFC3339Nano), or empty = from start
	// Kind filters by event kind ("egress", "secret_open"). Empty = all kinds.
	// Empty Kind on stored events matches "secret_open" (back-compat).
	Kind string
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

// PruneSecretAudit rewrites the local JSONL dropping events older than
// SB_SECRET_AUDIT_RETENTION_DAYS. No-op when retention is 0 or the file sink
// is not configured.
func (s *Service) PruneSecretAudit(_ context.Context) error {
	if s == nil {
		return nil
	}
	days := s.cfg.SecretAuditRetentionDays
	if days <= 0 {
		return nil
	}
	s.ensureSecretAuditSink()
	f := s.secretAuditFile
	if f == nil {
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	return f.Prune(cutoff)
}

// ListSecretAuditLocal scans the authoritative local JSONL for sandboxID.
func (s *Service) ListSecretAuditLocal(_ context.Context, sandboxID string, opts SecretAuditQuery) (events []SecretAuditEvent, nextCursor string, err error) {
	if s == nil {
		return nil, "", nil
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return nil, "", nil
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
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	defer f.Close()

	var matched []SecretAuditEvent
	var malformed int
	sc := bufio.NewScanner(f)
	// Audit lines are small (metadata only); 1MiB is ample.
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			malformed++
			continue
		}
		isGap := ev.Result == secretAuditResultGap || ev.Kind == secretAuditKindGap
		if !isGap && ev.SandboxID != sandboxID {
			continue
		}
		if !isGap && !secretAuditKindMatches(ev.Kind, opts.Kind) {
			continue
		}
		key := secretAuditEventCursorKey(ev)
		if !after.IsZero() {
			if ev.Time.Before(after) {
				continue
			}
			if ev.Time.Equal(after) && (afterKey == "" || key <= afterKey) {
				continue
			}
		}
		matched = append(matched, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	if malformed > 0 {
		matched = append(matched, SecretAuditEvent{
			Time:      time.Now().UTC(),
			SandboxID: sandboxID,
			Result:    secretAuditResultGap,
			Reason:    "malformed_jsonl",
			Kind:      secretAuditKindGap,
		})
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].Time.Equal(matched[j].Time) {
			return secretAuditEventCursorKey(matched[i]) < secretAuditEventCursorKey(matched[j])
		}
		return matched[i].Time.Before(matched[j].Time)
	})
	if len(matched) > limit {
		matched = matched[:limit]
	}
	if len(matched) == limit {
		last := matched[len(matched)-1]
		nextCursor = formatSecretAuditCursor(last)
	}
	return matched, nextCursor, nil
}

// ListSecretAudit returns local events merged with a live fan-out to reachable
// peers. Coverage.Missing lists peers that timed out or failed — never silent.
//
// Interim scale bounds (full indexed/central sink is parked in TODOS.md):
//   - prefer placement owner + SecretRecipients when known
//   - skip pure ingress roles (they do not host sandboxes)
//   - bounded parallel peer fetches under a short global deadline
func (s *Service) ListSecretAudit(ctx context.Context, sandboxID string, opts SecretAuditQuery) (SecretAuditPage, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	local, nextLocal, err := s.ListSecretAuditLocal(ctx, sandboxID, opts)
	if err != nil {
		return SecretAuditPage{}, err
	}

	selfID := ""
	selfURL := ""
	var members []cluster.Member
	prefer := map[string]struct{}{}
	if c := s.Cluster(); c != nil {
		selfID = c.SelfNodeID()
		selfURL = strings.TrimRight(c.SelfAPIURL(), "/")
		members = c.Members()
		if p, ok := c.PlacementOf(sandboxID); ok {
			if id := strings.TrimSpace(p.OwnerNodeID); id != "" {
				prefer[id] = struct{}{}
			}
			for _, id := range p.SecretRecipients {
				if id = strings.TrimSpace(id); id != "" {
					prefer[id] = struct{}{}
				}
			}
		}
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
		apiURL string
	}
	var jobs []peerJob
	deadPrefer := map[string]struct{}{}
	for id := range prefer {
		deadPrefer[id] = struct{}{}
	}
	for _, m := range members {
		if !m.Alive || strings.TrimSpace(m.APIURL) == "" {
			continue
		}
		if m.NodeID == selfID {
			delete(deadPrefer, m.NodeID)
			continue
		}
		role := strings.TrimSpace(m.Role)
		if role == config.NodeRoleIngress {
			continue // ingress never hosts sandboxes / local audit rows
		}
		if len(prefer) > 0 {
			if _, ok := prefer[m.NodeID]; !ok {
				continue
			}
		}
		delete(deadPrefer, m.NodeID)
		peerURL := strings.TrimRight(m.APIURL, "/")
		if peerURL == "" || peerURL == selfURL {
			continue
		}
		jobs = append(jobs, peerJob{nodeID: m.NodeID, apiURL: peerURL})
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
		results := make(chan peerResult, len(jobs))
		sem := make(chan struct{}, secretAuditFanoutParallel)
		var wg sync.WaitGroup
		for _, j := range jobs {
			wg.Add(1)
			go func(j peerJob) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-fanCtx.Done():
					results <- peerResult{nodeID: j.nodeID, err: fanCtx.Err()}
					return
				}
				defer func() { <-sem }()
				page, fetchErr := fetcher.FetchSandboxAuditFromPeer(fanCtx, j.apiURL, sandboxID, limit, opts.Cursor, opts.Kind)
				results <- peerResult{nodeID: j.nodeID, page: page, err: fetchErr}
			}(j)
		}
		go func() {
			wg.Wait()
			close(results)
		}()
		for r := range results {
			if r.err != nil {
				coverage.Missing = append(coverage.Missing, r.nodeID)
				continue
			}
			coverage.Answered = append(coverage.Answered, r.nodeID)
			for _, dto := range r.page.Events {
				ev := secretAuditEventFromDTO(dto)
				if !secretAuditKindMatches(ev.Kind, opts.Kind) {
					continue
				}
				merged = append(merged, ev)
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
	} else if nextCursor == "" && len(merged) > 0 && len(merged) == limit {
		nextCursor = formatSecretAuditCursor(merged[len(merged)-1])
	}
	return SecretAuditPage{Events: merged, Coverage: coverage, NextCursor: nextCursor}, nil
}

func (s *Service) secretAuditPath() string {
	if s != nil && s.secretAuditFile != nil && s.secretAuditFile.path != "" {
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
	return SecretAuditEvent{
		Time:          dto.Time,
		Actor:         dto.Actor,
		SandboxID:     dto.SandboxID,
		Ref:           dto.Ref,
		Result:        dto.Result,
		Reason:        dto.Reason,
		CorrelationID: dto.CorrelationID,
		NodeID:        dto.NodeID,
		Kind:          dto.Kind,
		Destination:   dto.Destination,
		Network:       dto.Network,
		BytesIn:       dto.BytesIn,
		BytesOut:      dto.BytesOut,
	}
}

// secretAuditKindMatches reports whether storedKind satisfies a query filter.
// Empty filter matches everything. Query "secret_open" also matches empty Kind
// (legacy secret-open lines). Gap markers always match so kind-filtered pages
// cannot hide silent drops.
func secretAuditKindMatches(storedKind, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	storedKind = strings.TrimSpace(storedKind)
	if storedKind == secretAuditKindGap {
		return true
	}
	if storedKind == "" {
		storedKind = secretAuditKindSecretOpen
	}
	return storedKind == filter
}

const secretAuditCursorSep = "\x1f"

func secretAuditEventCursorKey(ev SecretAuditEvent) string {
	return strings.Join([]string{
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
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, "", err
	}
	return ts, "", nil
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
