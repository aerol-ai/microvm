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
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

const (
	defaultSecretAuditLimit = 100
	maxSecretAuditLimit     = 1000
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
	if c := strings.TrimSpace(opts.Cursor); c != "" {
		after, err = time.Parse(time.RFC3339Nano, c)
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
			continue
		}
		if ev.SandboxID != sandboxID {
			continue
		}
		if !secretAuditKindMatches(ev.Kind, opts.Kind) {
			continue
		}
		if !after.IsZero() && !ev.Time.After(after) {
			continue
		}
		matched = append(matched, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Time.Before(matched[j].Time)
	})
	if len(matched) > limit {
		matched = matched[:limit]
	}
	if len(matched) == limit {
		nextCursor = matched[len(matched)-1].Time.UTC().Format(time.RFC3339Nano)
	}
	return matched, nextCursor, nil
}

// ListSecretAudit returns local events merged with a live fan-out to reachable
// peers. Coverage.Missing lists peers that timed out or failed — never silent.
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
	if c := s.Cluster(); c != nil {
		selfID = c.SelfNodeID()
		selfURL = strings.TrimRight(c.SelfAPIURL(), "/")
		members = c.Members()
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

	for _, m := range members {
		if !m.Alive || strings.TrimSpace(m.APIURL) == "" {
			continue
		}
		if m.NodeID == selfID {
			continue
		}
		peerURL := strings.TrimRight(m.APIURL, "/")
		if peerURL == "" || peerURL == selfURL {
			continue
		}
		if fetcher == nil {
			coverage.Missing = append(coverage.Missing, m.NodeID)
			continue
		}
		page, fetchErr := fetcher.FetchSandboxAuditFromPeer(ctx, peerURL, sandboxID, limit, opts.Cursor, opts.Kind)
		if fetchErr != nil {
			coverage.Missing = append(coverage.Missing, m.NodeID)
			continue
		}
		coverage.Answered = append(coverage.Answered, m.NodeID)
		for _, dto := range page.Events {
			ev := secretAuditEventFromDTO(dto)
			if !secretAuditKindMatches(ev.Kind, opts.Kind) {
				continue
			}
			merged = append(merged, ev)
		}
	}

	coverage.Partial = len(coverage.Missing) > 0
	merged = dedupeSecretAuditEvents(merged)
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Time.Before(merged[j].Time)
	})
	nextCursor := nextLocal
	if len(merged) > limit {
		merged = merged[:limit]
		nextCursor = merged[len(merged)-1].Time.UTC().Format(time.RFC3339Nano)
	} else if nextCursor == "" && len(merged) == limit {
		nextCursor = merged[len(merged)-1].Time.UTC().Format(time.RFC3339Nano)
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
// (legacy secret-open lines).
func secretAuditKindMatches(storedKind, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	storedKind = strings.TrimSpace(storedKind)
	if storedKind == "" {
		storedKind = secretAuditKindSecretOpen
	}
	return storedKind == filter
}

func dedupeSecretAuditEvents(events []SecretAuditEvent) []SecretAuditEvent {
	if len(events) == 0 {
		return events
	}
	type key struct {
		t, ref, result, actor, corr, kind, dest string
	}
	seen := make(map[key]struct{}, len(events))
	out := make([]SecretAuditEvent, 0, len(events))
	for _, ev := range events {
		k := key{
			t:      ev.Time.UTC().Format(time.RFC3339Nano),
			ref:    ev.Ref,
			result: ev.Result,
			actor:  ev.Actor,
			corr:   ev.CorrelationID,
			kind:   ev.Kind,
			dest:   ev.Destination,
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, ev)
	}
	return out
}
