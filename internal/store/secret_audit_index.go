package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The secret-audit index is a per-sandbox posting list over the local
// secrets.jsonl so a page of one sandbox's history costs O(page), not a scan
// of every retained fleet event. It is derived data: the JSONL stays the
// evidence, and anything that disagrees with the file is thrown away and
// rebuilt from it (secret_audit_index_meta.generation pins the file the
// offsets belong to). Rows are chunks of up to a few thousand entries so a
// hot sandbox costs one row rewrite per append batch rather than one row per
// event, which keeps the index at a few percent of the log's size and keeps
// its writes off the single SQLite writer's critical path.

// ErrSecretAuditIndexStale is returned when a write's expected meta no longer
// matches the stored one: another writer (rebuild, prune shift) moved the
// index first, and the caller's entries were computed against the old state.
var ErrSecretAuditIndexStale = errors.New("secret audit index moved underneath this write")

// SecretAuditIndexMeta describes how much of the audit file the index covers.
type SecretAuditIndexMeta struct {
	// Generation identifies the file the offsets belong to (hash of its first
	// line, as the export cursor uses). Retention rewrites the file and so
	// changes it.
	Generation string
	// IndexedThrough is the byte offset just past the last indexed line. The
	// reader scans [IndexedThrough, EOF) itself, so the index may lag the
	// file without ever hiding an event.
	IndexedThrough int64
	// LastLineOffset / LastEventHash pin the last indexed record so boot can
	// check, with one read, that the file still holds what the index says.
	LastLineOffset int64
	LastEventHash  string
	// AllowBreak carries the chain verifier's checkpoint state across
	// batches: true only right after a retention checkpoint.
	AllowBreak bool
	UpdatedAt  time.Time
}

// SecretAuditIndexKey is one posting list: a sandbox lifecycle. Gap markers
// (which every query must see) live under the empty sandbox id.
type SecretAuditIndexKey struct {
	SandboxID     string
	IncarnationID string
}

// SecretAuditIndexChunk is one bounded slice of a posting list. Entries are
// encoded relative to FirstOffset, so re-basing a chunk after retention is a
// column update and never touches the blob.
type SecretAuditIndexChunk struct {
	SecretAuditIndexKey
	Seq         int64
	FirstOffset int64
	LastOffset  int64
	MinTime     int64
	MaxTime     int64
	LastTime    int64
	N           int
	Entries     []byte
}

// NewSecretAuditIndexChunk encodes entries (file order) as chunk seq of key.
func NewSecretAuditIndexChunk(key SecretAuditIndexKey, seq int64, entries []auditlog.IndexEntry) (SecretAuditIndexChunk, error) {
	c := SecretAuditIndexChunk{SecretAuditIndexKey: key, Seq: seq}
	if len(entries) == 0 {
		return c, nil
	}
	c.FirstOffset = entries[0].Offset
	c.MinTime, c.MaxTime = entries[0].TimeNano, entries[0].TimeNano
	if err := c.Append(entries); err != nil {
		return SecretAuditIndexChunk{}, err
	}
	return c, nil
}

// Append extends the chunk with entries that follow its last one in file
// order. The row's summary columns supply the delta base, so appending never
// decodes the existing blob.
func (c *SecretAuditIndexChunk) Append(entries []auditlog.IndexEntry) error {
	if len(entries) == 0 {
		return nil
	}
	prev := auditlog.IndexEntry{Offset: c.LastOffset - c.FirstOffset, TimeNano: c.LastTime}
	rel := make([]auditlog.IndexEntry, len(entries))
	for i, e := range entries {
		if e.Offset < c.FirstOffset {
			return fmt.Errorf("index entry offset %d precedes chunk base %d", e.Offset, c.FirstOffset)
		}
		rel[i] = e
		rel[i].Offset = e.Offset - c.FirstOffset
	}
	buf, last, err := auditlog.AppendIndexEntries(c.Entries, prev, c.N > 0, rel)
	if err != nil {
		return err
	}
	if c.N == 0 {
		c.MinTime, c.MaxTime = entries[0].TimeNano, entries[0].TimeNano
	}
	for _, e := range entries {
		c.MinTime = min(c.MinTime, e.TimeNano)
		c.MaxTime = max(c.MaxTime, e.TimeNano)
	}
	c.Entries = buf
	c.LastOffset = c.FirstOffset + last.Offset
	c.LastTime = last.TimeNano
	c.N += len(entries)
	return nil
}

// Decode returns the chunk's entries with absolute file offsets.
func (c SecretAuditIndexChunk) Decode() ([]auditlog.IndexEntry, error) {
	entries, err := auditlog.DecodeIndexEntries(c.Entries)
	if err != nil {
		return nil, err
	}
	if len(entries) != c.N {
		return nil, auditlog.ErrIndexEntriesCorrupt
	}
	for i := range entries {
		entries[i].Offset += c.FirstOffset
	}
	return entries, nil
}

// GetSecretAuditIndexMeta returns the stored coverage, or ok=false when the
// index has never been built.
func (s *Store) GetSecretAuditIndexMeta(ctx context.Context) (SecretAuditIndexMeta, bool, error) {
	return readSecretAuditIndexMeta(ctx, s.db)
}

type dbQueryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func readSecretAuditIndexMeta(ctx context.Context, q dbQueryRower) (SecretAuditIndexMeta, bool, error) {
	var (
		m          SecretAuditIndexMeta
		allowBreak int
	)
	err := q.QueryRowContext(ctx, `
		SELECT generation, indexed_through, last_line_offset, last_event_hash, allow_break, updated_at
		FROM secret_audit_index_meta WHERE id = 1
	`).Scan(&m.Generation, &m.IndexedThrough, &m.LastLineOffset, &m.LastEventHash, &allowBreak, &m.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SecretAuditIndexMeta{}, false, nil
	}
	if err != nil {
		return SecretAuditIndexMeta{}, false, fmt.Errorf("read secret audit index meta: %w", err)
	}
	m.AllowBreak = allowBreak != 0
	return m, true, nil
}

func writeSecretAuditIndexMeta(ctx context.Context, exec dbExecer, m SecretAuditIndexMeta) error {
	allowBreak := 0
	if m.AllowBreak {
		allowBreak = 1
	}
	_, err := exec.ExecContext(ctx, `
		INSERT INTO secret_audit_index_meta (id, generation, indexed_through, last_line_offset, last_event_hash, allow_break, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			generation = excluded.generation,
			indexed_through = excluded.indexed_through,
			last_line_offset = excluded.last_line_offset,
			last_event_hash = excluded.last_event_hash,
			allow_break = excluded.allow_break,
			updated_at = excluded.updated_at
	`, m.Generation, m.IndexedThrough, m.LastLineOffset, m.LastEventHash, allowBreak, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("write secret audit index meta: %w", err)
	}
	return nil
}

// ResetSecretAuditIndex drops every posting list and pins meta to the start
// of a (re)build. The caller then streams the file back in with
// WriteSecretAuditIndex.
func (s *Store) ResetSecretAuditIndex(ctx context.Context, meta SecretAuditIndexMeta) error {
	if strings.TrimSpace(meta.Generation) == "" {
		return errors.New("reset secret audit index: generation is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secret audit index reset: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM secret_audit_index`); err != nil {
		return fmt.Errorf("reset secret audit index: %w", err)
	}
	if err := writeSecretAuditIndexMeta(ctx, tx, meta); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secret audit index reset: %w", err)
	}
	return nil
}

// LatestSecretAuditIndexChunks returns the open (highest-seq) chunk of each
// requested posting list, for appending. Missing keys are absent from the map.
func (s *Store) LatestSecretAuditIndexChunks(ctx context.Context, keys []SecretAuditIndexKey) (map[SecretAuditIndexKey]SecretAuditIndexChunk, error) {
	out := make(map[SecretAuditIndexKey]SecretAuditIndexChunk, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	stmt, err := s.db.PrepareContext(ctx, `
		SELECT chunk_seq, first_offset, last_offset, min_time, max_time, last_time, n, entries
		FROM secret_audit_index
		WHERE sandbox_id = ? AND incarnation_id = ?
		ORDER BY chunk_seq DESC
		LIMIT 1
	`)
	if err != nil {
		return nil, fmt.Errorf("prepare secret audit index tail read: %w", err)
	}
	defer stmt.Close()
	for _, k := range keys {
		c := SecretAuditIndexChunk{SecretAuditIndexKey: k}
		err := stmt.QueryRowContext(ctx, k.SandboxID, k.IncarnationID).Scan(
			&c.Seq, &c.FirstOffset, &c.LastOffset, &c.MinTime, &c.MaxTime, &c.LastTime, &c.N, &c.Entries)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read secret audit index tail: %w", err)
		}
		out[k] = c
	}
	return out, nil
}

// WriteSecretAuditIndex replaces the given chunks (by primary key) and
// advances meta in one transaction. expect is the meta the chunks were
// computed against; if the stored meta has moved, nothing is written and
// ErrSecretAuditIndexStale is returned so the caller recomputes.
func (s *Store) WriteSecretAuditIndex(ctx context.Context, expect, meta SecretAuditIndexMeta, chunks []SecretAuditIndexChunk) error {
	if strings.TrimSpace(meta.Generation) == "" {
		return errors.New("write secret audit index: generation is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secret audit index write: %w", err)
	}
	defer tx.Rollback()
	current, ok, err := readSecretAuditIndexMeta(ctx, tx)
	if err != nil {
		return err
	}
	if !ok || current.Generation != expect.Generation || current.IndexedThrough != expect.IndexedThrough {
		return ErrSecretAuditIndexStale
	}
	if len(chunks) > 0 {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO secret_audit_index
				(sandbox_id, incarnation_id, chunk_seq, first_offset, last_offset, min_time, max_time, last_time, n, entries)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(sandbox_id, incarnation_id, chunk_seq) DO UPDATE SET
				first_offset = excluded.first_offset,
				last_offset = excluded.last_offset,
				min_time = excluded.min_time,
				max_time = excluded.max_time,
				last_time = excluded.last_time,
				n = excluded.n,
				entries = excluded.entries
		`)
		if err != nil {
			return fmt.Errorf("prepare secret audit index write: %w", err)
		}
		defer stmt.Close()
		for _, c := range chunks {
			if c.N <= 0 || len(c.Entries) == 0 {
				return fmt.Errorf("write secret audit index: empty chunk for %q/%q seq %d", c.SandboxID, c.IncarnationID, c.Seq)
			}
			if _, err := stmt.ExecContext(ctx, c.SandboxID, c.IncarnationID, c.Seq, c.FirstOffset, c.LastOffset, c.MinTime, c.MaxTime, c.LastTime, c.N, c.Entries); err != nil {
				return fmt.Errorf("write secret audit index chunk: %w", err)
			}
		}
	}
	if err := writeSecretAuditIndexMeta(ctx, tx, meta); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secret audit index write: %w", err)
	}
	return nil
}

// ReadSecretAuditIndex returns the posting-list chunks a page for key may
// need, plus the meta they are consistent with, in one snapshot. An empty
// IncarnationID matches every lifecycle of the sandbox. Gap-marker chunks
// (empty sandbox id) are always included because every page must surface
// them. Chunks whose newest entry is older than minTime cannot contribute to
// a page after that cursor and are skipped in SQL.
func (s *Store) ReadSecretAuditIndex(ctx context.Context, key SecretAuditIndexKey, minTime int64) (SecretAuditIndexMeta, []SecretAuditIndexChunk, bool, error) {
	key.SandboxID = strings.TrimSpace(key.SandboxID)
	key.IncarnationID = strings.TrimSpace(key.IncarnationID)
	if key.SandboxID == "" {
		return SecretAuditIndexMeta{}, nil, false, errors.New("read secret audit index: sandbox id is required")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SecretAuditIndexMeta{}, nil, false, fmt.Errorf("begin secret audit index read: %w", err)
	}
	defer tx.Rollback()
	meta, ok, err := readSecretAuditIndexMeta(ctx, tx)
	if err != nil || !ok {
		return SecretAuditIndexMeta{}, nil, false, err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT sandbox_id, incarnation_id, chunk_seq, first_offset, last_offset, min_time, max_time, last_time, n, entries
		FROM secret_audit_index
		WHERE sandbox_id = ? AND (? = '' OR incarnation_id = ?) AND max_time >= ?
		UNION ALL
		SELECT sandbox_id, incarnation_id, chunk_seq, first_offset, last_offset, min_time, max_time, last_time, n, entries
		FROM secret_audit_index
		WHERE sandbox_id = '' AND max_time >= ?
		ORDER BY 1, 2, 3
	`, key.SandboxID, key.IncarnationID, key.IncarnationID, minTime, minTime)
	if err != nil {
		return SecretAuditIndexMeta{}, nil, false, fmt.Errorf("read secret audit index: %w", err)
	}
	defer rows.Close()
	var chunks []SecretAuditIndexChunk
	for rows.Next() {
		var c SecretAuditIndexChunk
		if err := rows.Scan(&c.SandboxID, &c.IncarnationID, &c.Seq, &c.FirstOffset, &c.LastOffset, &c.MinTime, &c.MaxTime, &c.LastTime, &c.N, &c.Entries); err != nil {
			return SecretAuditIndexMeta{}, nil, false, fmt.Errorf("scan secret audit index chunk: %w", err)
		}
		chunks = append(chunks, c)
	}
	if err := rows.Err(); err != nil {
		return SecretAuditIndexMeta{}, nil, false, fmt.Errorf("iterate secret audit index: %w", err)
	}
	return meta, chunks, true, nil
}

// ShiftSecretAuditIndex re-bases the index after retention rewrote the file.
// Retention drops a byte prefix (floor) and prepends one checkpoint line, so
// every surviving offset moves by the same delta: chunks entirely below the
// floor are deleted, the one chunk per list that straddles it is trimmed,
// and the rest are shifted in place. This is O(chunks), never O(events), and
// it is why prune does not have to rebuild the index from the kept lines.
func (s *Store) ShiftSecretAuditIndex(ctx context.Context, floor, delta int64, meta SecretAuditIndexMeta) error {
	if strings.TrimSpace(meta.Generation) == "" {
		return errors.New("shift secret audit index: generation is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secret audit index shift: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM secret_audit_index WHERE last_offset < ?`, floor); err != nil {
		return fmt.Errorf("drop pruned secret audit index chunks: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT sandbox_id, incarnation_id, chunk_seq, first_offset, n, entries
		FROM secret_audit_index
		WHERE first_offset < ? AND last_offset >= ?
	`, floor, floor)
	if err != nil {
		return fmt.Errorf("read straddling secret audit index chunks: %w", err)
	}
	var boundary []SecretAuditIndexChunk
	for rows.Next() {
		var c SecretAuditIndexChunk
		if err := rows.Scan(&c.SandboxID, &c.IncarnationID, &c.Seq, &c.FirstOffset, &c.N, &c.Entries); err != nil {
			rows.Close()
			return fmt.Errorf("scan straddling secret audit index chunk: %w", err)
		}
		boundary = append(boundary, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate straddling secret audit index chunks: %w", err)
	}
	rows.Close()
	for _, c := range boundary {
		entries, err := c.Decode()
		if err != nil {
			return fmt.Errorf("trim secret audit index chunk %q/%q seq %d: %w", c.SandboxID, c.IncarnationID, c.Seq, err)
		}
		kept := entries[:0]
		for _, e := range entries {
			if e.Offset >= floor {
				kept = append(kept, e)
			}
		}
		trimmed, err := NewSecretAuditIndexChunk(c.SecretAuditIndexKey, c.Seq, kept)
		if err != nil {
			return fmt.Errorf("re-encode trimmed secret audit index chunk: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE secret_audit_index
			SET first_offset = ?, last_offset = ?, min_time = ?, max_time = ?, last_time = ?, n = ?, entries = ?
			WHERE sandbox_id = ? AND incarnation_id = ? AND chunk_seq = ?
		`, trimmed.FirstOffset, trimmed.LastOffset, trimmed.MinTime, trimmed.MaxTime, trimmed.LastTime, trimmed.N, trimmed.Entries,
			c.SandboxID, c.IncarnationID, c.Seq); err != nil {
			return fmt.Errorf("write trimmed secret audit index chunk: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE secret_audit_index SET first_offset = first_offset + ?, last_offset = last_offset + ?
	`, delta, delta); err != nil {
		return fmt.Errorf("shift secret audit index chunks: %w", err)
	}
	if err := writeSecretAuditIndexMeta(ctx, tx, meta); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secret audit index shift: %w", err)
	}
	return nil
}

// SecretAuditIndexStats reports chunk and entry totals for observability
// and tests.
func (s *Store) SecretAuditIndexStats(ctx context.Context) (chunks, entries int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(n), 0) FROM secret_audit_index`).Scan(&chunks, &entries)
	if err != nil {
		return 0, 0, fmt.Errorf("secret audit index stats: %w", err)
	}
	return chunks, entries, nil
}
