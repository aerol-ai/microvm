// Package catalogue holds shared helpers for the investor benchmark catalogue
// artifact: cross-process atomic JSON merge (soak loops) and Pushgateway push.
package catalogue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MergeFunc receives the existing JSON bytes (nil/empty on first write) and
// returns the merged document to persist.
type MergeFunc func(existing []byte) ([]byte, error)

// AtomicMergeJSON reads path (if present), applies merge, and writes the result
// via temp file + rename. A sibling <path>.lock file is flock'd for the
// duration so concurrent soak-loop passes cannot interleave writes.
func AtomicMergeJSON(path string, merge MergeFunc) error {
	if merge == nil {
		return fmt.Errorf("catalogue: merge func is nil")
	}
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("catalogue: mkdir %s: %w", filepath.Dir(path), err)
	}
	unlock, err := acquireFileLock(lockPath)
	if err != nil {
		return err
	}
	defer unlock()

	var existing []byte
	if raw, err := os.ReadFile(path); err == nil {
		existing = raw
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("catalogue: read %s: %w", path, err)
	}

	merged, err := merge(existing)
	if err != nil {
		return err
	}
	if len(merged) == 0 {
		return fmt.Errorf("catalogue: merge returned empty document")
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".catalogue-*.json")
	if err != nil {
		return fmt.Errorf("catalogue: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(merged); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("catalogue: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("catalogue: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("catalogue: publish %s: %w", path, err)
	}
	return nil
}

// MergeEntriesDocument merges catalogue entry slices keyed by entry ID.
func MergeEntriesDocument(existing []byte, scenario string, entries []Entry) ([]byte, error) {
	doc := Document{Scenario: scenario, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &doc); err != nil {
			return nil, fmt.Errorf("catalogue: unmarshal existing: %w", err)
		}
	}
	byID := make(map[string]Entry, len(doc.Entries)+len(entries))
	for _, e := range doc.Entries {
		byID[e.ID] = e
	}
	for _, e := range entries {
		byID[e.ID] = e
	}
	doc.Entries = make([]Entry, 0, len(byID))
	for _, e := range byID {
		doc.Entries = append(doc.Entries, e)
	}
	doc.Summary = Summarize(doc.Entries)
	if doc.Scenario == "" {
		doc.Scenario = scenario
	}
	doc.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	return json.MarshalIndent(doc, "", "  ")
}

func acquireFileLock(lockPath string) (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("catalogue: open lock %s: %w", lockPath, err)
	}
	if err := flockExclusive(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("catalogue: flock %s: %w", lockPath, err)
	}
	return func() {
		_ = flockUnlock(f)
		_ = f.Close()
	}, nil
}
