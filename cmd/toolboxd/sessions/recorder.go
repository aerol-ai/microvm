package sessions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// recorder writes an asciinema v2 cast file. Writes are append-only and
// independent of attach state — recording captures everything the session
// produced, not just what was streamed live.
//
// Format reference: https://github.com/asciinema/asciinema/blob/main/doc/asciicast-v2.md
type recorder struct {
	path  string
	f     *os.File
	mu    sync.Mutex
	start time.Time
}

type asciinemaHeader struct {
	Version   int            `json:"version"`
	Width     int            `json:"width"`
	Height    int            `json:"height"`
	Timestamp int64          `json:"timestamp"`
	Title     string         `json:"title,omitempty"`
	Env       map[string]any `json:"env,omitempty"`
}

func newRecorder(path string, cols, rows int, title string) (*recorder, error) {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("recorder mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("recorder open: %w", err)
	}
	now := time.Now().UTC()
	header := asciinemaHeader{
		Version:   2,
		Width:     cols,
		Height:    rows,
		Timestamp: now.Unix(),
		Title:     title,
		Env:       map[string]any{"SHELL": os.Getenv("SHELL"), "TERM": os.Getenv("TERM")},
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Write(append(encoded, '\n')); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &recorder{path: path, f: f, start: now}, nil
}

// WriteOutput appends an output event ("o") for the given bytes.
func (r *recorder) WriteOutput(p []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return
	}
	elapsed := time.Since(r.start).Seconds()
	frame := []any{elapsed, "o", string(p)}
	if encoded, err := json.Marshal(frame); err == nil {
		_, _ = r.f.Write(append(encoded, '\n'))
	}
}

// WriteInput appends an input event ("i") for the given bytes. Useful for
// keystroke replay, but not all viewers render it.
func (r *recorder) WriteInput(p []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return
	}
	elapsed := time.Since(r.start).Seconds()
	frame := []any{elapsed, "i", string(p)}
	if encoded, err := json.Marshal(frame); err == nil {
		_, _ = r.f.Write(append(encoded, '\n'))
	}
}

// Close finalizes the cast file. Subsequent writes are no-ops.
func (r *recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// Sync best-effort fsyncs the underlying cast file so a pre-snapshot
// quiesce signal (Phase 3 PR-B) gets the partial recording onto disk
// before Firecracker freezes the guest's memory. A nil recorder or a
// recorder that has already been Close()d is a no-op — the snapshot
// is a pause, not a destroy, and a session without an attached
// recording is the common case (template captures have no sessions).
func (r *recorder) Sync() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	return r.f.Sync()
}

// Path returns the on-disk path of the cast file.
func (r *recorder) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}
