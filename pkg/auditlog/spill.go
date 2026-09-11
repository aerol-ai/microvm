package auditlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// The audit directory's durable overflow buffer. The daemon's audit writer
// and every WASM worker subprocess on the node append to the same
// secrets.spill.jsonl under the same flock; the daemon's writer drains it
// into secrets.jsonl. Keeping the writer here means there is exactly one
// implementation of "append evidence durably under the audit lock": one
// lock acquisition, one write, one fsync per batch, never per event, and
// never on a path a sandbox is waiting on.

const (
	// LockFileName is the stable flock sidecar for the whole audit
	// directory. It carries no data; every writer, reader, drain and
	// retention pass takes it, so the file must never be renamed.
	LockFileName = "secrets.jsonl.lock"
	// SpillFileName is the overflow buffer the daemon's writer drains.
	SpillFileName = "secrets.spill.jsonl"
)

// ErrNoSpillPath reports a SpillFile with no destination.
var ErrNoSpillPath = errors.New("audit spill path is unset")

// WithFileLock runs fn holding an exclusive flock on lockPath. The sidecar
// is opened read-only: it only needs a stable descriptor, and a read-only
// open cannot hide a buffered-write failure on close.
func WithFileLock(lockPath string, fn func() error) error {
	if lockPath == "" {
		return errors.New("audit lock path is unset")
	}
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(lf.Fd()), unix.LOCK_UN) }()
	return fn()
}

// SpillFile is one audit directory's overflow buffer.
type SpillFile struct {
	Path     string
	LockPath string
}

// SpillFileIn names the spill buffer and lock of an audit directory.
func SpillFileIn(dir string) SpillFile {
	if dir == "" {
		return SpillFile{}
	}
	return SpillFile{Path: filepath.Join(dir, SpillFileName), LockPath: filepath.Join(dir, LockFileName)}
}

// Append durable-appends events as one write and one fsync under the audit
// lock. Events get an id and a time if they lack one. Either every line
// lands or the error covers the whole batch: a torn spill line is repaired
// by the daemon's drain (which counts it as a gap), so a crash mid-write
// loses at most this batch and never corrupts what came before.
func (s SpillFile) Append(events []Event) error {
	if s.Path == "" || s.LockPath == "" {
		return ErrNoSpillPath
	}
	if len(events) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return fmt.Errorf("audit spill mkdir: %w", err)
	}
	var buf []byte
	now := time.Now().UTC()
	for i := range events {
		ev := events[i]
		if ev.Time.IsZero() {
			ev.Time = now
		}
		EnsureEventID(&ev)
		line, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("audit spill marshal: %w", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return WithFileLock(s.LockPath, func() error {
		f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(buf); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	})
}

// GapMarker is the record that stands in for dropped events: one marker
// per flush, carrying the count, so overflow costs the writer one line
// rather than one per drop and the stream stays honest about the loss.
func GapMarker(node string, dropped int64, now time.Time) Event {
	return Event{
		Time:    now,
		Actor:   node,
		Result:  "gap",
		Reason:  "overflow",
		NodeID:  node,
		Kind:    "gap",
		Dropped: dropped,
	}
}
