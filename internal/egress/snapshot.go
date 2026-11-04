package egress

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// snapshotVersion guards the on-disk format.
const snapshotVersion = 1

// Snapshot is the gateway's persisted state: attached sandboxes (with their
// block reasons) and the bridges it binds on. On restart the gateway restores
// it with every sandbox restart-blocked in memory until sandboxd's Sync
// (D13), and binds its listeners from the bridge list before sandboxd
// reconnects (eng re-review S5). Learn-mode recordings live in per-sandbox
// files beside it (S9).
type Snapshot struct {
	Version int      `json:"version"`
	Specs   []Spec   `json:"specs"`
	Bridges []Bridge `json:"bridges,omitempty"`
}

// SaveSnapshot writes s atomically: temp file, fsync, rename, then fsync of
// the directory so the rename itself is durable.
func SaveSnapshot(path string, s Snapshot) error {
	s.Version = snapshotVersion
	// Injected credentials never touch the disk (P3-2).
	specs := make([]Spec, len(s.Specs))
	for i, sp := range s.Specs {
		sp.Secrets = nil
		specs[i] = sp
	}
	s.Specs = specs
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// LoadSnapshot reads a snapshot. A missing file returns ok=false and no
// error: the gateway then leaves the kernel sets untouched until Sync (D13).
// A corrupt file is an error, and the caller waits for Sync instead of
// trusting it.
func LoadSnapshot(path string) (Snapshot, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Snapshot{}, false, fmt.Errorf("egress: corrupt snapshot %s: %w", path, err)
	}
	if s.Version != snapshotVersion {
		return Snapshot{}, false, fmt.Errorf("egress: snapshot %s has version %d, want %d", path, s.Version, snapshotVersion)
	}
	return s, true, nil
}
