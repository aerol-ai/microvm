// Package raftlogdir keeps track of where a node's Raft log (raft-wal)
// lives when SB_RAFT_WAL_DIR puts it on a disk of its own.
//
// A Raft commit waits for the leader's log write and then a follower's, one
// after the other, so the log's disk sets the commit time. On the cell
// bench, a log sharing its disk with the snapshots and the FSM's recovery
// blobs took 2 to 5 ms a write under load; on a disk of its own, about 1 ms,
// and Raft apply p99 came under 25 ms (plans/kubernetes-v2-architecture.md
// §9.5).
//
// A log must never move by accident. A node that opened an empty log where
// its old one was would forget entries it had acknowledged, and Raft does
// not survive that. So the first start with a log elsewhere records where it
// is, in the Raft data directory, and every start after must find it there.
// Tools that read or move a node's Raft files (backup, recover-quorum,
// reset) follow the same record.
//
// The record is a file named raft-wal, where the log's directory is by
// default. A sandboxd too old to read it then fails to make that directory
// and does not start, rather than open an empty log in its place: rolling a
// server back is safe.
package raftlogdir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DefaultName is the log's directory inside the Raft data directory.
	DefaultName = "raft-wal"
	// LocationFile, in the Raft data directory, names the directory that
	// holds the log when it is elsewhere. It takes the default directory's
	// place, so an older sandboxd cannot open an empty log there.
	LocationFile = DefaultName
	// metaFile and segmentSuffix are raft-wal's own files: a directory
	// holding either holds a log.
	metaFile      = "wal-meta.db"
	segmentSuffix = ".wal"
	// stableFile is the Raft stable store internal/cluster keeps beside the
	// log. A node that has one has run.
	stableFile = "raft-stable.bolt"
)

// Recorded is the log directory dataDir's LocationFile names, or "" when
// there is none (the default directory, or nothing yet).
func Recorded(dataDir string) (string, error) {
	path := filepath.Join(dataDir, LocationFile)
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && st.IsDir()) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("raft log: %w", err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("raft log: %s is neither the log's directory nor a record of where it is", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("raft log: read %s: %w", path, err)
	}
	dir := strings.TrimSpace(string(b))
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("raft log: %s in %s names %q, not an absolute path", LocationFile, dataDir, dir)
	}
	return filepath.Clean(dir), nil
}

// Dir is the directory that holds the node's log, for the tools that read
// or move its Raft files: the recorded one, else DefaultName in dataDir.
func Dir(dataDir string) (string, error) {
	rec, err := Recorded(dataDir)
	if err != nil || rec != "" {
		return rec, err
	}
	return filepath.Join(dataDir, DefaultName), nil
}

// Resolve is the log directory sandboxd opens, given the Raft data directory
// and SB_RAFT_WAL_DIR (configured, "" when unset):
//
//   - Nothing recorded and nothing configured (or the default configured):
//     DefaultName in dataDir, as before SB_RAFT_WAL_DIR.
//   - Nothing recorded, a directory configured: that directory, recorded,
//     but only for a new node. A log already in DefaultName would be left
//     behind; one already in the configured directory is not this node's to
//     take (another node's, or this node's from before its data directory
//     was replaced).
//   - A directory recorded: that one. A configured directory must be the
//     same. Once the node has run, the recorded directory must hold a log:
//     an empty one is a disk that is not mounted.
func Resolve(dataDir, configured string) (string, error) {
	def := filepath.Join(dataDir, DefaultName)
	if configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("raft log: SB_RAFT_WAL_DIR=%q is not an absolute path", configured)
		}
		configured = filepath.Clean(configured)
	}
	rec, err := Recorded(dataDir)
	if err != nil {
		return "", err
	}
	switch {
	case rec != "":
		if configured != "" && configured != rec {
			return "", fmt.Errorf("raft log: this node's log is in %s (%s names it), but SB_RAFT_WAL_DIR is %s; a node's log does not move: set SB_RAFT_WAL_DIR back, or replace the node", rec, filepath.Join(dataDir, LocationFile), configured)
		}
		if !HoldsLog(rec) && exists(filepath.Join(dataDir, stableFile)) {
			return "", fmt.Errorf("raft log: this node's log should be in %s, which holds none; is its disk mounted?", rec)
		}
		return rec, nil
	case configured == "" || configured == def:
		return def, nil
	}
	if HoldsLog(def) {
		return "", fmt.Errorf("raft log: a log is already in %s, which SB_RAFT_WAL_DIR=%s would leave behind; a node's log does not move: unset SB_RAFT_WAL_DIR, or replace the node", def, configured)
	}
	if HoldsLog(configured) {
		return "", fmt.Errorf("raft log: %s already holds a Raft log that %s does not name (another node's, or this node's before its data directory was replaced); empty it first", configured, dataDir)
	}
	// The record takes the default directory's place. It holds no log
	// (above); anything else in it is not ours to delete.
	if err := os.Remove(def); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("raft log: %s must be empty for SB_RAFT_WAL_DIR to take its place: %w", def, err)
	}
	if err := record(dataDir, configured); err != nil {
		return "", err
	}
	return configured, nil
}

// HoldsLog reports whether dir has raft-wal's files in it.
func HoldsLog(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Type().IsRegular() && (e.Name() == metaFile || strings.HasSuffix(e.Name(), segmentSuffix)) {
			return true
		}
	}
	return false
}

// record writes LocationFile durably before the log is opened there: the
// file, then the directory entry, so a crash leaves the old state or the new
// one. A crash after it and before the log's first write leaves a record of
// an empty directory, which Resolve accepts until the node has run.
func record(dataDir, dir string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("raft log: record %s in %s: %w", dir, dataDir, err)
		}
	}()
	if err = os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, "."+LocationFile+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.WriteString(dir + "\n")
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dataDir, LocationFile))
	}
	if err == nil {
		err = syncDir(dataDir)
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
