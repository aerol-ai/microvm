package raftlogdir

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxRecord bounds what is read of a record: a path, and a line feed.
const maxRecord = 4096

// Trusted is the log directory a tool running as root may act on (back up,
// move aside, delete). Without privilege mode split it is Recorded, as
// before. In split, sandboxd runs as its own user, which owns the Raft data
// directory and so writes the record: a tool running as root takes a log
// outside that directory only from SB_RAFT_WAL_DIR in its own env files
// (configured, "" when unset). The record is read without following a link
// and without blocking, and one that names anything else is refused, never
// acted on. No record is "": the log is in DefaultName, inside dataDir.
func Trusted(dataDir, configured string, split bool) (string, error) {
	if !split {
		return Recorded(dataDir)
	}
	rec, err := recordedNoFollow(dataDir)
	if err != nil || rec == "" {
		return "", err
	}
	want := ""
	if configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("raft log: SB_RAFT_WAL_DIR=%q is not an absolute path", configured)
		}
		want = filepath.Clean(configured)
	}
	if rec != want {
		return "", fmt.Errorf("raft log: %s names %s, but SB_RAFT_WAL_DIR in the env files is %q; in privilege mode split "+
			"a tool running as root takes the log's directory only from those settings, so it acts on neither: "+
			"set SB_RAFT_WAL_DIR to the log's directory if that is where it is",
			filepath.Join(dataDir, LocationFile), rec, configured)
	}
	return rec, nil
}

// recordedNoFollow is Recorded, read through one handle opened without
// following a link (openRecord), its kind taken from that handle.
func recordedNoFollow(dataDir string) (string, error) {
	path := filepath.Join(dataDir, LocationFile)
	f, err := openRecord(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("raft log: %s: %w (a link is refused)", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("raft log: %w", err)
	}
	if st.IsDir() {
		return "", nil
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("raft log: %s is neither the log's directory nor a record of where it is", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return "", fmt.Errorf("raft log: read %s: %w", path, err)
	}
	if len(b) > maxRecord {
		return "", fmt.Errorf("raft log: %s is longer than a path", path)
	}
	dir := strings.TrimSpace(string(b))
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("raft log: %s in %s names %q, not an absolute path", LocationFile, dataDir, dir)
	}
	return filepath.Clean(dir), nil
}
