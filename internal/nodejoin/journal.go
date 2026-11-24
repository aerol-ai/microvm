package nodejoin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// fileJournal records what a command wrote, so a failure before sandboxd
// restarts puts every file back as it was (§11: "join writes its files,
// then restarts; if it fails before the restart, it removes what it
// wrote"). Each write is atomic on its own; the journal makes the set
// all-or-nothing from the operator's point of view.
type fileJournal struct {
	entries []journalEntry
}

type journalEntry struct {
	path    string
	old     []byte
	existed bool
	mode    os.FileMode
}

// remember notes path's content before the first change to it. It reads
// the file itself, never what a link names (O_NOFOLLOW, then the open file's
// own kind): in privilege mode split the certificate folders and the data
// folder are sandboxd's user's, and a link that user left there would have
// root read any file, which a rollback would then write back into that
// folder. sandboxd makes no link there, so one is refused.
func (j *fileJournal) remember(path string) error {
	for _, e := range j.entries {
		if e.path == path {
			return nil
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		j.entries = append(j.entries, journalEntry{path: path})
		return nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("%s is a symbolic link; init and join replace only files, never through a link", path)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (%v); init and join replace only files", path, st.Mode().Type())
	}
	old, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	j.entries = append(j.entries, journalEntry{path: path, old: old, existed: true, mode: st.Mode().Perm()})
	return nil
}

// write replaces path atomically, making its directory (0700) if needed.
func (j *fileJournal) write(path string, data []byte, mode os.FileMode) error {
	if err := j.remember(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	return cluster.WriteFileAtomic(path, data, mode)
}

// mergeEnv is mergeEnvFile through the journal.
func (j *fileJournal) mergeEnv(path, header string, set envSet) error {
	if err := j.remember(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return mergeEnvFile(path, header, set)
}

// remove deletes path; a missing file is fine.
func (j *fileJournal) remove(path string) error {
	if err := j.remember(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// changed reports whether any file now differs from before: a re-run
// that wrote the same bytes needs no restart.
func (j *fileJournal) changed() bool {
	for _, e := range j.entries {
		now, err := os.ReadFile(e.path)
		exists := err == nil
		if exists != e.existed || (exists && string(now) != string(e.old)) {
			return true
		}
	}
	return false
}

// rollback restores every file, newest change first, and returns the
// paths it could not restore.
func (j *fileJournal) rollback() []string {
	var failed []string
	for i := len(j.entries) - 1; i >= 0; i-- {
		e := j.entries[i]
		var err error
		if e.existed {
			err = cluster.WriteFileAtomic(e.path, e.old, e.mode)
		} else if rmErr := os.Remove(e.path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			err = rmErr
		}
		if err != nil {
			failed = append(failed, e.path)
		}
	}
	return failed
}
