package nodeupgrade

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// FileStore keeps release files named by their SHA-256, under
// /var/lib/sandboxd/upgrade/files on a node. Uploads for `apply --from`
// (single-node and the cluster leader), files a server caches for a
// rollout, and files a worker copies from a server all land here
// (plans/kubectl-style-cluster-ops.md §6.3, §6.6). Naming by hash makes a
// repeated upload or copy a no-op and lets every reader check the bytes
// again against the name.
type FileStore struct {
	Dir string
	// MaxBytes caps one file; zero means MaxFileBytes.
	MaxBytes int64
	// MaxTotalBytes caps everything stored, for a store that takes
	// uploads (upgradewire.MaxUploadTotalBytes); zero means no cap. Put
	// refuses past it with ErrStoreFull.
	MaxTotalBytes int64
}

// ErrStoreFull is returned by Put when the store already holds, or the
// body would take it past, MaxTotalBytes. Nothing is kept.
var ErrStoreFull = errors.New("the node holds 2 GiB of uploaded release files already; start the upgrade, or wait an hour for unused ones to be pruned")

var storeHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrHashMismatch is returned by Put when the body does not hash to the
// name it was sent under. Nothing is kept.
var ErrHashMismatch = errors.New("file does not match its SHA-256")

// ErrBadHash is returned for a name that is not 64 lower-case hex digits,
// before any path is built from it.
var ErrBadHash = errors.New("not a SHA-256 in lower-case hex")

// FileStoreDir is the store's directory under a node's upgrade state
// directory (StateDirFor).
func FileStoreDir(stateDir string) string { return filepath.Join(stateDir, "files") }

func (s FileStore) max() int64 {
	if s.MaxBytes > 0 {
		return s.MaxBytes
	}
	return maxFileBytes
}

// Path is where the file with this hash lives. It refuses any name that is
// not a SHA-256, so a request path can never escape Dir.
func (s FileStore) Path(sum string) (string, error) {
	if !storeHashRe.MatchString(sum) {
		return "", ErrBadHash
	}
	return filepath.Join(s.Dir, sum), nil
}

// Has reports whether the file is present.
func (s FileStore) Has(sum string) bool {
	p, err := s.Path(sum)
	if err != nil {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Put streams r into the store under sum. It returns created=false when the
// file was already there (r is not read). The body is written to a temp
// file, hashed on the way, and renamed into place only when its hash is
// sum, so a reader never sees a partial or wrong file.
func (s FileStore) Put(sum string, r io.Reader) (created bool, size int64, err error) {
	dst, err := s.Path(sum)
	if err != nil {
		return false, 0, err
	}
	if fi, statErr := os.Stat(dst); statErr == nil && fi.Mode().IsRegular() {
		return false, fi.Size(), nil
	}
	limit, full := s.max(), false
	if s.MaxTotalBytes > 0 {
		// Uploads in flight count too (their .put-* files), so two at once
		// cannot each take the whole room.
		left := s.MaxTotalBytes - s.storedBytes()
		if left <= 0 {
			return false, 0, ErrStoreFull
		}
		if left < limit {
			limit, full = left, true
		}
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return false, 0, err
	}
	tmp, err := os.CreateTemp(s.Dir, ".put-*")
	if err != nil {
		return false, 0, err
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	n, got, err := streamToFileMax(r, tmpName, 0o600, limit)
	if err != nil {
		_ = os.Remove(tmpName)
		if full && strings.HasPrefix(err.Error(), "larger than") {
			return false, 0, ErrStoreFull
		}
		return false, 0, err
	}
	if got != sum {
		_ = os.Remove(tmpName)
		return false, 0, fmt.Errorf("%w: got %s", ErrHashMismatch, got)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return false, 0, err
	}
	return true, n, nil
}

// storedBytes adds up the regular files in the store, temp files included.
func (s FileStore) storedBytes() int64 {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total
}

// Open opens a stored file for reading. The caller should check the hash of
// what it reads (the reader's side of "named by hash").
func (s FileStore) Open(sum string) (*os.File, error) {
	p, err := s.Path(sum)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// Materialize makes dir hold each file of files (asset name -> SHA-256)
// under its asset name, as Request.From expects. It hard-links from the
// store and copies when a link is not possible (another file system).
// Every file must be in the store.
func (s FileStore) Materialize(dir string, files map[string]string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, sum := range files {
		if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
			return fmt.Errorf("bad file name %q", name)
		}
		src, err := s.Path(sum)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		dst := filepath.Join(dir, name)
		_ = os.Remove(dst)
		if err := os.Link(src, dst); err == nil {
			continue
		}
		in, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		_, got, err := streamToFileMax(in, dst, 0o600, s.max())
		_ = in.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if got != sum {
			_ = os.Remove(dst)
			return fmt.Errorf("%s: %w", name, ErrHashMismatch)
		}
	}
	return nil
}

// Prune deletes stored files not in keep whose last change is older than
// age (§6.6: uploads no rollout uses within an hour). It returns how many
// it removed. Temp files of interrupted Puts are pruned the same way.
func (s FileStore) Prune(now time.Time, age time.Duration, keep map[string]bool) (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if keep[e.Name()] || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < age {
			continue
		}
		if os.Remove(filepath.Join(s.Dir, e.Name())) == nil {
			removed++
		}
	}
	return removed, nil
}
