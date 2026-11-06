// Package safetar unpacks a tar archive (gzip is detected) into one folder
// without letting any entry write outside it. toolboxd uses it for
// upload's extract=true, inside the sandbox; the aerolvm CLI uses it for
// `cp -r` downloads, where the archive comes from an untrusted sandbox and
// lands on the user's own machine (plans/agent-sandbox-feature-parity.md,
// F3, X4, CEO review R9).
//
// Two layers keep entries inside the folder. Each entry is checked first:
// no absolute name, no ".." anywhere in it, no hard links, no device files
// or pipes, and no symlink whose target leaves the folder. Then every write
// goes through an os.Root on the folder, which the kernel-level resolution
// of os.Root never lets out, so a chain of symlinks that each look harmless
// on their own still cannot carry a write outside (a name check alone
// misses that).
//
// Every file is written to a fresh temp file in its folder and renamed into
// place, never truncated in place: a hard link already inside the folder
// (pnpm's node_modules has many) that points at a file outside cannot carry
// the new content out to it.
//
// On a failure part way through, what was already written stays, like
// `tar -x` (owner decision P1); the error names the failing entry and how
// many entries were written before it.
package safetar

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Limits caps one extraction. A zero field means no cap.
type Limits struct {
	// MaxEntries is the most entries the archive may hold.
	MaxEntries int
	// MaxBytes is the most file content the archive may unpack to, so a
	// small gzip cannot expand to fill the disk.
	MaxBytes int64
}

// Result counts what was written.
type Result struct {
	Entries int
	Bytes   int64
}

// The kinds of failure, matched with errors.Is.
var (
	// ErrUnsafe is an entry that could write outside the folder, or one of
	// a kind that is never allowed (hard link, device, pipe).
	ErrUnsafe = errors.New("unsafe archive entry")
	// ErrTooLarge is an archive past its Limits.
	ErrTooLarge = errors.New("archive is over its limit")
	// ErrCorrupt is a stream that is not a readable tar (or gzip) archive.
	ErrCorrupt = errors.New("not a valid tar archive")
)

// EntryError says which entry failed and how many were written first.
type EntryError struct {
	// Entry is the entry's name as the archive gives it; empty when the
	// archive itself could not be read.
	Entry string
	// Written is the number of entries written before the failure. They
	// stay on disk.
	Written int
	Err     error
}

func (e *EntryError) Error() string {
	if e.Entry == "" {
		return fmt.Sprintf("%v (%d entries written before it)", e.Err, e.Written)
	}
	return fmt.Sprintf("archive entry %q: %v (%d entries written before it)", e.Entry, e.Err, e.Written)
}

func (e *EntryError) Unwrap() error { return e.Err }

// Extract unpacks r into the existing folder dest.
func Extract(r io.Reader, dest string, limits Limits) (Result, error) {
	var res Result
	root, err := os.OpenRoot(dest)
	if err != nil {
		return res, err
	}
	defer root.Close()

	buffered := bufio.NewReader(r)
	src := io.Reader(buffered)
	if magic, _ := buffered.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return res, &EntryError{Err: fmt.Errorf("%w: %v", ErrCorrupt, err)}
		}
		defer gz.Close()
		src = gz
	}

	type folderMode struct {
		name  string
		mode  fs.FileMode
		mtime time.Time
	}
	var folders []folderMode
	var links []string
	reader := tar.NewReader(src)
	seen := 0
	for {
		hdr, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if out := removeEscapingLinks(root, links, res.Entries); out != nil && out.cannotRemove {
				return res, out.EntryError
			}
			return res, &EntryError{Written: res.Entries, Err: fmt.Errorf("%w: %v", ErrCorrupt, err)}
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		fail := func(err error) (Result, error) {
			if escapes(err) {
				err = fmt.Errorf("%w: %v", ErrUnsafe, err)
			}
			// Links made so far are checked on this exit too: an entry
			// before the failure can already have made one lead out, and
			// the partial result stays on disk.
			if out := removeEscapingLinks(root, links, res.Entries); out != nil && out.cannotRemove {
				return res, out.EntryError
			}
			return res, &EntryError{Entry: hdr.Name, Written: res.Entries, Err: err}
		}
		seen++
		if limits.MaxEntries > 0 && seen > limits.MaxEntries {
			return fail(fmt.Errorf("%w: more than %d entries", ErrTooLarge, limits.MaxEntries))
		}
		name, err := entryName(hdr.Name)
		if err != nil {
			return fail(err)
		}
		if name == "." {
			// The folder itself: its mode is the caller's, not the archive's.
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o755); err != nil {
				return fail(err)
			}
			folders = append(folders, folderMode{name: name, mode: hdr.FileInfo().Mode().Perm(), mtime: hdr.ModTime})
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // TypeRegA still appears in old archives
			if limits.MaxBytes > 0 && hdr.Size > limits.MaxBytes-res.Bytes {
				return fail(fmt.Errorf("%w: more than %d bytes of file content", ErrTooLarge, limits.MaxBytes))
			}
			n, err := writeFile(root, name, reader, hdr)
			res.Bytes += n
			if err != nil {
				return fail(err)
			}
		case tar.TypeSymlink:
			if err := writeSymlink(root, name, hdr.Linkname); err != nil {
				return fail(err)
			}
			links = append(links, name)
		case tar.TypeLink:
			return fail(fmt.Errorf("%w: hard links are not allowed", ErrUnsafe))
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return fail(fmt.Errorf("%w: device files and pipes are not allowed", ErrUnsafe))
		default:
			return fail(fmt.Errorf("%w: entry type %q is not supported", ErrUnsafe, string(hdr.Typeflag)))
		}
		res.Entries++
	}
	// Before the folder modes, which can make its folder read-only.
	if out := removeEscapingLinks(root, links, res.Entries); out != nil {
		return res, out.EntryError
	}
	// Folder modes go on last, deepest first, so a read-only folder does not
	// stop its own contents being written.
	for i := len(folders) - 1; i >= 0; i-- {
		f := folders[i]
		if err := root.Chmod(f.name, f.mode); err != nil {
			return res, &EntryError{Entry: f.name, Written: res.Entries, Err: err}
		}
		_ = root.Chtimes(f.name, f.mtime, f.mtime)
	}
	return res, nil
}

// entryName turns an archive name into a path inside the folder, or refuses
// it. ".." is refused anywhere, even where it would stay inside: no honest
// archive tool writes one, and refusing it outright leaves nothing to get
// wrong.
func entryName(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%w: empty name", ErrUnsafe)
	}
	if strings.HasPrefix(raw, "/") || filepath.IsAbs(raw) || filepath.VolumeName(raw) != "" {
		return "", fmt.Errorf("%w: absolute path", ErrUnsafe)
	}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return "", fmt.Errorf("%w: \"..\" in the path", ErrUnsafe)
		}
	}
	return filepath.FromSlash(path.Clean(raw)), nil
}

// writeFile writes one regular file through a fresh temp file and a rename,
// returning the bytes written.
func writeFile(root *os.Root, name string, content io.Reader, hdr *tar.Header) (int64, error) {
	dir := filepath.Dir(name)
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	tmp := filepath.Join(dir, ".tar-"+randomSuffix())
	out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, content)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		// Permission bits only: setuid and setgid from an archive are not
		// honoured, which matters most on a user's own machine.
		err = root.Chmod(tmp, hdr.FileInfo().Mode().Perm())
	}
	if err == nil {
		_ = root.Chtimes(tmp, hdr.ModTime, hdr.ModTime)
		err = root.Rename(tmp, name)
	}
	if err != nil {
		_ = root.Remove(tmp)
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		return n, err
	}
	return n, nil
}

// writeSymlink makes a symlink after checking its target stays inside the
// folder: first by its name, then by asking os.Root to resolve it, which
// catches a chain of links that only escapes when followed. A dangling
// link inside the folder is allowed, as tar allows it.
func writeSymlink(root *os.Root, name, target string) error {
	if target == "" {
		return fmt.Errorf("%w: symlink with no target", ErrUnsafe)
	}
	if strings.HasPrefix(target, "/") || filepath.IsAbs(target) || filepath.VolumeName(target) != "" {
		return fmt.Errorf("%w: symlink to the absolute path %q", ErrUnsafe, target)
	}
	joined := path.Join(path.Dir(filepath.ToSlash(name)), filepath.ToSlash(target))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return fmt.Errorf("%w: symlink to %q points outside the folder", ErrUnsafe, target)
	}
	if err := root.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	// Like tar -x: an entry replaces what is at its name (a file or a link,
	// never a folder with contents).
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := root.Symlink(target, name); err != nil {
		return err
	}
	if _, err := root.Stat(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		_ = root.Remove(name)
		return fmt.Errorf("%w: symlink to %q points outside the folder", ErrUnsafe, target)
	}
	return nil
}

// linkOutError is removeEscapingLinks' answer: the refusal, and whether a
// link that leads out could not be removed (then it is the error to return,
// whatever else failed).
type linkOutError struct {
	*EntryError
	cannotRemove bool
}

// removeEscapingLinks checks again every link the archive made and removes
// any that now leads out of the folder. writeSymlink checks a link when it
// is made, but a later entry can change what it resolves through: "a" ->
// "s/c/.." is dangling (so allowed) until a later "s/c" -> ".." makes it
// lead out. Writes never follow it out (os.Root), but the link would stay on
// disk for whatever reads the folder next, such as the user's own tools after
// `aerolvm cp -r` down. Extract runs this on EVERY exit, the end of the
// archive and each failure part way, since a failure leaves what was written.
// It answers nil when no link leads out. Every exit returns the
// *EntryError inside, the type Extract documents for all of its errors.
func removeEscapingLinks(root *os.Root, links []string, written int) *linkOutError {
	var first *linkOutError
	for _, name := range links {
		if _, err := root.Stat(name); err == nil || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := removeLink(root, name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return &linkOutError{EntryError: &EntryError{Entry: name, Written: written, Err: fmt.Errorf("%w: symlink points outside the folder and could not be removed: %v", ErrUnsafe, err)}, cannotRemove: true}
		}
		if first == nil {
			first = &linkOutError{EntryError: &EntryError{Entry: name, Written: written, Err: fmt.Errorf("%w: symlink points outside the folder once later entries are in place", ErrUnsafe)}}
		}
	}
	return first
}

// removeLink is (*os.Root).Remove; tests make it fail.
var removeLink = (*os.Root).Remove

// escapes reports os.Root refusing a path that leaves the folder (through a
// symlink that was already there, say). os.Root does not export the error,
// only its text.
func escapes(err error) bool {
	return err != nil && !errors.Is(err, ErrUnsafe) && strings.Contains(err.Error(), "path escapes from parent")
}

func randomSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
