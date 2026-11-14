package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aerol-ai/microvm/internal/safetar"
)

// errCodeFileExists marks the 412 a create_only upload gets when the file is
// already there.
const errCodeFileExists = "file_exists"

// uploadOptions are POST /files/upload's write options (plans/agent-sandbox-
// feature-parity.md, F2). None is set by Daytona or by an SDK call that does
// not ask for one, so a plain upload behaves as it always has: parent folders
// are made and an existing file is replaced in place.
type uploadOptions struct {
	// Append adds to the end of an existing file (making it if missing).
	Append bool
	// CreateOnly writes only when the file does not exist yet; otherwise the
	// upload is a 412. The kernel decides (O_EXCL, or RENAME_NOREPLACE with
	// Atomic), so of two racing uploads exactly one wins.
	CreateOnly bool
	// Atomic writes a temp file beside the target and renames it into place,
	// so a reader sees the old file or the new one, never half of it.
	Atomic bool
	// Mode is the file's permissions after the write, when modeSet. Without
	// it a new file is 0644 and an existing one keeps its own.
	Mode    os.FileMode
	modeSet bool
	// Extract unpacks the uploaded tar (gzip detected) into path, a folder
	// (plan F3), through internal/safetar.
	Extract bool
}

// parseUploadOptions reads the options from the query or the form. Options
// that cannot work together are a 400 that names both.
func parseUploadOptions(r *http.Request) (uploadOptions, error) {
	var opts uploadOptions
	for _, flag := range []struct {
		name string
		dst  *bool
	}{{"append", &opts.Append}, {"create_only", &opts.CreateOnly}, {"atomic", &opts.Atomic}, {"extract", &opts.Extract}} {
		value, err := parseOptionalBool(r.FormValue(flag.name))
		if err != nil {
			return opts, fmt.Errorf("%s must be true or false", flag.name)
		}
		*flag.dst = value
	}
	if raw := strings.TrimSpace(r.FormValue("mode")); raw != "" {
		mode, err := parseFileMode(raw, 0)
		if err != nil {
			return opts, err
		}
		opts.Mode, opts.modeSet = mode, true
	}
	if opts.Extract {
		// The write options shape one file; an archive writes many, each
		// through a temp file and a rename already.
		for _, other := range []struct {
			name string
			set  bool
		}{{"append", opts.Append}, {"create_only", opts.CreateOnly}, {"atomic", opts.Atomic}, {"mode", opts.modeSet}} {
			if other.set {
				return opts, fmt.Errorf("extract and %s cannot be used together: extract unpacks an archive into a folder, %s shapes one file", other.name, other.name)
			}
		}
	}
	switch {
	case opts.Append && opts.CreateOnly:
		return opts, errors.New("append and create_only cannot be used together: append adds to a file that may exist, create_only refuses one that does")
	case opts.Append && opts.Atomic:
		return opts, errors.New("append and atomic cannot be used together: an atomic write replaces the whole file")
	}
	return opts, nil
}

// handleUpload is POST /files/upload (multipart: path and file).
func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	maxBytes := envInt64("SB_UPLOAD_MAX_BYTES", 256*1024*1024)
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form (or too large)")
		return
	}

	targetPath := strings.TrimSpace(r.FormValue("path"))
	if targetPath == "" {
		targetPath = strings.TrimSpace(r.URL.Query().Get("path"))
	}
	if targetPath == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	opts, err := parseUploadOptions(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	if opts.Extract {
		s.extractUpload(w, targetPath, header.Filename, file)
		return
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		writeFilesystemError(w, err)
		return
	}
	if err := writeUpload(targetPath, file, opts); err != nil {
		if opts.CreateOnly && errors.Is(err, fs.ErrExist) {
			writeErrorCode(w, http.StatusPreconditionFailed, targetPath+" already exists and create_only is set", errCodeFileExists)
			return
		}
		writeFilesystemError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"path": targetPath,
		"name": header.Filename,
	})
}

// writeUpload writes src to target as opts ask.
func writeUpload(target string, src io.Reader, opts uploadOptions) error {
	switch {
	case opts.Atomic:
		return writeUploadAtomic(target, src, opts)
	case opts == uploadOptions{}:
		return writeMultipartFile(target, src)
	}
	flags := os.O_WRONLY | os.O_CREATE
	switch {
	case opts.Append:
		flags |= os.O_APPEND
	case opts.CreateOnly:
		flags |= os.O_EXCL
	default:
		flags |= os.O_TRUNC
	}
	// 0666 less the umask: the rw-r--r-- uploads have always had. With a mode
	// the file starts private and gets the mode once written.
	perm := os.FileMode(0o666)
	if opts.modeSet {
		perm = 0o600
	}
	out, _, err := openFile(target, flags, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if opts.modeSet {
		return os.Chmod(target, opts.Mode)
	}
	return nil
}

// writeUploadAtomic writes a fresh temp file beside target, then renames it
// over target (or, with CreateOnly, into place only if target is free). The
// file the caller replaces keeps its mode and owner unless a mode is given.
// A failed upload removes its temp file and leaves target as it was.
func writeUploadAtomic(target string, src io.Reader, opts uploadOptions) error {
	mode := os.FileMode(0o644)
	var previous os.FileInfo
	if info, err := os.Stat(target); err == nil && info.Mode().IsRegular() {
		previous = info
		mode = info.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
	}
	if opts.modeSet {
		mode = opts.Mode
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".upload-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := io.Copy(tmp, src); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if previous != nil {
		if stat, ok := previous.Sys().(*syscall.Stat_t); ok {
			_ = tmp.Chown(int(stat.Uid), int(stat.Gid))
		}
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := placePath(tmpName, target, !opts.CreateOnly); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// extractUpload unpacks an uploaded tar into the folder dest, made if
// missing. The caps stop a small gzip from filling the sandbox disk. On a
// failure part way, what was written stays (owner decision P1) and the
// error names the failing entry and the count written.
func (s *server) extractUpload(w http.ResponseWriter, dest, name string, archive io.Reader) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		writeFilesystemError(w, err)
		return
	}
	limits := safetar.Limits{
		MaxEntries: envInt("SB_EXTRACT_MAX_ENTRIES", 200_000),
		MaxBytes:   envInt64("SB_EXTRACT_MAX_BYTES", 4<<30),
	}
	res, err := safetar.Extract(archive, dest, limits)
	if err != nil {
		switch {
		case errors.Is(err, safetar.ErrUnsafe), errors.Is(err, safetar.ErrCorrupt):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, safetar.ErrTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		default:
			writeFilesystemError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"path":    dest,
		"name":    name,
		"entries": res.Entries,
		"bytes":   res.Bytes,
	})
}
