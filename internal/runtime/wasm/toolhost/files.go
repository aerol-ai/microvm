package toolhost

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func (h *Host) handleUpload(w http.ResponseWriter, r *http.Request) {
	const maxBytes = 256 * 1024 * 1024
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

	root, rel, _, err := openInWorkDir(h.workDir, targetPath)
	if err != nil {
		writeOpenError(w, err)
		return
	}
	defer root.Close()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	if err := root.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := atomicWriteFile(root, rel, file); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"path": targetPath,
		"name": header.Filename,
	})
}

func (h *Host) handleDownload(w http.ResponseWriter, r *http.Request) {
	targetPath := strings.TrimSpace(r.URL.Query().Get("path"))
	if targetPath == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	root, rel, hostPath, err := openInWorkDir(h.workDir, targetPath)
	if err != nil {
		writeOpenError(w, err)
		return
	}
	defer root.Close()

	// Stream from the file: this handler runs inside sandboxd, so reading a
	// large guest file whole would land it in daemon memory, even when the
	// client only wants its first window (the agent read_file tool).
	f, err := root.Open(rel)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if info.IsDir() {
		// Same status and text os.ReadFile produced for a directory.
		writeError(w, http.StatusInternalServerError, "read "+hostPath+": is a directory")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+strconvQuote(filepath.Base(hostPath)))
	if info.Mode().IsRegular() {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func (h *Host) handleListFiles(w http.ResponseWriter, r *http.Request) {
	targetPath := strings.TrimSpace(r.URL.Query().Get("path"))
	root, rel, _, err := openInWorkDir(h.workDir, targetPath)
	if err != nil {
		writeOpenError(w, err)
		return
	}
	defer root.Close()
	dir, err := root.Open(rel)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	writeJSON(w, http.StatusOK, names)
}

// writeOpenError answers a failed openInWorkDir: a path the caller cannot
// have is its mistake (400); a work directory the daemon cannot open is not
// (500).
func writeOpenError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, errPathEscape) {
		status = http.StatusBadRequest
	}
	writeError(w, status, err.Error())
}

// atomicWriteFile writes rel inside root via a temp file in the same
// directory and a rename, both through the root.
func atomicWriteFile(root *os.Root, rel string, src multipart.File) error {
	var suffix [8]byte
	_, _ = rand.Read(suffix[:])
	tmpName := filepath.Join(filepath.Dir(rel), ".upload-"+hex.EncodeToString(suffix[:]))
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	cleanup := func() { _ = root.Remove(tmpName) }
	if _, err := io.Copy(tmp, src); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := root.Chmod(tmpName, 0o644); err != nil {
		cleanup()
		return err
	}
	if err := root.Rename(tmpName, rel); err != nil {
		cleanup()
		return err
	}
	return nil
}

func strconvQuote(s string) string {
	if s == "" {
		return `""`
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
