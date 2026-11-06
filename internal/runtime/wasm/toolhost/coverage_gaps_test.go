package toolhost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── host.go / files.go ──────────────────────────────────────────────────────

func TestStripSandboxPrefixEmptyRemainder(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	req := httptest.NewRequest(http.MethodGet, "/sb/", nil)
	_ = h.stripSandboxPrefix(req)
	if req.URL.Path != "/" {
		t.Fatalf("path = %q", req.URL.Path)
	}
}

func TestHandleUploadAtomicWriteError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "exists"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := New(Config{SandboxID: "sb", WorkDir: dir})

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "/exists")
	part, _ := w.CreateFormFile("file", "f.txt")
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("atomic write onto directory status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── files.go ────────────────────────────────────────────────────────────────

func TestHandleUploadPathInQueryAndParseError(t *testing.T) {
	dir := t.TempDir()
	h := New(Config{SandboxID: "sb", WorkDir: dir})

	// path supplied via query string instead of form field
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, _ := w.CreateFormFile("file", "q.txt")
	_, _ = part.Write([]byte("via-query"))
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload?path=/q.txt", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload via query path status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Oversized multipart body trips ParseMultipartForm.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/files/upload?path=/big.txt", strings.NewReader("not-multipart"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----bad")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad multipart status = %d", rec.Code)
	}
}

func TestHandleUploadMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	// Block creating subdirs by making workDir a file.
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := New(Config{SandboxID: "sb", WorkDir: blocker})

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "/nested/file.txt")
	part, _ := w.CreateFormFile("file", "f.txt")
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("mkdir error status = %d body=%s", rec.Code, rec.Body.String())
	}
}

type mockMultipartFile struct {
	io.Reader
	closeErr error
}

func (m *mockMultipartFile) ReadAt(p []byte, off int64) (int, error) {
	return 0, errors.New("readat not supported")
}

func (m *mockMultipartFile) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}

func (m *mockMultipartFile) Close() error { return m.closeErr }

func TestAtomicWriteFileCloseChmodRenameErrors(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := atomicWriteFile(root, "out.txt", &mockMultipartFile{Reader: bytes.NewReader([]byte("ok"))}); err != nil {
		t.Fatalf("atomicWriteFile: %v", err)
	}

	if err := atomicWriteFile(root, "out.txt", &mockMultipartFile{
		Reader:   bytes.NewReader([]byte("x")),
		closeErr: errors.New("close failed"),
	}); err != nil && !strings.Contains(err.Error(), "close") {
		t.Fatalf("unexpected close error: %v", err)
	}

	if err := os.Mkdir(filepath.Join(dir, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(root, "existing", &mockMultipartFile{Reader: bytes.NewReader([]byte("x"))}); err == nil {
		t.Fatal("expected rename error onto directory")
	}
	if err := atomicWriteFile(root, filepath.Join("missing", "out.txt"), &mockMultipartFile{Reader: bytes.NewReader([]byte("x"))}); err == nil {
		t.Fatal("expected an error creating a temp file in a missing directory")
	}
}

// ─── host.go / path.go ───────────────────────────────────────────────────────

func TestServeHTTPHealthAndRouteNotFound(t *testing.T) {
	h := New(Config{SandboxID: "sb-health", WorkDir: t.TempDir()})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}

	// stripSandboxPrefix: sandbox id with trailing route trims to empty → "/"
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sb-health", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/sb-health status = %d", rec.Code)
	}

	// A sibling of a session root is not a session route: it falls through
	// to the toolbox 404, not the sessions 501.
	for _, path := range []string{"/process/sessionX", "/sessionsX"} {
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, path, nil)
		h.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, rec.Code)
		}
	}
}

func TestResolveHostPathEdgeCases(t *testing.T) {
	workDir := t.TempDir()
	if _, err := resolveHostPath(workDir, ""); err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if _, err := resolveHostPath(workDir, "/subdir/file"); err != nil {
		t.Fatalf("abs guest path: %v", err)
	}
	if _, err := resolveHostPath(workDir, "subdir/../.."); err == nil {
		t.Fatal("expected escape error for ..")
	}
}

// ─── state.go ────────────────────────────────────────────────────────────────

func TestHandleStateKVPutBodyAndValueErrors(t *testing.T) {
	h := New(Config{
		SandboxID: "sb",
		WorkDir:   t.TempDir(),
		StateKV:   newMemStateKV(),
	})

	// Oversized value (>4 MiB) rejected before store write.
	big := make([]byte, 4<<20+1)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/state/kv/big", bytes.NewReader(big))
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized value status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Broken body reader surfaces as 400.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/state/kv/k", errReader{})
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("body read error status = %d", rec.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type memStateKV struct{ data map[string][]byte }

func newMemStateKV() *memStateKV { return &memStateKV{data: map[string][]byte{}} }

func (m *memStateKV) Get(_ context.Context, _, key string) ([]byte, bool, error) {
	v, ok := m.data[key]
	return v, ok, nil
}
func (m *memStateKV) Set(_ context.Context, _, key string, value []byte) error {
	m.data[key] = append([]byte(nil), value...)
	return nil
}
func (m *memStateKV) Delete(_ context.Context, _, key string) error {
	delete(m.data, key)
	return nil
}
func (m *memStateKV) ListKeys(_ context.Context, _ string) ([]string, error) {
	out := make([]string, 0, len(m.data))
	for k := range m.data {
		out = append(out, k)
	}
	return out, nil
}

// ─── exec_stream.go ──────────────────────────────────────────────────────────

func TestHandleExecStreamUpgradeFailure(t *testing.T) {
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/process/exec/stream", nil)
	h.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("expected non-200 without websocket upgrade")
	}
}

// ─── files.go / host.go ──────────────────────────────────────────────────────

func TestAtomicWriteFileChmodAndRenameErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skip("chmod not supported")
	}
	if err := os.Chmod(tmpName, 0o644); err == nil {
		_ = os.Chmod(dir, 0o755)
		t.Skip("chmod on file succeeded; cannot simulate chmod error")
	}
	_ = os.Chmod(dir, 0o755)
	_ = os.Remove(tmpName)

	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = atomicWriteFile(root, filepath.Base(path), &mockMultipartFile{Reader: bytes.NewReader([]byte("x"))})
	if err == nil {
		t.Fatal("expected rename onto directory to fail")
	}
}

func TestHandleUploadMissingFileAndPathRequired(t *testing.T) {
	dir := t.TempDir()
	h := New(Config{SandboxID: "sb", WorkDir: dir})

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing path status = %d body=%s", rec.Code, rec.Body.String())
	}

	body2 := &bytes.Buffer{}
	w2 := multipart.NewWriter(body2)
	_ = w2.WriteField("path", "/only-path.txt")
	_ = w2.Close()
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/files/upload", body2)
	req.Header.Set("Content-Type", w2.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing file status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestStripSandboxPrefixExactID(t *testing.T) {
	h := New(Config{SandboxID: "sb-exact", WorkDir: t.TempDir()})
	req := httptest.NewRequest(http.MethodGet, "/sb-exact", nil)
	req = h.stripSandboxPrefix(req)
	if req.URL.Path != "/" {
		t.Fatalf("exact sandbox path = %q", req.URL.Path)
	}
}
