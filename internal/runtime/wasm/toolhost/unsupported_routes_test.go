package toolhost

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Daytona facade forwards these to every sandbox; a WASM sandbox has no
// filesystem or terminal for them, so it answers a clear 501 rather than the
// default 404 (plan B1). Auth still comes first.
func TestUnsupportedDaytonaRoutesAnswer501(t *testing.T) {
	handler := New(Config{SandboxID: "sb", AuthToken: "tok", WorkDir: t.TempDir()}).Handler()
	routes := [][2]string{
		{http.MethodDelete, "/files"},
		{http.MethodPost, "/files/folder"},
		{http.MethodPost, "/files/replace"},
		{http.MethodPost, "/files/permissions"},
		{http.MethodGet, "/files/info"},
		{http.MethodPost, "/files/move"},
		{http.MethodPost, "/files/copy"},
		{http.MethodGet, "/files/search"},
		{http.MethodGet, "/files/find"},
		{http.MethodGet, "/files?path=/&depth=2"},
		{http.MethodGet, "/files?path=/&limit=10"},
		{http.MethodGet, "/files?path=/&extended=true"},
		{http.MethodPost, "/lsp/start"},
		{http.MethodGet, "/lsp"},
		{http.MethodPost, "/process/pty"},
		{http.MethodGet, "/process/pty/s1/connect"},
	}
	for _, route := range routes {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(route[0], route[1], nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token = %d, want 401", route[0], route[1], rec.Code)
		}
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(route[0], route[1], nil)
		req.Header.Set("Authorization", "Bearer tok")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501", route[0], route[1], rec.Code)
		}
	}
	// GET /files is the WASM list and must not be swallowed by the 501s.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files?path=/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	handler.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("GET /files answered 501")
	}
}

// File watching is offered on gVisor and Firecracker only (plan F5, Q8): a
// WASM sandbox answers the same clear 501, after auth.
func TestFileWatchAnswers501(t *testing.T) {
	handler := New(Config{SandboxID: "sb", AuthToken: "tok", WorkDir: t.TempDir()}).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files/watch?path=/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("watch without a token = %d, want 401", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/files/watch?path=/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), "gVisor or Firecracker") {
		t.Fatalf("watch = %d %s, want the file-watching 501", rec.Code, rec.Body.String())
	}
}

// The WASM upload writes plainly; it refuses toolboxd's upload options (plan
// F2, F3) with a 501 instead of ignoring them and answering 201.
func TestUploadRefusesToolboxdOptions(t *testing.T) {
	workDir := t.TempDir()
	handler := New(Config{SandboxID: "sb", AuthToken: "tok", WorkDir: workDir}).Handler()
	upload := func(query string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField("path", "/f.txt")
		part, _ := mw.CreateFormFile("file", "f.txt")
		_, _ = part.Write([]byte("data"))
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/files/upload?"+query, &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, query := range []string{"append=true", "create_only=true", "atomic=1", "extract=true", "mode=600"} {
		rec := upload(query)
		name := strings.SplitN(query, "=", 2)[0]
		if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), name) {
			t.Fatalf("upload ?%s = %d %s, want a 501 naming %s", query, rec.Code, rec.Body.String(), name)
		}
	}
	if _, err := os.Stat(filepath.Join(workDir, "f.txt")); !os.IsNotExist(err) {
		t.Fatalf("a refused upload wrote the file: %v", err)
	}
	// Plain uploads, and options turned off, still work.
	for _, query := range []string{"", "append=false&create_only=0"} {
		if rec := upload(query); rec.Code != http.StatusCreated {
			t.Fatalf("upload ?%s = %d %s", query, rec.Code, rec.Body.String())
		}
	}
}
