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

// The guest can make symlinks in its own directory. A link that points out of
// it must not carry a download, a listing or an upload onto the daemon's
// host; a link that stays inside still works.
func TestHostFilesStayInsideTheWorkDir(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{work, outside} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("host-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "inside.txt"), []byte("guest-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(work, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"rel-file":   "../outside/secret",
		"abs-file":   secret,
		"rel-dir":    "../outside",
		"inner-link": "inside.txt",
		// Each link alone stays inside; followed in turn they climb out
		// (inner/up is the work dir, so chain is its parent).
		"inner/up": "..",
		"chain":    "inner/up/..",
	} {
		if err := os.Symlink(target, filepath.Join(work, link)); err != nil {
			t.Fatal(err)
		}
	}
	h := New(Config{SandboxID: "sb-links", WorkDir: work})
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	for _, path := range []string{
		"/files/download?path=/rel-file", "/files/download?path=/abs-file", "/files/download?path=/rel-dir/secret", "/files?path=/rel-dir",
		"/files/download?path=/chain/outside/secret", "/files?path=/chain", "/files?path=/chain/outside",
	} {
		rec := get(path)
		if rec.Code < 400 || strings.Contains(rec.Body.String(), "host-secret") || strings.Contains(rec.Body.String(), `"secret"`) {
			t.Errorf("GET %s = %d %q; want refused, nothing from the host", path, rec.Code, rec.Body.String())
		}
	}
	if rec := get("/files/download?path=/inner-link"); rec.Code != http.StatusOK || rec.Body.String() != "guest-data" {
		t.Fatalf("a link inside the work dir = %d %q", rec.Code, rec.Body.String())
	}

	upload := func(path string) *httptest.ResponseRecorder {
		body := &bytes.Buffer{}
		form := multipart.NewWriter(body)
		_ = form.WriteField("path", path)
		part, _ := form.CreateFormFile("file", "planted")
		_, _ = part.Write([]byte("written-through-a-link"))
		_ = form.Close()
		req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
		req.Header.Set("Content-Type", form.FormDataContentType())
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, req)
		return rec
	}
	for _, path := range []string{"/rel-dir/planted", "/chain/outside/planted"} {
		rec := upload(path)
		if _, err := os.Stat(filepath.Join(outside, "planted")); err == nil || rec.Code < 400 {
			t.Fatalf("upload to %s = %d; the file landed outside the work dir: %v", path, rec.Code, err == nil)
		}
	}
	// Uploading onto the link's own name replaces the link; it does not
	// write through it.
	if rec := upload("/rel-file"); rec.Code != http.StatusCreated {
		t.Fatalf("upload onto a link name = %d %q", rec.Code, rec.Body.String())
	}
	if data, _ := os.ReadFile(secret); string(data) != "host-secret" {
		t.Fatalf("upload wrote through a link: host file is now %q", data)
	}
	if fi, err := os.Lstat(filepath.Join(work, "rel-file")); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("rel-file after upload: %v, %v; want a regular file in the work dir", fi, err)
	}
}
