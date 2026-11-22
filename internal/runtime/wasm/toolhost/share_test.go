package toolhost

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestUploadSharedWithGroup: in privilege mode split the toolbox gives
// what it writes to the worker's group (the workdir's setgid group), its
// folders 2770 and its files 0660, and chowns nothing.
func TestUploadSharedWithGroup(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := t.TempDir()
	if err := os.Chmod(dir, os.ModeSetgid|0o770); err != nil {
		t.Fatal(err)
	}
	// A uid sandboxd cannot chown to: Share must not try.
	gid := os.Getgid()
	if gid == 0 {
		// Root's gid 0 is no owner at all; root may share with any group.
		gid = 4242
	}
	h := New(Config{SandboxID: "sb", WorkDir: dir, Owner: Owner{UID: 4242424, GID: gid, Share: true}})
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "/a/b/f.txt")
	part, _ := w.CreateFormFile("file", "f.txt")
	_, _ = part.Write([]byte("data"))
	_ = w.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload %d %s", rec.Code, rec.Body.String())
	}
	for path, want := range map[string]os.FileMode{"a": os.ModeDir | os.ModeSetgid | 0o770, "a/b": os.ModeDir | os.ModeSetgid | 0o770, "a/b/f.txt": 0o660} {
		st, err := os.Stat(filepath.Join(dir, path))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode() != want {
			t.Errorf("%s mode %v, want %v", path, st.Mode(), want)
		}
	}
}
