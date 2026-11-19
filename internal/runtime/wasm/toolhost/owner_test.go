package toolhost_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
)

// An upload is the guest's file: it and every folder made for it belong to
// the uid the sandbox's worker runs as, or the guest could not change it.
func TestHostUploadHandsFilesToTheWorker(t *testing.T) {
	owner := toolhost.Owner{UID: os.Getuid(), GID: os.Getgid()}
	if os.Geteuid() == 0 {
		owner = toolhost.Owner{UID: 65534, GID: 65534}
	}
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := newHost(t, func(c *toolhost.Config) { c.WorkDir = work; c.Owner = owner })
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	_ = w.WriteField("path", "existing/new/deeper/up.txt")
	part, _ := w.CreateFormFile("file", "up.txt")
	_, _ = part.Write([]byte("uploaded"))
	_ = w.Close()
	rec := serve(h, http.MethodPost, "/files/upload", body.Bytes(), map[string]string{"Content-Type": w.FormDataContentType()})
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d %s", rec.Code, rec.Body.String())
	}
	for _, rel := range []string{"existing/new", "existing/new/deeper", "existing/new/deeper/up.txt"} {
		st, err := os.Lstat(filepath.Join(work, rel))
		if err != nil {
			t.Fatal(err)
		}
		if uid := int(st.Sys().(*syscall.Stat_t).Uid); uid != owner.UID {
			t.Fatalf("%s owner = %d, want %d", rel, uid, owner.UID)
		}
	}
	if os.Geteuid() == 0 {
		// A folder that was there is left as it was.
		st, _ := os.Lstat(filepath.Join(work, "existing"))
		if uid := st.Sys().(*syscall.Stat_t).Uid; uid != 0 {
			t.Fatalf("existing folder re-owned to %d", uid)
		}
	}
	// A folder that cannot be made fails the upload.
	if err := os.WriteFile(filepath.Join(work, "blocker"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	body.Reset()
	w = multipart.NewWriter(body)
	_ = w.WriteField("path", "blocker/x/up.txt")
	part, _ = w.CreateFormFile("file", "up.txt")
	_, _ = part.Write([]byte("x"))
	_ = w.Close()
	rec = serve(h, http.MethodPost, "/files/upload", body.Bytes(), map[string]string{"Content-Type": w.FormDataContentType()})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("upload under a file = %d", rec.Code)
	}
}
