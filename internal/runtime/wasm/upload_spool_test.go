package wasm

import (
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestServeToolboxUploadUsesDriverSpool: an upload past the toolbox host's
// 64 MiB in-memory budget spills into the driver's spool
// (Config.UploadSpoolDir), not the shared temp folder, and is gone after.
func TestServeToolboxUploadUsesDriverSpool(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	workDir := filepath.Join(runDir, "sb-up")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	spoolDir := filepath.Join(dir, "upload-spool")
	shared := t.TempDir()
	t.Setenv("TMPDIR", shared)
	d := New(Config{RunDir: runDir, ModulesDir: dir, UploadSpoolDir: spoolDir}, nil)
	d.mu.Lock()
	d.byID["sb-up"] = &sandboxInstance{sandboxID: "sb-up", workDir: workDir, status: models.SandboxStatusStarted}
	d.mu.Unlock()

	const size = 64<<20 + 64<<10
	var sharedDuring, spoolDuring []os.DirEntry
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("file", "big.bin")
		if err == nil {
			_, err = io.Copy(part, io.LimitReader(fillReader{}, size))
		}
		// The host has consumed the file's bytes and holds the spill.
		sharedDuring, _ = os.ReadDir(shared)
		spoolDuring, _ = os.ReadDir(spoolDir)
		if err == nil {
			err = mw.WriteField("path", "/big.bin")
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	d.ServeToolbox(req.Context(), "sb-up", "tok", rec, withBearer(req, "tok"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	if len(sharedDuring) != 0 || len(spoolDuring) != 1 {
		t.Fatalf("mid-upload: shared temp %v, spool %v; want nothing and one request folder", sharedDuring, spoolDuring)
	}
	if info, err := os.Stat(filepath.Join(workDir, "big.bin")); err != nil || info.Size() != size {
		t.Fatalf("uploaded file = %v, %v", info, err)
	}
	for _, folder := range []string{shared, spoolDir} {
		if entries, _ := os.ReadDir(folder); len(entries) != 0 {
			t.Fatalf("%s holds %d entries after the request", folder, len(entries))
		}
	}
}

// fillReader is an endless stream of filler bytes, a chunk per read.
type fillReader struct{}

var fillChunk = make([]byte, 64<<10)

func (fillReader) Read(p []byte) (int, error) { return copy(p, fillChunk), nil }

func withBearer(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
