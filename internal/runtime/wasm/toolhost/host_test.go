package toolhost_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/pkg/models"
)

type stubExec struct {
	last models.ExecRequest
}

func (s *stubExec) Exec(_ *http.Request, req models.ExecRequest) (models.ExecResult, error) {
	s.last = req
	return models.ExecResult{Stdout: "ok", ExitCode: 0}, nil
}

func TestHostFilesAndExec(t *testing.T) {
	dir := t.TempDir()
	exec := &stubExec{}
	host := toolhost.New(toolhost.Config{
		SandboxID: "sb-1",
		WorkDir:   dir,
		AuthToken: "tok",
		Exec:      exec,
	})
	h := host.Handler()

	t.Run("health", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("upload download", func(t *testing.T) {
		body := &bytes.Buffer{}
		w := multipart.NewWriter(body)
		_ = w.WriteField("path", "/hello.txt")
		part, err := w.CreateFormFile("file", "hello.txt")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(part, "hello wasm")
		_ = w.Close()

		req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload status = %d body=%s", rec.Code, rec.Body.String())
		}
		if _, err := os.Stat(filepath.Join(dir, "hello.txt")); err != nil {
			t.Fatalf("file on disk: %v", err)
		}

		req = httptest.NewRequest(http.MethodGet, "/files/download?path=/hello.txt", nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("download status = %d", rec.Code)
		}
		if got := rec.Body.String(); got != "hello wasm" {
			t.Fatalf("download body = %q", got)
		}
	})

	t.Run("exec", func(t *testing.T) {
		payload, _ := json.Marshal(models.ExecRequest{Command: "echo hi"})
		req := httptest.NewRequest(http.MethodPost, "/process/execute", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("exec status = %d body=%s", rec.Code, rec.Body.String())
		}
		if exec.last.Command != "echo hi" {
			t.Fatalf("command = %q", exec.last.Command)
		}
	})

	t.Run("path escape rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/files/download?path=/../../../etc/passwd", nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
	})
}
