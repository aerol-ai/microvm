package toolhost_test

import (
	"bytes"
	"context"
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

type memStateKV struct {
	data map[string][]byte
}

func newMemStateKV() *memStateKV {
	return &memStateKV{data: map[string][]byte{}}
}

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

	t.Run("sessions list empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("sessions list status = %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestHostStateKV(t *testing.T) {
	kv := newMemStateKV()
	host := toolhost.New(toolhost.Config{
		SandboxID: "sb-kv",
		WorkDir:   t.TempDir(),
		StateKV:   kv,
	})
	h := host.Handler()

	t.Run("put get delete list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/state/kv/counter", bytes.NewReader([]byte("42")))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("put status = %d body=%s", rec.Code, rec.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/state/kv/counter", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != "42" {
			t.Fatalf("get status = %d body=%q", rec.Code, rec.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/state/kv/", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d", rec.Code)
		}
		var listed struct {
			Keys []string `json:"keys"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
			t.Fatalf("list json: %v", err)
		}
		if len(listed.Keys) != 1 || listed.Keys[0] != "counter" {
			t.Fatalf("keys = %v", listed.Keys)
		}

		req = httptest.NewRequest(http.MethodDelete, "/state/kv/counter", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("delete status = %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodGet, "/state/kv/counter", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("get after delete status = %d", rec.Code)
		}
	})
}
