//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fifo makes a named pipe in a fresh folder, next to a file holding
// "needle", and returns both paths.
func fifo(t *testing.T) (dir, pipe string) {
	t.Helper()
	dir = t.TempDir()
	pipe = filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one needle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, pipe
}

// answer runs h and fails the test if it has not answered within 5 s: a
// handler that opened a named pipe would wait forever for its other end.
func answer(t *testing.T, h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h(rr, r)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s %s did not answer: it is waiting on a named pipe", r.Method, r.URL)
	}
	return rr
}

func multipartUpload(t *testing.T, target string, fields map[string]string, body []byte) *http.Request {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	_ = mw.WriteField("path", target)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, err := mw.CreateFormFile("file", "x")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(body)
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/files/upload", &b)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// Every file route refuses a named pipe at once, with 409, and leaves it a
// pipe. Before, each one waited for the pipe's other end: a download until
// something wrote, an upload until something read, holding a thread after
// the caller gave up; a small upload "succeeded" with its bytes lost in the
// pipe (agent-sandbox fixed the same, kubernetes-sigs/agent-sandbox#2222).
func TestFileRoutesRefuseNamedPipes(t *testing.T) {
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	big := bytes.Repeat([]byte("x"), 128<<10)
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		req  func(dir, pipe string) *http.Request
	}{
		{"download", srv.handleDownload, func(_, p string) *http.Request {
			return httptest.NewRequest(http.MethodGet, "/files/download?path="+url.QueryEscape(p), nil)
		}},
		{"upload", srv.handleUpload, func(_, p string) *http.Request { return multipartUpload(t, p, nil, []byte("hello")) }},
		{"upload, large", srv.handleUpload, func(_, p string) *http.Request { return multipartUpload(t, p, nil, big) }},
		{"upload, append", srv.handleUpload, func(_, p string) *http.Request {
			return multipartUpload(t, p, map[string]string{"append": "true"}, []byte("hello"))
		}},
		{"upload, mode", srv.handleUpload, func(_, p string) *http.Request {
			return multipartUpload(t, p, map[string]string{"mode": "0644"}, []byte("hello"))
		}},
		{"envd read", srv.handleEnvdFileRead, func(_, p string) *http.Request {
			return httptest.NewRequest(http.MethodGet, "/files?path="+url.QueryEscape(p), nil)
		}},
		{"envd write", srv.handleEnvdOctetStreamWrite, func(_, p string) *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/files?path="+url.QueryEscape(p), bytes.NewReader(big))
			r.Header.Set("Content-Type", "application/octet-stream")
			return r
		}},
		{"envd multipart write", srv.handleEnvdMultipartWrite, func(_, p string) *http.Request {
			r := multipartUpload(t, p, nil, big)
			r.URL.RawQuery = "path=" + url.QueryEscape(p)
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, pipe := fifo(t)
			rr := answer(t, tc.h, tc.req(dir, pipe))
			body := rr.Body.String()
			if rr.Code != http.StatusConflict || !strings.Contains(body, "is a named pipe, not a file") {
				t.Fatalf("status %d, body %s; want 409 naming the pipe", rr.Code, body)
			}
			if info, err := os.Lstat(pipe); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
				t.Fatalf("the pipe was replaced: %v %v", info, err)
			}
		})
	}
}

// An atomic upload writes a new file beside the target and renames it into
// place: it never opens the pipe, so it neither waits nor is refused.
func TestAtomicUploadReplacesANamedPipe(t *testing.T) {
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, pipe := fifo(t)
	rr := answer(t, srv.handleUpload, multipartUpload(t, pipe, map[string]string{"atomic": "true"}, []byte("hello")))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	if got, err := os.ReadFile(pipe); err != nil || string(got) != "hello" {
		t.Fatalf("after an atomic upload: %q %v", got, err)
	}
}

// A search skips a named pipe in the folder and still finds the match in
// the file next to it; a replace refuses the pipe and edits the file.
func TestDaytonaSearchAndReplaceSkipNamedPipes(t *testing.T) {
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dir, pipe := fifo(t)
	rr := answer(t, srv.handleDaytonaFindInFiles, httptest.NewRequest(http.MethodGet,
		"/files/find?path="+url.QueryEscape(dir)+"&pattern=needle", nil))
	var matches []daytonaMatchResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &matches); rr.Code != http.StatusOK || err != nil || len(matches) != 1 ||
		matches[0].File != filepath.Join(dir, "a.txt") {
		t.Fatalf("search: %d %s", rr.Code, rr.Body)
	}

	body, _ := json.Marshal(daytonaReplaceRequest{Files: []string{pipe, filepath.Join(dir, "a.txt")}, Pattern: "needle", NewValue: "pin"})
	rr = answer(t, srv.handleDaytonaReplaceInFiles, httptest.NewRequest(http.MethodPost, "/files/replace", bytes.NewReader(body)))
	var results []daytonaReplaceResult
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil || len(results) != 2 {
		t.Fatalf("replace: %d %s", rr.Code, rr.Body)
	}
	if results[0].Success || !strings.Contains(results[0].Error, "is not a file") || !results[1].Success {
		t.Fatalf("replace results = %+v", results)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "one pin\n" {
		t.Fatalf("the file next to the pipe: %q", got)
	}
}

// A socket is refused like a pipe: its open fails with ENXIO, which openFile
// names for what it is. A device still opens, and a write-only open of a
// file still works.
func TestOpenFileKinds(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, _, err := openFile(sock, os.O_RDONLY, 0); err == nil || !strings.Contains(err.Error(), "is a socket, not a file") {
		t.Fatalf("a socket: %v", err)
	}
	_, pipe := fifo(t)
	if _, _, err := openFile(pipe, os.O_WRONLY, 0); err == nil || !strings.Contains(err.Error(), "is a named pipe, not a file") {
		t.Fatalf("a write-only open of a pipe with no reader: %v", err)
	}
	f, info, err := openFile("/dev/null", os.O_RDONLY, 0)
	if err != nil || info.Mode()&os.ModeDevice == 0 {
		t.Fatalf("/dev/null: %v %v", info, err)
	}
	// Back in blocking mode: a read is a plain read, here an end of file.
	if n, err := f.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatalf("read /dev/null: %d %v", n, err)
	}
	_ = f.Close()
	if _, _, err := openFile(filepath.Join(dir, "missing", "x"), os.O_RDONLY, 0); !os.IsNotExist(err) {
		t.Fatalf("a missing path: %v", err)
	}
	w, _, err := openFile(filepath.Join(dir, "new"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
}
