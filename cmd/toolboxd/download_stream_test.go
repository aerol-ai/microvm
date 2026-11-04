package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestHandleDownloadStreamsFile pins the streaming download: the body is the
// file, Content-Length is set for regular files, and a client may stop
// reading early (the agent read_file tool reads one window of a large file).
func TestHandleDownloadStreamsFile(t *testing.T) {
	s := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewServer(http.HandlerFunc(s.handleDownload))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "big.bin")
	data := bytes.Repeat([]byte("0123456789abcdef"), 64*1024) // 1 MiB
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.URL + "/files/download?path=" + url.QueryEscape(path))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Length") != strconv.Itoa(len(data)) {
		t.Fatalf("status %d, Content-Length %q", resp.StatusCode, resp.Header.Get("Content-Length"))
	}
	head := make([]byte, 100)
	if _, err := io.ReadFull(resp.Body, head); err != nil || !bytes.Equal(head, data[:100]) {
		t.Fatalf("head read = %q, %v", head, err)
	}
	_ = resp.Body.Close() // stop early; the handler must not mind

	resp, err = http.Get(srv.URL + "/files/download?path=" + url.QueryEscape(path))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("full body mismatch (%d bytes, err %v)", len(body), err)
	}

	resp, err = http.Get(srv.URL + "/files/download?path=" + url.QueryEscape(filepath.Dir(path)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("directory status = %d, want 500 (unchanged from os.ReadFile)", resp.StatusCode)
	}
	resp, err = http.Get(srv.URL + "/files/download?path=" + url.QueryEscape(path+".missing"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", resp.StatusCode)
	}
}
