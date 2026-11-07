package apiclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Plan F4: a client size cap on downloads, and the buffered download
// retries like any safe call (it used to be sent once).
func TestDownloadMaxBytesAndRetry(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch r.URL.Query().Get("path") {
		case "/flaky":
			if n == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("ok"))
		case "/sized":
			w.Header().Set("Content-Length", "10")
			_, _ = w.Write([]byte("0123456789"))
		case "/streamed":
			// No Content-Length: the size shows only as it arrives.
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(strings.Repeat("x", 10)))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no such file"}`))
		}
	}))
	t.Cleanup(server.Close)
	client := fastRetryClient(server.URL, server.Client())

	if data, err := client.DownloadFile(ctx, "sb-1", "/flaky"); err != nil || string(data) != "ok" || calls.Load() != 2 {
		t.Fatalf("download after a 503 = %q, %v (%d calls)", data, err, calls.Load())
	}
	calls.Store(0)
	if _, err := client.DownloadFileWithOptions(ctx, "sb-1", "/sized", sdktypes.DownloadFileOptions{MaxBytes: 5}); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("sized file over the cap = %v", err)
	}
	if data, err := client.DownloadFileWithOptions(ctx, "sb-1", "/sized", sdktypes.DownloadFileOptions{MaxBytes: 10}); err != nil || string(data) != "0123456789" {
		t.Fatalf("file at the cap = %q, %v", data, err)
	}
	body, err := client.DownloadFileStreamWithOptions(ctx, "sb-1", "/streamed", sdktypes.DownloadFileOptions{MaxBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(body)
	body.Close()
	if !errors.Is(err, ErrFileTooLarge) || string(data) != "xxxx" {
		t.Fatalf("streamed file over the cap = %q, %v; want the first 4 bytes then ErrFileTooLarge", data, err)
	}
	if _, err := body.Read(make([]byte, 1)); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("read after the cap = %v", err)
	}
	if data, err := client.DownloadFileWithOptions(ctx, "sb-1", "/streamed", sdktypes.DownloadFileOptions{MaxBytes: 10}); err != nil || len(data) != 10 {
		t.Fatalf("streamed file at the cap = %d bytes, %v", len(data), err)
	}
	if _, err := client.DownloadFile(ctx, "sb-1", "/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	bad := NewClient("http://[::1", ClientOptions{PATToken: "t"})
	if _, err := bad.DownloadFile(ctx, "sb-1", "/x"); err == nil {
		t.Fatal("a bad base URL did not fail")
	}
}
