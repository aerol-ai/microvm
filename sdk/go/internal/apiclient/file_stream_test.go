package apiclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

const streamTestSize = 64 << 20 // 64 MiB, the D14 required-proof size

// patternReader yields n bytes of a repeating pattern without allocating.
type patternReader struct{ left int64 }

func (p *patternReader) Read(b []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > p.left {
		b = b[:p.left]
	}
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	p.left -= int64(len(b))
	return len(b), nil
}

func totalAlloc() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.TotalAlloc
}

// TestUploadFileStreamBoundedMemory is the D14 proof for uploads: a 64 MiB
// upload allocates a small, fixed amount, not the file size.
func TestUploadFileStreamBoundedMemory(t *testing.T) {
	var gotPath string
	var gotBytes int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || r.URL.Path != "/v1/sandboxes/sb-1/toolbox/files/upload" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			if part.FormName() == "path" {
				b, _ := io.ReadAll(part)
				gotPath = string(b)
				continue
			}
			gotBytes, _ = io.Copy(io.Discard, part)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})

	before := totalAlloc()
	if err := client.UploadFileStream(context.Background(), "sb-1", "/work/big.bin", &patternReader{left: streamTestSize}); err != nil {
		t.Fatalf("UploadFileStream: %v", err)
	}
	allocated := totalAlloc() - before
	if gotPath != "/work/big.bin" || gotBytes != streamTestSize {
		t.Fatalf("server saw path %q and %d bytes", gotPath, gotBytes)
	}
	if allocated > 16<<20 {
		t.Fatalf("a 64 MiB upload allocated %d MiB; the body is being buffered", allocated>>20)
	}
}

// TestDownloadFileStreamBoundedMemory is the D14 proof for downloads, plus
// the read_file shape: reading a window and closing early is fine.
func TestDownloadFileStreamBoundedMemory(t *testing.T) {
	chunk := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("path") {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no such file"}`))
			return
		}
		for written := 0; written < streamTestSize; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	ctx := context.Background()

	before := totalAlloc()
	body, err := client.DownloadFileStream(ctx, "sb-1", "/work/big.bin")
	if err != nil {
		t.Fatalf("DownloadFileStream: %v", err)
	}
	n, err := io.Copy(io.Discard, body)
	_ = body.Close()
	allocated := totalAlloc() - before
	if err != nil || n != streamTestSize {
		t.Fatalf("read %d bytes, err %v", n, err)
	}
	if allocated > 16<<20 {
		t.Fatalf("a 64 MiB download allocated %d MiB; the body is being buffered", allocated>>20)
	}

	body, err = client.DownloadFileStream(ctx, "sb-1", "/work/big.bin")
	if err != nil {
		t.Fatalf("DownloadFileStream (window): %v", err)
	}
	window := make([]byte, 257)
	if _, err := io.ReadFull(body, window); err != nil || !bytes.Equal(window, chunk[:257]) {
		t.Fatalf("window read = %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatalf("early close: %v", err)
	}

	if _, err := client.DownloadFileStream(ctx, "sb-1", "/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing file error = %v, want ErrNotFound", err)
	}
}

func TestUploadFileStreamErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid multipart form (or too large)"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	err := client.UploadFileStream(context.Background(), "sb-1", "/x", strings.NewReader("data"))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("server rejection error = %v", err)
	}
	// A failing reader aborts the upload instead of sending a truncated file.
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server2.Close()
	client2 := NewClient(server2.URL, ClientOptions{PATToken: "pat", HTTPClient: server2.Client()})
	boom := errors.New("disk read failed")
	if err := client2.UploadFileStream(context.Background(), "sb-1", "/x", io.MultiReader(strings.NewReader("part"), errReader{boom})); err == nil {
		t.Fatal("a reader error must fail the upload")
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestListQuerySendsLimit(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	if _, _, err := client.ListPageWithQuery(context.Background(), ListQuery{Limit: 20}, "tok"); err != nil {
		t.Fatalf("ListPageWithQuery: %v", err)
	}
	if seen[0] != "limit=20&page_token=tok" {
		t.Fatalf("query = %q, want limit=20&page_token=tok", seen[0])
	}
}
