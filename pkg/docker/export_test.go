package docker

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// TestExportImageTar_HappyPath pins the daemon contract the template
// puller in PR 6-B.2 relies on: GET /images/{ref}/get, body returned
// untouched. If the path drifts, the puller silently fetches nothing
// and the consumer-side cluster replication breaks.
func TestExportImageTar_HappyPath(t *testing.T) {
	const body = "fake-tar-contents-not-actually-a-tar"
	var lastPath atomic.Value
	lastPath.Store("")
	var calls atomic.Int64
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		lastPath.Store(r.URL.Path)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})
	c := &Client{logger: slog.Default(), streamClient: &http.Client{Transport: transport}}

	rc, err := c.ExportImageTar(context.Background(), "aerolvm-build/tpl-foo:latest")
	if err != nil {
		t.Fatalf("ExportImageTar: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", string(got), body)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
	// PathEscape encodes ':' as %3A, so the ref segment is opaque to URL
	// parsers — the daemon sees the literal ref.
	if got := lastPath.Load().(string); !strings.HasPrefix(got, "/images/") || !strings.HasSuffix(got, "/get") {
		t.Errorf("path = %q, want /images/<ref>/get", got)
	}
}

// TestExportImageTar_HTTPError surfaces the status code + body so an
// operator chasing a stuck puller sees the daemon's actual reason rather
// than a generic "export failed".
func TestExportImageTar_HTTPError(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("no such image")),
			Header:     make(http.Header),
		}, nil
	})
	c := &Client{logger: slog.Default(), streamClient: &http.Client{Transport: transport}}
	_, err := c.ExportImageTar(context.Background(), "missing:latest")
	if err == nil {
		t.Fatal("ExportImageTar returned nil despite 404")
	}
	if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "no such image") {
		t.Errorf("err = %v, want status + body in message", err)
	}
}

func TestExportImageTar_RejectsEmptyRef(t *testing.T) {
	c := &Client{logger: slog.Default()}
	if _, err := c.ExportImageTar(context.Background(), ""); err == nil {
		t.Error("empty ref accepted")
	}
	if _, err := c.ExportImageTar(context.Background(), "   "); err == nil {
		t.Error("blank ref accepted")
	}
}
