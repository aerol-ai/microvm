package docker

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// importCapture wires a fake Docker daemon transport so we can inspect
// exactly what ImportImage emits without standing up a real daemon. The
// PR 6-B.1 push pipeline cares about three things on the import side:
//   - the request lands on /images/create
//   - fromSrc=- so the daemon reads the body as a tar (not a URL)
//   - repo+tag come from DestTag, byte-exactly
type importCapture struct {
	client       *Client
	calls        atomic.Int64
	lastPath     atomic.Value // string
	lastQuery    atomic.Value // string
	lastBodySize atomic.Int64
	lastCT       atomic.Value // string

	statusCode int
	body       string
}

func newImportCapture(statusCode int, body string) *importCapture {
	cap := &importCapture{statusCode: statusCode, body: body}
	cap.lastPath.Store("")
	cap.lastQuery.Store("")
	cap.lastCT.Store("")
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		cap.calls.Add(1)
		cap.lastPath.Store(r.URL.Path)
		cap.lastQuery.Store(r.URL.RawQuery)
		cap.lastCT.Store(r.Header.Get("Content-Type"))
		if r.Body != nil {
			n, _ := io.Copy(io.Discard, r.Body)
			cap.lastBodySize.Store(n)
		}
		return &http.Response{
			StatusCode: cap.statusCode,
			Body:       io.NopCloser(strings.NewReader(cap.body)),
			Header:     make(http.Header),
		}, nil
	})
	cap.client = &Client{
		logger:       slog.Default(),
		streamClient: &http.Client{Transport: transport},
		httpClient:   &http.Client{Transport: transport},
	}
	return cap
}

// TestImportImage_HappyPath pins the exact daemon contract the template
// push pipeline will rely on. If any of these query params drift,
// ImportImage silently turns into a "fetch from URL" call (fromSrc != -)
// or lands the image under the wrong name — both break PR 6-B.2's
// downstream pull.
func TestImportImage_HappyPath(t *testing.T) {
	cap := newImportCapture(http.StatusOK, `{"status":"sha256:abc"}`+"\n")

	body := strings.Repeat("X", 4096)
	if err := cap.client.ImportImage(context.Background(), ImportImageRequest{
		DestTag: BuiltImageNamespace + "/tpl-foo:latest",
		Tar:     strings.NewReader(body),
	}); err != nil {
		t.Fatalf("ImportImage: %v", err)
	}

	if cap.calls.Load() != 1 {
		t.Fatalf("transport calls = %d, want 1", cap.calls.Load())
	}
	if path := cap.lastPath.Load().(string); path != "/images/create" {
		t.Errorf("path = %q, want /images/create", path)
	}
	q, err := url.ParseQuery(cap.lastQuery.Load().(string))
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if got := q.Get("fromSrc"); got != "-" {
		t.Errorf("fromSrc = %q, want %q — daemon would try to fetch a URL instead of reading the body", got, "-")
	}
	if got := q.Get("repo"); got != BuiltImageNamespace+"/tpl-foo" {
		t.Errorf("repo = %q, want %q", got, BuiltImageNamespace+"/tpl-foo")
	}
	if got := q.Get("tag"); got != "latest" {
		t.Errorf("tag = %q, want %q", got, "latest")
	}
	if got := cap.lastCT.Load().(string); got != "application/x-tar" {
		t.Errorf("Content-Type = %q, want application/x-tar — daemon would misparse the body otherwise", got)
	}
	if got := cap.lastBodySize.Load(); got != int64(len(body)) {
		t.Errorf("body bytes = %d, want %d (tar reader must be fully drained into the request)", got, len(body))
	}
}

// TestImportImage_DefaultsTagToLatest documents that the splitDestRef
// helper (shared with PushImage) treats a bare repo as tag=latest. The
// template push code path passes "<ns>/tpl-<id>:latest" explicitly so
// this is defensive, but if a future caller forgets the :latest
// suffix the import still produces a usable image rather than failing.
func TestImportImage_DefaultsTagToLatest(t *testing.T) {
	cap := newImportCapture(http.StatusOK, "")
	if err := cap.client.ImportImage(context.Background(), ImportImageRequest{
		DestTag: BuiltImageNamespace + "/tpl-bare",
		Tar:     strings.NewReader(""),
	}); err != nil {
		t.Fatalf("ImportImage: %v", err)
	}
	q, _ := url.ParseQuery(cap.lastQuery.Load().(string))
	if got := q.Get("tag"); got != "latest" {
		t.Errorf("tag = %q, want %q (default)", got, "latest")
	}
	if got := q.Get("repo"); got != BuiltImageNamespace+"/tpl-bare" {
		t.Errorf("repo = %q, want %q", got, BuiltImageNamespace+"/tpl-bare")
	}
}

// TestImportImage_StreamError pins the "HTTP 200 but the body says
// error" arm. The pull path has the same behavior — without scanning
// the NDJSON, an unparseable tar would surface later as a confusing
// "image not found on inspect" instead of the daemon's actual reason.
func TestImportImage_StreamError(t *testing.T) {
	cap := newImportCapture(http.StatusOK, `{"errorDetail":{"message":"invalid tar header"}}`+"\n")
	err := cap.client.ImportImage(context.Background(), ImportImageRequest{
		DestTag: BuiltImageNamespace + "/tpl-bad:latest",
		Tar:     strings.NewReader("not a tar"),
	})
	if err == nil {
		t.Fatal("ImportImage returned nil despite error in stream")
	}
	if !strings.Contains(err.Error(), "invalid tar header") {
		t.Errorf("err = %v, want it to carry the daemon's message", err)
	}
}

// TestImportImage_HTTPError covers the early-failure path: the daemon
// returns 4xx/5xx before emitting any NDJSON. We surface the status
// code and body for operator-friendly logs, matching the shape of
// pullImage's HTTP-level error.
func TestImportImage_HTTPError(t *testing.T) {
	cap := newImportCapture(http.StatusInternalServerError, "boom")
	err := cap.client.ImportImage(context.Background(), ImportImageRequest{
		DestTag: BuiltImageNamespace + "/tpl-500:latest",
		Tar:     strings.NewReader(""),
	})
	if err == nil {
		t.Fatal("ImportImage returned nil despite HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want status and body in message", err)
	}
}

// TestImportImage_RejectsEmptyInputs guards the call site — a forgotten
// tag would silently push an empty repo to the daemon, and a nil reader
// would send an empty body that the daemon happily accepts as a 0-byte
// image. Both are user errors we want to fail fast on.
func TestImportImage_RejectsEmptyInputs(t *testing.T) {
	cap := newImportCapture(http.StatusOK, "")

	if err := cap.client.ImportImage(context.Background(), ImportImageRequest{
		DestTag: "",
		Tar:     strings.NewReader("x"),
	}); err == nil {
		t.Error("empty DestTag accepted")
	}
	if err := cap.client.ImportImage(context.Background(), ImportImageRequest{
		DestTag: BuiltImageNamespace + "/tpl-x:latest",
		Tar:     nil,
	}); err == nil {
		t.Error("nil Tar reader accepted")
	}
	if cap.calls.Load() != 0 {
		t.Errorf("transport called %d times despite input validation; should fail before any HTTP", cap.calls.Load())
	}
}
