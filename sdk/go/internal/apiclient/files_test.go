package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// fakeToolbox answers /version with features and records every other call;
// reply decides the answer to call n (counting from 0) of a route.
type fakeToolbox struct {
	mu       sync.Mutex
	features []string
	calls    []*http.Request
	reply    func(r *http.Request, n int) (int, any, http.Header)
}

func (f *fakeToolbox) serve(t *testing.T) (*Client, *httptest.Server) {
	t.Helper()
	perRoute := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/toolbox/version") {
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "test", "features": f.features})
			return
		}
		f.mu.Lock()
		f.calls = append(f.calls, r.Clone(context.Background()))
		n := perRoute[r.Method+r.URL.Path]
		perRoute[r.Method+r.URL.Path]++
		f.mu.Unlock()
		status, body, header := http.StatusOK, any(nil), http.Header(nil)
		if f.reply != nil {
			status, body, header = f.reply(r, n)
		}
		for k, v := range header {
			w.Header()[k] = v
		}
		if body == nil {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	return fastRetryClient(server.URL, server.Client()), server
}

func (f *fakeToolbox) recorded() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.calls...)
}

func errBody(message, code string) models.ErrorResponse {
	return models.ErrorResponse{Error: message, Code: code}
}

func TestListFilesSendsCapAndReadsExtendedInfo(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{FeatureFileVerbs}}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		big := int64(5 << 30)
		target := "f.txt"
		entries := []map[string]any{
			{"name": "a", "isDir": true, "size": 64, "mode": "drwxr-xr-x", "permissions": "0755", "owner": "root", "group": "root", "modTime": "2026-01-01T00:00:00Z", "path": "/w/a", "size_bytes": 64},
			{"name": "big", "isDir": false, "size": 2147483647, "path": "/w/big", "size_bytes": big},
			{"name": "link", "size": 5, "path": "/w/link", "size_bytes": 5, "symlink_target": target},
		}
		return http.StatusOK, entries, http.Header{listTruncatedHeader: {"true"}}
	}
	client, _ := fake.serve(t)

	list, err := client.ListFiles(ctx, "sb-1", "/w", sdktypes.ListFilesOptions{})
	if err != nil {
		t.Fatal(err)
	}
	q := fake.recorded()[0].URL.Query()
	if q.Get("path") != "/w" || q.Get("depth") != "1" || q.Get("limit") != "10000" || q.Get("extended") != "true" {
		t.Fatalf("query = %v, want the default depth and cap sent explicitly", q)
	}
	if !list.Truncated || len(list.Entries) != 3 {
		t.Fatalf("list = %+v", list)
	}
	if list.Entries[1].Size != 5<<30 || list.Entries[2].SymlinkTarget != "f.txt" || !list.Entries[0].IsDir || list.Entries[0].Path != "/w/a" {
		t.Fatalf("entries = %+v", list.Entries)
	}

	if _, err := client.ListFiles(ctx, "sb-1", "/w", sdktypes.ListFilesOptions{Depth: 3, Limit: 7}); err != nil {
		t.Fatal(err)
	}
	if q := fake.recorded()[1].URL.Query(); q.Get("depth") != "3" || q.Get("limit") != "7" {
		t.Fatalf("query = %v", q)
	}
}

// ER4: an agent that does not list files.verbs would ignore the cap (and,
// for move, overwrite=false), so the SDK refuses before calling it.
func TestFileVerbsFailClosedOnOlderAgent(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{}}
	client, _ := fake.serve(t)
	calls := map[string]func() error{
		"ListFiles": func() error {
			_, err := client.ListFiles(ctx, "sb-1", "/", sdktypes.ListFilesOptions{})
			return err
		},
		"MoveFile without overwrite": func() error {
			return client.MoveFile(ctx, "sb-1", "/a", "/b", sdktypes.MoveFileOptions{})
		},
		"CopyFile": func() error {
			return client.CopyFile(ctx, "sb-1", "/a", "/b", sdktypes.CopyFileOptions{})
		},
		"MakeDir without parents": func() error {
			return client.MakeDir(ctx, "sb-1", "/d", sdktypes.MakeDirOptions{})
		},
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrUnsupportedFeature) {
			t.Fatalf("%s on an older agent = %v, want ErrUnsupportedFeature", name, err)
		}
	}
	if got := fake.recorded(); len(got) != 0 {
		t.Fatalf("an older agent was sent %d file calls", len(got))
	}
	// Options an older agent applies the same way need no check.
	if err := client.MoveFile(ctx, "sb-1", "/a", "/b", sdktypes.MoveFileOptions{Overwrite: true}); err != nil {
		t.Fatalf("move with overwrite: %v", err)
	}
	if err := client.MakeDir(ctx, "sb-1", "/d", sdktypes.MakeDirOptions{Parents: true}); err != nil {
		t.Fatalf("mkdir -p: %v", err)
	}
	if got := fake.recorded(); len(got) != 2 || got[0].URL.Query().Get("overwrite") != "true" || got[1].URL.Query().Get("parents") != "true" {
		t.Fatalf("calls = %d", len(got))
	}
}

func TestGetFileInfoAndExists(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		switch r.URL.Query().Get("path") {
		case "/new-agent":
			return http.StatusOK, map[string]any{"name": "new-agent", "size": 2147483647, "size_bytes": int64(3 << 30), "path": "/new-agent"}, nil
		case "/old-agent":
			// No size_bytes or path: an agent that ignores extended=true.
			return http.StatusOK, map[string]any{"name": "old-agent", "size": 12}, nil
		case "/gone":
			return http.StatusNotFound, errBody("stat /gone: no such file or directory", codeFileNotFound), nil
		case "/gone-old-agent":
			return http.StatusNotFound, errBody("stat /gone-old-agent: no such file or directory", ""), nil
		case "/no-sandbox":
			return http.StatusNotFound, errBody("sandbox not found", ""), nil
		}
		return http.StatusInternalServerError, errBody("boom", ""), nil
	}
	client, _ := fake.serve(t)

	info, err := client.GetFileInfo(ctx, "sb-1", "/new-agent")
	if err != nil || info.Size != 3<<30 || info.Path != "/new-agent" {
		t.Fatalf("info = %+v, %v", info, err)
	}
	if fake.recorded()[0].URL.Query().Get("extended") != "true" {
		t.Fatal("extended not asked for")
	}
	info, err = client.GetFileInfo(ctx, "sb-1", "/old-agent")
	if err != nil || info.Size != 12 || info.Path != "/old-agent" {
		t.Fatalf("old agent info = %+v, %v", info, err)
	}

	cases := []struct {
		path    string
		want    bool
		wantErr bool
	}{
		{"/new-agent", true, false},
		{"/gone", false, false},
		{"/gone-old-agent", false, false},
		{"/no-sandbox", false, true},
		{"/broken", false, true},
	}
	for _, tc := range cases {
		got, err := client.FileExists(ctx, "sb-1", tc.path)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Fatalf("FileExists(%s) = %v, %v", tc.path, got, err)
		}
	}
}

// Plan section 10: a retried delete or mkdir that finds its work already
// done succeeds; the first attempt still reports the error.
func TestDeleteAndMakeDirRetryFindsWorkDone(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{FeatureFileVerbs}}
	// n counts per route, and every delete is one route (the path is in
	// the query), so the cases that fail only their first try count their
	// own tries.
	tries := map[string]int{}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		path := r.URL.Query().Get("path")
		tries[path]++
		switch {
		case strings.HasPrefix(path, "/lost-reply"):
			// The first attempt did the work, but its reply was lost.
			if n == 0 {
				return http.StatusBadGateway, nil, nil
			}
			if r.Method == http.MethodDelete {
				return http.StatusNotFound, errBody("lstat: no such file or directory", codeFileNotFound), nil
			}
			return http.StatusConflict, errBody(path+" already exists", codeFolderExists), nil
		case strings.HasPrefix(path, "/route-missing"):
			if tries[path] == 1 {
				return http.StatusServiceUnavailable, nil, http.Header{"Retry-After": {"0"}}
			}
			return http.StatusNotFound, errBody("not found", ""), nil
		case path == "/refused-then-missing":
			// A 429 is sent before any work: the path was never there.
			if tries[path] == 1 {
				return http.StatusTooManyRequests, nil, http.Header{"Retry-After": {"0"}}
			}
			return http.StatusNotFound, errBody("lstat: no such file or directory", codeFileNotFound), nil
		case path == "/missing":
			return http.StatusNotFound, errBody("lstat /missing: no such file or directory", codeFileNotFound), nil
		case path == "/a-file":
			return http.StatusConflict, errBody("mkdir /a-file: file exists", ""), nil
		}
		return http.StatusNoContent, nil, nil
	}
	client, _ := fake.serve(t)

	if err := client.DeleteFile(ctx, "sb-1", "/lost-reply-del", sdktypes.DeleteFileOptions{Recursive: true}); err != nil {
		t.Fatalf("retried delete that finds the path gone = %v, want success", err)
	}
	if got := fake.recorded()[0].URL.Query().Get("recursive"); got != "true" {
		t.Fatalf("recursive = %q", got)
	}
	if err := client.MakeDir(ctx, "sb-1", "/lost-reply-dir", sdktypes.MakeDirOptions{Mode: 0o750 | os.ModeSticky}); err != nil {
		t.Fatalf("retried mkdir that finds the folder = %v, want success", err)
	}
	if q := fake.recorded()[2].URL.Query(); q.Get("parents") != "false" || q.Get("mode") != "1750" {
		t.Fatalf("mkdir query = %v", q)
	}
	if err := client.DeleteFile(ctx, "sb-1", "/missing", sdktypes.DeleteFileOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("first-attempt 404 = %v, want ErrNotFound", err)
	}
	if err := client.MakeDir(ctx, "sb-1", "/a-file", sdktypes.MakeDirOptions{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("mkdir over a file = %v, want ErrConflict", err)
	}
	// A 404 with no code on a retry is not "already deleted": it can be an
	// agent too old to have the route.
	if err := client.DeleteFile(ctx, "sb-1", "/route-missing", sdktypes.DeleteFileOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retried delete with an uncoded 404 = %v", err)
	}
	// After a 429 the server did nothing, so a 404 on the retry means the
	// path never existed, not that this call deleted it.
	if err := client.DeleteFile(ctx, "sb-1", "/refused-then-missing", sdktypes.DeleteFileOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of a missing path after a 429 = %v, want ErrNotFound", err)
	}
}

// Move and copy may have done their work when a reply is lost, so only a
// 429 or 503 (the server refused before doing anything) is retried.
func TestMoveAndCopyRetryOnlyRefusals(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{FeatureFileVerbs}}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		switch r.URL.Query().Get("source") {
		case "/refused-once":
			if n == 0 {
				return http.StatusServiceUnavailable, nil, nil
			}
		case "/bad-gateway":
			return http.StatusBadGateway, nil, nil
		case "/taken":
			return http.StatusConflict, errBody("rename /taken /b: file exists", ""), nil
		}
		return http.StatusNoContent, nil, nil
	}
	client, _ := fake.serve(t)

	if err := client.MoveFile(ctx, "sb-1", "/refused-once", "/b", sdktypes.MoveFileOptions{}); err != nil {
		t.Fatalf("move after a 503: %v", err)
	}
	if err := client.MoveFile(ctx, "sb-1", "/bad-gateway", "/b", sdktypes.MoveFileOptions{}); err == nil {
		t.Fatal("move through a 502 succeeded")
	}
	if err := client.MoveFile(ctx, "sb-1", "/taken", "/b", sdktypes.MoveFileOptions{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("move onto an existing file = %v, want ErrConflict", err)
	}
	if err := client.CopyFile(ctx, "sb-1", "/bad-gateway", "/b", sdktypes.CopyFileOptions{Recursive: true}); err == nil {
		t.Fatal("copy through a 502 succeeded")
	}
	calls := fake.recorded()
	counts := map[string]int{}
	for _, c := range calls {
		counts[c.URL.Path+" "+c.URL.Query().Get("source")]++
	}
	if counts["/v1/sandboxes/sb-1/toolbox/files/move /refused-once"] != 2 ||
		counts["/v1/sandboxes/sb-1/toolbox/files/move /bad-gateway"] != 1 ||
		counts["/v1/sandboxes/sb-1/toolbox/files/copy /bad-gateway"] != 1 {
		t.Fatalf("calls per request = %v", counts)
	}
	last := calls[len(calls)-1].URL.Query()
	if last.Get("overwrite") != "false" || last.Get("recursive") != "true" {
		t.Fatalf("copy query = %v", last)
	}
}

func TestSearchAndFindInFiles(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		if r.URL.Query().Get("pattern") == "none" {
			if strings.HasSuffix(r.URL.Path, "/search") {
				return http.StatusOK, map[string]any{"files": nil}, nil
			}
			return http.StatusOK, []map[string]any(nil), nil
		}
		if strings.HasSuffix(r.URL.Path, "/search") {
			return http.StatusOK, map[string]any{"files": []string{"/w/a.go"}}, nil
		}
		return http.StatusOK, []map[string]any{{"file": "/w/a.go", "line": 3, "content": "func main()"}}, nil
	}
	client, _ := fake.serve(t)
	files, err := client.SearchFiles(ctx, "sb-1", "/w", "*.go")
	if err != nil || len(files) != 1 || files[0] != "/w/a.go" {
		t.Fatalf("search = %v, %v", files, err)
	}
	matches, err := client.FindInFiles(ctx, "sb-1", "/w", "main")
	if err != nil || len(matches) != 1 || matches[0].Line != 3 {
		t.Fatalf("find = %v, %v", matches, err)
	}
	if files, err := client.SearchFiles(ctx, "sb-1", "/w", "none"); err != nil || files == nil || len(files) != 0 {
		t.Fatalf("empty search = %#v, %v", files, err)
	}
	if matches, err := client.FindInFiles(ctx, "sb-1", "/w", "none"); err != nil || matches == nil || len(matches) != 0 {
		t.Fatalf("empty find = %#v, %v", matches, err)
	}
}

func TestFileCallErrorsPassThrough(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{FeatureFileVerbs}}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		return http.StatusInsufficientStorage, errBody("sandbox disk is full: write: no space left on device", ""), nil
	}
	client, _ := fake.serve(t)
	var apiErr *APIError
	if _, err := client.ListFiles(ctx, "sb-1", "/", sdktypes.ListFilesOptions{}); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("list = %v", err)
	}
	if _, err := client.GetFileInfo(ctx, "sb-1", "/x"); err == nil {
		t.Fatal("info error swallowed")
	}
	if _, err := client.SearchFiles(ctx, "sb-1", "/", "*"); err == nil {
		t.Fatal("search error swallowed")
	}
	if _, err := client.FindInFiles(ctx, "sb-1", "/", "x"); err == nil {
		t.Fatal("find error swallowed")
	}
	if err := client.CopyFile(ctx, "sb-1", "/a", "/b", sdktypes.CopyFileOptions{}); !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message, "disk is full") {
		t.Fatalf("copy = %v", err)
	}
	bad := NewClient("http://[::1", ClientOptions{PATToken: "t"})
	if err := bad.DeleteFile(ctx, "sb-1", "/x", sdktypes.DeleteFileOptions{}); err == nil {
		t.Fatal("a bad base URL did not fail")
	}
}

func TestOctalMode(t *testing.T) {
	cases := map[os.FileMode]string{
		0o755:                 "755",
		0o700:                 "700",
		0o777 | os.ModeSticky: "1777",
		0o755 | os.ModeSetuid: "4755",
		0o750 | os.ModeSetgid: "2750",
		0o644 | os.ModeDir:    "644",
		os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0o777: "7777",
	}
	for mode, want := range cases {
		if got := octalMode(mode); got != want {
			t.Fatalf("octalMode(%v) = %s, want %s", mode, got, want)
		}
	}
}

// refuseFirstDelete fails the first DELETE with a dial error, as a refused
// connection does, before any byte of the request is sent.
type refuseFirstDelete struct {
	next    http.RoundTripper
	refused bool
}

func (r *refuseFirstDelete) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodDelete && !r.refused {
		r.refused = true
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}
	return r.next.RoundTrip(req)
}

// A refused connection sent nothing, so a coded 404 on the retry still
// means the path was never there, as in the other four SDKs.
func TestDeleteAfterARefusedConnectionStillReportsTheMissingPath(t *testing.T) {
	fake := &fakeToolbox{features: []string{FeatureFileVerbs}}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		return http.StatusNotFound, errBody("lstat: no such file or directory", codeFileNotFound), nil
	}
	client, _ := fake.serve(t)
	refuse := &refuseFirstDelete{next: client.httpClient.Transport}
	if refuse.next == nil {
		refuse.next = http.DefaultTransport
	}
	client.httpClient = &http.Client{Transport: refuse}
	if err := client.DeleteFile(context.Background(), "sb-1", "/never", sdktypes.DeleteFileOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete after a refused connection = %v, want ErrNotFound", err)
	}
	if !refuse.refused {
		t.Fatal("the first attempt was not refused")
	}
}
