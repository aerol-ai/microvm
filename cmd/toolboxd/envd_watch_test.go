package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freshPollRegistry gives a test its own polled-watcher registry.
func freshPollRegistry(t *testing.T) *envdPollRegistry {
	t.Helper()
	old, oldTTL := envdPollWatchers, envdPollIdleTTL
	reg := &envdPollRegistry{byID: map[string]*envdPollWatcher{}}
	envdPollWatchers = reg
	t.Cleanup(func() {
		for id := range reg.byID {
			reg.remove(id)
		}
		envdPollWatchers, envdPollIdleTTL = old, oldTTL
	})
	return reg
}

func connectBody(t *testing.T, v any) io.Reader {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(encodeConnectEnvelopeForTest(raw))
}

// readEnvelope reads one Connect envelope from a live stream.
func readEnvelope(t *testing.T, r io.Reader) (byte, map[string]any) {
	t.Helper()
	header := make([]byte, connectEnvelopeHeaderLen)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatalf("read envelope header: %v", err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[1:]))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read envelope payload: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("envelope %q: %v", payload, err)
	}
	return header[0], out
}

func startEnvdWatchDir(t *testing.T, srv *httptest.Server, ctx context.Context, body any, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+envdPrefix+"/filesystem.Filesystem/WatchDir", connectBody(t, body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/connect+json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func filesystemEvent(t *testing.T, env map[string]any) map[string]any {
	t.Helper()
	ev, ok := env["filesystem"].(map[string]any)
	if !ok {
		t.Fatalf("envelope %v is not a filesystem event", env)
	}
	return ev
}

func TestEnvdWatchDirStream(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeGvisor)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()

	resp := startEnvdWatchDir(t, srv, context.Background(), map[string]any{"path": dir, "recursive": true, "includeEntry": true}, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/connect+json" {
		t.Fatalf("WatchDir = %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if flags, env := readEnvelope(t, resp.Body); flags != 0 || env["start"] == nil {
		t.Fatalf("first envelope = %d %v, want start", flags, env)
	}
	fake := h.next()
	if !fake.recursive {
		t.Fatal("recursive not passed to the watcher")
	}
	fake.batch.add(watchEvent{Type: watchEventCreate, Path: filepath.Join(dir, "a.txt")})
	fake.batch.add(watchEvent{Type: watchEventWrite, Path: filepath.Join(dir, "a.txt")})
	fake.batch.add(watchEvent{Type: watchEventChmod, Path: filepath.Join(dir, "sub", "x")})
	fake.batch.add(watchEvent{Type: watchEventRemove, Path: filepath.Join(dir, "gone")})
	h.flush()
	want := []struct{ name, typ string }{
		{"a.txt", "EVENT_TYPE_CREATE"}, {"a.txt", "EVENT_TYPE_WRITE"},
		{"sub/x", "EVENT_TYPE_CHMOD"}, {"gone", "EVENT_TYPE_REMOVE"},
	}
	for i, w := range want {
		_, env := readEnvelope(t, resp.Body)
		ev := filesystemEvent(t, env)
		if ev["name"] != w.name || ev["type"] != w.typ {
			t.Fatalf("event %d = %v, want %s %s", i, ev, w.name, w.typ)
		}
		entry, hasEntry := ev["entry"].(map[string]any)
		switch {
		case i < 2 && (!hasEntry || entry["name"] != "a.txt" || entry["type"] != envdFileTypeFile):
			t.Fatalf("event %d entry = %v, want a.txt's info", i, ev["entry"])
		case i >= 2 && hasEntry:
			t.Fatalf("event %d for a missing path has an entry: %v", i, entry)
		}
	}

	// The folder goes: its last event, then a clean end of stream.
	fake.batch.add(watchEvent{Type: watchEventRename, Path: filepath.Join(dir, "a.txt")})
	fake.end("the watched folder was removed")
	_, env := readEnvelope(t, resp.Body)
	if ev := filesystemEvent(t, env); ev["type"] != "EVENT_TYPE_RENAME" || ev["entry"] != nil {
		t.Fatalf("last event = %v", ev)
	}
	if flags, env := readEnvelope(t, resp.Body); flags != connectFlagEndStream || len(env) != 0 {
		t.Fatalf("end = %d %v, want a clean end of stream", flags, env)
	}
	h.waitIdle()
}

// E2B has no overflow event: the stream ends with resource_exhausted so the
// caller knows to watch again.
func TestEnvdWatchDirOverflowEndsWithError(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeFirecracker)
	dir := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()
	resp := startEnvdWatchDir(t, srv, context.Background(), map[string]any{"path": dir}, nil)
	readEnvelope(t, resp.Body)
	fake := h.next()
	fake.batch.add(watchEvent{Type: watchEventCreate, Path: filepath.Join(dir, "before")})
	fake.batch.addOverflow(watchOverflowKernel, "")
	fake.batch.add(watchEvent{Type: watchEventCreate, Path: filepath.Join(dir, "after")})
	h.flush()
	if _, env := readEnvelope(t, resp.Body); filesystemEvent(t, env)["name"] != "before" {
		t.Fatalf("first event = %v", env)
	}
	flags, env := readEnvelope(t, resp.Body)
	errBody, _ := env["error"].(map[string]any)
	if flags != connectFlagEndStream || errBody["code"] != "resource_exhausted" || !strings.Contains(errBody["message"].(string), "watch the folder again") {
		t.Fatalf("end = %d %v, want a resource_exhausted error", flags, env)
	}
	h.waitIdle()
	if !fake.closed.Load() {
		t.Fatal("watch not closed after the overflow")
	}
}

func TestEnvdWatchDirKeepaliveAndClientGone(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeGvisor)
	dir := t.TempDir()
	srv := httptest.NewServer(authedRoutes(newEnvdTestServer(t)))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	resp := startEnvdWatchDir(t, srv, ctx, map[string]any{"path": dir}, map[string]string{"Keepalive-Ping-Interval": "0.02"})
	readEnvelope(t, resp.Body)
	fake := h.next()
	if _, env := readEnvelope(t, resp.Body); env["keepalive"] == nil {
		t.Fatalf("envelope = %v, want a keepalive", env)
	}
	cancel()
	h.waitIdle()
	if !fake.closed.Load() {
		t.Fatal("watch not closed after the client left")
	}
}

func TestEnvdWatchDirRequestErrors(t *testing.T) {
	newWatchHarness(t, watchRuntimeGvisor)
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	h := authedRoutes(newEnvdTestServer(t))
	cases := []struct {
		name   string
		body   io.Reader
		status int
	}{
		{"not an envelope", strings.NewReader("{}"), http.StatusBadRequest},
		{"missing folder", connectBody(t, map[string]any{"path": filepath.Join(dir, "nope")}), http.StatusNotFound},
		{"a file", connectBody(t, map[string]any{"path": file}), http.StatusConflict},
		{"no path", connectBody(t, map[string]any{}), http.StatusBadRequest},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/WatchDir", tc.body))
		if rr.Code != tc.status {
			t.Errorf("%s: WatchDir = %d %s, want %d", tc.name, rr.Code, rr.Body.String(), tc.status)
		}
	}
}

func envdCall(t *testing.T, h http.Handler, rpc string, body any) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if s, ok := body.(string); ok {
		reader = strings.NewReader(s)
	} else {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/"+rpc, reader)
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestEnvdPolledWatcher(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeGvisor)
	reg := freshPollRegistry(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	routes := authedRoutes(newEnvdTestServer(t))

	status, created := envdCall(t, routes, "CreateWatcher", map[string]any{"path": dir, "include_entry": true})
	id, _ := created["watcherId"].(string)
	if status != http.StatusOK || len(id) != 32 {
		t.Fatalf("CreateWatcher = %d %v", status, created)
	}
	fake := h.next()

	// Between polls events pile up, folded the same way as a stream batch.
	fake.batch.add(watchEvent{Type: watchEventCreate, Path: filepath.Join(dir, "a.txt")})
	fake.batch.add(watchEvent{Type: watchEventWrite, Path: filepath.Join(dir, "a.txt")})
	fake.batch.add(watchEvent{Type: watchEventWrite, Path: filepath.Join(dir, "a.txt")})
	status, got := envdCall(t, routes, "GetWatcherEvents", map[string]any{"watcher_id": id})
	events, _ := got["events"].([]any)
	if status != http.StatusOK || len(events) != 2 {
		t.Fatalf("GetWatcherEvents = %d %v, want 2 events", status, got)
	}
	first := events[0].(map[string]any)
	if first["name"] != "a.txt" || first["type"] != "EVENT_TYPE_CREATE" || first["entry"] == nil {
		t.Fatalf("first event = %v", first)
	}
	// Nothing new: an empty list, never null.
	status, got = envdCall(t, routes, "GetWatcherEvents", map[string]any{"watcherId": id})
	if events, ok := got["events"].([]any); status != http.StatusOK || !ok || len(events) != 0 {
		t.Fatalf("empty poll = %d %v", status, got)
	}

	// Remove frees it; removing again is not an error (a retried remove).
	for range 2 {
		if status, _ := envdCall(t, routes, "RemoveWatcher", map[string]any{"watcherId": id}); status != http.StatusOK {
			t.Fatalf("RemoveWatcher = %d", status)
		}
	}
	if !fake.closed.Load() || reg.count() != 0 {
		t.Fatal("removed watcher not closed")
	}
	if status, _ := envdCall(t, routes, "GetWatcherEvents", map[string]any{"watcherId": id}); status != http.StatusNotFound {
		t.Fatalf("poll after remove = %d, want 404", status)
	}
	h.waitIdle()
}

func TestEnvdPolledWatcherEnds(t *testing.T) {
	h := newWatchHarness(t, watchRuntimeFirecracker)
	reg := freshPollRegistry(t)
	dir := t.TempDir()
	routes := authedRoutes(newEnvdTestServer(t))

	t.Run("overflow answers once and removes the watcher", func(t *testing.T) {
		_, created := envdCall(t, routes, "CreateWatcher", map[string]any{"path": dir})
		id := created["watcherId"].(string)
		fake := h.next()
		fake.batch.add(watchEvent{Type: watchEventCreate, Path: filepath.Join(dir, "x")})
		fake.batch.addOverflow(watchOverflowBuffer, "")
		status, body := envdCall(t, routes, "GetWatcherEvents", map[string]any{"watcherId": id})
		if status != http.StatusTooManyRequests || !strings.Contains(body["message"].(string), "events were lost") {
			t.Fatalf("poll after overflow = %d %v", status, body)
		}
		if !fake.closed.Load() || reg.count() != 0 {
			t.Fatal("overflowed watcher kept")
		}
	})

	t.Run("a removed folder gives its last events, then the watcher is gone", func(t *testing.T) {
		_, created := envdCall(t, routes, "CreateWatcher", map[string]any{"path": dir})
		id := created["watcherId"].(string)
		fake := h.next()
		fake.batch.add(watchEvent{Type: watchEventRemove, Path: dir, IsDir: true})
		fake.end("the watched folder was removed")
		status, body := envdCall(t, routes, "GetWatcherEvents", map[string]any{"watcherId": id})
		events, _ := body["events"].([]any)
		if status != http.StatusOK || len(events) != 1 || events[0].(map[string]any)["name"] != "." {
			t.Fatalf("last poll = %d %v", status, body)
		}
		if status, _ := envdCall(t, routes, "GetWatcherEvents", map[string]any{"watcherId": id}); status != http.StatusNotFound {
			t.Fatalf("poll after the end = %d, want 404", status)
		}
	})

	t.Run("a watcher nobody polls is removed", func(t *testing.T) {
		envdPollIdleTTL = 20 * time.Millisecond
		envdCall(t, routes, "CreateWatcher", map[string]any{"path": dir})
		fake := h.next()
		deadline := time.Now().Add(5 * time.Second)
		for !fake.closed.Load() || reg.count() != 0 {
			if time.Now().After(deadline) {
				t.Fatal("idle watcher never removed")
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
	h.waitIdle()
}

func TestEnvdPolledWatcherRequestErrors(t *testing.T) {
	newWatchHarness(t, watchRuntimeGvisor)
	freshPollRegistry(t)
	routes := authedRoutes(newEnvdTestServer(t))
	for _, rpc := range []string{"CreateWatcher", "GetWatcherEvents", "RemoveWatcher"} {
		if status, _ := envdCall(t, routes, rpc, "{bad"); status != http.StatusBadRequest {
			t.Errorf("%s with bad JSON = %d, want 400", rpc, status)
		}
	}
	if status, _ := envdCall(t, routes, "CreateWatcher", map[string]any{"path": "/no/such/folder"}); status != http.StatusNotFound {
		t.Errorf("CreateWatcher on a missing folder = %d, want 404", status)
	}
	if status, _ := envdCall(t, routes, "GetWatcherEvents", map[string]any{"watcherId": "nope"}); status != http.StatusNotFound {
		t.Errorf("GetWatcherEvents for an unknown id = %d, want 404", status)
	}
}

func TestEnvdWatchEventsMapping(t *testing.T) {
	root := t.TempDir()
	events, lost := envdWatchEvents(root, []watchEvent{
		{Type: watchEventCreate, Path: root + "/a"},
		{Type: watchEventWrite, Path: root + "/b/c"},
		{Type: watchEventRemove, Path: root + "/d"},
		{Type: watchEventRename, Path: root + "/e"},
		{Type: watchEventChmod, Path: root},
		{Type: watchEventOverflow, Reason: watchOverflowKernel},
		{Type: watchEventCreate, Path: root + "/after"},
	}, false)
	want := []envdFilesystemEvent{
		{Name: "a", Type: "EVENT_TYPE_CREATE"}, {Name: "b/c", Type: "EVENT_TYPE_WRITE"},
		{Name: "d", Type: "EVENT_TYPE_REMOVE"}, {Name: "e", Type: "EVENT_TYPE_RENAME"},
		{Name: ".", Type: "EVENT_TYPE_CHMOD"},
	}
	if !lost || len(events) != len(want) {
		t.Fatalf("events = %v lost = %v", events, lost)
	}
	for i := range want {
		if events[i].Name != want[i].Name || events[i].Type != want[i].Type {
			t.Fatalf("event %d = %+v, want %+v", i, events[i], want[i])
		}
	}
	// A path outside the root keeps its absolute name rather than failing.
	if events, _ := envdWatchEvents("relative-root", []watchEvent{{Type: watchEventCreate, Path: "/abs/x"}}, false); events[0].Name != "/abs/x" {
		t.Fatalf("outside path named %q", events[0].Name)
	}
}
