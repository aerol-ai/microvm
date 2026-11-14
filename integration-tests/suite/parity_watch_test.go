//go:build integration

package suite

// Live checks for file watching (plans/agent-sandbox-feature-parity.md F5,
// B3, CEO review R8): it works on gVisor and Firecracker, a Docker sandbox
// answers a clear 501, and E2B's WatchDir uses the same watcher.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// watchRecorder collects a watch's events for the checks below.
type watchRecorder struct {
	mu     sync.Mutex
	events []sdktypes.FileEvent
}

func (r *watchRecorder) add(ev sdktypes.FileEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

// waitFor waits until want appears, in order, among the events.
func (r *watchRecorder) waitFor(t *testing.T, want ...sdktypes.FileEvent) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		r.mu.Lock()
		got := append([]sdktypes.FileEvent(nil), r.events...)
		r.mu.Unlock()
		i := 0
		for _, ev := range got {
			if i < len(want) && ev == want[i] {
				i++
			}
		}
		if i == len(want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("events %+v\nnever held, in order, %+v", got, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func watchSandbox(t *testing.T, runtime string) *microvm.Sandbox {
	t.Helper()
	sb := client(t).NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Runtime: runtime})
	waitRunning(t, sb)
	return sb
}

// assertWatchSeesChanges watches a folder and checks create, write, chmod,
// rename and remove all arrive, then that Stop ends the watch cleanly.
func assertWatchSeesChanges(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := "/tmp/uc-watch"
	parityExec(t, ctx, sb, "mkdir -p "+dir)
	rec := &watchRecorder{}
	h, err := sb.WatchFiles(ctx, dir, sdktypes.WatchOptions{OnEvent: rec.add})
	if err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}
	parityExec(t, ctx, sb, "echo one > "+dir+"/a.txt && echo two >> "+dir+"/a.txt && chmod 600 "+dir+"/a.txt && mv "+dir+"/a.txt "+dir+"/b.txt && rm "+dir+"/b.txt && echo ok")
	rec.waitFor(t,
		sdktypes.FileEvent{Type: sdktypes.FileEventCreate, Path: dir + "/a.txt"},
		sdktypes.FileEvent{Type: sdktypes.FileEventWrite, Path: dir + "/a.txt"},
		sdktypes.FileEvent{Type: sdktypes.FileEventChmod, Path: dir + "/a.txt"},
		sdktypes.FileEvent{Type: sdktypes.FileEventRename, Path: dir + "/a.txt"},
		sdktypes.FileEvent{Type: sdktypes.FileEventCreate, Path: dir + "/b.txt"},
		sdktypes.FileEvent{Type: sdktypes.FileEventRemove, Path: dir + "/b.txt"},
	)
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := h.Wait(); err != nil {
		t.Fatalf("Wait after Stop = %v", err)
	}
}

// UC-390 — a watch on gVisor sees create, write, chmod, rename and remove.
func TestParityFileWatchGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-390")
	assertWatchSeesChanges(t, watchSandbox(t, "gvisor"))
}

// UC-391 — a recursive watch on gVisor sees a file in a subfolder made after
// the watch started, even when the folder and file are made in one command,
// and a file in a subfolder that existed before.
func TestParityFileWatchRecursiveGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-391")
	sb := watchSandbox(t, "gvisor")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := "/tmp/uc-watch-tree"
	parityExec(t, ctx, sb, "mkdir -p "+dir+"/old")
	rec := &watchRecorder{}
	h, err := sb.WatchFiles(ctx, dir, sdktypes.WatchOptions{Recursive: true, OnEvent: rec.add})
	if err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}
	defer h.Stop()
	parityExec(t, ctx, sb, "echo x > "+dir+"/old/f.txt && mkdir -p "+dir+"/new/deep && echo y > "+dir+"/new/deep/g.txt && echo ok")
	rec.waitFor(t,
		sdktypes.FileEvent{Type: sdktypes.FileEventCreate, Path: dir + "/old/f.txt"},
		sdktypes.FileEvent{Type: sdktypes.FileEventCreate, Path: dir + "/new", IsDir: true},
		sdktypes.FileEvent{Type: sdktypes.FileEventCreate, Path: dir + "/new/deep/g.txt"},
	)
	// Removing the watched folder ends the watch with its reason.
	parityExec(t, ctx, sb, "rm -rf "+dir+" && echo ok")
	err = h.Wait()
	if err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("Wait after the folder was removed = %v, want the agent's reason", err)
	}
}

// UC-392 — the same watch on Firecracker, whose guest runs its own kernel.
func TestParityFileWatchFirecracker(t *testing.T) {
	harness.Require(t, sc, "UC-392")
	assertWatchSeesChanges(t, watchSandbox(t, "firecracker"))
}

// UC-393 — a Docker sandbox shares the node's inotify budget, so it answers
// a clear 501 (CEO review R8), as an API error, not a hang or a 404.
func TestParityFileWatchDockerRefused(t *testing.T) {
	harness.Require(t, sc, "UC-393")
	sb := watchSandbox(t, "docker")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := sb.WatchFiles(ctx, "/tmp", sdktypes.WatchOptions{})
	var apiErr *microvm.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotImplemented ||
		!strings.Contains(apiErr.Message, "gVisor or Firecracker") {
		t.Fatalf("watch on Docker = %v, want a 501 naming gVisor and Firecracker", err)
	}
	if errors.Is(err, microvm.ErrUnsupportedFeature) {
		t.Fatal("a current agent was reported as too old")
	}
}

// e2bRuntimeCall calls envd through the live E2B facade's runtime proxy.
func e2bRuntimeCall(t *testing.T, ctx context.Context, sandboxID, token, rpc, contentType string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(sc.BaseURL, "/")+"/e2b/runtime/filesystem.Filesystem/"+rpc, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("E2b-Sandbox-Id", sandboxID)
	req.Header.Set("X-Access-Token", token)
	resp, err := harness.HTTPClient(0).Do(req)
	if err != nil {
		t.Fatalf("%s: %v", rpc, err)
	}
	return resp
}

func readConnectEnvelope(t *testing.T, r io.Reader) (byte, map[string]any) {
	t.Helper()
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatalf("read envelope: %v", err)
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

// UC-394 — E2B's WatchDir through the live E2B facade on gVisor streams
// E2B-shaped events, and the polled CreateWatcher / GetWatcherEvents /
// RemoveWatcher calls work too (plan B3).
func TestParityE2BWatchDirGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-394")
	sb := watchSandbox(t, "gvisor")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/sandboxes/"+sb.ID, nil, nil)
	var detail struct {
		EnvdAccessToken string `json:"envdAccessToken"`
	}
	fcDecode(t, body, &detail)
	if st != http.StatusOK || detail.EnvdAccessToken == "" {
		t.Fatalf("E2B sandbox detail = %d %s", st, body)
	}
	dir := "/tmp/uc-e2b-watch"
	parityExec(t, ctx, sb, "mkdir -p "+dir)

	// Streamed WatchDir: start, then a create named relative to the folder.
	payload, _ := json.Marshal(map[string]any{"path": dir, "recursive": true})
	envelope := append([]byte{0, 0, 0, 0, 0}, payload...)
	binary.BigEndian.PutUint32(envelope[1:5], uint32(len(payload)))
	streamCtx, stopStream := context.WithCancel(ctx)
	resp := e2bRuntimeCall(t, streamCtx, sb.ID, detail.EnvdAccessToken, "WatchDir", "application/connect+json", envelope)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("WatchDir = %d %s", resp.StatusCode, b)
	}
	if _, env := readConnectEnvelope(t, resp.Body); env["start"] == nil {
		t.Fatalf("first WatchDir message = %v, want start", env)
	}
	parityExec(t, ctx, sb, "mkdir -p "+dir+"/sub && echo hi > "+dir+"/sub/e2b.txt && echo ok")
	for seen := false; !seen; {
		flags, env := readConnectEnvelope(t, resp.Body)
		if flags&0x02 != 0 {
			t.Fatalf("WatchDir ended early: %v", env)
		}
		if ev, ok := env["filesystem"].(map[string]any); ok && ev["name"] == "sub/e2b.txt" && ev["type"] == "EVENT_TYPE_CREATE" {
			seen = true
		}
	}
	stopStream()

	// Polled watcher.
	createBody, _ := json.Marshal(map[string]any{"path": dir})
	resp = e2bRuntimeCall(t, ctx, sb.ID, detail.EnvdAccessToken, "CreateWatcher", "application/json", createBody)
	var created struct {
		WatcherID string `json:"watcherId"`
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(raw, &created); err != nil || resp.StatusCode != http.StatusOK || created.WatcherID == "" {
		t.Fatalf("CreateWatcher = %d %s", resp.StatusCode, raw)
	}
	parityExec(t, ctx, sb, "echo hi > "+dir+"/polled.txt && echo ok")
	idBody, _ := json.Marshal(map[string]any{"watcherId": created.WatcherID})
	deadline := time.Now().Add(30 * time.Second)
	for found := false; !found; {
		resp = e2bRuntimeCall(t, ctx, sb.ID, detail.EnvdAccessToken, "GetWatcherEvents", "application/json", idBody)
		raw, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		var got struct {
			Events []struct{ Name, Type string } `json:"events"`
		}
		if err := json.Unmarshal(raw, &got); err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GetWatcherEvents = %d %s", resp.StatusCode, raw)
		}
		for _, ev := range got.Events {
			found = found || (ev.Name == "polled.txt" && ev.Type == "EVENT_TYPE_CREATE")
		}
		if !found && time.Now().After(deadline) {
			t.Fatal("GetWatcherEvents never reported polled.txt")
		}
		time.Sleep(300 * time.Millisecond)
	}
	resp = e2bRuntimeCall(t, ctx, sb.ID, detail.EnvdAccessToken, "RemoveWatcher", "application/json", idBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("RemoveWatcher = %d", resp.StatusCode)
	}
}
