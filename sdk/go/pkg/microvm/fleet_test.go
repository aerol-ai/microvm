package microvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// fakeSandboxd keeps sandboxes by name the way the real server does (names
// unique per owner, a second create of a name is a 409). lookupBarrier holds
// the first N name lookups until all N arrive, so N concurrent callers all
// miss before any of them creates.
type fakeSandboxd struct {
	mu                  sync.Mutex
	sandboxes           map[string]models.Sandbox
	requests            []string
	nextID              int
	pageSize            int
	conflictWithoutName bool
	deleteStatus        map[string]int
	barrierLeft         int
	release             chan struct{}
}

func newFakeSandboxd(t *testing.T, lookupBarrier int) (*fakeSandboxd, *Client) {
	t.Helper()
	f := &fakeSandboxd{sandboxes: map[string]models.Sandbox{}, pageSize: 2, deleteStatus: map[string]int{}, barrierLeft: lookupBarrier, release: make(chan struct{})}
	if lookupBarrier == 0 {
		close(f.release)
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	zero := 0
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, Retry: &sdktypes.RetryConfig{MaxRetries: &zero}})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	return f, client
}

func (f *fakeSandboxd) add(name string, tags map[string]string, image string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("sb-%03d", f.nextID)
	f.sandboxes[id] = models.Sandbox{ID: id, Name: name, Image: image, Tags: tags, Status: "started"}
	return id
}

func (f *fakeSandboxd) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, method+" ") {
			n++
		}
	}
	return n
}

func (f *fakeSandboxd) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	writeJSON := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes" && r.URL.Query().Has("name"):
		f.mu.Lock()
		wait := f.barrierLeft > 0
		if wait {
			f.barrierLeft--
			if f.barrierLeft == 0 {
				close(f.release)
			}
		}
		f.mu.Unlock()
		<-f.release
		name := r.URL.Query().Get("name")
		f.mu.Lock()
		hits := []models.Sandbox{}
		for _, sb := range f.sandboxes {
			if sb.Name == name {
				hits = append(hits, sb)
			}
		}
		f.mu.Unlock()
		writeJSON(http.StatusOK, hits)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes":
		f.mu.Lock()
		var matched []models.Sandbox
		for _, sb := range f.sandboxes {
			ok := true
			for key, values := range r.URL.Query() {
				if tag, isTag := strings.CutPrefix(key, "tag."); isTag && sb.Tags[tag] != values[0] {
					ok = false
				}
			}
			if ok {
				matched = append(matched, sb)
			}
		}
		f.mu.Unlock()
		sort.Slice(matched, func(i, j int) bool { return matched[i].ID < matched[j].ID })
		start, _ := strconv.Atoi(r.URL.Query().Get("page_token"))
		end := min(start+f.pageSize, len(matched))
		if end < len(matched) {
			w.Header().Set("X-Cluster-List-Next-Page-Token", strconv.Itoa(end))
		}
		page := []models.Sandbox{}
		if start < len(matched) {
			page = matched[start:end]
		}
		writeJSON(http.StatusOK, page)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
		var req models.CreateSandboxRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.conflictWithoutName {
			writeJSON(http.StatusConflict, models.ErrorResponse{Error: "sandbox id already reserved"})
			return
		}
		for _, sb := range f.sandboxes {
			if req.Name != "" && sb.Name == req.Name {
				writeJSON(http.StatusConflict, models.ErrorResponse{Error: "sandbox name already in use"})
				return
			}
		}
		f.nextID++
		sb := models.Sandbox{ID: fmt.Sprintf("sb-%03d", f.nextID), Name: req.Name, Image: req.Image, Tags: req.Tags, Status: "started"}
		f.sandboxes[sb.ID] = sb
		writeJSON(http.StatusCreated, models.CreateSandboxResponse{Sandbox: sb})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/sandboxes/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/sandboxes/")
		f.mu.Lock()
		status, forced := f.deleteStatus[id]
		if !forced {
			status = http.StatusNotFound
			if _, ok := f.sandboxes[id]; ok {
				delete(f.sandboxes, id)
				status = http.StatusNoContent
			}
		}
		f.mu.Unlock()
		if status == http.StatusNoContent {
			w.WriteHeader(status)
			return
		}
		writeJSON(status, models.ErrorResponse{Error: fmt.Sprintf("delete failed with %d", status)})
	default:
		writeJSON(http.StatusNotFound, models.ErrorResponse{Error: "not found"})
	}
}

func TestGetOrCreate(t *testing.T) {
	ctx := context.Background()
	t.Run("creates when the name is free", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		sb, created, err := client.GetOrCreate(ctx, " agent-1 ", sdktypes.CreateSandboxOptions{Image: "alpine", Tags: map[string]string{"team": "x"}})
		if err != nil || !created || sb.Name != "agent-1" || sb.Tags["team"] != "x" || sb.client != client {
			t.Fatalf("GetOrCreate = (%+v, %v, %v)", sb, created, err)
		}
		if f.count("GET") != 1 || f.count("POST") != 1 {
			t.Fatalf("requests = %q", f.requests)
		}
	})
	t.Run("returns the existing sandbox without creating", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		id := f.add("agent-1", nil, "ubuntu")
		sb, created, err := client.GetOrCreate(ctx, "agent-1", sdktypes.CreateSandboxOptions{Image: "alpine", Name: "agent-1"})
		if err != nil || created || sb.ID != id || sb.Image != "ubuntu" || f.count("POST") != 0 {
			t.Fatalf("GetOrCreate = (%+v, %v, %v), requests %q", sb, created, err, f.requests)
		}
	})
	t.Run("concurrent callers get one sandbox", func(t *testing.T) {
		const callers = 8
		f, client := newFakeSandboxd(t, callers)
		type result struct {
			id      string
			created bool
			err     error
		}
		results := make(chan result, callers)
		for range callers {
			go func() {
				sb, created, err := client.GetOrCreate(ctx, "shared", sdktypes.CreateSandboxOptions{Image: "alpine"})
				r := result{created: created, err: err}
				if sb != nil {
					r.id = sb.ID
				}
				results <- r
			}()
		}
		ids := map[string]bool{}
		made := 0
		for range callers {
			r := <-results
			if r.err != nil {
				t.Fatalf("GetOrCreate: %v", r.err)
			}
			ids[r.id] = true
			if r.created {
				made++
			}
		}
		if len(ids) != 1 || made != 1 || len(f.sandboxes) != 1 || f.count("POST") != callers {
			t.Fatalf("ids %v, created %d, sandboxes %d, posts %d", ids, made, len(f.sandboxes), f.count("POST"))
		}
	})
	t.Run("a conflict on something else is returned", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		f.conflictWithoutName = true
		_, _, err := client.GetOrCreate(ctx, "agent-1", sdktypes.CreateSandboxOptions{Image: "alpine"})
		var apiErr *APIError
		if !errors.Is(err, ErrConflict) || !errors.As(err, &apiErr) || apiErr.Message != "sandbox id already reserved" {
			t.Fatalf("GetOrCreate error = %v", err)
		}
	})
	t.Run("bad names are refused before any request", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		for _, tc := range []struct{ name, optName string }{{"", ""}, {"  ", ""}, {"a", "b"}} {
			if _, _, err := client.GetOrCreate(ctx, tc.name, sdktypes.CreateSandboxOptions{Name: tc.optName}); err == nil {
				t.Fatalf("GetOrCreate(%q, Name %q) succeeded", tc.name, tc.optName)
			}
		}
		if len(f.requests) != 0 {
			t.Fatalf("requests = %q", f.requests)
		}
	})
	t.Run("a lookup failure is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"no"}`))
		}))
		defer server.Close()
		client, _ := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
		if _, _, err := client.GetOrCreate(ctx, "agent-1", sdktypes.CreateSandboxOptions{}); !errors.Is(err, ErrAuth) {
			t.Fatalf("GetOrCreate error = %v, want ErrAuth", err)
		}
	})
}

func TestDestroyAll(t *testing.T) {
	ctx := context.Background()
	tags := map[string]string{"run": "42", "team": "x"}
	t.Run("deletes every match across pages", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		var doomed []string
		for i := range 5 {
			doomed = append(doomed, f.add(fmt.Sprintf("a-%d", i), tags, "alpine"))
		}
		kept := []string{f.add("other", map[string]string{"run": "41", "team": "x"}, "alpine"), f.add("untagged", nil, "alpine")}
		gone, err := client.DestroyAll(ctx, tags)
		if err != nil || strings.Join(gone, ",") != strings.Join(doomed, ",") {
			t.Fatalf("DestroyAll = (%v, %v), want %v", gone, err, doomed)
		}
		if len(f.sandboxes) != len(kept) || f.count("GET") != 3 || f.count("DELETE") != 5 {
			t.Fatalf("left %v after %q", f.sandboxes, f.requests)
		}
		again, err := client.DestroyAll(ctx, tags)
		if err != nil || len(again) != 0 {
			t.Fatalf("second DestroyAll = (%v, %v), want nothing", again, err)
		}
	})
	t.Run("an already gone sandbox counts as deleted", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		first, second := f.add("a", tags, "alpine"), f.add("b", tags, "alpine")
		f.deleteStatus[first] = http.StatusNotFound
		gone, err := client.DestroyAll(ctx, tags)
		if err != nil || len(gone) != 2 || gone[0] != first || gone[1] != second {
			t.Fatalf("DestroyAll = (%v, %v)", gone, err)
		}
	})
	t.Run("a failed delete stops and reports what was deleted", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		first, second, third := f.add("a", tags, "alpine"), f.add("b", tags, "alpine"), f.add("c", tags, "alpine")
		f.deleteStatus[second] = http.StatusInternalServerError
		gone, err := client.DestroyAll(ctx, tags)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError || !strings.Contains(err.Error(), second) {
			t.Fatalf("DestroyAll error = %v", err)
		}
		if len(gone) != 1 || gone[0] != first {
			t.Fatalf("gone = %v, want [%s]", gone, first)
		}
		if _, ok := f.sandboxes[third]; !ok || f.count("DELETE") != 2 {
			t.Fatalf("third sandbox touched: %q", f.requests)
		}
	})
	t.Run("needs a tag", func(t *testing.T) {
		f, client := newFakeSandboxd(t, 0)
		if _, err := client.DestroyAll(ctx, nil); err == nil {
			t.Fatal("DestroyAll(nil) succeeded")
		}
		if len(f.requests) != 0 {
			t.Fatalf("requests = %q", f.requests)
		}
	})
	t.Run("a list failure is returned", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"no"}`))
		}))
		defer server.Close()
		client, _ := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
		if _, err := client.DestroyAll(ctx, tags); !errors.Is(err, ErrAuth) {
			t.Fatalf("DestroyAll error = %v, want ErrAuth", err)
		}
	})
}

func TestSandboxClose(t *testing.T) {
	newSandbox := func(t *testing.T) (*fakeSandboxd, *Sandbox) {
		f, client := newFakeSandboxd(t, 0)
		sb, _, err := client.GetOrCreate(context.Background(), "box", sdktypes.CreateSandboxOptions{Image: "alpine"})
		if err != nil {
			t.Fatalf("GetOrCreate: %v", err)
		}
		return f, sb
	}
	t.Run("does nothing by default", func(t *testing.T) {
		f, sb := newSandbox(t)
		if err := sb.Close(context.Background()); err != nil || f.count("DELETE") != 0 {
			t.Fatalf("Close = %v, requests %q", err, f.requests)
		}
	})
	t.Run("deletes once with DestroyOnClose, even after ctx is done", func(t *testing.T) {
		f, sb := newSandbox(t)
		sb.DestroyOnClose = true
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := sb.Close(ctx); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if f.count("DELETE") != 1 || len(f.sandboxes) != 0 {
			t.Fatalf("requests %q, left %v", f.requests, f.sandboxes)
		}
	})
	t.Run("an already gone sandbox counts as deleted", func(t *testing.T) {
		f, sb := newSandbox(t)
		sb.DestroyOnClose = true
		f.deleteStatus[sb.ID] = http.StatusNotFound
		if err := sb.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
	t.Run("a failed delete is returned and can be retried", func(t *testing.T) {
		f, sb := newSandbox(t)
		sb.DestroyOnClose = true
		f.deleteStatus[sb.ID] = http.StatusInternalServerError
		var apiErr *APIError
		if err := sb.Close(context.Background()); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("Close error = %v", err)
		}
		delete(f.deleteStatus, sb.ID)
		if err := sb.Close(context.Background()); err != nil || len(f.sandboxes) != 0 {
			t.Fatalf("retried Close = %v, left %v", err, f.sandboxes)
		}
	})
}
