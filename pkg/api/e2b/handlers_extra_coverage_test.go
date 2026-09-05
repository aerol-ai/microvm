package e2b

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// createE2BSandbox drives a real create through the facade and returns its ID.
func createE2BSandbox(t *testing.T, handler http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes",
		strings.NewReader(`{"templateID":"base","timeout":120}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var created sandboxResponse
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.SandboxID == "" {
		t.Fatal("create response missing sandboxID")
	}
	return created.SandboxID
}

func TestE2BDeleteSandbox(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	// Delete an existing sandbox → 204.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/e2b/sandboxes/"+id, nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}

	// Deleting again → 404.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodDelete, "/e2b/sandboxes/"+id, nil))
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("re-delete status = %d, want 404", rr2.Code)
	}
}

func TestE2BHandlerNotFoundPaths(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"get", http.MethodGet, "/e2b/sandboxes/missing", ""},
		{"delete", http.MethodDelete, "/e2b/sandboxes/missing", ""},
		{"pause", http.MethodPost, "/e2b/sandboxes/missing/pause", ""},
		{"connect", http.MethodPost, "/e2b/sandboxes/missing/connect", `{"timeout":90}`},
		{"timeout", http.MethodPost, "/e2b/sandboxes/missing/timeout", `{"timeout":30}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("%s status = %d, want 404; body=%s", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestE2BConnectValidation(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	// Bad JSON → 400.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/connect",
		strings.NewReader(`{bad`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status = %d, want 400", rr.Code)
	}

	// timeout <= 0 → 400.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/connect",
		strings.NewReader(`{"timeout":0}`)))
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("zero timeout status = %d, want 400", rr2.Code)
	}
}

func TestE2BPauseRunningSandbox(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/pause", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("pause status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	// Pausing an already-stopped sandbox is idempotent → 204.
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/pause", nil))
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("re-pause status = %d, want 204", rr2.Code)
	}
}

func TestE2BCreateIdempotentReplay(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	body := `{"templateID":"base","timeout":120,"metadata":{"k":"v"}}`

	do := func() sandboxResponse {
		req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(body))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("create status = %d; body=%s", rr.Code, rr.Body.String())
		}
		var resp sandboxResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	first := do()
	// Identical request → replay of the same deterministic sandbox.
	second := do()
	if first.SandboxID != second.SandboxID {
		t.Fatalf("idempotent replay returned different IDs: %s vs %s", first.SandboxID, second.SandboxID)
	}
}

func TestE2BCreateMissingTemplate(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes",
		strings.NewReader(`{"timeout":120}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestE2BCreateBadJSON(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{bad`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestE2BSnapshotCreateListDelete(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	id := createE2BSandbox(t, handler)

	// Create a snapshot.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+"/snapshots",
		strings.NewReader(`{"name":"snap-cov"}`)))
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("create snapshot status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var snap snapshotInfoResponse
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snap.SnapshotID == "" {
		t.Fatalf("snapshot response missing snapshotID: %s", rr.Body.String())
	}

	// List snapshots.
	rrList := httptest.NewRecorder()
	handler.ServeHTTP(rrList, httptest.NewRequest(http.MethodGet, "/e2b/snapshots", nil))
	if rrList.Code != http.StatusOK {
		t.Fatalf("list snapshots status = %d", rrList.Code)
	}

	// Delete the snapshot by its returned ID.
	rrDel := httptest.NewRecorder()
	handler.ServeHTTP(rrDel, httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+snap.SnapshotID, nil))
	if rrDel.Code != http.StatusNoContent {
		t.Fatalf("delete snapshot status = %d; body=%s", rrDel.Code, rrDel.Body.String())
	}

	// Deleting again → 404 (resolveSnapshotDeleteTarget exhausts every lookup).
	rrDel2 := httptest.NewRecorder()
	handler.ServeHTTP(rrDel2, httptest.NewRequest(http.MethodDelete, "/e2b/templates/"+snap.SnapshotID, nil))
	if rrDel2.Code != http.StatusNotFound {
		t.Fatalf("re-delete snapshot status = %d, want 404", rrDel2.Code)
	}
}

// --- pure helpers ---

func TestTimeoutDeadlineAndEndAt(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// nil sandbox → not ok.
	if _, ok := timeoutDeadline(nil, sandboxMeta{}); ok {
		t.Fatal("nil sandbox should not yield a deadline")
	}

	// OnTimeout=pause uses StopAtAge.
	sb := &models.Sandbox{CreatedAt: base, Lifecycle: models.Lifecycle{StopAtAge: time.Hour}}
	d, ok := timeoutDeadline(sb, sandboxMeta{OnTimeout: "pause"})
	if !ok || !d.Equal(base.Add(time.Hour)) {
		t.Fatalf("pause deadline = %v ok=%v", d, ok)
	}

	// OnTimeout=kill uses DestroyAtAge.
	sb2 := &models.Sandbox{CreatedAt: base, Lifecycle: models.Lifecycle{DestroyAtAge: 2 * time.Hour}}
	d, ok = timeoutDeadline(sb2, sandboxMeta{OnTimeout: "kill"})
	if !ok || !d.Equal(base.Add(2*time.Hour)) {
		t.Fatalf("kill deadline = %v ok=%v", d, ok)
	}

	// endAt falls back to TimeoutSeconds when no lifecycle age set.
	sb3 := &models.Sandbox{CreatedAt: base}
	if got := timeoutEndAt(sb3, sandboxMeta{TimeoutSeconds: 60}); !got.Equal(base.Add(time.Minute)) {
		t.Fatalf("endAt timeoutSeconds = %v", got)
	}
	// endAt falls back to CreatedAt when nothing else applies.
	if got := timeoutEndAt(sb3, sandboxMeta{}); !got.Equal(base) {
		t.Fatalf("endAt fallback = %v", got)
	}
}

func TestParsePagination(t *testing.T) {
	mk := func(q string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?"+q, nil)
	}

	limit, offset, err := parsePagination(mk("limit=10&nextToken=5"), 100)
	if err != nil || limit != 10 || offset != 5 {
		t.Fatalf("parsePagination = %d,%d,%v", limit, offset, err)
	}
	// Defaults when absent.
	limit, offset, err = parsePagination(mk(""), 50)
	if err != nil || limit != 50 || offset != 0 {
		t.Fatalf("parsePagination defaults = %d,%d,%v", limit, offset, err)
	}
	// Invalid limit / nextToken → error.
	if _, _, err := parsePagination(mk("limit=0"), 50); err == nil {
		t.Fatal("expected error for limit=0")
	}
	if _, _, err := parsePagination(mk("nextToken=-1"), 50); err == nil {
		t.Fatal("expected error for negative nextToken")
	}
}

func TestSnapshotNameFromID(t *testing.T) {
	// Not prefixed → false.
	if _, ok := snapshotNameFromID("plainstring"); ok {
		t.Fatal("non-prefixed ID should not decode")
	}
	// Round trip a known name through the encoder used by the facade.
	id := snapshotIDFromName("my-snap")
	name, ok := snapshotNameFromID(id)
	if !ok || !strings.Contains(name, "my-snap") {
		t.Fatalf("snapshotNameFromID(%q) = %q,%v", id, name, ok)
	}
}

func TestDefaultSandboxMeta(t *testing.T) {
	meta := defaultSandboxMeta(&models.Sandbox{ID: "sb"})
	if !meta.Secure {
		t.Fatal("default meta should be secure")
	}
	if meta.OnTimeout != "kill" {
		t.Fatalf("default OnTimeout = %q, want kill", meta.OnTimeout)
	}
}

func TestForwardedListAppliesExactPlacementIDsBeforeSerialization(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	keep := createE2BSandbox(t, handler)
	createDrop := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base","timeout":121}`))
	createDropRR := httptest.NewRecorder()
	handler.ServeHTTP(createDropRR, createDrop)
	if createDropRR.Code != http.StatusCreated {
		t.Fatalf("create drop status = %d; body=%s", createDropRR.Code, createDropRR.Body.String())
	}
	var dropped sandboxResponse
	if err := json.NewDecoder(createDropRR.Body).Decode(&dropped); err != nil {
		t.Fatalf("decode drop sandbox: %v", err)
	}
	drop := dropped.SandboxID

	req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?ids="+keep, nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("forwarded list status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var items []listedSandboxResponse
	if err := json.NewDecoder(rr.Body).Decode(&items); err != nil {
		t.Fatalf("decode forwarded list: %v", err)
	}
	if len(items) != 1 || items[0].SandboxID != keep {
		t.Fatalf("forwarded list = %+v, want only %q (excluding %q)", items, keep, drop)
	}

	publicReq := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?ids="+keep, nil)
	publicRR := httptest.NewRecorder()
	handler.ServeHTTP(publicRR, publicReq)
	if publicRR.Code != http.StatusOK {
		t.Fatalf("public list status = %d; body=%s", publicRR.Code, publicRR.Body.String())
	}
	items = nil
	if err := json.NewDecoder(publicRR.Body).Decode(&items); err != nil {
		t.Fatalf("decode public list: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("public ids query unexpectedly changed API behavior: %+v", items)
	}
}
