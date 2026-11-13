package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/kubeapi"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// seenCall is what the API handler received from the backend.
type seenCall struct {
	method, path, key, surface string
	access                     controlplane.Access
	body                       models.CreateSandboxRequest
}

func recordingHandler(status int, reply any) (http.Handler, *[]seenCall) {
	var mu sync.Mutex
	var calls []seenCall
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, _, _ := remotemcp.Handoff(r.Context())
		c := seenCall{method: r.Method, path: r.URL.Path, key: r.Header.Get(clustercreate.HeaderIdempotencyKey),
			surface: auditlog.SurfaceFromContext(r.Context()), access: access}
		_ = json.NewDecoder(r.Body).Decode(&c.body)
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}), &calls
}

func kubeCtx() context.Context {
	return kubeapi.ContextWithUser(context.Background(), kubeapi.User{Name: "alice"})
}

func TestKubeBackendCallsTheAPIAsTheKubernetesUser(t *testing.T) {
	h, calls := recordingHandler(http.StatusCreated, models.Sandbox{ID: "sb-1"})
	b := &KubeBackend{handler: h, specs: func() cluster.SpecSummaryReader { return nil }, now: time.Now}
	ctx := kubeCtx()
	id, err := b.Create(ctx, "team:a", models.CreateSandboxRequest{Name: "web", Image: "alpine"}, "kubeapi/a/web")
	if err != nil || id != "sb-1" {
		t.Fatalf("Create = %q %v", id, err)
	}
	if err := b.SetRunning(ctx, "team:a", "sb-1", false); err != nil {
		t.Fatal(err)
	}
	if err := b.SetRunning(ctx, "team:a", "sb-1", true); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, "team:a", "sb-1"); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /v1/sandboxes", "POST /v1/sandboxes/sb-1/stop", "POST /v1/sandboxes/sb-1/start", "DELETE /v1/sandboxes/sb-1"}
	if len(*calls) != len(want) {
		t.Fatalf("calls = %+v", *calls)
	}
	for i, c := range *calls {
		if c.method+" "+c.path != want[i] {
			t.Fatalf("call %d = %s %s, want %s", i, c.method, c.path, want[i])
		}
		a := c.access
		if a.Identity.OwnerRef != "team:a" || a.Role != controlplane.RoleRunner || a.Fleet ||
			a.Principal.Kind != controlplane.PrincipalKubernetes || a.Principal.ID != "kubernetes:alice" || c.surface != auditlog.SurfaceKubernetes {
			t.Fatalf("call %d as %+v on %q", i, a, c.surface)
		}
	}
	first := (*calls)[0]
	if first.key != "kubeapi/a/web" || first.body.Name != "web" || first.body.Image != "alpine" {
		t.Fatalf("create = %+v", first)
	}
}

func TestKubeBackendErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		reply  any
		reason string
		msg    string
	}{
		{http.StatusConflict, models.ErrorResponse{Error: "name taken"}, "Conflict", "name taken"},
		{http.StatusForbidden, models.ErrorResponse{Error: "policy"}, "Forbidden", "policy"},
		{http.StatusNotFound, models.ErrorResponse{Error: "sandbox not found"}, "NotFound", "sandbox not found"},
		{http.StatusTooManyRequests, models.ErrorResponse{Error: "quota"}, "TooManyRequests", "quota"},
		{http.StatusServiceUnavailable, "plain", "ServiceUnavailable", `"plain"`},
		{http.StatusBadRequest, models.ErrorResponse{Error: "bad"}, "BadRequest", "bad"},
		{http.StatusUnprocessableEntity, models.ErrorResponse{Error: "bad"}, "Invalid", "bad"},
		{http.StatusGatewayTimeout, models.ErrorResponse{Error: "slow"}, "Timeout", "slow"},
		{http.StatusInternalServerError, models.ErrorResponse{Error: "boom"}, "InternalError", "boom"},
	} {
		h, _ := recordingHandler(tc.status, tc.reply)
		b := &KubeBackend{handler: h, specs: func() cluster.SpecSummaryReader { return nil }, now: time.Now}
		err := b.Delete(kubeCtx(), "team:a", "sb-1")
		var se *kubeapi.StatusError
		if !errors.As(err, &se) || se.Code != tc.status || se.Reason != tc.reason || se.Message != tc.msg {
			t.Errorf("%d = %#v", tc.status, err)
		}
	}
	h, _ := recordingHandler(http.StatusCreated, models.Sandbox{})
	b := &KubeBackend{handler: h, now: time.Now}
	if _, err := b.Create(kubeCtx(), "team:a", models.CreateSandboxRequest{}, "k"); err == nil {
		t.Fatal("a create without an id")
	}
}

// Through the real API: the owner scoping applies, so a namespace cannot
// touch another team's sandbox.
func TestKubeBackendThroughTheRealAPI(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "kube.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{ID: "sb-00000000000000aa", Name: "web", Image: "alpine", Status: models.SandboxStatusStarted,
		OwnerRef: "team:a", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, nil, nil, nil)
	b := NewServer(logger, svc, nil, nil, config.Config{}, "pat-token", nil).KubeBackend()
	err = b.Delete(kubeCtx(), "team:b", "sb-00000000000000aa")
	var se *kubeapi.StatusError
	if !errors.As(err, &se) || se.Code != http.StatusNotFound {
		t.Fatalf("another team's delete = %#v", err)
	}
	if got := b.Specs(kubeCtx(), []kubeapi.SpecRef{{ID: "sb-00000000000000aa"}}); len(got) != 0 {
		t.Fatalf("specs on a single node = %v", got)
	}
}

type fakeSpecReader struct {
	calls int
	err   error
}

func (f *fakeSpecReader) SpecSummaries(_ context.Context, ids []string) (map[string]cluster.SpecSummary, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]cluster.SpecSummary{}
	for _, id := range ids {
		out[id] = cluster.SpecSummary{Image: "img-" + id, CPU: 1, MemoryMB: 256}
	}
	return out, nil
}

func TestKubeBackendSpecs(t *testing.T) {
	r := &fakeSpecReader{}
	clock := time.Unix(1000, 0)
	b := &KubeBackend{specs: func() cluster.SpecSummaryReader { return r }, now: func() time.Time { return clock }}
	ids := make([]kubeapi.SpecRef, cluster.MaxSpecSummaryBatch+1)
	for i := range ids {
		id := "sb-" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676))
		ids[i] = kubeapi.SpecRef{ID: id, Incarnation: "inc-1"}
	}
	got := b.Specs(context.Background(), ids)
	if len(got) != len(ids) || r.calls != 2 || got[ids[0].ID].Image != "img-"+ids[0].ID {
		t.Fatalf("%d summaries in %d calls", len(got), r.calls)
	}
	// Cached for a minute.
	b.Specs(context.Background(), ids[:3])
	if r.calls != 2 {
		t.Fatalf("not cached: %d calls", r.calls)
	}
	// The same ID made again (a keyed create after a delete) is another
	// sandbox: read again, not shown with the deleted one's spec.
	if b.Specs(context.Background(), []kubeapi.SpecRef{{ID: ids[0].ID, Incarnation: "inc-2"}}); r.calls != 3 {
		t.Fatalf("a new incarnation answered from the cache: %d calls", r.calls)
	}
	if b.Specs(context.Background(), []kubeapi.SpecRef{{ID: ids[0].ID, Incarnation: "inc-2"}}); r.calls != 3 {
		t.Fatalf("the new incarnation is not cached: %d calls", r.calls)
	}
	clock = clock.Add(2 * time.Minute)
	r.err = errors.New("servers away")
	if got := b.Specs(context.Background(), ids[:3]); len(got) != 0 || r.calls != 4 {
		t.Fatalf("a failed read = %v, %d calls", got, r.calls)
	}
	none := &KubeBackend{specs: func() cluster.SpecSummaryReader { return nil }, now: time.Now}
	if got := none.Specs(context.Background(), []kubeapi.SpecRef{{ID: "sb-a"}}); len(got) != 0 {
		t.Fatalf("no reader = %v", got)
	}
}
