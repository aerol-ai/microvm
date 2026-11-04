package daytona

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type coverage97NotReadyCluster struct {
	*cluster.Noop
	members []cluster.Member
}

func (c *coverage97NotReadyCluster) Members() []cluster.Member { return c.members }
func (c *coverage97NotReadyCluster) PlacementPage(cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	return cluster.PlacementPageResponse{}
}

func TestCoverage97PaginatedListViewNotReady(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, newDaytonaTestCipher(t), newMountsManagerForTest(t), nil)
	members := make([]cluster.Member, 257)
	for i := range members {
		members[i] = cluster.Member{NodeID: "owner", Alive: true}
	}
	svc.AttachCluster(&coverage97NotReadyCluster{
		Noop:    cluster.NewNoop("self", "http://self", ""),
		members: members,
	})

	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/paginated", nil)
	rr := httptest.NewRecorder()
	h.listSandboxesPaginated(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", rr.Header().Get("Retry-After"))
	}
}

func TestCoverage97ClosedStoreAndEnvHydration(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, newDaytonaTestCipher(t), newMountsManagerForTest(t), nil)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-env", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/sb-env?include_env=true", nil)
	req.SetPathValue("idOrName", "sb-env")
	rr := httptest.NewRecorder()
	h.getSandbox(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("include_env status = %d body = %s", rr.Code, rr.Body.String())
	}

	ids := make([]string, 501)
	for i := range ids {
		ids[i] = "sb-" + strconv.Itoa(i)
	}
	list := httptest.NewRequest(http.MethodGet, "/daytona/sandbox?ids="+strings.Join(ids, ","), nil)
	list.Header.Set("X-Cluster-Forwarded", "1")
	listRR := httptest.NewRecorder()
	h.listSandboxes(listRR, list)
	if listRR.Code != http.StatusBadRequest {
		t.Fatalf("forwarded ids status = %d body = %s", listRR.Code, listRR.Body.String())
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.resolveSandbox(context.Background(), "missing"); err == nil {
		t.Fatal("closed store resolved a sandbox")
	}
	if err := h.hydrateEnvIfRequested(req, &models.Sandbox{ID: "sb-env"}); err == nil {
		t.Fatal("closed store hydrated env")
	}
}

func TestCoverage97IncludeEnvRejectsCorruptSeal(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, st, nil, nil, nil, newDaytonaTestCipher(t), newMountsManagerForTest(t), nil)
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-seal", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(context.Background(), "sb-seal", []byte("not-a-seal")); err != nil {
		t.Fatal(err)
	}
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	req := httptest.NewRequest(http.MethodGet, "/daytona/sandbox/sb-seal?include_env=true", nil)
	req.SetPathValue("idOrName", "sb-seal")
	rr := httptest.NewRecorder()
	h.getSandbox(rr, req)
	if rr.Code < 400 {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func coverage97Exec(t *testing.T, st *store.Store, query string) {
	t.Helper()
	rv := reflect.ValueOf(st).Elem()
	field := rv.FieldByName("db")
	db := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(*sql.DB)
	if _, err := db.ExecContext(context.Background(), query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func TestCoverage97LifecycleAndCreatePersist(t *testing.T) {
	env := newDaytonaContractEnv(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &handlers{deps: Deps{Service: env.service, Logger: logger}}

	missing := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/missing/autostop/1", nil)
	missing.SetPathValue("idOrName", "missing")
	missing.SetPathValue("interval", "1")
	rr := httptest.NewRecorder()
	h.setAutoStopInterval(rr, missing)
	if rr.Code < 400 {
		t.Fatalf("missing autostop status = %d", rr.Code)
	}

	now := time.Now().UTC()
	if err := env.store.Create(context.Background(), &models.Sandbox{
		ID: "sb-life", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	huge := httptest.NewRequest(http.MethodPost, "/daytona/sandbox/sb-life/autostop/50000", nil)
	huge.SetPathValue("idOrName", "sb-life")
	huge.SetPathValue("interval", "50000")
	rr = httptest.NewRecorder()
	h.setAutoStopInterval(rr, huge)
	if rr.Code < 400 {
		t.Fatalf("huge autostop status = %d body = %s", rr.Code, rr.Body.String())
	}

	coverage97Exec(t, env.store, "DROP TABLE sandboxes")
	if _, _, err := h.resolveSandbox(context.Background(), "sb-life"); err == nil {
		t.Fatal("resolved a sandbox after its table was dropped")
	}

	env2 := newDaytonaContractEnv(t)
	h2 := &handlers{deps: Deps{Service: env2.service, Logger: logger}}
	coverage97Exec(t, env2.store, "DROP TABLE sandbox_compat_state")
	req := httptest.NewRequest(http.MethodPost, "/daytona/sandbox", strings.NewReader(`{"snapshot":"alpine:3.20"}`))
	rr = httptest.NewRecorder()
	h2.createSandbox(rr, req)
	if rr.Code < 400 {
		t.Fatalf("create status = %d body = %s", rr.Code, rr.Body.String())
	}
}
