package e2b

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage97ListRejectsTooManyForwardedIDs(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = "sb-" + strconv.Itoa(i)
	}
	req := httptest.NewRequest(http.MethodGet, "/e2b/sandboxes?ids="+strings.Join(ids, ","), nil)
	req.Header.Set("X-Cluster-Forwarded", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCoverage97DeleteMissingSnapshot(t *testing.T) {
	_, _, handler := newE2BHandlerTestEnv(t)
	req := httptest.NewRequest(http.MethodDelete, "/e2b/templates/missing-snap", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCoverage97CreateClaimOnClosedStore(t *testing.T) {
	_, st, handler := newE2BHandlerTestEnv(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code < 400 {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCoverage97CreateClaimAndTemplateLookup(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc, Logger: slog.Default()})
	execStoreSQL(t, st, "DROP TABLE sandbox_snapshots")
	if _, _, err := h.resolveTemplate(context.Background(), snapshotIDFromName("missing-snap")); err == nil {
		t.Fatal("missing snapshot table resolved an encoded template id")
	}
	if _, _, err := h.resolveTemplate(context.Background(), "not-in-map"); err == nil {
		t.Fatal("missing snapshot table resolved a bare template id")
	}

	svc2, st2, _ := newE2BHandlerTestEnv(t)
	h2 := newHandlers(Deps{Service: svc2, Logger: slog.Default()})
	execStoreSQL(t, st2, "DROP TABLE request_idempotency")
	req := httptest.NewRequest(http.MethodPost, "/e2b/sandboxes", strings.NewReader(`{"templateID":"base"}`))
	rr := httptest.NewRecorder()
	h2.createSandbox(rr, req)
	if rr.Code < 400 {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestCoverage97ReplayAndDeleteLookups(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	h := newHandlers(Deps{Service: svc, Logger: slog.Default()})
	execStoreSQL(t, st, "DROP TABLE request_idempotency")
	if _, _, _, err := h.loadReplayableCreateResult(context.Background(), &models.IdempotentRequestRecord{
		Scope: "e2b-create", Fingerprint: "fp", TargetID: "missing-sandbox",
	}); err == nil {
		t.Fatal("replay cleanup ignored a missing idempotency table")
	}
	execStoreSQL(t, st, "DROP TABLE sandbox_snapshots")
	if _, _, err := h.resolveSnapshotDeleteTarget(context.Background(), "not-an-encoded-id"); err == nil {
		t.Fatal("delete target resolved without a snapshot table")
	}
}
