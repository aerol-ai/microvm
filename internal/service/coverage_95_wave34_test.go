package service

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type failDurableSink struct{}

func (failDurableSink) Emit(SecretAuditEvent) {}
func (failDurableSink) EmitDurable(SecretAuditEvent) error {
	return io.ErrClosedPipe
}

type emitOnlySink struct{}

func (emitOnlySink) Emit(SecretAuditEvent) {}

func TestWave34AuditIngestRemainingBranches(t *testing.T) {
	st, err := storepkg.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Create(t.Context(), &models.Sandbox{ID: "sb-ing", Image: "wasm", Status: models.SandboxStatusStarted, AuditIncarnationID: "inc-1"}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st, cfg: config.Config{EnterpriseMode: true}, secretAudit: failDurableSink{}}
	ing := &auditIngestServer{svc: svc, token: "master-key"}

	// Non-loopback clients are rejected before JSON parsing.
	ext := httptest.NewRequest(http.MethodPost, auditIngestPath, strings.NewReader(`{}`))
	ext.RemoteAddr = "8.8.8.8:9"
	rec := httptest.NewRecorder()
	ing.handleEgress(rec, ext)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("external = %d", rec.Code)
	}

	oversized := httptest.NewRequest(http.MethodPost, auditIngestPath, strings.NewReader(strings.Repeat("x", auditIngestMaxBody+8)))
	oversized.RemoteAddr = "127.0.0.1:1"
	rec = httptest.NewRecorder()
	ing.handleEgress(rec, oversized)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized = %d", rec.Code)
	}

	emptyDest := httptest.NewRequest(http.MethodPost, auditIngestPath, strings.NewReader(`{"destination":""}`))
	emptyDest.RemoteAddr = "127.0.0.1:1"
	emptyDest.Header.Set(auditIngestHeaderCap, scopedAuditCapability(t, "master-key", "sb-ing", "inc-1"))
	rec = httptest.NewRecorder()
	ing.handleEgress(rec, emptyDest)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty dest = %d", rec.Code)
	}

	durableFail := httptest.NewRequest(http.MethodPost, auditIngestPath, strings.NewReader(`{"destination":"h:1"}`))
	durableFail.RemoteAddr = "127.0.0.1:1"
	durableFail.Header.Set(auditIngestHeaderCap, scopedAuditCapability(t, "master-key", "sb-ing", "inc-1"))
	rec = httptest.NewRecorder()
	ing.handleEgress(rec, durableFail)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("durable fail = %d", rec.Code)
	}

	ent := &Service{store: st, cfg: config.Config{EnterpriseMode: true}, secretAudit: emitOnlySink{}}
	ing.svc = ent
	noDurable := httptest.NewRequest(http.MethodPost, auditIngestPath, strings.NewReader(`{"destination":"h:1"}`))
	noDurable.RemoteAddr = "127.0.0.1:1"
	noDurable.Header.Set(auditIngestHeaderCap, scopedAuditCapability(t, "master-key", "sb-ing", "inc-1"))
	rec = httptest.NewRecorder()
	ing.handleEgress(rec, noDurable)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("enterprise no durable = %d", rec.Code)
	}

	if err := (&Service{cfg: config.Config{EnableCluster: true}}).validateEgressAuditBinding(t.Context(), "sb", "inc"); err == nil {
		t.Fatal("cluster without client must fail")
	}
	if err := (&Service{cfg: config.Config{EnableCluster: true}, cluster: cluster.NewNoop("self", "", "")}).validateEgressAuditBinding(t.Context(), "sb", "inc"); err == nil {
		t.Fatal("missing placement must fail")
	}

	logged := &Service{cfg: config.Config{EgressAttributionEnabled: true, AuditIngestPort: 0}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := logged.StartAuditIngestServer(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logged.StopAuditIngestServer)
}
