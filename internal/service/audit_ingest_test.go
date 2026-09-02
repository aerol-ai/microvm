package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
)

func scopedAuditCapability(t *testing.T, key, sandboxID, incarnationID string) string {
	t.Helper()
	capability, err := auditlog.MintEgressCapability(key, sandboxID, incarnationID, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func TestAuditIngestRequiresScopedCapabilityAndDurableWrite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Upsert(t.Context(), &models.Sandbox{ID: "sb-bound", Image: "wasm", Status: models.SandboxStatusStarted}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{DBPath: dbPath, EnterpriseMode: true}, store: st}
	t.Cleanup(svc.CloseSecretAuditSink)
	ing := &auditIngestServer{svc: svc, token: "master-key"}
	body := []byte(`{"destination":"example.com:443","network":"tcp"}`)

	withoutCap := httptest.NewRequest(http.MethodPost, auditIngestPath, bytes.NewReader(body))
	withoutCap.RemoteAddr = "127.0.0.1:1234"
	withoutCap.Header.Set("X-Aerol-Audit-Token", "master-key")
	withoutCapRec := httptest.NewRecorder()
	ing.handleEgress(withoutCapRec, withoutCap)
	if withoutCapRec.Code != http.StatusUnauthorized {
		t.Fatalf("master-token-only status = %d, want 401", withoutCapRec.Code)
	}

	req := httptest.NewRequest(http.MethodPost, auditIngestPath, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(auditIngestHeaderCap, scopedAuditCapability(t, "master-key", "sb-bound", "inc-1"))
	rec := httptest.NewRecorder()
	ing.handleEgress(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("scoped capability status = %d body=%s", rec.Code, rec.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(dbPath), "audit", secretAuditFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"sandbox_id":"sb-bound"`)) || bytes.Contains(raw, []byte(`"sandbox_id":"forged"`)) {
		t.Fatalf("durable audit binding incorrect: %s", raw)
	}
	var event SecretAuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(raw), &event); err != nil {
		t.Fatal(err)
	}
	if event.Time.Year() == 2000 || time.Since(event.Time) > time.Minute {
		t.Fatalf("audit ingest trusted worker event_time: %s", event.Time)
	}

	forged := httptest.NewRequest(http.MethodPost, auditIngestPath, bytes.NewBufferString(`{"sandbox_id":"forged","destination":"example.com:443","kind":"gap","event_time":"2000-01-01T00:00:00Z"}`))
	forged.RemoteAddr = "127.0.0.1:1234"
	forged.Header.Set(auditIngestHeaderCap, scopedAuditCapability(t, "master-key", "sb-bound", "inc-1"))
	forgedRec := httptest.NewRecorder()
	ing.handleEgress(forgedRec, forged)
	if forgedRec.Code != http.StatusBadRequest {
		t.Fatalf("worker-controlled audit fields status = %d, want 400", forgedRec.Code)
	}
}

func TestEnterpriseAuditIngestRejectsNonDurableSink(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Upsert(t.Context(), &models.Sandbox{ID: "sb", Image: "wasm", Status: models.SandboxStatusStarted}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{EnterpriseMode: true}, store: st, secretAudit: &memSecretAuditSink{}}
	ing := &auditIngestServer{svc: svc, token: "master-key"}
	req := httptest.NewRequest(http.MethodPost, auditIngestPath, bytes.NewBufferString(`{"destination":"host:9"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(auditIngestHeaderCap, scopedAuditCapability(t, "master-key", "sb", "inc"))
	rec := httptest.NewRecorder()
	ing.handleEgress(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestAuditIngestRejectsCapabilityAfterSandboxDeletion(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{store: st, secretAudit: &memSecretAuditSink{}}
	ing := &auditIngestServer{svc: svc, token: "master-key"}
	req := httptest.NewRequest(http.MethodPost, auditIngestPath, bytes.NewBufferString(`{"destination":"host:9"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(auditIngestHeaderCap, scopedAuditCapability(t, "master-key", "deleted", "inc-old"))
	rec := httptest.NewRecorder()
	ing.handleEgress(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
