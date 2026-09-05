package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
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
	if err := st.Create(t.Context(), &models.Sandbox{ID: "sb-bound", Image: "wasm", Status: models.SandboxStatusStarted, AuditIncarnationID: "inc-1"}); err != nil {
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
	if err := st.Create(t.Context(), &models.Sandbox{ID: "sb", Image: "wasm", Status: models.SandboxStatusStarted, AuditIncarnationID: "inc"}); err != nil {
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

func TestAuditIngestRejectsCapabilityAfterStandaloneIDReuse(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.SetSecretCipher(newTestCipher(t))
	ctx := t.Context()
	old := &models.Sandbox{ID: "sb-reused", Image: "wasm", Status: models.SandboxStatusStarted, OwnerRef: "tenant-old", AuditIncarnationID: "inc-old"}
	if err := st.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	replacement := &models.Sandbox{ID: old.ID, Image: "wasm", Status: models.SandboxStatusStarted, OwnerRef: "tenant-new", AuditIncarnationID: "inc-new"}
	if err := st.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	svc := &Service{store: st}
	if err := svc.validateEgressAuditBinding(ctx, old.ID, "inc-old"); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("old capability binding error = %v, want stale", err)
	}
	if err := svc.validateEgressAuditBinding(ctx, old.ID, "inc-new"); err != nil {
		t.Fatalf("replacement capability binding error = %v", err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, old.ID, "inc-old"); err != nil || got != "tenant-old" {
		t.Fatalf("retained old ACL = %q, %v", got, err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, old.ID, "inc-new"); err != nil || got != "tenant-new" {
		t.Fatalf("replacement ACL = %q, %v", got, err)
	}
}

func TestPersistedStandaloneAuditIncarnationRotatesAndRollbackPreservesHistory(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	st.SetSecretCipher(newTestCipher(t))
	ctx := t.Context()
	svc := &Service{store: st}

	old := &models.Sandbox{ID: "sb-service-reuse", Image: "wasm", Status: models.SandboxStatusStarted, OwnerRef: "tenant-old", ToolboxToken: "toolbox-old"}
	if err := svc.persistSandboxCreate(ctx, old); err != nil {
		t.Fatalf("persist old sandbox: %v", err)
	}
	wantOld := auditlog.LocalIncarnationID(old.ID, old.ToolboxToken)
	if old.AuditIncarnationID != wantOld || svc.secretIncarnationForSeal(old.ID) != wantOld {
		t.Fatalf("old incarnation model=%q service=%q want=%q", old.AuditIncarnationID, svc.secretIncarnationForSeal(old.ID), wantOld)
	}
	if err := st.Delete(ctx, old.ID); err != nil {
		t.Fatal(err)
	}

	replacement := &models.Sandbox{ID: old.ID, Image: "wasm", Status: models.SandboxStatusStarted, OwnerRef: "tenant-new", ToolboxToken: "toolbox-new"}
	if err := svc.persistSandboxCreate(ctx, replacement); err != nil {
		t.Fatalf("persist replacement sandbox: %v", err)
	}
	wantNew := auditlog.LocalIncarnationID(replacement.ID, replacement.ToolboxToken)
	if replacement.AuditIncarnationID != wantNew || wantNew == wantOld {
		t.Fatalf("replacement incarnation=%q old=%q want=%q", replacement.AuditIncarnationID, wantOld, wantNew)
	}
	if err := svc.validateEgressAuditBinding(ctx, replacement.ID, wantOld); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("old generated capability binding error = %v, want stale", err)
	}
	if err := svc.validateEgressAuditBinding(ctx, replacement.ID, wantNew); err != nil {
		t.Fatalf("replacement generated capability binding error = %v", err)
	}

	if err := st.RollbackSandboxCreate(ctx, replacement.ID, replacement.AuditIncarnationID); err != nil {
		t.Fatalf("rollback replacement: %v", err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, old.ID, wantOld); err != nil || got != "tenant-old" {
		t.Fatalf("prior lifecycle ACL after replacement rollback = %q, %v", got, err)
	}
	if exists, err := st.HasSandboxAuditACL(ctx, old.ID, wantNew); err != nil || exists {
		t.Fatalf("replacement ACL after rollback exists=%v err=%v", exists, err)
	}
}

func TestPrepareAuditIncarnationRejectsConcurrentDifferentLifecycle(t *testing.T) {
	svc := &Service{}
	first, err := svc.prepareAuditIncarnation("sb-concurrent", "toolbox-a")
	if err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	if _, err := svc.prepareAuditIncarnation("sb-concurrent", "toolbox-b"); err == nil {
		t.Fatal("different concurrent lifecycle reused pending audit incarnation")
	}
	if same, err := svc.prepareAuditIncarnation("sb-concurrent", "toolbox-a"); err != nil || same != first {
		t.Fatalf("same lifecycle prepare = %q, %v; want %q", same, err, first)
	}
	svc.clearPendingAuditIncarnation("sb-concurrent", first)
	if got := svc.secretIncarnationForSeal("sb-concurrent"); got != "" {
		t.Fatalf("pending audit incarnation remained after clear: %q", got)
	}
}

func TestAuditIngestServerLifecycleAndScopedRequest(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Create(t.Context(), &models.Sandbox{ID: "sb-live", Image: "wasm", Status: models.SandboxStatusStarted, AuditIncarnationID: "inc-live"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sink := &memSecretAuditSink{}
	svc := &Service{
		cfg: config.Config{
			DBPath:                   dbPath,
			EgressAttributionEnabled: true,
			AuditIngestPort:          -1,
			AuditIngestToken:         "lifecycle-master-key",
		},
		store:       st,
		secretAudit: sink,
	}
	if err := svc.StartAuditIngestServer(ctx); err != nil {
		t.Fatalf("StartAuditIngestServer: %v", err)
	}
	t.Cleanup(svc.StopAuditIngestServer)

	port := os.Getenv("SB_AUDIT_INGEST_PORT")
	if n, err := strconv.Atoi(port); err != nil || n <= 0 {
		t.Fatalf("published ingest port = %q, want non-zero integer", port)
	}
	wantSpill := filepath.Join(filepath.Dir(dbPath), "audit")
	if got := os.Getenv("SB_AUDIT_SPILL_DIR"); got != wantSpill {
		t.Fatalf("published spill dir = %q, want %q", got, wantSpill)
	}
	if got := svc.auditIngestToken(); got != "lifecycle-master-key" {
		t.Fatalf("auditIngestToken = %q", got)
	}

	capability, incarnationID, err := svc.IssueEgressAuditCapabilityForSandbox("sb-live", 0)
	if err != nil {
		t.Fatalf("IssueEgressAuditCapabilityForSandbox: %v", err)
	}
	if incarnationID != "inc-live" {
		t.Fatalf("standalone incarnation = %q, want inc-live", incarnationID)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://127.0.0.1:"+port+auditIngestPath,
		strings.NewReader(`{"destination":"api.example:443","network":"tcp"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(auditIngestHeaderCap, capability)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST audit ingest: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST status = %d, want 202", resp.StatusCode)
	}
	events := sink.Events()
	if len(events) != 1 || events[0].SandboxID != "sb-live" || events[0].Destination != "api.example:443" {
		t.Fatalf("events = %+v", events)
	}

	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for os.Getenv("SB_AUDIT_INGEST_PORT") != "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := os.Getenv("SB_AUDIT_INGEST_PORT"); got != "" {
		t.Fatalf("ingest port remained published after cancellation: %q", got)
	}
	if got := os.Getenv("SB_AUDIT_SPILL_DIR"); got != "" {
		t.Fatalf("spill dir remained published after cancellation: %q", got)
	}
	// Shutdown is intentionally idempotent; daemon cleanup may race context
	// cancellation during process exit.
	svc.StopAuditIngestServer()
}

func TestAuditIngestServerDisabledGeneratedTokenAndBindFailure(t *testing.T) {
	var nilService *Service
	if err := nilService.StartAuditIngestServer(context.Background()); err != nil {
		t.Fatalf("nil StartAuditIngestServer: %v", err)
	}
	nilService.StopAuditIngestServer()

	disabled := &Service{}
	if err := disabled.StartAuditIngestServer(context.Background()); err != nil {
		t.Fatalf("disabled StartAuditIngestServer: %v", err)
	}
	disabled.StopAuditIngestServer()
	if _, err := disabled.IssueEgressAuditCapability("sb", "inc", time.Minute); err == nil {
		t.Fatal("expected unavailable-token error")
	}

	generated := &Service{cfg: config.Config{EgressAttributionEnabled: true}}
	if err := generated.StartAuditIngestServer(nil); err != nil {
		t.Fatalf("generated-token StartAuditIngestServer: %v", err)
	}
	if got := generated.auditIngestToken(); len(got) != 64 {
		t.Fatalf("generated token length = %d, want 64 hex characters", len(got))
	}
	if _, err := generated.IssueEgressAuditCapability("sb", "inc", time.Minute); err != nil {
		t.Fatalf("IssueEgressAuditCapability: %v", err)
	}
	generated.StopAuditIngestServer()
	generated.StopAuditIngestServer()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	occupied := ln.Addr().(*net.TCPAddr).Port
	blocked := &Service{cfg: config.Config{EgressAttributionEnabled: true, AuditIngestPort: occupied, AuditIngestToken: "key"}}
	if err := blocked.StartAuditIngestServer(context.Background()); err == nil || !strings.Contains(err.Error(), "audit ingest listen") {
		t.Fatalf("bind error = %v", err)
	}
}

func TestAuditIngestRejectsMalformedAndNonLoopbackRequests(t *testing.T) {
	svc := &Service{secretAudit: &memSecretAuditSink{}}
	ing := &auditIngestServer{svc: svc, token: "master-key"}

	cases := []struct {
		name       string
		remoteAddr string
		body       string
		capability string
		want       int
	}{
		{name: "non_loopback", remoteAddr: "192.0.2.10:1234", body: `{"destination":"host:9"}`, capability: "x", want: http.StatusForbidden},
		{name: "bad_json", remoteAddr: "127.0.0.1:1234", body: `{`, capability: "x", want: http.StatusBadRequest},
		{name: "trailing_json", remoteAddr: "127.0.0.1:1234", body: `{"destination":"host:9"}{}`, capability: "x", want: http.StatusBadRequest},
		{name: "bad_capability", remoteAddr: "127.0.0.1:1234", body: `{"destination":"host:9"}`, capability: "invalid", want: http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, auditIngestPath, strings.NewReader(tc.body))
			req.RemoteAddr = tc.remoteAddr
			req.Header.Set(auditIngestHeaderCap, tc.capability)
			rec := httptest.NewRecorder()
			ing.handleEgress(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}

	rec := httptest.NewRecorder()
	(*auditIngestServer)(nil).handleEgress(rec, httptest.NewRequest(http.MethodPost, auditIngestPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil server status = %d, want 503", rec.Code)
	}
}

func TestValidateEgressAuditBindingClusterAndStoreFailures(t *testing.T) {
	if err := (*Service)(nil).validateEgressAuditBinding(context.Background(), "sb", "inc"); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("nil service error = %v", err)
	}
	clustered := &Service{cfg: config.Config{EnableCluster: true}}
	if err := clustered.validateEgressAuditBinding(context.Background(), "sb", "inc"); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("missing cluster error = %v", err)
	}
	clustered.cluster = &placementOnlyCluster{
		Noop: cluster.NewNoop("self", "", ""),
		placement: cluster.Placement{
			SandboxID:     "sb",
			OwnerNodeID:   "other",
			IncarnationID: "inc",
		},
	}
	if err := clustered.validateEgressAuditBinding(context.Background(), "sb", "inc"); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("foreign-owner error = %v", err)
	}
	clustered.cluster = &placementOnlyCluster{
		Noop: cluster.NewNoop("self", "", ""),
		placement: cluster.Placement{
			SandboxID:     "sb",
			OwnerNodeID:   "self",
			IncarnationID: "inc-current",
		},
	}
	if err := clustered.validateEgressAuditBinding(context.Background(), "sb", "inc-old"); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("stale-incarnation error = %v", err)
	}
	if err := clustered.validateEgressAuditBinding(context.Background(), "sb", "inc-current"); err != nil {
		t.Fatalf("current cluster binding: %v", err)
	}

	local := &Service{}
	if err := local.validateEgressAuditBinding(context.Background(), "sb", ""); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("missing store error = %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	local.store = st
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := local.validateEgressAuditBinding(context.Background(), "sb", ""); err == nil || errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("closed-store error = %v, want storage failure", err)
	}
}
