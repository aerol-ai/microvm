package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// sampleSandboxForAudit mirrors the store package's fixture so Create accepts it.
func sampleSandboxForAudit(id string) *models.Sandbox {
	now := time.Now().UTC().Round(0)
	return &models.Sandbox{
		ID: id, Image: "ubuntu:22.04", Status: models.SandboxStatusStarted,
		PublicURL: "https://" + id + ".example.com", ContainerID: "container-" + id, ContainerIP: "10.0.0.10",
		CPU: 2, MemoryMB: 2048, DiskGB: 20, OSUser: "root", ToolboxEnabled: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now, Runtime: models.RuntimeGvisor,
	}
}

// Connector wiring (plans/audit-export-connectors.md): the service keeps one
// tailer; the backend behind it comes from config, and a failing backend lags
// with backoff instead of dropping or hammering.

func newConnectorService(t *testing.T, cfg config.Config) *Service {
	t.Helper()
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(t.TempDir(), "state.db")
	}
	s := &Service{cfg: cfg}
	t.Cleanup(s.CloseSecretAuditSink)
	t.Cleanup(s.stopSecretAuditExportLoop)
	return s
}

func TestConfigureAuditExporterSelectsBackendFromConfig(t *testing.T) {
	t.Run("noop installs nothing", func(t *testing.T) {
		s := newConnectorService(t, config.Config{})
		if err := s.ConfigureAuditExporter(); err != nil {
			t.Fatal(err)
		}
		if s.getAuditExporter() != nil || s.auditBackend != nil {
			t.Fatal("noop must not install an exporter")
		}
		if err := s.AuditExportHealthy(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("legacy URL alias selects webhook", func(t *testing.T) {
		s := newConnectorService(t, config.Config{SecretAuditExportURL: "http://127.0.0.1:9/export"})
		s.ConfigureHTTPAuditExporter()
		if s.getAuditExporter() == nil || s.auditBackend == nil || s.auditBackend.Name() != auditexport.BackendWebhook {
			t.Fatalf("alias did not select the webhook backend: %v", s.auditBackend)
		}
	})
	t.Run("invalid configuration fails", func(t *testing.T) {
		s := newConnectorService(t, config.Config{AuditExportBackend: auditexport.BackendS3})
		if err := s.ConfigureAuditExporter(); err == nil || !strings.Contains(err.Error(), "S3_BUCKET") {
			t.Fatalf("err = %v", err)
		}
		if s.getAuditExporter() != nil {
			t.Fatal("a failed configuration must not leave a half-installed exporter")
		}
	})
	t.Run("file backend ships records with owner_ref", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "shipped.ndjson")
		s := newConnectorService(t, config.Config{AuditExportBackend: auditexport.BackendFile, AuditExportFilePath: out, AuditExportBatchMax: 2})
		if err := s.ConfigureAuditExporter(); err != nil {
			t.Fatal(err)
		}
		sink := s.secretAuditSink()
		for i := range 5 {
			emitSecretAuditOwned(sink, "sb-ship", "env:sb-ship", "node-a", "", "inc-1", "tenant-ship", nil)
			_ = i
		}
		if err := s.secretAuditFile.Sync(); err != nil {
			t.Fatal(err)
		}
		// Batch max 2 → three batches to drain five events.
		if err := s.drainSecretAuditExport(context.Background()); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(lines) != 5 {
			t.Fatalf("shipped %d lines, want 5: %q", len(lines), raw)
		}
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.OwnerRef != "tenant-ship" || ev.EventHash == "" || ev.PrevHash == "" {
			t.Fatalf("shipped record is not self-describing/chained: %+v", ev)
		}
		if secretAuditExportLagBytes.Value() != 0 {
			t.Fatalf("lag after full drain = %d", secretAuditExportLagBytes.Value())
		}
		if err := s.AuditExportHealthy(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

type countingExporter struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (c *countingExporter) ExportEvents(_ context.Context, b controlplane.AuditEventBatch) (string, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return "", errors.New("receiver down")
	}
	return b.Offset, nil
}

func TestSecretAuditExportBacksOffAfterFailureAndResetsOnSuccess(t *testing.T) {
	s := newConnectorService(t, config.Config{AuditExportFlushInterval: time.Second, AuditExportMaxBackoff: time.Minute})
	ex := &countingExporter{}
	ex.fail.Store(true)
	s.auditExportMu.Lock()
	s.auditExporter = ex
	s.auditExportMu.Unlock()
	sink := s.secretAuditSink()
	emitSecretAudit(sink, "sb-b", "env:sb-b", "node-a", "", "", nil)
	if err := s.secretAuditFile.Sync(); err != nil {
		t.Fatal(err)
	}

	if _, err := s.exportSecretAuditBatchOnce(context.Background()); err == nil {
		t.Fatal("first attempt must surface the failure")
	}
	if ex.calls.Load() != 1 || s.auditExportBackoff.Attempts() != 1 || s.auditExportNotBefore.IsZero() {
		t.Fatalf("backoff not armed: calls=%d attempts=%d notBefore=%v", ex.calls.Load(), s.auditExportBackoff.Attempts(), s.auditExportNotBefore)
	}
	if secretAuditExportLagBytes.Value() <= 0 {
		t.Fatal("lag gauge must show unexported bytes while the receiver is down")
	}
	// Inside the backoff window the tick is skipped without touching the receiver.
	if n, err := s.exportSecretAuditBatchOnce(context.Background()); err != nil || n != 0 || ex.calls.Load() != 1 {
		t.Fatalf("tick inside backoff: n=%d err=%v calls=%d", n, err, ex.calls.Load())
	}
	// Window elapsed, receiver still down: attempt again, backoff grows.
	s.auditExportNotBefore = time.Now().Add(-time.Millisecond)
	if _, err := s.exportSecretAuditBatchOnce(context.Background()); err == nil || ex.calls.Load() != 2 || s.auditExportBackoff.Attempts() != 2 {
		t.Fatalf("second attempt: err=%v calls=%d attempts=%d", err, ex.calls.Load(), s.auditExportBackoff.Attempts())
	}
	// Receiver recovers: success clears the backoff and the lag.
	ex.fail.Store(false)
	s.auditExportNotBefore = time.Now().Add(-time.Millisecond)
	if n, err := s.exportSecretAuditBatchOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("recovery: n=%d err=%v", n, err)
	}
	if s.auditExportBackoff.Attempts() != 0 || !s.auditExportNotBefore.IsZero() || secretAuditExportLagBytes.Value() != 0 {
		t.Fatalf("backoff/lag not reset: attempts=%d notBefore=%v lag=%d", s.auditExportBackoff.Attempts(), s.auditExportNotBefore, secretAuditExportLagBytes.Value())
	}
	// Nothing new: a clean tick reports zero lag and no receiver call.
	if n, err := s.exportSecretAuditBatchOnce(context.Background()); err != nil || n != 0 || ex.calls.Load() != 3 {
		t.Fatalf("idle tick: n=%d err=%v calls=%d", n, err, ex.calls.Load())
	}
}

func TestBackendExporterAdapterReturnsSubmittedOffset(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.ndjson")
	b, err := auditexport.Open(auditexport.Config{Backend: auditexport.BackendFile, File: auditexport.FileConfig{Path: out}})
	if err != nil {
		t.Fatal(err)
	}
	ad := backendExporter{backend: b}
	next, err := ad.ExportEvents(context.Background(), controlplane.AuditEventBatch{Offset: "77", Events: []json.RawMessage{json.RawMessage(`{"a":1}`)}})
	if err != nil || next != "77" {
		t.Fatalf("adapter = %q, %v", next, err)
	}
	if next, err := (backendExporter{}).ExportEvents(context.Background(), controlplane.AuditEventBatch{Offset: "5"}); err != nil || next != "5" {
		t.Fatalf("nil backend adapter = %q, %v", next, err)
	}
}

func TestAuditEventsCarryOwnerRefFromOneLocalRead(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sb := sampleSandboxForAudit("sb-owned")
	sb.OwnerRef = "tenant-q"
	sb.AuditIncarnationID = "inc-q"
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	s := &Service{cfg: config.Config{DBPath: dbPath, EgressAttributionEnabled: true}, store: st, cluster: cluster.NewNoop("node-a", "http://a", "")}
	t.Cleanup(s.CloseSecretAuditSink)

	inc, owner := s.auditIdentityFor("sb-owned")
	if inc != "inc-q" || owner != "tenant-q" {
		t.Fatalf("identity = (%q, %q)", inc, owner)
	}
	if inc, owner := s.auditIdentityFor("absent"); inc != "" || owner != "" {
		t.Fatalf("absent identity = (%q, %q)", inc, owner)
	}
	s.emitEgressAudit("sb-owned", "tcp", "example.com:443")
	if err := s.secretAuditFile.Sync(); err != nil {
		t.Fatal(err)
	}
	events, _, err := s.ListSecretAuditLocal(context.Background(), "sb-owned", SecretAuditQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].OwnerRef != "tenant-q" || events[0].IncarnationID != "inc-q" || events[0].Kind != secretAuditKindEgress {
		t.Fatalf("events = %+v", events)
	}
}

func TestPruneSecretAuditRetentionZeroRetainsNothingBeyondCrashBuffer(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sb := sampleSandboxForAudit("sb-zero")
	sb.OwnerRef = "tenant-z"
	sb.AuditIncarnationID = "inc-z"
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(context.Background(), sb.ID); err != nil {
		t.Fatal(err)
	}
	// The post-delete ACL row exists now (written atomically with the row).
	if ok, err := st.HasSandboxAuditACL(context.Background(), "sb-zero", "inc-z"); err != nil || !ok {
		t.Fatalf("precondition: acl exists=%v err=%v", ok, err)
	}
	s := &Service{cfg: config.Config{DBPath: dbPath, SecretAuditRetentionDays: 0}, store: st}
	t.Cleanup(s.CloseSecretAuditSink)
	sink := s.secretAuditSink()
	// One old event (beyond the 1-day crash buffer) and one fresh event.
	old := SecretAuditEvent{Time: time.Now().UTC().Add(-3 * 24 * time.Hour), SandboxID: "sb-zero", Ref: "env:old", Result: secretAuditResultSuccess, Reason: secretAuditReasonOK}
	if err := s.secretAuditFile.writeEvent(old); err != nil {
		t.Fatal(err)
	}
	emitSecretAudit(sink, "sb-zero", "env:fresh", "node-a", "", "", nil)
	if err := s.secretAuditFile.Sync(); err != nil {
		t.Fatal(err)
	}
	// A row written "now" has updated_at < the prune's now, so it is swept.
	time.Sleep(5 * time.Millisecond)
	if err := s.PruneSecretAudit(context.Background()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if ok, err := st.HasSandboxAuditACL(context.Background(), "sb-zero", "inc-z"); err != nil || ok {
		t.Fatalf("retention 0 must not retain post-delete ACLs: exists=%v err=%v", ok, err)
	}
	events, _, err := s.ListSecretAuditLocal(context.Background(), "sb-zero", SecretAuditQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Ref == "env:old" {
			t.Fatal("event older than the crash buffer survived retention 0")
		}
	}
	found := false
	for _, ev := range events {
		if ev.Ref == "env:fresh" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fresh event must survive as crash buffer: %+v", events)
	}
}

func TestSinkQueueAndOverflowPolicyFromConfig(t *testing.T) {
	s := newConnectorService(t, config.Config{AuditQueueMax: 3, AuditOverflowPolicy: "spill"})
	s.ensureSecretAuditSink()
	if s.secretAuditFile == nil || cap(s.secretAuditFile.ch) != 3 || !s.secretAuditFile.spillEnabled {
		t.Fatalf("queue/overflow not applied: file=%v", s.secretAuditFile)
	}
	e := newConnectorService(t, config.Config{EnterpriseMode: true, AuditOverflowPolicy: "gap"})
	e.ensureSecretAuditSink()
	if e.secretAuditFile == nil || cap(e.secretAuditFile.ch) != enterpriseSecretAuditBuffer || e.secretAuditFile.spillEnabled {
		t.Fatal("explicit gap policy must override the enterprise spill default")
	}
}

func TestPruneClusterAuditACLGatedOnGraceNotRetention(t *testing.T) {
	// Grace disabled: nothing is ever written to Raft, so no sweep is issued.
	s := &Service{cfg: config.Config{SecretAuditRetentionDays: 30, AuditDeletedGrace: 0}, cluster: cluster.NewNoop("n", "http://n", "")}
	if err := s.pruneClusterAuditACL(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := &Service{cfg: config.Config{SecretAuditRetentionDays: 0, AuditDeletedGrace: time.Hour}, cluster: cluster.NewNoop("n", "http://n", "")}
	if err := g.pruneClusterAuditACL(context.Background()); err != nil {
		t.Fatal(err)
	}
}
