package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func TestWave33AuditHelpersAndGuards(t *testing.T) {
	if err := writeFileAtomicDurable("", []byte("x"), 0o600); err == nil {
		t.Fatal("empty durable path")
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicDurable(filepath.Join(blocker, "tip"), []byte("x"), 0o600); err == nil {
		t.Fatal("durable write under a file parent")
	}
	okPath := filepath.Join(t.TempDir(), "cursor.json")
	if err := persistAuditExportCursor(okPath, auditExportCursor{Offset: 3, Generation: "g1", Head: "h1"}); err != nil {
		t.Fatal(err)
	}

	if _, err := newFileAuditSinkOpts(filepath.Join(blocker, "audit"), 0, true); err == nil {
		t.Fatal("mkdir under file must fail")
	}
	dir := t.TempDir()
	sink, err := newFileAuditSinkOpts(dir, 0, true)
	if err != nil || sink == nil {
		t.Fatalf("sink = %v %v", sink, err)
	}
	t.Cleanup(sink.Close)
	if err := sink.appendSpill(SecretAuditEvent{Result: "ok", SandboxID: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	if !sink.drainSpill() {
		t.Fatal("expected spill drain to find work")
	}
	if err := (*fileAuditSink)(nil).appendSpill(SecretAuditEvent{}); err == nil {
		t.Fatal("nil appendSpill")
	}
	if (*fileAuditSink)(nil).drainSpill() {
		t.Fatal("nil drainSpill")
	}

	lockAsDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(lockAsDir, secretAuditLockName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileAuditSinkOpts(lockAsDir, 1, false); err == nil {
		t.Fatal("lock-as-directory must fail")
	}
	dataAsDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataAsDir, secretAuditFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileAuditSinkOpts(dataAsDir, 1, false); err == nil {
		t.Fatal("jsonl-as-directory must fail")
	}
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, secretAuditFileName), []byte("{not-jsonl\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileAuditSinkOpts(broken, 1, false); err == nil {
		t.Fatal("tampered jsonl must fail chain verify")
	}

	if err := (*Service)(nil).ValidateSecretAuditSink(); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{SecretAuditStrictBoot: true}, secretAuditInitErr: os.ErrPermission}
	if err := svc.ValidateSecretAuditSink(); err == nil {
		t.Fatal("strict boot must surface init error")
	}
	(*Service)(nil).ConfigureHTTPAuditExporter()
	(&Service{}).ConfigureHTTPAuditExporter()
	(&Service{cfg: config.Config{SecretAuditExportURL: "http://127.0.0.1:9/export"}}).ConfigureHTTPAuditExporter()
	if (*Service)(nil).EgressAuditObserver() == nil {
		t.Fatal("nil observer")
	}
	_ = newSecretAuditCorrelationID()
	if tok, err := newAuditIngestToken(); err != nil || tok == "" {
		t.Fatalf("ingest token = %q %v", tok, err)
	}

	if blob, err := (*Service)(nil).loadSecretBlob(context.Background(), "ref"); blob != nil || err != nil {
		t.Fatalf("nil load = %v %v", blob, err)
	}
	if blob, err := (&Service{}).loadSecretBlob(context.Background(), ""); blob != nil || err != nil {
		t.Fatalf("empty ref load = %v %v", blob, err)
	}

	if wasmPathUnderDir("", "/x") || wasmPathUnderDir("/x", "") {
		t.Fatal("empty wasm path")
	}
	root := t.TempDir()
	if !wasmPathUnderDir(root, root) || !wasmPathUnderDir(root, filepath.Join(root, "mod.wasm")) {
		t.Fatal("in-dir wasm path")
	}
	if wasmPathUnderDir(root, filepath.Join(t.TempDir(), "outside.wasm")) {
		t.Fatal("outside wasm path")
	}

	if got := OwnerRefForCreate(controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "acme"},
	})); got != "acme" {
		t.Fatalf("owner = %q", got)
	}
	_ = time.Now()
}
