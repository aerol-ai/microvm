package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestConfigureSecretProviderRemainingOffline(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).ConfigureSecretProvider(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (&Service{}).ConfigureSecretProvider(ctx); err != nil {
		t.Fatal(err)
	}

	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	svc := &Service{store: st, cipher: cipher, cfg: config.Config{SecretProvider: "local"}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := svc.ConfigureSecretProvider(ctx); err != nil {
		t.Fatalf("local provider: %v", err)
	}
	svc.cfg.SecretProvider = "vault"
	if err := svc.ConfigureSecretProvider(ctx); err == nil {
		t.Fatal("vault provider was accepted")
	}
	svc.cfg.SecretProvider = "not-a-provider"
	if err := svc.ConfigureSecretProvider(ctx); err == nil {
		t.Fatal("unknown provider was accepted")
	}
}

func TestUpsertClusterSecretBlobWave32Fences(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	st := openSealTestStore(t)
	svc := &Service{
		store: st, cipher: cipher,
		cfg:     config.Config{EnableCluster: true},
		cluster: cluster.NewNoop("node-b", "http://b", ""),
	}

	denied := wave30BoundBlob(t, cipher, "sb-denied32", "inc-a", []string{"node-a"}, 1)
	if err := svc.UpsertClusterSecretBlob(ctx, denied, "node-a"); err == nil || !errors.Is(err, secrets.ErrRecipientDenied) {
		t.Fatalf("recipient denied = %v", err)
	}

	zeroGen := wave30BoundBlob(t, cipher, "sb-zerogen32", "inc-a", []string{"node-a", "node-b"}, 1)
	zeroGen.SealGeneration = 0
	if err := svc.UpsertClusterSecretBlob(ctx, zeroGen, "node-a"); err == nil || !strings.Contains(err.Error(), "seal_generation") {
		t.Fatalf("zero seal generation = %v", err)
	}

	refSwap := wave30BoundBlob(t, cipher, "sb-ref32", "inc-a", []string{"node-a", "node-b"}, 1)
	// ParseRef only accepts v1; a different incarnation keeps the ref parseable
	// while disagreeing with the authenticated envelope binding.
	refSwap.Ref = secrets.FormatRef("sb-ref32", "inc-other", secrets.RefVersion)
	refSwap.IncarnationID = "inc-other"
	if err := svc.UpsertClusterSecretBlob(ctx, refSwap, "node-a"); err == nil || !strings.Contains(err.Error(), "envelope ref") {
		t.Fatalf("envelope ref mismatch = %v", err)
	}

	blob := wave30BoundBlob(t, cipher, "sb-peer32", "inc-cur", []string{"node-a", "node-b"}, 1)
	cl := &wave30AuthCluster{Noop: cluster.NewNoop("node-b", "http://b", "")}
	svc.cluster = cl

	cl.placements = map[string]cluster.Placement{
		"sb-peer32": {SandboxID: "sb-peer32", IncarnationID: "inc-cur", SecretRecipients: []string{"node-a", "node-b"}},
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "no live placement") {
		t.Fatalf("orphaned = %v", err)
	}

	cl.placements["sb-peer32"] = cluster.Placement{
		SandboxID: "sb-peer32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-wrong"); err == nil || !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("originator denied = %v", err)
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, ""); err == nil || !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("blank originator = %v", err)
	}

	cl.placements["sb-peer32"] = cluster.Placement{
		SandboxID: "sb-peer32", OwnerNodeID: "node-a", IncarnationID: "inc-other",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err == nil || !strings.Contains(err.Error(), "incarnation_id") {
		t.Fatalf("placement incarnation = %v", err)
	}

	cl.placements["sb-peer32"] = cluster.Placement{
		SandboxID: "sb-peer32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		State: cluster.PlacementStateReserved, SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 0,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, blob, "node-a"); err != nil {
		t.Fatalf("reserved initial put: %v", err)
	}

	stagedFail := wave30BoundBlob(t, cipher, "sb-stage32", "inc-cur", []string{"node-a", "node-b"}, 3)
	cl.placements["sb-stage32"] = cluster.Placement{
		SandboxID: "sb-stage32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a"}, SecretSealGeneration: 1,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, stagedFail, "node-a"); err == nil || !strings.Contains(err.Error(), "next placement generation") {
		t.Fatalf("staged reseal skip = %v", err)
	}

	stagedOK := wave30BoundBlob(t, cipher, "sb-stage32", "inc-cur", []string{"node-a", "node-b"}, 2)
	if err := svc.UpsertClusterSecretBlob(ctx, stagedOK, "node-a"); err != nil {
		t.Fatalf("staged reseal: %v", err)
	}

	if err := st.ApplyPeerSecretDelete(ctx, "sb-tomb32", "inc-cur", 1); err != nil {
		t.Fatal(err)
	}
	newer := wave30BoundBlob(t, cipher, "sb-tomb32", "inc-cur", []string{"node-a", "node-b"}, 3)
	cl.placements["sb-tomb32"] = cluster.Placement{
		SandboxID: "sb-tomb32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 3,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, newer, "node-a"); err != nil {
		t.Fatalf("newer-than-tomb put: %v", err)
	}

	putSecretRow(t, st, "sb-stale32", "inc-cur", 5, []string{"node-a", "node-b"})
	stale := wave30BoundBlob(t, cipher, "sb-stale32", "inc-cur", []string{"node-a", "node-b"}, 3)
	cl.placements["sb-stale32"] = cluster.Placement{
		SandboxID: "sb-stale32", OwnerNodeID: "node-a", IncarnationID: "inc-cur",
		SecretRecipients: []string{"node-a", "node-b"}, SecretSealGeneration: 3,
	}
	if err := svc.UpsertClusterSecretBlob(ctx, stale, "node-a"); err == nil || !strings.Contains(err.Error(), "stale seal_generation") {
		t.Fatalf("local max-gen fence = %v", err)
	}

	closed := openSealTestStore(t)
	closedSvc := &Service{store: closed, cluster: cluster.NewNoop("node-b", "http://b", "")}
	valid := wave30BoundBlob(t, cipher, "sb-closed32", "inc-a", []string{"node-a", "node-b"}, 1)
	_ = closed.Close()
	if err := closedSvc.UpsertClusterSecretBlob(ctx, valid, "node-a"); err == nil {
		t.Fatal("closed-store tomb lookup succeeded")
	}
}

func TestWriteEventBatchAndPruneLockedIOWave32(t *testing.T) {
	genesis, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(genesis.Close)
	genesis.writeHook = func() {}
	genesis.chainMu.Lock()
	genesis.chainHead = ""
	genesis.chainMu.Unlock()
	if err := genesis.writeEventBatch([]SecretAuditEvent{{EventID: "genesis32", Result: secretAuditResultSuccess}}, false, false); err != nil {
		t.Fatalf("genesis non-durable: %v", err)
	}

	ro, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ro.Close)
	readonly, err := os.Open(ro.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = readonly.Close() })
	_ = ro.file.Close()
	ro.file = readonly
	// A read-only descriptor makes append fail and Truncate fail, which is the
	// only portable way to poison the writer without filling the disk.
	if err := ro.writeEventBatch([]SecretAuditEvent{{EventID: "ro32", Result: secretAuditResultSuccess}}, true, true); err == nil {
		t.Fatal("read-only append succeeded")
	}

	denied, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(denied.Close)
	if err := os.Chmod(denied.path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied.path, 0o600) })
	if err := denied.pruneLocked(time.Now().UTC(), "", ""); err == nil {
		t.Fatal("chmod-000 prune succeeded")
	}

	tmpDir, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tmpDir.Close)
	now := time.Now().UTC()
	if err := tmpDir.EmitDurable(SecretAuditEvent{Time: now.Add(-3 * time.Hour), EventID: "drop-tmp32", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := tmpDir.EmitDurable(SecretAuditEvent{Time: now, EventID: "keep-tmp32", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tmpDir.path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir.path + ".tmp") })
	if err := tmpDir.pruneLocked(now.Add(-time.Hour), "", ""); err == nil {
		t.Fatal("tmp-as-directory prune succeeded")
	}

	empty, err := newFileAuditSink(t.TempDir(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(empty.Close)
	if err := empty.pruneLocked(now, "", ""); err != nil {
		t.Fatalf("nothing-to-drop prune: %v", err)
	}

	spill, err := newFileAuditSinkOpts(t.TempDir(), 4, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spill.Close)
	// Point spill at a file the writer loop is not draining so chmod cannot
	// race a rename/remove of secrets.spill.jsonl.
	manualSpill := filepath.Join(t.TempDir(), "manual.spill")
	if err := os.WriteFile(manualSpill, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manualSpill, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(manualSpill, 0o600) })
	spill.spillPath = manualSpill
	if err := spill.appendSpill(SecretAuditEvent{EventID: "spill-chmod32"}); err == nil {
		t.Fatal("chmod-000 spill succeeded")
	}

	block := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistAuditExportCursor(filepath.Join(block, "cursor.json"), auditExportCursor{Generation: "g", Offset: 1, Head: "h"}); err == nil {
		t.Fatal("export cursor under a file succeeded")
	}
}

func TestSecretAuditQueryFiltersWave32(t *testing.T) {
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	if _, _, err := svc.ListSecretAuditLocal(nil, "sb-empty-path", SecretAuditQuery{}); err != nil {
		t.Fatalf("nil ctx local list: %v", err)
	}

	sink := svc.secretAuditSink().(*fileAuditSink)
	now := time.Now().UTC()
	for i, ev := range []SecretAuditEvent{
		{Time: now.Add(-2 * time.Second), EventID: "open-a", SandboxID: "sb-q32", IncarnationID: "inc-a", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess},
		{Time: now.Add(-time.Second), EventID: "open-b", SandboxID: "sb-q32", IncarnationID: "inc-b", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess},
		{Time: now, EventID: "egress-a", SandboxID: "sb-q32", IncarnationID: "inc-a", Kind: secretAuditKindEgress, Result: secretAuditResultSuccess},
		{Time: now.Add(time.Second), EventID: "gap-any", Kind: secretAuditKindGap, Result: secretAuditResultGap},
	} {
		ev.EventID += ""
		if err := sink.EmitDurable(ev); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if _, err := os.OpenFile(sink.path, os.O_APPEND|os.O_WRONLY, 0); err == nil {
		// Blank lines must be skipped so a trailing newline cannot fail integrity.
	}
	if err := os.WriteFile(sink.path, append(wave32ReadFile(t, sink.path), '\n', '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	incA, next, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{
		IncarnationID: "inc-a", Kind: secretAuditKindSecretOpen, Limit: 1,
	})
	if err != nil || len(incA) != 1 || incA[0].EventID != "open-a" || next == "" {
		t.Fatalf("incarnation+kind page = %+v next=%q err=%v", incA, next, err)
	}
	page2, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{
		IncarnationID: "inc-a", Cursor: next, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range page2 {
		if ev.EventID == "open-a" {
			t.Fatal("cursor replayed the first event")
		}
	}
	if _, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{Cursor: now.Format(time.RFC3339Nano)}); err == nil {
		t.Fatal("keyless cursor was accepted")
	}

	gaps, _, err := svc.ListSecretAuditLocal(context.Background(), "other-sandbox", SecretAuditQuery{Kind: secretAuditKindEgress})
	if err != nil || len(gaps) == 0 {
		t.Fatalf("gap events must survive kind/sandbox filters: %+v err=%v", gaps, err)
	}

	if _, _, err := (&Service{}).ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err != nil {
		t.Fatalf("fileless local list: %v", err)
	}
	_ = os.Remove(sink.path)
	if events, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{}); err != nil || len(events) != 0 {
		t.Fatalf("missing file = %+v err=%v", events, err)
	}

	trunc := &Service{
		cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")},
		cluster: &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
			},
			placement: cluster.Placement{SandboxID: "sb-trunc32", AuditNodesTruncated: true},
		},
	}
	t.Cleanup(trunc.CloseSecretAuditSink)
	if _, err := trunc.ListSecretAudit(context.Background(), "sb-trunc32", SecretAuditQuery{}); !errors.Is(err, ErrSecretAuditIndexIncomplete) {
		t.Fatalf("truncated index = %v", err)
	}

	acl := &Service{
		cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")},
		cluster: &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
			},
			acl:       cluster.AuditACL{IncarnationID: "inc-acl", AuditNodeIDs: []string{"self", "peer"}},
			aclExists: true,
		},
	}
	t.Cleanup(acl.CloseSecretAuditSink)
	page, err := acl.ListSecretAudit(context.Background(), "sb-acl32", SecretAuditQuery{IncarnationID: "inc-acl", Limit: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Coverage.Partial {
		t.Fatalf("ACL fan-out without fetcher = %+v", page.Coverage)
	}

	bad := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(bad.CloseSecretAuditSink)
	_ = bad.secretAuditSink()
	// A page read parses only records that can belong to it; a malformed
	// record claiming the queried sandbox must still fail the read.
	if err := os.WriteFile(bad.secretAuditFile.path, []byte(`{"sandbox_id":"sb",not-json`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bad.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err == nil {
		t.Fatal("malformed local evidence was accepted")
	}
	if err := os.Chmod(bad.secretAuditFile.path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad.secretAuditFile.path, 0o600) })
	if _, _, err := bad.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err == nil {
		t.Fatal("unreadable audit snapshot succeeded")
	}
}

func TestPruneAndExportAuditWave32(t *testing.T) {
	if err := (&Service{cfg: config.Config{SecretAuditRetentionDays: 0}}).PruneSecretAudit(nil); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"), SecretAuditRetentionDays: 30,
		EnterpriseMode: true, SecretAuditExternalWitness: true,
	}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if err := svc.PruneSecretAudit(context.Background()); err == nil {
		t.Fatal("witness-required prune succeeded")
	}
	svc.SetWitness(&stubWitness{})
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{Time: time.Now().UTC().Add(-48 * time.Hour), EventID: "old32", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	// An export cursor that does not cover the file must retain evidence rather
	// than rotate a head the exporter has not yet shipped.
	cursorPath := filepath.Join(filepath.Dir(svc.secretAuditFile.path), secretAuditExportOffset)
	if err := persistAuditExportCursor(cursorPath, auditExportCursor{Generation: "other", Offset: 0, Head: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.PruneSecretAudit(context.Background()); err != nil {
		t.Fatalf("export-guard prune: %v", err)
	}

	ok, err := svc.secretAuditFullyExported()
	if err != nil || ok {
		t.Fatalf("unexported head = %v %v", ok, err)
	}
	if ok, err := (*Service)(nil).secretAuditFullyExported(); err != nil || !ok {
		t.Fatalf("nil fully-exported = %v %v", ok, err)
	}
	_ = os.Remove(svc.secretAuditFile.path)
	if ok, err := svc.secretAuditFullyExported(); err != nil || !ok {
		t.Fatalf("missing file fully-exported = %v %v", ok, err)
	}

	st := openSealTestStore(t)
	acl := &Service{store: st, cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), SecretAuditRetentionDays: 1}}
	t.Cleanup(acl.CloseSecretAuditSink)
	if err := acl.PruneSecretAudit(context.Background()); err != nil {
		t.Fatalf("ACL prune: %v", err)
	}
	_ = st.Close()
	if err := acl.PruneSecretAudit(context.Background()); err == nil {
		t.Fatal("closed-store ACL prune succeeded")
	}
}

func TestLoadMountsSnapshotsAndEnvWave32(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := testEnvService(t)
	if specs, err := svc.loadMounts(ctx, "missing-mnt"); specs != nil || err != nil {
		t.Fatalf("missing mounts = %v %v", specs, err)
	}
	seedEnvSandbox(t, st, "sb-mnt32", nil)
	if err := st.PutMounts(ctx, "sb-mnt32", []byte{}); err != nil {
		t.Fatal(err)
	}
	if specs, err := svc.loadMounts(ctx, "sb-mnt32"); specs != nil || err != nil {
		t.Fatalf("empty mounts = %v %v", specs, err)
	}
	if err := st.PutMounts(ctx, "sb-mnt32", []byte("not-an-envelope")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.loadMounts(ctx, "sb-mnt32"); err == nil || !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("garbage mounts = %v", err)
	}
	plainBad, err := svc.cipher.Encrypt([]byte("{not-json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutMounts(ctx, "sb-mnt32", plainBad); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.loadMounts(ctx, "sb-mnt32"); err == nil || !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("bad mount json = %v", err)
	}
	sealed, err := svc.sealMounts([]models.MountSpec{{Type: models.MountTypeNFS, Source: "h:/e", Target: "/d"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutMounts(ctx, "sb-mnt32", sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListMounts(ctx, "missing"); err == nil {
		t.Fatal("list mounts on missing sandbox")
	}
	redacted, err := svc.ListMounts(ctx, "sb-mnt32")
	if err != nil || len(redacted) != 1 {
		t.Fatalf("list mounts = %+v err=%v", redacted, err)
	}
	svc.cipher = nil
	if _, err := svc.loadMounts(ctx, "sb-mnt32"); err == nil {
		t.Fatal("load mounts without cipher")
	}

	closed, err := storepkg.Open(filepath.Join(t.TempDir(), "mnt32.db"))
	if err != nil {
		t.Fatal(err)
	}
	closedSvc := &Service{store: closed, cipher: newTestCipher(t)}
	_ = closed.Close()
	if _, err := closedSvc.loadMounts(ctx, "sb"); err == nil {
		t.Fatal("closed-store loadMounts succeeded")
	}

	if _, err := (&Service{store: st}).RegisterSnapshot(ctx, nil); err == nil {
		t.Fatal("nil snapshot")
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Image: "alpine"}); err == nil {
		t.Fatal("nameless snapshot")
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "snap32"}); err == nil {
		t.Fatal("imageless snapshot")
	}
	got, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "snap32", Image: "alpine:local", SourceSandboxID: "sb-mnt32"})
	if err != nil || got.Name != "snap32" {
		t.Fatalf("register = %+v err=%v", got, err)
	}
	again, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "snap32", Image: "alpine:local", SourceSandboxID: "sb-mnt32"})
	if err != nil || again.Name != "snap32" {
		t.Fatalf("idempotent register = %+v err=%v", again, err)
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "snap32", Image: "alpine:other"}); !errors.Is(err, storepkg.ErrSnapshotNameConflict) {
		t.Fatalf("conflict register = %v", err)
	}
	if _, err := svc.CreateSnapshot(ctx, "sb-mnt32", models.CreateSandboxSnapshotRequest{}); err == nil {
		t.Fatal("nameless create snapshot")
	}
	existing, created, err := svc.CreateSnapshotWithOwnership(ctx, "sb-mnt32", models.CreateSandboxSnapshotRequest{Name: "snap32"})
	if err != nil || created || existing.Name != "snap32" {
		t.Fatalf("existing snapshot = %+v created=%v err=%v", existing, created, err)
	}
	if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "other", models.CreateSandboxSnapshotRequest{Name: "snap32"}); !errors.Is(err, storepkg.ErrSnapshotNameConflict) {
		t.Fatalf("foreign snapshot name = %v", err)
	}
	if _, _, err := svc.CreateSnapshotWithOwnership(ctx, "missing", models.CreateSandboxSnapshotRequest{Name: "snap-missing32"}); err == nil {
		t.Fatal("missing sandbox snapshot")
	}
	_ = st.Close()
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "after-close", Image: "alpine"}); err == nil {
		t.Fatal("closed register succeeded")
	}
}

func TestLifecycleDestroyWakeAndInFluxWave32(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{stopErr: errors.New("stop down")}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	now := time.Now().UTC()

	failStop := wave30SeedSandbox(t, st, "sb-stop-fail32", "inc-stop")
	failStop.ContainerID = "ctr-stop-fail32"
	failStop.LastActiveAt = now.Add(-2 * time.Hour)
	failStop.Lifecycle = models.Lifecycle{StopIfIdleFor: time.Minute}
	if err := st.Upsert(ctx, failStop); err != nil {
		t.Fatal(err)
	}
	okStop := wave30SeedSandbox(t, st, "sb-stop-ok32", "inc-stop")
	okStop.ContainerID = "ctr-stop-ok32"
	okStop.CreatedAt = now.Add(-2 * time.Hour)
	okStop.LastActiveAt = now.Add(-2 * time.Hour)
	okStop.Lifecycle = models.Lifecycle{StopAtAge: time.Minute}
	okStop.ExposedPorts = []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}}
	if err := st.Upsert(ctx, okStop); err != nil {
		t.Fatal(err)
	}
	svc.cfg.HTTPWakeDirectBypassEnabled = true
	svc.cfg.NetstatsPollInterval = time.Second
	svc.recordNetstatsActivity("sb-stop-ok32", now.Add(-3*time.Hour))
	svc.runLifecycleSweep(ctx)
	if len(rt.stopRefs) == 0 {
		t.Fatal("lifecycle sweep did not stop an idle sandbox")
	}

	(*Service)(nil).activityFloorFor(nil, false)
	svc.netstatsPollIsStale(now)
	svc.forgetNetstatsActivity("sb-stop-ok32")
	if !svc.netstatsRecentActivityAt("missing").IsZero() {
		t.Fatal("missing netstats leaked")
	}

	destroy := wave30SeedSandbox(t, st, "sb-evt-local32", "inc-local")
	destroy.ContainerIP = "10.9.8.7"
	destroy.ExposedPorts = []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}}
	svc.cfg.EnableCluster = true
	svc.AttachCluster(&wave30AuthCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{
			"sb-evt-local32": {SandboxID: "sb-evt-local32", OwnerNodeID: "self", IncarnationID: "inc-local"},
		},
	})
	if err := svc.handleDestroyEvent(ctx, destroy); err != nil {
		t.Fatalf("self-owned destroy event: %v", err)
	}
	if _, err := st.Get(ctx, destroy.ID); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("destroy event left the row: %v", err)
	}

	if _, err := svc.WakeAwarePortTarget(ctx, "missing", 80); err == nil {
		t.Fatal("wake missing sandbox")
	}
	started := wave30SeedSandbox(t, st, "sb-wake32", "inc-wake")
	if _, err := svc.WakeAwarePortTarget(ctx, started.ID, 80); err == nil {
		t.Fatal("wake without HTTP port")
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: started.ID, Port: 22, Protocol: models.ExposedPortProtocolTCP, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.WakeAwarePortTarget(ctx, started.ID, 22); err == nil {
		t.Fatal("wake TCP-only port")
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: started.ID, Port: 80, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.WakeAwarePortTarget(ctx, started.ID, 80); err == nil {
		t.Fatal("wake without container IP")
	}
	started.ContainerIP = "10.1.2.3"
	if err := st.Upsert(ctx, started); err != nil {
		t.Fatal(err)
	}
	ep, err := svc.WakeAwarePortTarget(ctx, started.ID, 80)
	if err != nil || !strings.Contains(ep.URL, "10.1.2.3:80") {
		t.Fatalf("wake docker = %+v err=%v", ep, err)
	}
	wasm := wave30SeedSandbox(t, st, "sb-wakwasm32", "inc-w")
	wasm.Runtime = models.RuntimeWasm
	if err := st.Upsert(ctx, wasm); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: wasm.ID, Port: 80, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.WakeAwarePortTarget(ctx, wasm.ID, 80); err == nil {
		t.Fatal("wake wasm without driver")
	}
	iso := wave30SeedSandbox(t, st, "sb-wakeiso32", "inc-i")
	iso.Runtime = models.RuntimeIsolate
	if err := st.Upsert(ctx, iso); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: iso.ID, Port: 80, Protocol: models.ExposedPortProtocolHTTP, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.WakeAwarePortTarget(ctx, iso.ID, 80); err == nil {
		t.Fatal("wake isolate without driver")
	}

	flux := &Service{caddy: caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})}
	p := cluster.Placement{
		SandboxID: "sb-flux32",
		ExposedPorts: map[int]string{
			80: models.ExposedPortProtocolHTTP,
			22: models.ExposedPortProtocolTCP,
		},
	}
	if err := flux.applyInFluxRoute(ctx, p); err != nil {
		t.Fatalf("path-mode in-flux: %v", err)
	}
	flux.cfg.Domain = "example.test"
	if err := flux.applyInFluxRoute(ctx, p); err != nil {
		t.Fatalf("SNI-mode in-flux: %v", err)
	}
	if host := dataPlaneHostForPlacement(cluster.Placement{OwnerDataPlaneHost: "https://dp.example:8443"}); host != "dp.example" {
		t.Fatalf("data-plane host = %q", host)
	}
	if host := hostFromURL("10.0.0.8:9000"); host != "10.0.0.8" {
		t.Fatalf("host:port = %q", host)
	}
	if host := hostFromURL("[::1]:443"); host != "::1" {
		t.Fatalf("ipv6 host = %q", host)
	}
	if port := l4ListenPort(":443"); port != 443 {
		t.Fatalf("l4 port = %d", port)
	}
	if port := l4ListenPort(""); port != 0 {
		t.Fatalf("blank l4 port = %d", port)
	}

	if err := svc.cleanupWasmSandboxArtifacts(ctx, started); err != nil {
		t.Fatal(err)
	}
	if err := (*Service)(nil).cleanupWasmSandboxArtifacts(ctx, wasm); err != nil {
		t.Fatal(err)
	}
}

func TestRefanoutReconcileAndAuthorizeWave32(t *testing.T) {
	ctx := context.Background()
	st := openSealTestStore(t)
	cipher := newTestCipher(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cl := &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", "")}
	svc := &Service{
		cfg: config.Config{EnableCluster: true}, store: st, cipher: cipher,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
		cluster:        cl, logger: logger, testSecretPeerPusher: &fakePeerPusher{},
	}

	if _, err := svc.prepareSecretRefanoutRecord(ctx, storepkg.ClusterSecretRecord{Ref: "not-a-ref"}, false, nil); err == nil {
		t.Fatal("invalid refanout ref")
	}
	unbound := storepkg.ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-unbound32", "inc-a", secrets.RefVersion),
		SandboxID: "sb-unbound32", Version: secrets.RefVersion,
		SealedPayload: []byte("not-sealed"), SealGeneration: 1, Recipients: []string{"node-a", "node-b"},
	}
	if _, err := svc.prepareSecretRefanoutRecord(ctx, unbound, false, nil); err == nil {
		t.Fatal("unbound refanout row")
	}

	blob := wave30BoundBlob(t, cipher, "sb-refan32", "inc-a", []string{"node-a", "node-b"}, 1)
	if err := newSecretBlobStore(st).Put(ctx, blob); err != nil {
		t.Fatal(err)
	}
	rec := storepkg.ClusterSecretRecord{
		Ref: blob.Ref, SandboxID: blob.SandboxID,
		Version: blob.Version, Recipients: blob.Recipients, SealedPayload: blob.SealedPayload,
		SealGeneration: blob.SealGeneration,
	}
	if got, err := svc.prepareSecretRefanoutRecord(ctx, rec, true, nil); err != nil || got != nil {
		t.Fatalf("missing placement should retire: %v %v", got, err)
	}
	cl.placements = map[string]cluster.Placement{
		"sb-refan32": {SandboxID: "sb-refan32", IncarnationID: "inc-a", State: cluster.PlacementStateDeleting},
	}
	if err := newSecretBlobStore(st).Put(ctx, blob); err != nil && !errors.Is(err, storepkg.ErrClusterSecretTombBlocksPut) {
		// Retirement tombs the row; a later put may be fenced. Re-seed via a fresh id below.
	}

	live := wave30BoundBlob(t, cipher, "sb-live32", "inc-a", []string{"node-a", "node-b"}, 1)
	if err := newSecretBlobStore(st).Put(ctx, live); err != nil {
		t.Fatal(err)
	}
	liveRec := storepkg.ClusterSecretRecord{
		Ref: live.Ref, SandboxID: live.SandboxID,
		Version: live.Version, Recipients: live.Recipients, SealedPayload: live.SealedPayload,
		SealGeneration: live.SealGeneration,
	}
	cl.placements["sb-live32"] = cluster.Placement{SandboxID: "sb-live32", IncarnationID: "inc-a", OwnerNodeID: "node-a"}
	got, err := svc.prepareSecretRefanoutRecord(ctx, liveRec, true, cl.placements)
	if err != nil || got == nil || got.SandboxID != "sb-live32" {
		t.Fatalf("live refanout blob = %+v err=%v", got, err)
	}
	svc.cfg.EnableCluster = false
	solo := liveRec
	solo.Recipients = []string{"node-a"}
	if got, err := svc.prepareSecretRefanoutRecord(ctx, solo, false, cl.placements); err != nil || got != nil {
		t.Fatalf("single recipient = %v %v", got, err)
	}
	solo.Recipients = nil
	if got, err := svc.prepareSecretRefanoutRecord(ctx, solo, false, cl.placements); err != nil || got != nil {
		t.Fatalf("empty recipients = %v %v", got, err)
	}
	solo.Recipients = []string{"node-a", "node-b"}
	solo.SealGeneration = 0
	if _, err := svc.prepareSecretRefanoutRecord(ctx, solo, false, cl.placements); err == nil {
		t.Fatal("zero generation refanout")
	}
	svc.cfg.EnableCluster = true

	if err := svc.runSecretRefanoutScan(ctx, &fakePeerPusher{}); err != nil {
		t.Fatalf("refanout scan: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_ = svc.runSecretRefanoutScan(cancelled, &fakePeerPusher{})
	svc.startSecretMaintenanceScan(ctx, "already running", nil)
	svc.secretRefanoutRunning = true
	svc.startSecretMaintenanceScan(ctx, "busy", func(context.Context) error { return errors.New("should not run") })
	svc.secretRefanoutRunning = false
	(*Service)(nil).startSecretRetirementScan(ctx)

	if err := st.UpsertSecretPutOutbox(ctx, "sb-put32", "inc-a", 1, []string{"node-b"}); err != nil {
		t.Fatal(err)
	}
	failPlace := &Service{
		cfg: config.Config{EnableCluster: true}, store: st, logger: logger,
		cluster:              &wave30AuthCluster{Noop: cluster.NewNoop("node-a", "http://a", ""), err: errors.New("raft down")},
		testSecretPeerPusher: &fakePeerPusher{},
	}
	if err := failPlace.ReconcileSecretPutOutbox(nil); err == nil {
		t.Fatal("put reconcile ignored placement failure")
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-del32", "inc-a", []string{"node-b"}, 1); err != nil {
		t.Fatal(err)
	}
	// Force a staged delete so authoritative placement lookup runs.
	retired := []string{"node-b"}
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-delpromo32", "inc-a", secrets.RefVersion),
		SandboxID: "sb-delpromo32", Version: secrets.RefVersion,
		Recipients: []string{"node-a", "node-c"}, RetireRecipients: &retired,
		SealedPayload: []byte("sealed"), SealGeneration: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := failPlace.ReconcileSecretDeleteOutbox(ctx); err == nil {
		t.Fatal("delete reconcile ignored placement failure")
	}

	if _, err := (*Service)(nil).AuthorizeSandboxAuditAccess(ctx, "sb", "inc"); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("nil authorize = %v", err)
	}
	sb := wave30SeedSandbox(t, st, "sb-auth32", "inc-a")
	sb.OwnerRef = "tenant-a"
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.AuthorizeSandboxAuditAccess(ctx, "sb-auth32", ""); err != nil || got != "inc-a" {
		t.Fatalf("local current = %q %v", got, err)
	}
	tenant := controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{OwnerRef: "tenant-a"}})
	if _, err := svc.AuthorizeSandboxAuditAccess(tenant, "sb-auth32", "inc-a"); err != nil {
		t.Fatalf("owner authorize: %v", err)
	}
	foreign := controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{OwnerRef: "other"}})
	if _, err := svc.AuthorizeSandboxAuditAccess(foreign, "sb-auth32", "inc-a"); err == nil {
		t.Fatal("foreign owner was authorized")
	}
	op := controlplane.ContextWithAccess(ctx, controlplane.Access{Operator: true})
	if _, err := svc.AuthorizeSandboxAuditAccess(op, "missing-auth32", "inc-a"); err == nil {
		t.Fatal("operator authorized a missing sandbox")
	}
	aclCl := &stubMembersCluster{
		Noop:      cluster.NewNoop("self", "http://self", ""),
		placement: cluster.Placement{SandboxID: "sb-acl-auth32", IncarnationID: "inc-a", OwnerRef: "tenant-a"},
		acl:       cluster.AuditACL{IncarnationID: "inc-a", OwnerRef: "tenant-a"},
		aclExists: true,
	}
	auth := &Service{cluster: aclCl}
	if got, err := auth.AuthorizeSandboxAuditAccess(op, "sb-acl-auth32", ""); err != nil || got != "inc-a" {
		t.Fatalf("placement incarnation authorize = %q %v", got, err)
	}
	if _, err := auth.AuthorizeSandboxAuditAccess(tenant, "sb-acl-auth32", "inc-a"); err != nil {
		t.Fatalf("placement owner authorize: %v", err)
	}

	svc.AttachSnapshotPusher(nil, nil)
	_ = mergeManagedRuntimes(nil, map[string]*models.SandboxRuntimeState{"a": {}})
}

func wave32ReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublicTrafficAndEasyGuardsWave32(t *testing.T) {
	ctx := context.Background()
	deny := false
	sb := &models.Sandbox{
		ID: "sb-pub32", AllowPublicTraffic: &deny,
		ExposedPorts:  []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}, {Port: 0}},
		CustomDomains: []models.CustomDomain{{Hostname: "ex.test"}, {Hostname: ""}},
	}
	svc := &Service{caddy: caddy.New(config.Config{EnableCaddy: false}), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := svc.deleteSandboxPublicRoutes(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.deleteSandboxPublicRoutes(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := svc.cleanupPublicTrafficDisabledIngressState(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.cleanupPublicTrafficDisabledIngressState(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := svc.syncExposedPortRoute(ctx, sb, models.ExposedPort{Port: 80, Protocol: models.ExposedPortProtocolHTTP}); err != nil {
		t.Fatal(err)
	}

	if secretAuditKindMatches("", "egress") || !secretAuditKindMatches(secretAuditKindGap, "egress") || !secretAuditKindMatches(secretAuditKindEgress, "egress") {
		t.Fatal("kind matcher")
	}
	if !secretAuditEventMatches(SecretAuditEvent{SandboxID: "sb", Kind: secretAuditKindSecretOpen}, "sb", "", "", time.Time{}, "") {
		t.Fatal("empty after matches")
	}
	after := time.Now().UTC()
	if secretAuditEventMatches(SecretAuditEvent{SandboxID: "sb", Time: after.Add(-time.Second)}, "sb", "", "", after, "k") {
		t.Fatal("before-cursor matched")
	}
	_ = dedupeSecretAuditEvents(nil)
	_ = dedupeSecretAuditEvents([]SecretAuditEvent{{EventID: "a", Time: after}, {EventID: "a", Time: after}})
	_ = formatSecretAuditCursor(SecretAuditEvent{Time: after, EventID: "a"})
	if _, _, err := parseSecretAuditCursor(""); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(SecretAuditEvent{EventID: "unused32"})
	_ = raw
}
