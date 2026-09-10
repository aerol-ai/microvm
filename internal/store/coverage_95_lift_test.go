package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestSetSecretCipherNilAndAssign(t *testing.T) {
	var nilStore *Store
	nilStore.SetSecretCipher(nil)

	st := newTestStore(t)
	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	st.SetSecretCipher(ciph)
	if st.secretCipher == nil {
		t.Fatal("SetSecretCipher did not store cipher")
	}
}

func TestUpsertSandboxAuditACLRemainingBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertSandboxAuditACL(ctx, "", "tenant", "inc"); err == nil {
		t.Fatal("empty sandbox accepted")
	}

	// Live row with empty audit_incarnation_id binds on first ACL write.
	sb := sampleSandbox("sb-bind-acl")
	sb.AuditIncarnationID = ""
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandboxAuditACL(ctx, sb.ID, "tenant-a", "inc-bind"); err != nil {
		t.Fatalf("bind empty incarnation: %v", err)
	}
	if got, err := st.CurrentSandboxAuditIncarnation(ctx, sb.ID); err != nil || got != "inc-bind" {
		t.Fatalf("bound incarnation = %q err=%v", got, err)
	}
	if err := st.UpsertSandboxAuditACL(ctx, sb.ID, "tenant-a", "inc-bind"); err != nil {
		t.Fatalf("matching incarnation upsert: %v", err)
	}
	if err := st.UpsertSandboxAuditACL(ctx, sb.ID, "tenant-b", "inc-other"); err == nil {
		t.Fatal("live incarnation conflict accepted")
	}

	// RAISE(IGNORE) makes the bind UPDATE affect 0 rows — concurrent lifecycle.
	st2 := newTestStore(t)
	sb2 := sampleSandbox("sb-bind-race")
	sb2.AuditIncarnationID = ""
	if err := st2.Create(ctx, sb2); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.db.ExecContext(ctx, `
		CREATE TRIGGER skip_acl_bind BEFORE UPDATE ON sandboxes
		BEGIN SELECT RAISE(IGNORE); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := st2.UpsertSandboxAuditACL(ctx, sb2.ID, "tenant", "inc-race"); err == nil {
		t.Fatal("expected concurrent bind failure")
	}

	st3 := newTestStore(t)
	sb3 := sampleSandbox("sb-bind-abort")
	sb3.AuditIncarnationID = ""
	if err := st3.Create(ctx, sb3); err != nil {
		t.Fatal(err)
	}
	if _, err := st3.db.ExecContext(ctx, `
		CREATE TRIGGER abort_acl_bind BEFORE UPDATE ON sandboxes
		BEGIN SELECT RAISE(ABORT, 'forced bind abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := st3.UpsertSandboxAuditACL(ctx, sb3.ID, "tenant", "inc-abort"); err == nil {
		t.Fatal("expected bind abort")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.UpsertSandboxAuditACL(ctx, "sb", "t", "inc"); err == nil {
		t.Fatal("closed db upsert should fail")
	}
}

func TestPruneSandboxAuditACLZeroCutoffAndClosed(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if n, err := st.PruneSandboxAuditACL(ctx, time.Time{}); err != nil || n != 0 {
		t.Fatalf("zero cutoff = %d %v", n, err)
	}
	if err := st.UpsertSandboxAuditACL(ctx, "sb-old", "t", "inc-old"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_audit_acl SET updated_at = ?`, old); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneSandboxAuditACL(ctx, time.Now().UTC().Add(-24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune = %d err=%v", n, err)
	}
	_ = st.Close()
	if _, err := st.PruneSandboxAuditACL(ctx, time.Now()); err == nil {
		t.Fatal("closed db prune should fail")
	}
}

func TestCreateWithSealedEnvRemainingBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	empty := sampleSandbox("sb-empty-sealed")
	if err := st.CreateWithSealedEnv(ctx, empty, nil); err != nil {
		t.Fatalf("empty sealedEnv: %v", err)
	}

	named := sampleSandbox("sb-name-ok")
	if err := st.Create(ctx, named); err != nil {
		t.Fatal(err)
	}
	conflict := sampleSandbox("sb-name-conflict")
	conflict.Name = named.ID
	if err := st.CreateWithSealedEnv(ctx, conflict, []byte("sealed")); !errors.Is(err, ErrSandboxNameConflict) {
		t.Fatalf("name conflict = %v", err)
	}

	dup := sampleSandbox("sb-empty-sealed")
	if err := st.CreateWithSealedEnv(ctx, dup, []byte("sealed")); !errors.Is(err, models.ErrSandboxExists) {
		t.Fatalf("duplicate insert = %v", err)
	}

	acl := sampleSandbox("sb-sealed-acl")
	acl.OwnerRef = "tenant-acl"
	acl.AuditIncarnationID = "inc-acl"
	if err := st.CreateWithSealedEnv(ctx, acl, []byte("sealed-acl")); err != nil {
		t.Fatalf("sealed+acl: %v", err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, acl.ID, acl.AuditIncarnationID); err != nil || got != "tenant-acl" {
		t.Fatalf("acl = %q err=%v", got, err)
	}

	st2 := newTestStore(t)
	if _, err := st2.db.ExecContext(ctx, `
		CREATE TRIGGER env_reject BEFORE INSERT ON sandbox_env
		BEGIN SELECT RAISE(ABORT, 'forced env abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := st2.CreateWithSealedEnv(ctx, sampleSandbox("sb-env-fail"), []byte("sealed")); err == nil {
		t.Fatal("expected putEnvExec abort")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.CreateWithSealedEnv(ctx, sampleSandbox("sb-closed"), []byte("sealed")); err == nil {
		t.Fatal("closed db create should fail")
	}
}

func TestRollbackSandboxCreateEmptyAndClosed(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.RollbackSandboxCreate(ctx, "", "inc"); err != nil {
		t.Fatalf("empty id: %v", err)
	}
	sb := sampleSandbox("sb-rollback-2")
	sb.AuditIncarnationID = "inc-rb"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.RollbackSandboxCreate(ctx, sb.ID, "inc-rb"); err != nil {
		t.Fatal(err)
	}
	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.RollbackSandboxCreate(ctx, "sb", "inc"); err == nil {
		t.Fatal("closed db rollback should fail")
	}
}

func TestApplyPutOutboxInTxViaPutClusterSecret(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ref := secrets.FormatRef("sb-out", "inc-out", secrets.RefVersion)
	base := ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-out", Version: secrets.RefVersion,
		Recipients: []string{"self", "peer-a"}, SealedPayload: []byte("sealed"),
		SealGeneration: 2,
	}

	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "not-a-ref", SandboxID: "sb-out", Version: 1, SealedPayload: []byte("x"), SealGeneration: 1,
		PutOutboxRecipients: &[]string{"peer-a"},
	}); err == nil {
		t.Fatal("invalid ref outbox accepted")
	}

	// Nil PutOutboxRecipients clears any prior job after a successful put.
	if _, err := st.PutClusterSecret(ctx, base); err != nil {
		t.Fatalf("base put: %v", err)
	}

	empty := []string{}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-out", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed-2"),
		SealGeneration: 3, PutOutboxRecipients: &empty, PutOutboxIncarnationID: "inc-other",
	}); err == nil {
		t.Fatal("empty peers with mismatched incarnation accepted")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-out", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed-2"),
		SealGeneration: 3, PutOutboxRecipients: &empty, PutOutboxIncarnationID: "inc-out",
	}); err != nil {
		t.Fatalf("empty peers clear: %v", err)
	}

	peers := []string{"peer-a", "peer-b"}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-out", Version: secrets.RefVersion,
		Recipients: []string{"self", "peer-a", "peer-b"}, SealedPayload: []byte("sealed-3"),
		SealGeneration: 4, PutOutboxRecipients: &peers,
	}); err == nil {
		t.Fatal("missing put-outbox incarnation accepted")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-out", Version: secrets.RefVersion,
		Recipients: []string{"self", "peer-a", "peer-b"}, SealedPayload: []byte("sealed-3"),
		SealGeneration: 4, PutOutboxRecipients: &peers, PutOutboxIncarnationID: "inc-other",
	}); err == nil {
		t.Fatal("mismatched put-outbox incarnation accepted")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-out", Version: secrets.RefVersion,
		Recipients: []string{"self", "peer-a", "peer-b"}, SealedPayload: []byte("sealed-3"),
		SealGeneration: 4, PutOutboxRecipients: &peers, PutOutboxIncarnationID: "inc-out",
	}); err != nil {
		t.Fatalf("journal peers: %v", err)
	}
	got, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-out", "inc-out")
	if err != nil || got == nil || got.SealGeneration != 4 || len(got.Recipients) != 2 {
		t.Fatalf("outbox = %+v err=%v", got, err)
	}

	// Nil recipients pointer clears the journalled job on the next put.
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-out", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed-4"),
		SealGeneration: 5,
	}); err != nil {
		t.Fatalf("clear via nil pointer: %v", err)
	}
	if got, err = st.GetSecretPutOutboxForIncarnation(ctx, "sb-out", "inc-out"); err != nil || got != nil {
		t.Fatalf("cleared outbox = %+v err=%v", got, err)
	}
}

func TestDeleteClusterSecretsOriginatorWithOutboxBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if gen, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "", "inc", []string{"peer"}); err != nil || gen != 0 {
		t.Fatalf("empty sandbox = %d %v", gen, err)
	}
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-del", "", []string{"peer"}); err == nil {
		t.Fatal("empty incarnation accepted")
	}

	ref := secrets.FormatRef("sb-del", "inc-del", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-del", Version: secrets.RefVersion,
		Recipients: []string{"self", "peer"}, SealedPayload: []byte("sealed"),
		SealGeneration: 3,
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-del", "inc-del", []string{"peer", "self"})
	if err != nil || gen != 4 {
		t.Fatalf("first delete gen=%d err=%v, want 4 (seal 3 + 1)", gen, err)
	}
	again, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-del", "inc-del", []string{"peer"})
	if err != nil || again <= gen {
		t.Fatalf("second delete gen=%d err=%v, want > %d", again, err, gen)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb", "inc", nil); err == nil {
		t.Fatal("closed db delete should fail")
	}
}

func TestApplyPeerSecretDeleteRemainingBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.ApplyPeerSecretDelete(ctx, "", "inc", 1); err != nil {
		t.Fatalf("empty sandbox: %v", err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb", "", 1); err == nil {
		t.Fatal("empty incarnation accepted")
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-none", "inc-none", 2); err != nil {
		t.Fatalf("missing row delete: %v", err)
	}

	ref := secrets.FormatRef("sb-peer", "inc-peer", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-peer", Version: secrets.RefVersion,
		Recipients: []string{"a"}, SealedPayload: []byte("sealed"), SealGeneration: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-peer", "inc-peer", 2); err != nil {
		t.Fatal(err)
	}
	// Higher tomb generation must be preserved when a stale equal-or-lower delete repeats.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE cluster_secret_tombs SET generation = 9 WHERE sandbox_id = ? AND incarnation_id = ?
	`, "sb-peer", "inc-peer"); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-peer", "inc-peer", 2); err != nil {
		t.Fatal(err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "sb-peer", "inc-peer"); err != nil || gen != 9 {
		t.Fatalf("tomb gen=%d err=%v, want 9", gen, err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.ApplyPeerSecretDelete(ctx, "sb", "inc", 1); err == nil {
		t.Fatal("closed db peer delete should fail")
	}
}

func TestUpsertSecretPutOutboxRemainingBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertSecretPutOutbox(ctx, "sb-merge", "inc-merge", 2, nil); err != nil {
		t.Fatalf("empty recipients: %v", err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-merge", "inc-merge", 3, []string{"peer-a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-merge", "inc-merge", 2, []string{"peer-stale"}); err != nil {
		t.Fatalf("stale gen skip: %v", err)
	}
	got, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-merge", "inc-merge")
	if err != nil || got == nil || got.SealGeneration != 3 || len(got.Recipients) != 1 || got.Recipients[0] != "peer-a" {
		t.Fatalf("after stale skip = %+v err=%v", got, err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-merge", "inc-merge", 3, []string{"peer-b"}); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetSecretPutOutboxForIncarnation(ctx, "sb-merge", "inc-merge")
	if err != nil || got == nil || len(got.Recipients) != 2 {
		t.Fatalf("merged = %+v err=%v", got, err)
	}

	if _, err := st.db.ExecContext(ctx, `
		UPDATE cluster_secret_put_outbox SET recipients_json = '{' WHERE sandbox_id = ?
	`, "sb-merge"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-merge", "inc-merge", 3, []string{"peer-c"}); err == nil {
		t.Fatal("corrupt merge JSON should fail")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.UpsertSecretPutOutbox(ctx, "sb", "inc", 1, []string{"p"}); err == nil {
		t.Fatal("closed db upsert should fail")
	}
}

func TestDeleteEnvAndPutEnvExecErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-env-del")
	if err := st.CreateWithSealedEnv(ctx, sb, []byte("blob")); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteEnv(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if err := putEnvExec(ctx, st.db, sb.ID, []byte("again")); err != nil {
		t.Fatalf("putEnvExec: %v", err)
	}

	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER env_del_abort BEFORE DELETE ON sandbox_env
		BEGIN SELECT RAISE(ABORT, 'forced env delete abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteEnv(ctx, sb.ID); err == nil {
		t.Fatal("expected delete abort")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.DeleteEnv(ctx, "sb"); err == nil {
		t.Fatal("closed db DeleteEnv should fail")
	}
	if err := putEnvExec(ctx, closed.db, "sb", []byte("x")); err == nil {
		t.Fatal("closed db putEnvExec should fail")
	}
}

func TestEnsureWasmCheckpointCleanupRefRemainingBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.EnsureWasmCheckpointCleanupRef(ctx, "", "ref"); err == nil {
		t.Fatal("empty sandbox accepted")
	}
	if _, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb", ""); err == nil {
		t.Fatal("empty ref accepted")
	}
	id, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb-new-clean", "aocr://sb-new-clean:latest")
	if err != nil || id <= 0 {
		t.Fatalf("insert = %d err=%v", id, err)
	}

	st2 := newTestStore(t)
	if _, err := st2.db.ExecContext(ctx, `
		CREATE TRIGGER wasm_clean_abort BEFORE INSERT ON wasm_checkpoint_pushes
		BEGIN SELECT RAISE(ABORT, 'forced cleanup insert abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.EnsureWasmCheckpointCleanupRef(ctx, "sb", "aocr://x"); err == nil {
		t.Fatal("expected insert abort")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.EnsureWasmCheckpointCleanupRef(ctx, "sb", "aocr://x"); err == nil {
		t.Fatal("closed db ensure should fail")
	}
}

func TestDeleteOrphanedWasmStateKVClosedAndLimit(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.PutWasmStateKV(ctx, "orphan-a", "k", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := st.PutWasmStateKV(ctx, "orphan-b", "k", []byte("2")); err != nil {
		t.Fatal(err)
	}
	n, err := st.DeleteOrphanedWasmStateKV(ctx, 1)
	if err != nil || n != 1 {
		t.Fatalf("bounded delete = %d err=%v", n, err)
	}
	n, err = st.DeleteOrphanedWasmStateKV(ctx, -1)
	if err != nil || n != 1 {
		t.Fatalf("default limit delete = %d err=%v", n, err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.DeleteOrphanedWasmStateKV(ctx, 10); err == nil {
		t.Fatal("closed db orphan sweep should fail")
	}
}

func TestPruneClusterSecretTombsGuardsAndClosed(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if n, err := st.PruneClusterSecretTombs(ctx, time.Time{}, 10); err != nil || n != 0 {
		t.Fatalf("zero cutoff = %d %v", n, err)
	}
	if n, err := st.PruneClusterSecretTombs(ctx, time.Now(), 0); err != nil || n != 0 {
		t.Fatalf("zero limit = %d %v", n, err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_tombs (sandbox_id, incarnation_id, deleted_at, generation)
		VALUES ('eligible', 'inc-eligible', ?, 1)
	`, old); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneClusterSecretTombs(ctx, time.Now().UTC().Add(-24*time.Hour), 10); err != nil || n != 1 {
		t.Fatalf("prune = %d err=%v", n, err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.PruneClusterSecretTombs(ctx, time.Now(), 10); err == nil {
		t.Fatal("closed db prune should fail")
	}
}

func TestToolboxTokenStorageAndCreateCipherPaths(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if got, err := st.toolboxTokenStorage(nil); err != nil || len(got) != 0 {
		t.Fatalf("nil sandbox = %q err=%v", got, err)
	}
	presealed := sampleSandbox("sb-presealed")
	presealed.ToolboxTokenSealed = []byte("already-sealed")
	got, err := st.toolboxTokenStorage(presealed)
	if err != nil || string(got) != "already-sealed" {
		t.Fatalf("presealed = %q err=%v", got, err)
	}
	plain := sampleSandbox("sb-plain-token")
	plain.ToolboxToken = "plain-token"
	if _, err := st.toolboxTokenStorage(plain); err == nil {
		t.Fatal("plaintext token without cipher should fail")
	}
	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "token.key"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetSecretCipher(ciph)
	if _, err := st.toolboxTokenStorage(plain); err != nil {
		t.Fatalf("seal token: %v", err)
	}
	plain.AuditIncarnationID = "inc-token"
	if err := st.Create(ctx, plain); err != nil {
		t.Fatalf("Create with sealed token: %v", err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.Create(ctx, sampleSandbox("sb-closed-create")); err == nil {
		t.Fatal("closed db Create should fail")
	}
}

func TestAuditIncarnationLookupsAndTombClear(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if got, err := st.CurrentSandboxAuditIncarnation(ctx, ""); err != nil || got != "" {
		t.Fatalf("empty current = %q %v", got, err)
	}
	if got, err := st.LatestRetainedSandboxAuditIncarnation(ctx, ""); err != nil || got != "" {
		t.Fatalf("empty latest = %q %v", got, err)
	}
	if got, err := st.CurrentSandboxAuditIncarnation(ctx, "missing"); err != nil || got != "" {
		t.Fatalf("missing current = %q %v", got, err)
	}
	if got, err := st.LatestRetainedSandboxAuditIncarnation(ctx, "missing"); err != nil || got != "" {
		t.Fatalf("missing latest = %q %v", got, err)
	}
	if err := st.ClearClusterSecretTombForIncarnation(ctx, "", "inc"); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearClusterSecretTombForIncarnation(ctx, "sb", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_tombs (sandbox_id, incarnation_id, deleted_at, generation)
		VALUES ('sb-tomb', 'inc-tomb', ?, 1)
	`, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearClusterSecretTombForIncarnation(ctx, "sb-tomb", "inc-tomb"); err != nil {
		t.Fatal(err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.CurrentSandboxAuditIncarnation(ctx, "sb"); err == nil {
		t.Fatal("closed current should fail")
	}
	if _, err := closed.LatestRetainedSandboxAuditIncarnation(ctx, "sb"); err == nil {
		t.Fatal("closed latest should fail")
	}
	if err := closed.ClearClusterSecretTombForIncarnation(ctx, "sb", "inc"); err == nil {
		t.Fatal("closed tomb clear should fail")
	}
}

func TestSecretDeleteOutboxHelpersRemainingBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.UpsertSecretDeleteOutbox(ctx, "", "inc", []string{"peer"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb", "inc", nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb", "", []string{"peer"}, 1); err == nil {
		t.Fatal("missing incarnation accepted")
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb", "inc", []string{"peer"}, 0); err == nil {
		t.Fatal("zero generation accepted")
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-del-ob", "inc-del-ob", []string{"peer-a"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-del-ob", "inc-del-ob", []string{"peer-b"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-del-ob", "inc-del-ob", []string{"peer-c"}, 1); err != nil {
		t.Fatal(err)
	}
	promoted, err := st.MarkSecretDeleteOutboxPromoted(ctx, "", "inc", 1)
	if err != nil || promoted {
		t.Fatalf("empty sandbox promote = %v %v", promoted, err)
	}
	if _, err := st.MarkSecretDeleteOutboxPromoted(ctx, "sb", "", 1); err == nil {
		t.Fatal("empty incarnation promote accepted")
	}
	ok, err := st.MarkSecretDeleteOutboxPromoted(ctx, "sb-del-ob", "inc-del-ob", 2)
	if err != nil || ok {
		t.Fatalf("not-awaiting promote = %v %v", ok, err)
	}
	if _, err := st.db.ExecContext(ctx, `
		UPDATE cluster_secret_delete_outbox SET awaiting_promotion = 1 WHERE sandbox_id = ?
	`, "sb-del-ob"); err != nil {
		t.Fatal(err)
	}
	ok, err = st.MarkSecretDeleteOutboxPromoted(ctx, "sb-del-ob", "inc-del-ob", 2)
	if err != nil || !ok {
		t.Fatalf("promote = %v %v", ok, err)
	}
	if err := st.BumpSecretDeleteOutboxAttempt(ctx, "", "inc", 1); err != nil {
		t.Fatal(err)
	}
	if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb", "", 1); err == nil {
		t.Fatal("empty incarnation bump accepted")
	}
	if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb-del-ob", "inc-del-ob", 2); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSecretDeleteOutbox(ctx, "", "inc", 1); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSecretDeleteOutbox(ctx, "sb", "", 1); err == nil {
		t.Fatal("empty incarnation delete accepted")
	}
	if err := st.DeleteSecretDeleteOutbox(ctx, "sb-del-ob", "inc-del-ob", 2); err != nil {
		t.Fatal(err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.UpsertSecretDeleteOutbox(ctx, "sb", "inc", []string{"p"}, 1); err == nil {
		t.Fatal("closed upsert delete outbox should fail")
	}
	if _, err := closed.MarkSecretDeleteOutboxPromoted(ctx, "sb", "inc", 1); err == nil {
		t.Fatal("closed promote should fail")
	}
	if err := closed.BumpSecretDeleteOutboxAttempt(ctx, "sb", "inc", 1); err == nil {
		t.Fatal("closed bump should fail")
	}
	if err := closed.DeleteSecretDeleteOutbox(ctx, "sb", "inc", 1); err == nil {
		t.Fatal("closed delete outbox should fail")
	}
}

func TestOriginatorDeleteAndPutOutboxSQLFailures(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ref := secrets.FormatRef("sb-sql", "inc-sql", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-sql", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed"), SealGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER tomb_abort BEFORE INSERT ON cluster_secret_tombs
		BEGIN SELECT RAISE(ABORT, 'forced tomb abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-sql", "inc-sql", []string{"peer"}); err == nil {
		t.Fatal("expected tomb abort")
	}

	st2 := newTestStore(t)
	peers := []string{"peer-a"}
	if _, err := st2.db.ExecContext(ctx, `
		CREATE TRIGGER put_outbox_abort BEFORE INSERT ON cluster_secret_put_outbox
		BEGIN SELECT RAISE(ABORT, 'forced put outbox abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-po", "inc-po", secrets.RefVersion),
		SandboxID: "sb-po", Version: secrets.RefVersion,
		Recipients: []string{"self", "peer-a"}, SealedPayload: []byte("sealed"),
		SealGeneration: 1, PutOutboxRecipients: &peers, PutOutboxIncarnationID: "inc-po",
	}); err == nil {
		t.Fatal("expected put-outbox insert abort")
	}

	st3 := newTestStore(t)
	if _, err := st3.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-clr", "inc-clr", secrets.RefVersion),
		SandboxID: "sb-clr", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed"), SealGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st3.UpsertSecretPutOutbox(ctx, "sb-clr", "inc-clr", 1, []string{"peer-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st3.db.ExecContext(ctx, `
		CREATE TRIGGER put_outbox_del_abort BEFORE DELETE ON cluster_secret_put_outbox
		BEGIN SELECT RAISE(ABORT, 'forced put outbox delete abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st3.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-clr", "inc-clr", secrets.RefVersion),
		SandboxID: "sb-clr", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed-2"), SealGeneration: 2,
	}); err == nil {
		t.Fatal("expected put-outbox clear abort")
	}

	if _, err := st.GetClusterSecretForSandboxIncarnation(ctx, "", "inc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty get = %v", err)
	}
	if err := st.DeleteClusterSecretRowsForIncarnation(ctx, "", "inc"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteClusterSecretRowsForIncarnation(ctx, "sb", ""); err == nil {
		t.Fatal("empty incarnation row delete accepted")
	}
}

func TestSecretLifecycleStatsInvalidOldest(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.SecretLifecycleStats(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_delete_outbox
			(sandbox_id, incarnation_id, recipients_json, generation, attempts, created_at, updated_at)
		VALUES ('sb-bad-ts', 'inc', '["p"]', 1, 0, 'not-a-time', 'not-a-time')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SecretLifecycleStats(ctx); err == nil {
		t.Fatal("invalid oldest timestamp should fail")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.SecretLifecycleStats(ctx); err == nil {
		t.Fatal("closed stats should fail")
	}
}

func TestCreateACLAbortAndRollbackACLDeleteAbort(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER acl_insert_abort BEFORE INSERT ON sandbox_audit_acl
		BEGIN SELECT RAISE(ABORT, 'forced acl insert abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	sb := sampleSandbox("sb-acl-abort")
	sb.AuditIncarnationID = "inc-acl-abort"
	if err := st.Create(ctx, sb); err == nil {
		t.Fatal("expected ACL insert abort")
	}

	st2 := newTestStore(t)
	sb2 := sampleSandbox("sb-rb-acl")
	sb2.AuditIncarnationID = "inc-rb-acl"
	if err := st2.Create(ctx, sb2); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.db.ExecContext(ctx, `
		CREATE TRIGGER acl_del_abort BEFORE DELETE ON sandbox_audit_acl
		BEGIN SELECT RAISE(ABORT, 'forced acl delete abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := st2.RollbackSandboxCreate(ctx, sb2.ID, "inc-rb-acl"); err == nil {
		t.Fatal("expected ACL delete abort during rollback")
	}
}

func TestSecretRetirementAndListBatchBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	retire := []string{"old-peer"}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-ret", "inc-ret", secrets.RefVersion),
		SandboxID: "sb-ret", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed"),
		SealGeneration: 2, RetireRecipients: &retire,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: "not-a-ref", SandboxID: "sb-ret", Version: 1, SealedPayload: []byte("x"),
		SealGeneration: 3, RetireRecipients: &retire,
	}); err == nil {
		t.Fatal("retirement with invalid ref accepted")
	}

	if _, err := st.ListClusterSecretsBatch(ctx, "", 0); err == nil {
		t.Fatal("zero limit accepted")
	}
	batch, err := st.ListClusterSecretsBatch(ctx, "", 10)
	if err != nil || len(batch) == 0 {
		t.Fatalf("batch = %v err=%v", batch, err)
	}
	if _, err := st.ListClusterSecretsBatch(ctx, batch[0].Ref, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE cluster_secrets SET recipients_json = '{' WHERE sandbox_id = 'sb-ret'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListClusterSecretsBatch(ctx, "", 10); err == nil {
		t.Fatal("corrupt recipients should fail list")
	}

	if _, _, err := st.ClusterSecretSealGeneration(ctx, "", "inc"); err != nil {
		t.Fatal(err)
	}
	if gen, ok, err := st.ClusterSecretSealGeneration(ctx, "missing", "inc"); err != nil || ok || gen != 0 {
		t.Fatalf("missing gen = %d ok=%v err=%v", gen, ok, err)
	}

	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "", "inc", []string{"p"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-upd", "inc-upd", []string{"peer-a"}, 3); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-upd", "inc-upd", []string{"peer-b"}, 3); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-upd", "inc-upd", nil, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListSecretDeleteOutboxBatch(ctx, 0); err == nil {
		t.Fatal("zero delete-outbox limit accepted")
	}

	if _, err := st.GetSandboxAuditACLOwnerRef(ctx, "sb", ""); err != nil {
		t.Fatal(err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.ListClusterSecretsBatch(ctx, "", 10); err == nil {
		t.Fatal("closed list should fail")
	}
	if _, _, err := closed.ClusterSecretSealGeneration(ctx, "sb", "inc"); err == nil {
		t.Fatal("closed generation should fail")
	}
	if err := closed.UpdateSecretDeleteOutboxRecipients(ctx, "sb", "inc", []string{"p"}, 1); err == nil {
		t.Fatal("closed update recipients should fail")
	}
	if _, err := closed.GetSandboxAuditACLOwnerRef(ctx, "sb", "inc"); err == nil {
		t.Fatal("closed ACL get should fail")
	}
	if _, err := closed.ListSecretDeleteOutboxBatch(ctx, 10); err == nil {
		t.Fatal("closed delete-outbox list should fail")
	}
}

func TestOriginatorDeleteSecretAndOutboxAborts(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-orig", "inc-orig", secrets.RefVersion),
		SandboxID: "sb-orig", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed"), SealGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER secret_del_abort BEFORE DELETE ON cluster_secrets
		BEGIN SELECT RAISE(ABORT, 'forced secret delete abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-orig", "inc-orig", []string{"peer"}); err == nil {
		t.Fatal("expected secret delete abort")
	}

	st2 := newTestStore(t)
	if err := st2.UpsertSecretPutOutbox(ctx, "sb-orig2", "inc-orig2", 1, []string{"peer"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.db.ExecContext(ctx, `
		CREATE TRIGGER put_ob_del_abort BEFORE DELETE ON cluster_secret_put_outbox
		BEGIN SELECT RAISE(ABORT, 'forced put outbox delete abort'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.DeleteClusterSecretsOriginatorWithOutbox(ctx, "sb-orig2", "inc-orig2", []string{"peer"}); err == nil {
		t.Fatal("expected put-outbox delete abort")
	}
}

func TestPutOutboxListUpdateAndRetirementEmptyKeep(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.ListSecretPutOutboxBatch(ctx, 0); err == nil {
		t.Fatal("zero put-outbox limit accepted")
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "", "inc", []string{"p"}, 1); err == nil {
		t.Fatal("empty sandbox update accepted")
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb", "", []string{"p"}, 1); err == nil {
		t.Fatal("empty incarnation update accepted")
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb", "inc", []string{"p"}, 0); err == nil {
		t.Fatal("zero generation update accepted")
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb-missing", "inc", []string{"p"}, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing update = %v", err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-list", "inc-list", 2, []string{"peer-a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretPutOutboxRecipients(ctx, "sb-list", "inc-list", []string{"peer-b"}, 2); err != nil {
		t.Fatal(err)
	}
	batch, err := st.ListSecretPutOutboxBatch(ctx, 10)
	if err != nil || len(batch) != 1 || batch[0].Recipients[0] != "peer-b" {
		t.Fatalf("put-outbox batch = %+v err=%v", batch, err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE cluster_secret_put_outbox SET recipients_json = '{' WHERE sandbox_id = 'sb-list'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListSecretPutOutboxBatch(ctx, 10); err == nil {
		t.Fatal("corrupt put-outbox list should fail")
	}

	// Retirement whose only targets are still current recipients clears the job.
	retire := []string{"self"}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-keep", "inc-keep", secrets.RefVersion),
		SandboxID: "sb-keep", Version: secrets.RefVersion,
		Recipients: []string{"self"}, SealedPayload: []byte("sealed"),
		SealGeneration: 1, RetireRecipients: &retire,
	}); err != nil {
		t.Fatal(err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.ListSecretPutOutboxBatch(ctx, 10); err == nil {
		t.Fatal("closed put-outbox list should fail")
	}
	if err := closed.UpdateSecretPutOutboxRecipients(ctx, "sb", "inc", []string{"p"}, 1); err == nil {
		t.Fatal("closed put-outbox update should fail")
	}
}
