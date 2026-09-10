package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestPutClusterSecretRemainingBranches(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ref := secrets.FormatRef("sb-put", "inc-put", secrets.RefVersion)

	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: " ", SandboxID: "sb-put", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("empty ref")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: " ", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("empty sandbox")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 0, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("zero version")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 0, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("zero generation")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 1}); err == nil {
		t.Fatal("empty payload")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: "not-a-ref", SandboxID: "sb-put", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("ref mismatch")
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: secrets.FormatRef("other", "inc-put", secrets.RefVersion), SandboxID: "sb-put", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("sandbox/ref mismatch")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if _, err := closed.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("closed db begin")
	}

	// Row planted with a different sandbox_id than the ref encodes so the
	// ownership conflict is reachable (ParseRef otherwise rejects a mismatch).
	now := time.Now().UTC()
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secrets (ref, sandbox_id, version, recipients_json, sealed_payload, seal_generation, created_at, updated_at)
		VALUES (?, ?, 1, '[]', ?, 1, ?, ?)
	`, ref, "sb-other", []byte("old"), now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 2, SealedPayload: []byte("newer")}); !errors.Is(err, ErrClusterSecretPayloadConflict) {
		t.Fatalf("cross-sandbox conflict = %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `DELETE FROM cluster_secrets WHERE ref = ?`, ref); err != nil {
		t.Fatal(err)
	}

	base := ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 3, SealedPayload: []byte("same")}
	if _, err := st.PutClusterSecret(ctx, base); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 2, SealedPayload: []byte("stale")}); !errors.Is(err, ErrClusterSecretStaleGeneration) {
		t.Fatalf("stale = %v", err)
	}
	conflict := base
	conflict.SealedPayload = []byte("different")
	if _, err := st.PutClusterSecret(ctx, conflict); !errors.Is(err, ErrClusterSecretPayloadConflict) {
		t.Fatalf("equal-gen conflict = %v", err)
	}

	// Idempotent rewrite still applies tomb/outbox so a retried originator
	// PUT recovers after a crash between the row write and those side tables.
	retire := []string{"old-peer"}
	outbox := []string{"new-peer"}
	idem := base
	idem.RetireRecipients = &retire
	idem.PutOutboxRecipients = &outbox
	idem.PutOutboxIncarnationID = "inc-put"
	if _, err := st.PutClusterSecret(ctx, idem); err != nil {
		t.Fatalf("idempotent+retire: %v", err)
	}

	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_tombs (sandbox_id, incarnation_id, deleted_at, generation)
		VALUES (?, ?, ?, 9)
	`, "sb-tomb", "inc-tomb", now); err != nil {
		t.Fatal(err)
	}
	tombRef := secrets.FormatRef("sb-tomb", "inc-tomb", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: tombRef, SandboxID: "sb-tomb", Version: 1, SealGeneration: 9, SealedPayload: []byte("blocked")}); !errors.Is(err, ErrClusterSecretTombBlocksPut) {
		t.Fatalf("tomb blocks = %v", err)
	}

	scan := newTestStore(t)
	if _, err := scan.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.db.ExecContext(ctx, `ALTER TABLE cluster_secrets DROP COLUMN sealed_payload`); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 2, SealedPayload: []byte("y")}); err == nil {
		t.Fatal("existing-row scan error")
	}

	tombScan := newTestStore(t)
	if _, err := tombScan.db.ExecContext(ctx, `ALTER TABLE cluster_secret_tombs DROP COLUMN generation`); err != nil {
		t.Fatal(err)
	}
	if _, err := tombScan.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("tomb scan error")
	}

	insAbort := newTestStore(t)
	if _, err := insAbort.db.ExecContext(ctx, `
		CREATE TRIGGER abort_secret_put BEFORE INSERT ON cluster_secrets
		BEGIN SELECT RAISE(ABORT, 'blocked put'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := insAbort.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 1, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("insert abort")
	}

	tombDel := newTestStore(t)
	if _, err := tombDel.db.ExecContext(ctx, `
		CREATE TRIGGER abort_tomb_del BEFORE DELETE ON cluster_secret_tombs
		BEGIN SELECT RAISE(ABORT, 'blocked tomb delete'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := tombDel.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_tombs (sandbox_id, incarnation_id, deleted_at, generation)
		VALUES (?, ?, ?, 1)
	`, "sb-put", "inc-put", now); err != nil {
		t.Fatal(err)
	}
	if _, err := tombDel.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-put", Version: 1, SealGeneration: 2, SealedPayload: []byte("x")}); err == nil {
		t.Fatal("tomb delete abort")
	}
}

func TestInsertSandboxAndUpsertRemaining(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	deny := false
	sb := sampleSandbox("sb-ins-full")
	sb.Name = "named-full"
	sb.GPUs = &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 1, DeviceIDs: []string{"0"}}
	sb.NetworkAllowOut = []string{"1.1.1.1/32"}
	sb.NetworkDenyOut = []string{"10.0.0.0/8"}
	sb.AllowPublicTraffic = &deny
	sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	sb.AuditIncarnationID = "inc-full"
	sb.OwnerRef = "tenant-a"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create full: %v", err)
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil || got.GPUs == nil || got.GPUs.Vendor != models.GPUVendorNVIDIA {
		t.Fatalf("gpus = %+v err=%v", got, err)
	}

	noCipher := sampleSandbox("sb-token")
	noCipher.ToolboxToken = "plain-token"
	if err := st.Create(ctx, noCipher); err == nil {
		t.Fatal("toolbox token without cipher")
	}

	dupName := sampleSandbox("sb-dup-name")
	dupName.Name = "named-full"
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.insertSandbox(ctx, tx, dupName); !errors.Is(err, ErrSandboxNameConflict) {
		_ = tx.Rollback()
		t.Fatalf("name conflict = %v", err)
	}
	_ = tx.Rollback()

	tx, err = st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.insertSandbox(ctx, tx, sampleSandbox("sb-ins-full")); !errors.Is(err, models.ErrSandboxExists) {
		_ = tx.Rollback()
		t.Fatalf("id conflict = %v", err)
	}
	_ = tx.Rollback()

	abort := newTestStore(t)
	if _, err := abort.db.ExecContext(ctx, `
		CREATE TRIGGER abort_ins BEFORE INSERT ON sandboxes
		BEGIN SELECT RAISE(ABORT, 'blocked insert'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := abort.Create(ctx, sampleSandbox("sb-abort")); err == nil {
		t.Fatal("insert abort")
	}

	if got := mustMarshalStringSlice(nil); got != "[]" {
		t.Fatalf("nil slice = %s", got)
	}
	if got := mustMarshalStringSlice([]string{"a", "b"}); got == "[]" {
		t.Fatal("non-empty slice marshaled to []")
	}
	if got, err := marshalGPUs(nil); err != nil || got != "" {
		t.Fatalf("nil gpus = %q err=%v", got, err)
	}
	if got, err := marshalGPUs(&models.GPURequest{Vendor: models.GPUVendorAMD, Count: 2}); err != nil || got == "" {
		t.Fatalf("gpus json = %q err=%v", got, err)
	}

	up := sampleSandbox("sb-upsert")
	up.Name = "upsert-a"
	if err := st.Upsert(ctx, up); err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	up.Image = "ubuntu:24.04"
	if err := st.Upsert(ctx, up); err != nil {
		t.Fatalf("upsert no-incarnation: %v", err)
	}

	inc := sampleSandbox("sb-upsert-inc")
	inc.AuditIncarnationID = "inc-1"
	inc.OwnerRef = "tenant-a"
	inc.GPUs = &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 1}
	inc.NetworkAllowOut = []string{"8.8.8.8/32"}
	if err := st.Upsert(ctx, inc); err != nil {
		t.Fatalf("upsert with incarnation: %v", err)
	}
	inc.Image = "alpine:3"
	if err := st.Upsert(ctx, inc); err != nil {
		t.Fatalf("upsert same incarnation: %v", err)
	}
	inc.AuditIncarnationID = "inc-2"
	if err := st.Upsert(ctx, inc); err == nil {
		t.Fatal("incarnation conflict")
	}

	named := sampleSandbox("sb-upsert-name")
	named.Name = "upsert-a"
	if err := st.Upsert(ctx, named); !errors.Is(err, ErrSandboxNameConflict) {
		t.Fatalf("upsert name conflict = %v", err)
	}

	tok := sampleSandbox("sb-upsert-tok")
	tok.ToolboxToken = "plain"
	if err := st.Upsert(ctx, tok); err == nil {
		t.Fatal("upsert toolbox without cipher")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.Upsert(ctx, sampleSandbox("sb-closed")); err == nil {
		t.Fatal("upsert closed")
	}

	aclAbort := newTestStore(t)
	if _, err := aclAbort.db.ExecContext(ctx, `
		CREATE TRIGGER abort_acl BEFORE INSERT ON sandbox_audit_acl
		BEGIN SELECT RAISE(ABORT, 'blocked acl'); END;
	`); err != nil {
		t.Fatal(err)
	}
	acl := sampleSandbox("sb-acl-abort")
	acl.AuditIncarnationID = "inc-acl"
	if err := aclAbort.Upsert(ctx, acl); err == nil {
		t.Fatal("acl abort")
	}

	execAbort := newTestStore(t)
	if _, err := execAbort.db.ExecContext(ctx, `
		CREATE TRIGGER abort_up BEFORE INSERT ON sandboxes
		BEGIN SELECT RAISE(ABORT, 'blocked upsert'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := execAbort.Upsert(ctx, sampleSandbox("sb-up-abort")); err == nil {
		t.Fatal("upsert exec abort")
	}

	lookup := newTestStore(t)
	seed := sampleSandbox("sb-lookup")
	seed.AuditIncarnationID = "inc-l"
	if err := lookup.Create(ctx, seed); err != nil {
		t.Fatal(err)
	}
	if _, err := lookup.db.ExecContext(ctx, `ALTER TABLE sandboxes DROP COLUMN audit_incarnation_id`); err != nil {
		t.Fatal(err)
	}
	again := sampleSandbox("sb-lookup")
	again.AuditIncarnationID = "inc-l"
	if err := lookup.Upsert(ctx, again); err == nil {
		t.Fatal("incarnation lookup scan error")
	}
}

func TestValidateCurrentSecretSchemaRemaining(t *testing.T) {
	ctx := context.Background()

	closed := newTestStore(t)
	_ = closed.Close()
	if err := validateCurrentSecretSchema(closed.db); err == nil {
		t.Fatal("closed db")
	}

	envJSON := newTestStore(t)
	if _, err := envJSON.db.ExecContext(ctx, `ALTER TABLE sandboxes ADD COLUMN env_json TEXT`); err != nil {
		t.Fatal(err)
	}
	if err := validateCurrentSecretSchema(envJSON.db); err == nil {
		t.Fatal("env_json leftover")
	}

	plainTok := newTestStore(t)
	if _, err := plainTok.db.ExecContext(ctx, `ALTER TABLE sandboxes ADD COLUMN toolbox_token TEXT`); err != nil {
		t.Fatal(err)
	}
	if err := validateCurrentSecretSchema(plainTok.db); err == nil {
		t.Fatal("toolbox_token leftover")
	}

	dropSealed := newTestStore(t)
	if _, err := dropSealed.db.ExecContext(ctx, `ALTER TABLE sandboxes DROP COLUMN toolbox_token_sealed`); err != nil {
		t.Fatal(err)
	}
	if err := validateCurrentSecretSchema(dropSealed.db); err == nil {
		t.Fatal("missing toolbox_token_sealed")
	}

	dropInc := newTestStore(t)
	if _, err := dropInc.db.ExecContext(ctx, `ALTER TABLE sandboxes DROP COLUMN audit_incarnation_id`); err != nil {
		t.Fatal(err)
	}
	if err := validateCurrentSecretSchema(dropInc.db); err == nil {
		t.Fatal("missing audit_incarnation_id")
	}

	dropCol := newTestStore(t)
	if _, err := dropCol.db.ExecContext(ctx, `ALTER TABLE cluster_secrets DROP COLUMN seal_generation`); err != nil {
		t.Fatal(err)
	}
	if err := validateCurrentSecretSchema(dropCol.db); err == nil {
		t.Fatal("missing required column")
	}

	badPK := newTestStore(t)
	if _, err := badPK.db.ExecContext(ctx, `DROP TABLE cluster_secrets`); err != nil {
		t.Fatal(err)
	}
	if _, err := badPK.db.ExecContext(ctx, `
		CREATE TABLE cluster_secrets (
			ref TEXT,
			seal_generation INTEGER
		)
	`); err != nil {
		t.Fatal(err)
	}
	if err := validateCurrentSecretSchema(badPK.db); err == nil {
		t.Fatal("wrong PK")
	}

	if err := validateRequiredTableShape(closed.db, "cluster_secrets", map[string]int{"ref": 1}); err == nil {
		t.Fatal("closed required table")
	}
}

func TestApplySecretRetirementAndGenerationHelpers(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySecretRetirementInTx(ctx, tx, ClusterSecretRecord{Ref: "bad", RetireRecipients: &[]string{"p"}}); err == nil {
		_ = tx.Rollback()
		t.Fatal("invalid ref retirement")
	}
	_ = tx.Rollback()

	tx, err = st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applySecretRetirementInTx(ctx, tx, ClusterSecretRecord{Ref: secrets.FormatRef("sb-ret", "inc-ret", secrets.RefVersion)}); err != nil {
		_ = tx.Rollback()
		t.Fatalf("nil retire list: %v", err)
	}
	retire := []string{"old-peer"}
	if err := applySecretRetirementInTx(ctx, tx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-ret", "inc-ret", secrets.RefVersion),
		SandboxID: "sb-ret", SealGeneration: 2,
		Recipients: []string{"keep-peer"}, RetireRecipients: &retire,
	}); err != nil {
		_ = tx.Rollback()
		t.Fatalf("retire: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	tombTx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nextClusterSecretDeleteGenerationTx(ctx, tombTx, "sb-ret", "inc-ret"); err != nil {
		_ = tombTx.Rollback()
		t.Fatalf("next gen: %v", err)
	}
	_ = tombTx.Rollback()

	badTomb := newTestStore(t)
	if _, err := badTomb.db.ExecContext(ctx, `ALTER TABLE cluster_secret_tombs DROP COLUMN generation`); err != nil {
		t.Fatal(err)
	}
	tx, err = badTomb.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nextClusterSecretDeleteGenerationTx(ctx, tx, "sb", "inc"); err == nil {
		_ = tx.Rollback()
		t.Fatal("tomb generation scan")
	}
	_ = tx.Rollback()

	badSeal := newTestStore(t)
	if _, err := badSeal.db.ExecContext(ctx, `ALTER TABLE cluster_secrets DROP COLUMN seal_generation`); err != nil {
		t.Fatal(err)
	}
	tx, err = badSeal.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nextClusterSecretDeleteGenerationTx(ctx, tx, "sb", "inc"); err == nil {
		_ = tx.Rollback()
		t.Fatal("seal generation scan")
	}
	_ = tx.Rollback()
}

func TestStoreRemainingErrorPaths(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	if inc, err := st.CurrentSandboxAuditIncarnation(ctx, ""); err != nil || inc != "" {
		t.Fatalf("empty current inc = %q %v", inc, err)
	}
	if inc, err := st.LatestRetainedSandboxAuditIncarnation(ctx, ""); err != nil || inc != "" {
		t.Fatalf("empty retained inc = %q %v", inc, err)
	}

	now := time.Now().UTC()
	if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "slot-1", TemplateID: "tpl"}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "slot-1", "/tmp/api", "/tmp/run", 4, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl", "sb-vmm", now); err != nil {
		t.Fatal(err)
	}
	slot, err := st.GetFirecrackerVMMSlotBySandbox(ctx, "sb-vmm")
	if err != nil || slot == nil || slot.LoadedAt.IsZero() || slot.AllocatedAt.IsZero() {
		t.Fatalf("allocated slot = %+v err=%v", slot, err)
	}
	if err := st.ReleaseFirecrackerVMMSlot(ctx, "sb-vmm", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if released, err := st.GetFirecrackerVMMSlotByID(ctx, "slot-1"); err != nil || released == nil || released.ReleasedAt.IsZero() {
		t.Fatalf("released slot = %+v err=%v", released, err)
	}

	sb := sampleSandbox("sb-rollback")
	sb.AuditIncarnationID = "inc-rb"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.RollbackSandboxCreate(ctx, "", "inc-rb"); err != nil {
		t.Fatalf("empty rollback: %v", err)
	}
	if err := st.RollbackSandboxCreate(ctx, sb.ID, "inc-rb"); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	rbAbort := newTestStore(t)
	if err := rbAbort.Create(ctx, sampleSandbox("sb-rb-abort")); err != nil {
		t.Fatal(err)
	}
	if _, err := rbAbort.db.ExecContext(ctx, `
		CREATE TRIGGER abort_rb BEFORE DELETE ON sandboxes
		BEGIN SELECT RAISE(ABORT, 'blocked rollback'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := rbAbort.RollbackSandboxCreate(ctx, "sb-rb-abort", "inc"); err == nil {
		t.Fatal("rollback delete abort")
	}

	aclRB := newTestStore(t)
	aclSB := sampleSandbox("sb-acl-rb")
	aclSB.AuditIncarnationID = "inc-acl-rb"
	if err := aclRB.Create(ctx, aclSB); err != nil {
		t.Fatal(err)
	}
	if _, err := aclRB.db.ExecContext(ctx, `
		CREATE TRIGGER abort_acl_rb BEFORE DELETE ON sandbox_audit_acl
		BEGIN SELECT RAISE(ABORT, 'blocked acl rollback'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := aclRB.RollbackSandboxCreate(ctx, aclSB.ID, "inc-acl-rb"); err == nil {
		t.Fatal("rollback acl abort")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.Delete(ctx, "x"); err == nil {
		t.Fatal("delete closed")
	}
	if _, err := closed.CurrentSandboxAuditIncarnation(ctx, "x"); err == nil {
		t.Fatal("current inc closed")
	}
	if _, err := closed.LatestRetainedSandboxAuditIncarnation(ctx, "x"); err == nil {
		t.Fatal("retained inc closed")
	}
	if err := closed.RollbackSandboxCreate(ctx, "x", "inc"); err == nil {
		t.Fatal("rollback closed")
	}
	if _, err := closed.GetFirecrackerVMMSlotBySandbox(ctx, "sb"); err == nil {
		t.Fatal("vmm get closed")
	}

	if _, err := scanFirecrackerVMMSlot(lift2FakeSlotRow{err: errors.New("scan fail")}); err == nil {
		t.Fatal("scan error")
	}

	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := validateCurrentSecretSchema(db); err == nil {
		t.Fatal("missing sandboxes table")
	}
}

func TestStoreCoverage95MoreLift2(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	st.SetSecretCipher(ciph)

	tok := sampleSandbox("sb-seal-tok")
	tok.ToolboxToken = "guest-token"
	tok.AuditIncarnationID = "inc-tok"
	if err := st.Create(ctx, tok); err != nil {
		t.Fatalf("create sealed toolbox token: %v", err)
	}
	if err := st.CreateWithSealedEnv(ctx, sampleSandbox("sb-env"), []byte("sealed-env")); err != nil {
		t.Fatalf("CreateWithSealedEnv: %v", err)
	}
	if blob, err := st.GetEnv(ctx, "sb-env"); err != nil || string(blob) != "sealed-env" {
		t.Fatalf("GetEnv = %q err=%v", blob, err)
	}
	if _, err := st.GetEnv(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetEnv missing = %v", err)
	}
	if err := st.DeleteEnv(ctx, "sb-env"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetMounts(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMounts missing = %v", err)
	}

	now := time.Now().UTC()
	ready := now
	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-ready", Image: "img", Status: models.TemplateStatusReady, CreatedAt: now, UpdatedAt: now, ReadyAt: &ready}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-pending", Image: "img", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-nosnap", Image: "img", Status: models.TemplateStatusReadyNoSnapshot, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	readyIDs, catalog, err := st.ListTemplateInventoryIDs(ctx)
	if err != nil || len(catalog) < 3 || len(readyIDs) < 2 {
		t.Fatalf("inventory ready=%v catalog=%v err=%v", readyIDs, catalog, err)
	}
	if ids, err := st.ListReadyTemplateIDs(ctx); err != nil || len(ids) < 2 {
		t.Fatalf("ready ids=%v err=%v", ids, err)
	}

	if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "orphan-1", TemplateID: "tpl-ready"}, now); err != nil {
		t.Fatal(err)
	}
	n, err := st.ReleaseOrphanedFirecrackerVMMSlots(ctx, now)
	if err != nil || n < 1 {
		t.Fatalf("release orphans = %d err=%v", n, err)
	}

	id, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb-wasm", "registry/ref")
	if err != nil || id == 0 {
		t.Fatalf("ensure wasm = %d err=%v", id, err)
	}
	again, err := st.EnsureWasmCheckpointCleanupRef(ctx, "sb-wasm", "registry/ref")
	if err != nil || again != id {
		t.Fatalf("ensure wasm idempotent = %d want %d err=%v", again, id, err)
	}
	if _, err := st.EnsureWasmCheckpointCleanupRef(ctx, "", ""); err == nil {
		t.Fatal("empty wasm cleanup")
	}

	if err := st.SetFleetSuspended(ctx, tok.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFleetSuspended(ctx, "missing", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fleet missing = %v", err)
	}

	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "", "inc", nil, 1); err != nil {
		t.Fatalf("empty sandbox outbox: %v", err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb", "", nil, 1); err == nil {
		t.Fatal("empty incarnation")
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb", "inc", nil, 0); err == nil {
		t.Fatal("zero generation")
	}
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-out", "inc-out", []string{"peer-a"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-out", "inc-out", []string{"peer-b"}, 2); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-out", "inc-out", nil, 2); err != nil {
		t.Fatal(err)
	}

	if err := st.ApplyPeerSecretDelete(ctx, "", "inc", 1); err != nil {
		t.Fatalf("empty peer delete: %v", err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb", "", 1); err == nil {
		t.Fatal("peer delete empty incarnation")
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb", "inc", 0); err == nil {
		t.Fatal("peer delete zero gen")
	}
	ref := secrets.FormatRef("sb-peer", "inc-peer", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-peer", Version: 1, SealGeneration: 5, SealedPayload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-peer", "inc-peer", 4); err != nil {
		t.Fatalf("stale peer delete should ACK: %v", err)
	}
	if err := st.ApplyPeerSecretDelete(ctx, "sb-peer", "inc-peer", 5); err != nil {
		t.Fatalf("peer delete current gen: %v", err)
	}

	rec, created, err := st.ClaimIdempotentRequest(ctx, "scope", "fp-1", now, time.Minute)
	if err != nil || !created || rec == nil {
		t.Fatalf("claim insert = %+v created=%v err=%v", rec, created, err)
	}
	rec2, created, err := st.ClaimIdempotentRequest(ctx, "scope", "fp-1", now, time.Minute)
	if err != nil || created {
		t.Fatalf("claim existing created=%v err=%v rec=%+v", created, err, rec2)
	}
	if _, _, err := st.ClaimIdempotentRequest(ctx, "", "fp", now, time.Minute); err == nil {
		t.Fatal("empty scope")
	}
	if _, _, err := st.ClaimIdempotentRequest(ctx, "scope", "", now, time.Minute); err == nil {
		t.Fatal("empty fingerprint")
	}

	if err := st.CreateTemplate(ctx, nil); err == nil {
		t.Fatal("nil template")
	}
	if err := st.CreateTemplate(ctx, &models.Template{ID: "bad id!", Image: "img"}); err == nil {
		t.Fatal("invalid template id")
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.Create(ctx, sampleSandbox("x")); err == nil {
		t.Fatal("create closed")
	}
	if err := closed.CreateWithSealedEnv(ctx, sampleSandbox("x"), []byte("e")); err == nil {
		t.Fatal("create+env closed")
	}
	if _, _, err := closed.ListTemplateInventoryIDs(ctx); err == nil {
		t.Fatal("inventory closed")
	}
	if _, err := closed.GetEnv(ctx, "x"); err == nil {
		t.Fatal("getenv closed")
	}
	if _, err := closed.ReleaseOrphanedFirecrackerVMMSlots(ctx, now); err == nil {
		t.Fatal("orphans closed")
	}
	if _, err := closed.EnsureWasmCheckpointCleanupRef(ctx, "sb", "ref"); err == nil {
		t.Fatal("wasm closed")
	}
	if err := closed.SetFleetSuspended(ctx, "x", true); err == nil {
		t.Fatal("fleet closed")
	}
	if err := closed.UpdateSecretDeleteOutboxRecipients(ctx, "sb", "inc", []string{"p"}, 1); err == nil {
		t.Fatal("outbox update closed")
	}
	if err := closed.ApplyPeerSecretDelete(ctx, "sb", "inc", 1); err == nil {
		t.Fatal("peer delete closed")
	}
	if _, _, err := closed.ClaimIdempotentRequest(ctx, "s", "f", now, time.Second); err == nil {
		t.Fatal("claim closed")
	}
}

func TestStoreUncoveredGuardsAndSQLErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	empty := &models.Sandbox{}
	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.Create(ctx, empty); err == nil {
		t.Fatal("create begin on closed empty identity")
	}
	if err := closed.CreateWithSealedEnv(ctx, empty, []byte("env")); err == nil {
		t.Fatal("create+env begin on closed empty identity")
	}
	emptyInc := &models.Sandbox{AuditIncarnationID: "inc"}
	if err := closed.Upsert(ctx, emptyInc); err == nil {
		t.Fatal("upsert begin on closed empty identity")
	}

	acl := newTestStore(t)
	if _, err := acl.db.ExecContext(ctx, `
		CREATE TRIGGER abort_create_acl BEFORE INSERT ON sandbox_audit_acl
		BEGIN SELECT RAISE(ABORT, 'blocked create acl'); END;
	`); err != nil {
		t.Fatal(err)
	}
	sb := sampleSandbox("sb-create-acl")
	sb.AuditIncarnationID = "inc-create-acl"
	if err := acl.Create(ctx, sb); err == nil {
		t.Fatal("create acl abort")
	}
	envSB := sampleSandbox("sb-env-acl")
	envSB.AuditIncarnationID = "inc-env-acl"
	if err := acl.CreateWithSealedEnv(ctx, envSB, []byte("e")); err == nil {
		t.Fatal("create+env acl abort")
	}

	if err := st.RemoveCustomDomain(ctx, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove domain empty = %v", err)
	}
	if err := st.SetCustomDomainStatus(ctx, "", models.CustomDomainReady, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set domain empty = %v", err)
	}
	if ok, err := st.IsTemplateReferenced(ctx, ""); err != nil || ok {
		t.Fatalf("template ref empty = %v %v", ok, err)
	}
	if ok, err := st.IsTemplateReferencedByVMM(ctx, ""); err != nil || ok {
		t.Fatalf("vmm ref empty = %v %v", ok, err)
	}
	if rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "", ""); err != nil || rec != nil {
		t.Fatalf("delete outbox empty = %+v %v", rec, err)
	}
	if rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "", "inc"); err != nil || rec != nil {
		t.Fatalf("put outbox empty = %+v %v", rec, err)
	}

	now := time.Now().UTC()
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_delete_outbox (sandbox_id, incarnation_id, recipients_json, generation, awaiting_promotion, attempts, created_at, updated_at)
		VALUES ('sb-bad-json', 'inc-bad', '{not-json', 1, 0, 0, ?, ?)
	`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-bad-json", "inc-bad"); err == nil {
		t.Fatal("corrupt delete outbox json")
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_put_outbox (sandbox_id, incarnation_id, seal_generation, recipients_json, attempts, created_at, updated_at)
		VALUES ('sb-bad-json', 'inc-bad', 1, '{not-json', 0, ?, ?)
	`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-bad-json", "inc-bad"); err == nil {
		t.Fatal("corrupt put outbox json")
	}

	ref := secrets.FormatRef("sb-idem-tomb", "inc-idem", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-idem-tomb", Version: 1, SealGeneration: 4, SealedPayload: []byte("same")}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_tombs (sandbox_id, incarnation_id, deleted_at, generation)
		VALUES ('sb-idem-tomb', 'inc-idem', ?, 1)
	`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER abort_idem_tomb BEFORE DELETE ON cluster_secret_tombs
		BEGIN SELECT RAISE(ABORT, 'blocked idempotent tomb clear'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-idem-tomb", Version: 1, SealGeneration: 4, SealedPayload: []byte("same")}); err == nil {
		t.Fatal("idempotent tomb clear abort")
	}

	if n, err := st.PruneClusterSecretTombs(ctx, time.Time{}, 10); err != nil || n != 0 {
		t.Fatalf("prune zero cutoff = %d %v", n, err)
	}
	if n, err := st.DeleteOrphanedWasmStateKV(ctx, 0); err != nil {
		t.Fatalf("orphan kv default limit: %v (n=%d)", err, n)
	}
	if _, err := st.WasmDigestsInUse(ctx, []string{"deadbeef"}); err != nil {
		t.Fatal(err)
	}

	drop := newTestStore(t)
	if _, err := drop.db.ExecContext(ctx, `DROP TABLE cluster_secret_delete_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := drop.GetSecretDeleteOutboxForIncarnation(ctx, "sb", "inc"); err == nil {
		t.Fatal("delete outbox scan after drop")
	}
	if _, err := drop.SecretLifecycleStats(ctx); err == nil {
		t.Fatal("lifecycle stats after drop")
	}

	scanPut := newTestStore(t)
	if _, err := scanPut.db.ExecContext(ctx, `DROP TABLE cluster_secret_put_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := scanPut.GetSecretPutOutboxForIncarnation(ctx, "sb", "inc"); err == nil {
		t.Fatal("put outbox scan after drop")
	}

	if _, err := closed.IsTemplateReferenced(ctx, "tpl"); err == nil {
		t.Fatal("template ref closed")
	}
	if _, err := closed.IsTemplateReferencedByVMM(ctx, "tpl"); err == nil {
		t.Fatal("vmm ref closed")
	}
	if _, err := closed.WasmDigestsInUse(ctx, []string{"d"}); err == nil {
		t.Fatal("wasm digests closed")
	}
	if _, err := closed.MarkTemplateUnhealthy(ctx, "tpl", "x"); err == nil {
		t.Fatal("unhealthy closed")
	}
	if _, err := closed.MarkTemplatePushPending(ctx, "tpl"); err == nil {
		t.Fatal("push pending closed")
	}
	if _, err := closed.TryReserveHostPort(ctx, "sb", 80, 18000, "tcp", "http://x", now); err == nil {
		t.Fatal("reserve port closed")
	}
	if _, err := closed.DeleteOrphanedWasmStateKV(ctx, 8); err == nil {
		t.Fatal("orphan kv closed")
	}
	if _, err := closed.PruneClusterSecretTombs(ctx, now, 8); err == nil {
		t.Fatal("prune tombs closed")
	}
	if err := closed.RemoveCustomDomain(ctx, "sb", "host.example"); err == nil {
		t.Fatal("remove domain closed")
	}
	if err := closed.SetCustomDomainStatus(ctx, "host.example", models.CustomDomainReady, ""); err == nil {
		t.Fatal("set domain closed")
	}
}

func TestStoreUncoveredSecretAndLookupErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	ref := secrets.FormatRef("sb-side", "inc-side", secrets.RefVersion)

	if err := st.CreateTemplate(ctx, &models.Template{ID: "has space", Image: "img"}); err == nil {
		t.Fatal("invalid template id")
	}

	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-side", Version: 1, SealGeneration: 2, SealedPayload: []byte("p")}); err != nil {
		t.Fatal(err)
	}

	retireAbort := newTestStore(t)
	if _, err := retireAbort.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-side", Version: 1, SealGeneration: 2, SealedPayload: []byte("p")}); err != nil {
		t.Fatal(err)
	}
	if _, err := retireAbort.db.ExecContext(ctx, `
		CREATE TRIGGER abort_retire BEFORE INSERT ON cluster_secret_delete_outbox
		BEGIN SELECT RAISE(ABORT, 'blocked retire'); END;
	`); err != nil {
		t.Fatal(err)
	}
	retire := []string{"old"}
	if _, err := retireAbort.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-side", Version: 1, SealGeneration: 2, SealedPayload: []byte("p"), RetireRecipients: &retire}); err == nil {
		t.Fatal("idempotent retire abort")
	}
	if _, err := retireAbort.PutClusterSecret(ctx, ClusterSecretRecord{Ref: secrets.FormatRef("sb-new", "inc-new", secrets.RefVersion), SandboxID: "sb-new", Version: 1, SealGeneration: 1, SealedPayload: []byte("n"), RetireRecipients: &retire}); err == nil {
		t.Fatal("insert-path retire abort")
	}

	outboxAbort := newTestStore(t)
	if _, err := outboxAbort.PutClusterSecret(ctx, ClusterSecretRecord{Ref: ref, SandboxID: "sb-side", Version: 1, SealGeneration: 2, SealedPayload: []byte("p")}); err != nil {
		t.Fatal(err)
	}
	if _, err := outboxAbort.db.ExecContext(ctx, `
		CREATE TRIGGER abort_put_ob BEFORE INSERT ON cluster_secret_put_outbox
		BEGIN SELECT RAISE(ABORT, 'blocked put outbox'); END;
	`); err != nil {
		t.Fatal(err)
	}
	peers := []string{"peer"}
	if _, err := outboxAbort.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-side", Version: 1, SealGeneration: 2, SealedPayload: []byte("p"),
		PutOutboxRecipients: &peers, PutOutboxIncarnationID: "inc-side",
	}); err == nil {
		t.Fatal("idempotent put-outbox abort")
	}

	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyPutOutboxInTx(ctx, tx, ClusterSecretRecord{Ref: "bad"}); err == nil {
		_ = tx.Rollback()
		t.Fatal("invalid put-outbox ref")
	}
	_ = tx.Rollback()

	clearOB := newTestStore(t)
	seedPeers := []string{"peer"}
	if _, err := clearOB.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-clr", "inc-clr", secrets.RefVersion),
		SandboxID: "sb-clr", Version: 1, SealGeneration: 1, SealedPayload: []byte("x"),
		PutOutboxRecipients: &seedPeers, PutOutboxIncarnationID: "inc-clr",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := clearOB.db.ExecContext(ctx, `
		CREATE TRIGGER abort_clear_ob BEFORE DELETE ON cluster_secret_put_outbox
		BEGIN SELECT RAISE(ABORT, 'blocked clear'); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := clearOB.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-clr", "inc-clr", secrets.RefVersion),
		SandboxID: "sb-clr", Version: 1, SealGeneration: 2, SealedPayload: []byte("y"),
	}); err == nil {
		t.Fatal("nil put-outbox clear abort")
	}
	emptyPeers := []string{}
	if _, err := clearOB.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-clr", "inc-clr", secrets.RefVersion),
		SandboxID: "sb-clr", Version: 1, SealGeneration: 2, SealedPayload: []byte("y"),
		PutOutboxRecipients: &emptyPeers,
	}); err == nil {
		t.Fatal("empty put-outbox clear abort")
	}

	if err := st.UpdateSecretDeleteOutboxRecipients(ctx, "sb-miss", "inc-miss", nil, 1); err != nil {
		t.Fatal(err)
	}
	delOB := newTestStore(t)
	if _, err := delOB.db.ExecContext(ctx, `DROP TABLE cluster_secret_delete_outbox`); err != nil {
		t.Fatal(err)
	}
	if err := delOB.UpdateSecretDeleteOutboxRecipients(ctx, "sb", "inc", nil, 1); err == nil {
		t.Fatal("update delete-outbox after drop")
	}

	peerScan := newTestStore(t)
	if _, err := peerScan.db.ExecContext(ctx, `ALTER TABLE cluster_secrets DROP COLUMN seal_generation`); err != nil {
		t.Fatal(err)
	}
	if err := peerScan.ApplyPeerSecretDelete(ctx, "sb", "inc", 1); err == nil {
		t.Fatal("peer delete secret scan")
	}
	tombScan := newTestStore(t)
	if _, err := tombScan.db.ExecContext(ctx, `ALTER TABLE cluster_secret_tombs DROP COLUMN generation`); err != nil {
		t.Fatal(err)
	}
	if err := tombScan.ApplyPeerSecretDelete(ctx, "sb", "inc", 1); err == nil {
		t.Fatal("peer delete tomb scan")
	}

	stats := newTestStore(t)
	if _, err := stats.db.ExecContext(ctx, `DROP TABLE cluster_secret_put_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := stats.SecretLifecycleStats(ctx); err == nil {
		t.Fatal("stats without put outbox")
	}
	stats2 := newTestStore(t)
	if _, err := stats2.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_delete_outbox (sandbox_id, incarnation_id, recipients_json, generation, awaiting_promotion, attempts, created_at, updated_at)
		VALUES ('sb', 'inc', '[]', 1, 0, 0, ?, ?)
	`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := stats2.db.ExecContext(ctx, `DROP TABLE cluster_secret_tombs`); err != nil {
		t.Fatal(err)
	}
	if _, err := stats2.SecretLifecycleStats(ctx); err == nil {
		t.Fatal("stats without tombs")
	}

	nameCheck := newTestStore(t)
	if _, err := nameCheck.db.ExecContext(ctx, `DROP TABLE sandboxes`); err != nil {
		t.Fatal(err)
	}
	named := sampleSandbox("sb-name-check")
	named.Name = "has-a-name"
	if err := nameCheck.Create(ctx, named); err == nil {
		t.Fatal("name availability query after drop")
	}

	if _, err := st.List(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListByOwner(ctx, "nobody"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListByRuntime(ctx, models.RuntimeGvisor); err != nil {
		t.Fatal(err)
	}
}

func TestStoreLastNineLines(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-noimg", Image: ""}); err == nil {
		t.Fatal("empty image")
	}
	if _, err := st.DeletePendingImageGCIfScheduledAt(ctx, "", time.Now()); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if err := st.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "race-1", TemplateID: "tpl-race"}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkFirecrackerVMMSlotLoaded(ctx, "race-1", "/tmp/api", "/tmp/run", 5, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		CREATE TRIGGER skip_vmm_alloc BEFORE UPDATE ON firecracker_vmm_pool
		BEGIN SELECT RAISE(IGNORE); END;
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AllocateFirecrackerVMMSlot(ctx, "tpl-race", "sb-race", now); err == nil {
		t.Fatal("contested allocate")
	}

	scan := newTestStore(t)
	if err := scan.InsertFirecrackerVMMSlot(ctx, FirecrackerVMMSlot{ID: "scan-1", TemplateID: "tpl-scan"}, now); err != nil {
		t.Fatal(err)
	}
	if err := scan.MarkFirecrackerVMMSlotLoaded(ctx, "scan-1", "/tmp/api", "/tmp/run", 6, now); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.db.ExecContext(ctx, `ALTER TABLE firecracker_vmm_pool DROP COLUMN loaded_at`); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.AllocateFirecrackerVMMSlot(ctx, "tpl-scan", "sb-scan", now); err == nil {
		t.Fatal("allocate scan error")
	}

	if err := st.SchedulePendingImageGC(ctx, "img-x", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RefreshPendingImageGCIfExists(ctx, "img-x", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeletePendingImageGCIfScheduledAt(ctx, "img-x", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	vol := &models.Volume{ID: "vol-1", Tenant: "t1", Name: "data", Backend: "s3", Source: "s3://b/k"}
	if err := st.CreateVolume(ctx, vol); err != nil {
		t.Fatal(err)
	}
	afterVolumeBeforeCount = func(*sql.Tx) {}
	t.Cleanup(func() { afterVolumeBeforeCount = nil })
	if _, _, err := st.GetOrCreateVolume(ctx, &models.Volume{ID: "vol-2", Tenant: "t1", Name: "other", Backend: "s3", Source: "s3://b/o"}, 10); err != nil {
		t.Fatalf("GetOrCreateVolume with count hook: %v", err)
	}

	noACL := sampleSandbox("sb-vol-noacl")
	noACL.AuditIncarnationID = ""
	if err := st.Create(ctx, noACL); err != nil {
		t.Fatal(err)
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t1", VolumeID: "vol-1", SandboxID: noACL.ID, IncarnationID: "inc-x",
		Target: "/data", Source: "src",
	}}); err == nil {
		t.Fatal("attachment without live incarnation")
	}

	aclDrop := newTestStore(t)
	if err := aclDrop.CreateVolume(ctx, &models.Volume{ID: "vol-x", Tenant: "t", Name: "n", Backend: "s3"}); err != nil {
		t.Fatal(err)
	}
	if err := aclDrop.Create(ctx, sampleSandbox("sb-acl-drop")); err != nil {
		t.Fatal(err)
	}
	if _, err := aclDrop.db.ExecContext(ctx, `DROP TABLE sandbox_audit_acl`); err != nil {
		t.Fatal(err)
	}
	if err := aclDrop.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t", VolumeID: "vol-x", SandboxID: "sb-acl-drop", IncarnationID: "inc",
		Target: "/data", Source: "src",
	}}); err == nil {
		t.Fatal("attachment after acl drop")
	}

	if err := st.SeedContainerNetnsSlot(ctx, "ns-1", now); err != nil {
		t.Fatal(err)
	}
	afterNetnsFreeSelect = func(string) {}
	t.Cleanup(func() { afterNetnsFreeSelect = nil })
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-ns", now); err != nil {
		t.Fatalf("reserve netns: %v", err)
	}

	closed := newTestStore(t)
	_ = closed.Close()
	if err := closed.CreateVolume(ctx, &models.Volume{ID: "v", Tenant: "t", Name: "n", Backend: "s3"}); err == nil {
		t.Fatal("create volume closed")
	}
	if _, err := closed.CountVolumes(ctx, "t"); err == nil {
		t.Fatal("count volumes closed")
	}
	if err := closed.DeleteVolume(ctx, "t", "v"); err == nil {
		t.Fatal("delete volume closed")
	}
}

func TestStoreCross95HooksAndScanErrors(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	tap := newTestStore(t)
	if err := tap.SeedFirecrackerTapSlot(ctx, FirecrackerTapSlot{
		TapName: "tap-x", CIDR: "10.9.0.0/30", HostIP: "10.9.0.1", GuestIP: "10.9.0.2", VsockCID: 8,
	}, now); err != nil {
		t.Fatal(err)
	}
	afterTapAllocateSelect = func(string) {}
	t.Cleanup(func() { afterTapAllocateSelect = nil })
	if _, err := tap.AllocateFirecrackerTapSlot(ctx, "sb-tap", now); err != nil {
		t.Fatalf("allocate tap: %v", err)
	}

	afterVolumeMissSelect = func(tx *sql.Tx) {
		_, _ = tx.ExecContext(ctx, `
			INSERT INTO volumes (id, tenant, name, backend, source, created_at)
			VALUES ('vol-race', 't-race', 'shared', 's3', 's3://b/k', ?)
		`, now)
	}
	t.Cleanup(func() { afterVolumeMissSelect = nil })
	if _, created, err := tap.GetOrCreateVolume(ctx, &models.Volume{ID: "vol-loser", Tenant: "t-race", Name: "shared", Backend: "s3", Source: "s3://b/k"}, 0); err != nil || created {
		t.Fatalf("raced volume created=%v err=%v", created, err)
	}

	ns := newTestStore(t)
	if err := ns.SeedContainerNetnsSlot(ctx, "ns-scan", now); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.db.ExecContext(ctx, `ALTER TABLE container_netns_slots DROP COLUMN state`); err != nil {
		t.Fatal(err)
	}
	if _, err := ns.ReserveContainerNetnsSlot(ctx, "sb-ns-scan", now); err == nil {
		t.Fatal("reserve after drop state")
	}

	claim := newTestStore(t)
	if err := claim.SeedContainerNetnsSlot(ctx, "ns-pool", now); err != nil {
		t.Fatal(err)
	}
	pre, err := claim.BeginPrewarmContainerNetnsSlot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.FinishPrewarmContainerNetnsSlot(ctx, pre.SlotID, "/var/run/netns/x", "10.1.0.2", now); err != nil {
		t.Fatal(err)
	}
	if _, err := claim.db.ExecContext(ctx, `ALTER TABLE container_netns_slots DROP COLUMN state`); err != nil {
		t.Fatal(err)
	}
	if _, err := claim.ClaimPooledContainerNetnsSlot(ctx, "sb-claim", now); err == nil {
		t.Fatal("claim after drop state")
	}
}

func TestStoreCross95EmptyGuards(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := upsertSandboxAuditACLExec(ctx, st.db, "", "owner", "", time.Now()); err == nil {
		t.Fatal("empty acl ids")
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := upsertSecretDeleteOutboxTx(ctx, tx, "", "inc", nil, nil, 1, false); err != nil {
		_ = tx.Rollback()
		t.Fatalf("empty sandbox outbox: %v", err)
	}
	if err := upsertSecretDeleteOutboxTx(ctx, tx, "sb", "", []string{"peer"}, nil, 1, false); err == nil {
		_ = tx.Rollback()
		t.Fatal("empty incarnation outbox")
	}
	_ = tx.Rollback()
	if err := st.BumpSecretPutOutboxAttempt(ctx, "", "inc", 1); err == nil {
		t.Fatal("bump empty sandbox")
	}
	if err := st.DeleteSecretPutOutbox(ctx, "", "inc", 1); err == nil {
		t.Fatal("delete put-outbox empty sandbox")
	}

	path := filepath.Join(t.TempDir(), "tok.db")
	sealed, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ciph, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	sealed.SetSecretCipher(ciph)
	sb := sampleSandbox("sb-open-tok")
	sb.ToolboxToken = "guest"
	if err := sealed.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	_ = sealed.Close()
	reopen, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopen.Close() })
	if _, err := reopen.Get(ctx, sb.ID); err == nil {
		t.Fatal("get sealed token without cipher")
	}
}

type lift2FakeSlotRow struct{ err error }

func (f lift2FakeSlotRow) Scan(...any) error { return f.err }
