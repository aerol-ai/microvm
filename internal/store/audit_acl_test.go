package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSandboxAuditACLAtomicCreateAndRetentionPrune(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	sb := sampleSandbox("sb-audit-acl")
	sb.OwnerRef = "tenant-a"
	sb.AuditIncarnationID = "inc-live-a"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, sb.ID, sb.AuditIncarnationID); err != nil || got != "tenant-a" {
		t.Fatalf("atomic create ACL=%q err=%v", got, err)
	}

	old := now.Add(-48 * time.Hour)
	if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_audit_acl SET updated_at = ? WHERE sandbox_id = ?`, old, sb.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneSandboxAuditACL(ctx, now.Add(-24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("live ACL prune=%d err=%v, want 0", n, err)
	}
	if err := st.Delete(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneSandboxAuditACL(ctx, now.Add(-24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("deleted ACL prune=%d err=%v, want 1", n, err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, sb.ID, sb.AuditIncarnationID); err != nil || got != "" {
		t.Fatalf("ACL after retention prune=%q err=%v", got, err)
	}

	sealed := sampleSandbox("sb-audit-sealed")
	sealed.OwnerRef = "tenant-b"
	sealed.AuditIncarnationID = "inc-live-b"
	sealed.Env = map[string]string{"TOKEN": "secret"}
	if err := st.CreateWithSealedEnv(ctx, sealed, []byte("sealed-env")); err != nil {
		t.Fatalf("CreateWithSealedEnv: %v", err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, sealed.ID, sealed.AuditIncarnationID); err != nil || got != "tenant-b" {
		t.Fatalf("sealed create ACL=%q err=%v", got, err)
	}

	// Distinct incarnations coexist under the compound PK.
	if err := st.UpsertSandboxAuditACL(ctx, "sb-inc", "tenant-c", "inc-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandboxAuditACL(ctx, "sb-inc", "tenant-d", "inc-b"); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, "sb-inc", "inc-a"); err != nil || got != "tenant-c" {
		t.Fatalf("inc-a ACL=%q err=%v", got, err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, "sb-inc", "inc-b"); err != nil || got != "tenant-d" {
		t.Fatalf("inc-b ACL=%q err=%v", got, err)
	}
}

func TestSandboxAuditACLAtomicUpsertAndLifecycleFence(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-upsert-acl")
	sb.OwnerRef = "tenant-a"
	sb.AuditIncarnationID = "inc-upsert"
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatalf("Upsert insert: %v", err)
	}
	if got, err := st.CurrentSandboxAuditIncarnation(ctx, sb.ID); err != nil || got != sb.AuditIncarnationID {
		t.Fatalf("CurrentSandboxAuditIncarnation = %q, %v", got, err)
	}

	replacement := *sb
	replacement.AuditIncarnationID = "inc-replacement"
	if err := st.Upsert(ctx, &replacement); err == nil || !strings.Contains(err.Error(), "incarnation conflict") {
		t.Fatalf("Upsert lifecycle replacement error = %v, want incarnation conflict", err)
	}
	if got, err := st.CurrentSandboxAuditIncarnation(ctx, sb.ID); err != nil || got != sb.AuditIncarnationID {
		t.Fatalf("lifecycle changed after rejected upsert: %q, %v", got, err)
	}
}

func TestSandboxAuditACLRetainsOwnerlessOperatorEvidence(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-operator-audit")
	sb.OwnerRef = ""
	sb.AuditIncarnationID = "inc-operator"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	exists, err := st.HasSandboxAuditACL(ctx, sb.ID, sb.AuditIncarnationID)
	if err != nil || !exists {
		t.Fatalf("ownerless audit ACL exists=%v err=%v", exists, err)
	}
	if err := st.UpsertSandboxAuditACL(ctx, sb.ID, "", sb.AuditIncarnationID); err != nil {
		t.Fatalf("UpsertSandboxAuditACL: %v", err)
	}
	exists, err = st.HasSandboxAuditACL(ctx, sb.ID, sb.AuditIncarnationID)
	if err != nil || !exists {
		t.Fatalf("ownerless incarnation ACL exists=%v err=%v", exists, err)
	}
}

func TestSandboxAuditACLRejectsMissingLifecycle(t *testing.T) {
	st := newTestStore(t)
	if err := st.UpsertSandboxAuditACL(context.Background(), "sb", "tenant-a", ""); err == nil {
		t.Fatal("missing incarnation must be rejected")
	}
	if exists, err := st.HasSandboxAuditACL(context.Background(), "sb", ""); err != nil || exists {
		t.Fatalf("empty incarnation lookup = %v, %v", exists, err)
	}
}

func TestSandboxAuditACLPrunesOldIncarnationWhileReusedIDIsLive(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.UpsertSandboxAuditACL(ctx, "sb-reused-live", "tenant-old", "inc-old"); err != nil {
		t.Fatal(err)
	}
	sb := sampleSandbox("sb-reused-live")
	sb.OwnerRef = "tenant-new"
	sb.AuditIncarnationID = "inc-new"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_audit_acl SET updated_at = ? WHERE sandbox_id = ? AND incarnation_id = ?`, old, sb.ID, "inc-old"); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneSandboxAuditACL(ctx, time.Now().UTC().Add(-24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("reused live ACL prune=%d err=%v, want 1", n, err)
	}
	if exists, err := st.HasSandboxAuditACL(ctx, sb.ID, "inc-old"); err != nil || exists {
		t.Fatalf("old lifecycle retained=%v err=%v", exists, err)
	}
	if exists, err := st.HasSandboxAuditACL(ctx, sb.ID, "inc-new"); err != nil || !exists {
		t.Fatalf("current lifecycle retained=%v err=%v", exists, err)
	}
}

func TestSandboxAuditACLRejectsStaleRefreshAcrossIDReuse(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if err := st.UpsertSandboxAuditACL(ctx, "sb-reused", "tenant-old", "inc-old"); err != nil {
		t.Fatal(err)
	}
	replacement := sampleSandbox("sb-reused")
	replacement.OwnerRef = "tenant-new"
	replacement.AuditIncarnationID = "inc-new"
	if err := st.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}

	if err := st.UpsertSandboxAuditACL(ctx, replacement.ID, "tenant-old", "inc-old"); err == nil {
		t.Fatal("stale lifecycle refreshed retained ACL while replacement was live")
	}
	if got, err := st.CurrentSandboxAuditIncarnation(ctx, replacement.ID); err != nil || got != "inc-new" {
		t.Fatalf("current incarnation after stale refresh = %q, err=%v", got, err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, replacement.ID, "inc-new"); err != nil || got != "tenant-new" {
		t.Fatalf("replacement ACL after stale refresh = %q, err=%v", got, err)
	}
}

func TestSandboxReadsUseExactLifecyclePointerAcrossClockSkew(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const sandboxID = "sb-clock-skew"
	if err := st.UpsertSandboxAuditACL(ctx, sandboxID, "tenant-old", "inc-old"); err != nil {
		t.Fatal(err)
	}
	// A retained record can carry an arbitrarily later timestamp after clock
	// correction. It must never become the live lifecycle by sort order.
	if _, err := st.db.ExecContext(ctx, `
		UPDATE sandbox_audit_acl SET updated_at = ?
		WHERE sandbox_id = ? AND incarnation_id = ?
	`, time.Now().UTC().Add(365*24*time.Hour), sandboxID, "inc-old"); err != nil {
		t.Fatal(err)
	}

	sb := sampleSandbox(sandboxID)
	sb.OwnerRef = "tenant-new"
	sb.Runtime = "wasm"
	sb.AuditIncarnationID = "inc-new"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}

	assertLifecycle := func(label string, got []*models.Sandbox, err error) {
		t.Helper()
		if err != nil || len(got) != 1 || got[0].AuditIncarnationID != "inc-new" {
			t.Fatalf("%s lifecycle = %+v, err=%v", label, got, err)
		}
	}
	point, err := st.Get(ctx, sandboxID)
	if err != nil || point.AuditIncarnationID != "inc-new" {
		t.Fatalf("Get lifecycle = %+v, err=%v", point, err)
	}
	all, err := st.List(ctx)
	assertLifecycle("List", all, err)
	owned, err := st.ListByOwner(ctx, "tenant-new")
	assertLifecycle("ListByOwner", owned, err)
	wasm, err := st.ListByRuntime(ctx, "wasm")
	assertLifecycle("ListByRuntime", wasm, err)
	if got, err := st.CurrentSandboxAuditIncarnation(ctx, sandboxID); err != nil || got != "inc-new" {
		t.Fatalf("CurrentSandboxAuditIncarnation = %q, err=%v", got, err)
	}
	if err := st.Delete(ctx, sandboxID); err != nil {
		t.Fatal(err)
	}
	if got, err := st.LatestRetainedSandboxAuditIncarnation(ctx, sandboxID); err != nil || got != "inc-new" {
		t.Fatalf("LatestRetainedSandboxAuditIncarnation = %q, err=%v", got, err)
	}
}

func TestRollbackSandboxCreateRemovesAuditExistenceRecord(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-create-rollback")
	sb.OwnerRef = "tenant-a"
	if err := st.UpsertSandboxAuditACL(ctx, sb.ID, "tenant-old", "inc-old"); err != nil {
		t.Fatal(err)
	}
	sb.AuditIncarnationID = "inc-aborted"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.RollbackSandboxCreate(ctx, sb.ID, sb.AuditIncarnationID); err != nil {
		t.Fatalf("RollbackSandboxCreate: %v", err)
	}
	if _, err := st.Get(ctx, sb.ID); err != ErrNotFound {
		t.Fatalf("sandbox after rollback = %v, want ErrNotFound", err)
	}
	if exists, err := st.HasSandboxAuditACL(ctx, sb.ID, "inc-aborted"); err != nil || exists {
		t.Fatalf("aborted audit ACL exists=%v err=%v", exists, err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, sb.ID, "inc-old"); err != nil || got != "tenant-old" {
		t.Fatalf("prior retained ACL=%q err=%v", got, err)
	}
}

func TestSecretDeleteOutboxBatchRotatesAttemptedRows(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 70; i++ {
		id := fmt.Sprintf("sb-outbox-%02d", i)
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO cluster_secret_delete_outbox
				(sandbox_id, incarnation_id, recipients_json, generation, attempts, created_at, updated_at)
			VALUES (?, ?, '["peer"]', 1, 0, ?, ?)
		`, id, "inc-"+id, base.Add(time.Duration(i)*time.Second), base); err != nil {
			t.Fatal(err)
		}
	}
	first, err := st.ListSecretDeleteOutboxBatch(ctx, 64)
	if err != nil || len(first) != 64 {
		t.Fatalf("first batch len=%d err=%v", len(first), err)
	}
	for _, rec := range first {
		if err := st.BumpSecretDeleteOutboxAttempt(ctx, rec.SandboxID, rec.IncarnationID, rec.Generation); err != nil {
			t.Fatal(err)
		}
	}
	second, err := st.ListSecretDeleteOutboxBatch(ctx, 64)
	if err != nil || len(second) != 64 {
		t.Fatalf("second batch len=%d err=%v", len(second), err)
	}
	seenNew := 0
	for _, rec := range second {
		if rec.SandboxID >= "sb-outbox-64" {
			seenNew++
		}
	}
	if seenNew != 6 {
		t.Fatalf("unattempted rows in second batch=%d, want 6", seenNew)
	}
}

func TestClusterSecretTombPruneIsBoundedAndPreservesLiveState(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	for _, id := range []string{"eligible-a", "eligible-b", "pending", "live", "sealed"} {
		if _, err := st.db.ExecContext(ctx, `
			INSERT INTO cluster_secret_tombs (sandbox_id, incarnation_id, deleted_at, generation)
			VALUES (?, ?, ?, 1)
		`, id, "inc-"+id, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_tombs (sandbox_id, incarnation_id, deleted_at, generation)
		VALUES ('recent', 'inc-recent', ?, 1)
	`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secret_delete_outbox
			(sandbox_id, incarnation_id, recipients_json, generation, attempts, created_at, updated_at)
		VALUES ('pending', 'inc-pending', '["peer"]', 1, 0, ?, ?)
	`, old, old); err != nil {
		t.Fatal(err)
	}
	live := sampleSandbox("live")
	if err := st.Create(ctx, live); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `
		INSERT INTO cluster_secrets
			(ref, sandbox_id, version, recipients_json, sealed_payload, seal_generation, created_at, updated_at)
		VALUES ('secret://sealed', 'sealed', 1, '[]', X'01', 1, ?, ?)
	`, old, old); err != nil {
		t.Fatal(err)
	}

	cutoff := now.Add(-24 * time.Hour)
	if n, err := st.PruneClusterSecretTombs(ctx, cutoff, 1); err != nil || n != 1 {
		t.Fatalf("first prune=%d err=%v, want 1", n, err)
	}
	if n, err := st.PruneClusterSecretTombs(ctx, cutoff, 1); err != nil || n != 1 {
		t.Fatalf("second prune=%d err=%v, want 1", n, err)
	}
	for _, id := range []string{"pending", "live", "sealed", "recent"} {
		generation, err := st.ClusterSecretTombGenerationForIncarnation(ctx, id, "inc-"+id)
		if err != nil || generation == 0 {
			t.Fatalf("protected tomb %q generation=%d err=%v", id, generation, err)
		}
	}
	stats, err := st.SecretLifecycleStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OutboxPending != 1 || stats.Tombstones != 4 || stats.OldestOutbox.IsZero() {
		t.Fatalf("stats = %+v, want pending=1 tombstones=4 with oldest", stats)
	}
}

func TestCurrentSandboxAuditIdentityOneRead(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-identity")
	sb.OwnerRef = "tenant-z"
	sb.AuditIncarnationID = "inc-z"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	inc, owner, err := st.CurrentSandboxAuditIdentity(ctx, sb.ID)
	if err != nil || inc != "inc-z" || owner != "tenant-z" {
		t.Fatalf("identity = (%q, %q, %v)", inc, owner, err)
	}
	if inc, owner, err := st.CurrentSandboxAuditIdentity(ctx, "absent"); err != nil || inc != "" || owner != "" {
		t.Fatalf("absent identity = (%q, %q, %v)", inc, owner, err)
	}
	if inc, owner, err := st.CurrentSandboxAuditIdentity(ctx, "  "); err != nil || inc != "" || owner != "" {
		t.Fatalf("blank identity = (%q, %q, %v)", inc, owner, err)
	}
}
