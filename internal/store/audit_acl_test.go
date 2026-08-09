package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestSandboxAuditACLAtomicCreateAndRetentionPrune(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	sb := sampleSandbox("sb-audit-acl")
	sb.OwnerRef = "tenant-a"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, sb.ID); err != nil || got != "tenant-a" {
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
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, sb.ID); err != nil || got != "" {
		t.Fatalf("ACL after retention prune=%q err=%v", got, err)
	}

	sealed := sampleSandbox("sb-audit-sealed")
	sealed.OwnerRef = "tenant-b"
	sealed.Env = map[string]string{"TOKEN": "secret"}
	if err := st.CreateWithSealedEnv(ctx, sealed, []byte("sealed-env")); err != nil {
		t.Fatalf("CreateWithSealedEnv: %v", err)
	}
	if got, err := st.GetSandboxAuditACLOwnerRef(ctx, sealed.ID); err != nil || got != "tenant-b" {
		t.Fatalf("sealed create ACL=%q err=%v", got, err)
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
				(sandbox_id, recipients_json, generation, attempts, created_at, updated_at)
			VALUES (?, '["peer"]', 1, 0, ?, ?)
		`, id, base.Add(time.Duration(i)*time.Second), base); err != nil {
			t.Fatal(err)
		}
	}
	first, err := st.ListSecretDeleteOutboxBatch(ctx, 64)
	if err != nil || len(first) != 64 {
		t.Fatalf("first batch len=%d err=%v", len(first), err)
	}
	for _, rec := range first {
		if err := st.BumpSecretDeleteOutboxAttempt(ctx, rec.SandboxID); err != nil {
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
