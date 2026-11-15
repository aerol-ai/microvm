package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// seedRecreateWithBackups makes a recreate-policy row whose sealed secret is
// held by self and two backups, with a push to one of them still pending.
func seedRecreateWithBackups(t *testing.T, st *Store, id, inc string, gen int64) {
	t.Helper()
	ctx := context.Background()
	sb := sampleSandbox(id)
	sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
		Ref: secrets.FormatRef(id, inc, secrets.RefVersion), SandboxID: id, Version: secrets.RefVersion,
		Recipients: []string{"self", "b1", "b2"}, SealedPayload: []byte("sealed"),
		SealGeneration: gen, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, id, inc, gen, []string{"b2"}); err != nil {
		t.Fatal(err)
	}
}

// TestClearRecreateFailoverRetiringBackups: turning the recreate policy off
// journals the backups' delete and drops pending pushes in the same write,
// keeps the owner's copy, and changes nothing a second time.
func TestClearRecreateFailoverRetiringBackups(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	seedRecreateWithBackups(t, st, "sb-off", "inc-off", 3)

	changed, retired, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb-off", "inc-off", "self")
	if err != nil || !changed || retired != 2 {
		t.Fatalf("clear: changed=%v retired=%d err=%v", changed, retired, err)
	}
	if got, _ := st.Get(ctx, "sb-off"); got.Failover != nil && got.Failover.ShouldRecreate() {
		t.Fatalf("policy still recreate: %+v", got.Failover)
	}
	job, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-off", "inc-off")
	if err != nil || job == nil {
		t.Fatalf("delete job: %+v err=%v", job, err)
	}
	if !reflect.DeepEqual(job.Recipients, []string{"b1", "b2"}) || job.Generation != 3 || job.AwaitingPromotion {
		t.Fatalf("delete job = %+v, want b1 and b2 at generation 3, promoted", job)
	}
	if put, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-off", "inc-off"); err != nil || put != nil {
		t.Fatalf("pending push kept: %+v err=%v", put, err)
	}
	if own, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-off", "inc-off"); err != nil || own == nil {
		t.Fatalf("owner's copy gone: %+v err=%v", own, err)
	}

	changed, retired, err = st.ClearRecreateFailoverRetiringBackups(ctx, "sb-off", "inc-off", "self")
	if err != nil || changed || retired != 0 {
		t.Fatalf("second clear: changed=%v retired=%d err=%v", changed, retired, err)
	}
}

// TestClearRecreateFailoverRetiringBackupsEdges covers the rows it must
// leave alone or only partly change.
func TestClearRecreateFailoverRetiringBackupsEdges(t *testing.T) {
	ctx := context.Background()

	t.Run("another policy keeps its secrets", func(t *testing.T) {
		st := newTestStore(t)
		seedRecreateWithBackups(t, st, "sb-x", "inc-x", 2)
		if _, err := st.ClearRecreateFailover(ctx, "sb-x"); err != nil {
			t.Fatal(err)
		}
		changed, retired, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb-x", "inc-x", "self")
		if err != nil || changed || retired != 0 {
			t.Fatalf("changed=%v retired=%d err=%v", changed, retired, err)
		}
		if put, _ := st.GetSecretPutOutboxForIncarnation(ctx, "sb-x", "inc-x"); put == nil {
			t.Fatal("a row it did not change lost its pending push")
		}
	})

	t.Run("no sealed secret", func(t *testing.T) {
		st := newTestStore(t)
		sb := sampleSandbox("sb-bare")
		sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		changed, retired, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb-bare", "inc-bare", "self")
		if err != nil || !changed || retired != 0 {
			t.Fatalf("changed=%v retired=%d err=%v", changed, retired, err)
		}
		if job, _ := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-bare", "inc-bare"); job != nil {
			t.Fatalf("delete job for nothing: %+v", job)
		}
	})

	t.Run("no node identity leaves the secrets", func(t *testing.T) {
		st := newTestStore(t)
		seedRecreateWithBackups(t, st, "sb-anon", "inc-anon", 2)
		changed, retired, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb-anon", "inc-anon", "")
		if err != nil || !changed || retired != 0 {
			t.Fatalf("changed=%v retired=%d err=%v", changed, retired, err)
		}
		if job, _ := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-anon", "inc-anon"); job != nil {
			t.Fatalf("delete job without knowing self: %+v", job)
		}
		if put, _ := st.GetSecretPutOutboxForIncarnation(ctx, "sb-anon", "inc-anon"); put == nil {
			t.Fatal("pending push dropped without knowing self")
		}
	})

	t.Run("only the owner holds it", func(t *testing.T) {
		st := newTestStore(t)
		sb := sampleSandbox("sb-solo")
		sb.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if _, err := st.PutClusterSecret(ctx, ClusterSecretRecord{
			Ref: secrets.FormatRef("sb-solo", "inc-solo", secrets.RefVersion), SandboxID: "sb-solo", Version: secrets.RefVersion,
			Recipients: []string{"self"}, SealedPayload: []byte("sealed"), SealGeneration: 1, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		changed, retired, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb-solo", "inc-solo", "self")
		if err != nil || !changed || retired != 0 {
			t.Fatalf("changed=%v retired=%d err=%v", changed, retired, err)
		}
	})

	t.Run("a staged reseal's retirement is promoted with it", func(t *testing.T) {
		st := newTestStore(t)
		seedRecreateWithBackups(t, st, "sb-st", "inc-st", 4)
		tx, err := st.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := upsertSecretDeleteOutboxTx(ctx, tx, "sb-st", "inc-st", []string{"old"}, nil, 4, true, time.Time{}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, retired, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb-st", "inc-st", "self"); err != nil || retired != 2 {
			t.Fatalf("retired=%d err=%v", retired, err)
		}
		job, _ := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-st", "inc-st")
		if job == nil || !reflect.DeepEqual(job.Recipients, []string{"b1", "b2", "old"}) || job.AwaitingPromotion {
			t.Fatalf("delete job = %+v, want old, b1 and b2, promoted", job)
		}
	})

	t.Run("closed store", func(t *testing.T) {
		st := newTestStore(t)
		_ = st.Close()
		if _, _, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb", "inc", "self"); err == nil {
			t.Fatal("closed store: no error")
		}
	})
}

// TestClearRecreateFailoverRetiringBackupsFaults: any failing step rolls the
// whole transaction back, so the policy stays recreate and the backups keep
// their copies until the disarm is retried.
func TestClearRecreateFailoverRetiringBackupsFaults(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		inject func(t *testing.T, st *Store)
	}{
		{"policy write", func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE UPDATE", "sandboxes") }},
		{"unreadable generation", func(t *testing.T, st *Store) {
			cov96bExec(t, st.db, `UPDATE cluster_secrets SET seal_generation = 'x' WHERE sandbox_id = 'sb-f'`)
		}},
		{"undecodable recipients", func(t *testing.T, st *Store) {
			cov96bExec(t, st.db, `UPDATE cluster_secrets SET recipients_json = '{' WHERE sandbox_id = 'sb-f'`)
		}},
		{"delete job", func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE INSERT", "cluster_secret_delete_outbox") }},
		{"pending pushes", func(t *testing.T, st *Store) { cov96bFailOn(t, st, "BEFORE DELETE", "cluster_secret_put_outbox") }},
		{"commit", func(t *testing.T, st *Store) { cov96bFailCommitOn(t, st, "AFTER DELETE", "cluster_secret_put_outbox") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			seedRecreateWithBackups(t, st, "sb-f", "inc-f", 2)
			tc.inject(t, st)
			if changed, _, err := st.ClearRecreateFailoverRetiringBackups(ctx, "sb-f", "inc-f", "self"); err == nil || changed {
				t.Fatalf("changed=%v err=%v, want an error", changed, err)
			}
			if got, _ := st.Get(ctx, "sb-f"); got.Failover == nil || !got.Failover.ShouldRecreate() {
				t.Fatal("the policy changed although the transaction failed")
			}
			if job, _ := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-f", "inc-f"); job != nil {
				t.Fatalf("a delete job survived the failed transaction: %+v", job)
			}
		})
	}
}
