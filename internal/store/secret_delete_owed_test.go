package store

import (
	"context"
	"testing"
)

// The owner's UC-160 report is a snapshot of the whole outbox: per peer, how
// many rows still owe it a delete. A peer listed twice in one row counts once.
func TestSecretDeleteOwedByRecipient(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	owed, err := st.SecretDeleteOwedByRecipient(ctx)
	if err != nil || len(owed) != 0 {
		t.Fatalf("empty outbox = %v %v", owed, err)
	}
	for _, row := range []struct {
		sb    string
		peers []string
	}{
		{"sb-1", []string{"worker-x", "worker-y"}},
		{"sb-2", []string{"worker-x", "worker-x", " "}},
		{"sb-3", []string{"worker-z"}},
	} {
		if err := st.UpsertSecretDeleteOutbox(ctx, row.sb, "inc-"+row.sb, row.peers, 1); err != nil {
			t.Fatal(err)
		}
	}
	owed, err = st.SecretDeleteOwedByRecipient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if owed["worker-x"] != 2 || owed["worker-y"] != 1 || owed["worker-z"] != 1 || len(owed) != 3 {
		t.Fatalf("owed = %v, want worker-x:2 worker-y:1 worker-z:1", owed)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SecretDeleteOwedByRecipient(ctx); err == nil {
		t.Fatal("a closed store returned no error")
	}
}

// A row whose recipient list is not valid JSON must fail the count, not
// silently drop that row's debts from the report.
func TestSecretDeleteOwedByRecipientRejectsACorruptRow(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertSecretDeleteOutbox(ctx, "sb-1", "inc-1", []string{"worker-x"}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE cluster_secret_delete_outbox SET recipients_json = 'not json'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SecretDeleteOwedByRecipient(ctx); err == nil {
		t.Fatal("a corrupt outbox row was counted as owing nothing")
	}
}
