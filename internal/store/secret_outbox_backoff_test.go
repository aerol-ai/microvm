package store

import (
	"context"
	"testing"
	"time"
)

func TestSecretOutboxRetryDelaySchedule(t *testing.T) {
	want := map[int]time.Duration{
		-1: 0, 0: 0,
		1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 4: 4 * time.Minute, 5: 8 * time.Minute,
		6: 15 * time.Minute, 7: 15 * time.Minute, 40: 15 * time.Minute,
	}
	for attempts, d := range want {
		if got := SecretOutboxRetryDelay(attempts); got != d {
			t.Errorf("SecretOutboxRetryDelay(%d) = %v, want %v", attempts, got, d)
		}
	}
}

// The schedule is applied in the query: a row is listed only once its backoff
// has elapsed, a never-attempted row is always due, and a touch moves a row
// to the back without starting a backoff.
func TestListSecretDeleteOutboxDueHonorsBackoffAndTouch(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"sb-fresh", "sb-once", "sb-capped"} {
		if err := st.UpsertSecretDeleteOutbox(ctx, id, "inc", []string{"peer-b"}, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb-once", "inc", 1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		if err := st.BumpSecretDeleteOutboxAttempt(ctx, "sb-capped", "inc", 1); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	ids := func(recs []SecretDeleteOutboxRecord) []string {
		out := make([]string, 0, len(recs))
		for _, r := range recs {
			out = append(out, r.SandboxID)
		}
		return out
	}
	due, err := st.ListSecretDeleteOutboxDue(ctx, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(due); len(got) != 1 || got[0] != "sb-fresh" {
		t.Fatalf("due at attempt time = %v, want only the never-attempted row", got)
	}
	due, _ = st.ListSecretDeleteOutboxDue(ctx, now.Add(31*time.Second), 10)
	if got := ids(due); len(got) != 2 || got[1] != "sb-once" {
		t.Fatalf("due after 31s = %v, want fresh + once", got)
	}
	due, _ = st.ListSecretDeleteOutboxDue(ctx, now.Add(14*time.Minute), 10)
	if got := ids(due); len(got) != 2 {
		t.Fatalf("due after 14m = %v, capped row must still wait", got)
	}
	due, _ = st.ListSecretDeleteOutboxDue(ctx, now.Add(15*time.Minute+time.Second), 10)
	if got := ids(due); len(got) != 3 {
		t.Fatalf("due after the cap = %v, want every row", got)
	}
	all, _ := st.ListSecretDeleteOutboxBatch(ctx, 10)
	if len(all) != 3 {
		t.Fatalf("plain batch = %d rows, want 3 (standalone retirement reads every row)", len(all))
	}

	// Touch: back of the queue, attempts unchanged, still due.
	if err := st.TouchSecretDeleteOutbox(ctx, "sb-fresh", "inc", 1); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-fresh", "inc")
	if err != nil || rec == nil || rec.Attempts != 0 {
		t.Fatalf("touched row = %+v err=%v, want attempts 0", rec, err)
	}
	due, _ = st.ListSecretDeleteOutboxDue(ctx, time.Now().UTC().Add(time.Minute), 10)
	if got := ids(due); len(got) < 2 || got[len(got)-1] != "sb-fresh" {
		t.Fatalf("touched row must move to the back: %v", got)
	}
	if err := st.TouchSecretDeleteOutbox(ctx, "", "inc", 1); err != nil {
		t.Fatalf("blank sandbox id must be a no-op: %v", err)
	}
	if err := st.TouchSecretDeleteOutbox(ctx, "sb", "", 1); err == nil {
		t.Fatal("blank incarnation must be rejected")
	}
	if _, err := st.ListSecretDeleteOutboxDue(ctx, now, 0); err == nil {
		t.Fatal("non-positive limit must be rejected")
	}
}

func TestListSecretPutOutboxDueHonorsBackoffAndTouch(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertSecretPutOutbox(ctx, "sb-fresh", "inc", 1, []string{"peer-b"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSecretPutOutbox(ctx, "sb-twice", "inc", 1, []string{"peer-b"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := st.BumpSecretPutOutboxAttempt(ctx, "sb-twice", "inc", 1); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	due, err := st.ListSecretPutOutboxDue(ctx, now, 10)
	if err != nil || len(due) != 1 || due[0].SandboxID != "sb-fresh" {
		t.Fatalf("due at attempt time = %+v err=%v", due, err)
	}
	due, _ = st.ListSecretPutOutboxDue(ctx, now.Add(59*time.Second), 10)
	if len(due) != 1 {
		t.Fatalf("two attempts wait a full minute: %+v", due)
	}
	due, _ = st.ListSecretPutOutboxDue(ctx, now.Add(61*time.Second), 10)
	if len(due) != 2 {
		t.Fatalf("due after 61s = %+v, want both", due)
	}
	if err := st.TouchSecretPutOutbox(ctx, "sb-twice", "inc", 1); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-twice", "inc")
	if err != nil || rec == nil || rec.Attempts != 2 {
		t.Fatalf("touch must not count an attempt: %+v err=%v", rec, err)
	}
	// A re-upsert (a new obligation for the same identity) starts over.
	if err := st.UpsertSecretPutOutbox(ctx, "sb-twice", "inc", 1, []string{"peer-b", "peer-c"}); err != nil {
		t.Fatal(err)
	}
	rec, _ = st.GetSecretPutOutboxForIncarnation(ctx, "sb-twice", "inc")
	if rec == nil || rec.Attempts != 0 {
		t.Fatalf("re-upsert must reset attempts: %+v", rec)
	}
	if err := st.TouchSecretPutOutbox(ctx, "sb", "inc", 0); err == nil {
		t.Fatal("non-positive seal generation must be rejected")
	}
}
