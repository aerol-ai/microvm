package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestListIdempotentRequestsFiltersScopeAndState(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, fp := range []string{"a", "b", "c"} {
		if _, _, err := st.ClaimIdempotentRequest(ctx, "runloop.exec", fp, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.ClaimIdempotentRequest(ctx, "e2b.create", "a", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteIdempotentRequest(ctx, "runloop.exec", "b", "done", now, time.Hour); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		scope, state string
		limit        int
		want         int
	}{
		{"runloop.exec", models.RequestStatePending, 0, 2},
		{"runloop.exec", models.RequestStateReady, 10, 1},
		{"runloop.exec", models.RequestStatePending, 1, 1},
		{"e2b.create", models.RequestStatePending, maxIdempotentListRows + 1, 1},
		{"nobody", models.RequestStatePending, 5, 0},
	} {
		rows, err := st.ListIdempotentRequests(ctx, tc.scope, tc.state, "", tc.limit)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.scope, tc.state, err)
		}
		if len(rows) != tc.want {
			t.Errorf("%s/%s limit %d: %d rows, want %d", tc.scope, tc.state, tc.limit, len(rows), tc.want)
		}
		for _, row := range rows {
			if row.Scope != tc.scope || row.State != tc.state {
				t.Errorf("row %+v outside %s/%s", row, tc.scope, tc.state)
			}
		}
	}
	if _, err := st.ListIdempotentRequests(ctx, " ", models.RequestStatePending, "", 1); err == nil {
		t.Fatal("blank scope accepted")
	}
}

// A restart walks every pending row however many there are: each page
// starts after the last fingerprint of the one before, rows in other states
// are skipped by the index rather than counted against the page, and the walk
// ends on a short page.
func TestListIdempotentRequestsPagesByCursor(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 7 {
		fp := fmt.Sprintf("dev/rlx-%02d", i)
		if _, _, err := st.ClaimIdempotentRequest(ctx, "runloop.exec", fp, now, time.Hour); err != nil {
			t.Fatal(err)
		}
		if i%2 == 1 {
			if err := st.CompleteIdempotentRequest(ctx, "runloop.exec", fp, "done", now, time.Hour); err != nil {
				t.Fatal(err)
			}
		}
	}
	var seen []string
	after := ""
	for pages := 0; ; pages++ {
		if pages > 4 {
			t.Fatalf("walk did not end: %v", seen)
		}
		rows, err := st.ListIdempotentRequests(ctx, "runloop.exec", models.RequestStatePending, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			seen = append(seen, row.Fingerprint)
			after = row.Fingerprint
		}
		if len(rows) < 2 {
			break
		}
	}
	if fmt.Sprint(seen) != "[dev/rlx-00 dev/rlx-02 dev/rlx-04 dev/rlx-06]" {
		t.Fatalf("walked %v", seen)
	}
}

func TestDeleteExpiredIdempotentRequestsOnlyRemovesFreeRows(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	claim := func(fp string, at time.Time, ttl time.Duration) {
		t.Helper()
		if _, _, err := st.ClaimIdempotentRequest(ctx, "s", fp, at, ttl); err != nil {
			t.Fatal(err)
		}
	}
	claim("pending-live", now, time.Hour)
	claim("pending-expired", now.Add(-2*time.Hour), time.Hour)
	claim("ready-live", now, time.Hour)
	if err := st.CompleteIdempotentRequest(ctx, "s", "ready-live", "t", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	claim("ready-expired", now.Add(-3*time.Hour), time.Hour)
	if err := st.CompleteIdempotentRequest(ctx, "s", "ready-expired", "t", now.Add(-3*time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}

	if n, err := st.DeleteExpiredIdempotentRequests(ctx, now, 0); err != nil || n != 0 {
		t.Fatalf("zero limit = %d, %v", n, err)
	}
	if n, err := st.DeleteExpiredIdempotentRequests(ctx, now, 1); err != nil || n != 1 {
		t.Fatalf("first batch = %d, %v", n, err)
	}
	if n, err := st.DeleteExpiredIdempotentRequests(ctx, now, 10); err != nil || n != 1 {
		t.Fatalf("second batch = %d, %v", n, err)
	}
	for fp, want := range map[string]bool{"pending-live": true, "ready-live": true, "pending-expired": false, "ready-expired": false} {
		_, err := st.GetIdempotentRequest(ctx, "s", fp)
		if got := err == nil; got != want {
			t.Errorf("%s present = %v, want %v (%v)", fp, got, want, err)
		}
	}

	_ = st.Close()
	if _, err := st.DeleteExpiredIdempotentRequests(ctx, now, 1); err == nil {
		t.Fatal("closed store accepted a sweep")
	}
	if _, err := st.ListIdempotentRequests(ctx, "s", models.RequestStatePending, "", 1); err == nil {
		t.Fatal("closed store accepted a list")
	}
}

func TestSetIdempotentRequestTargetKeepsRowPending(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, _, err := st.ClaimIdempotentRequest(ctx, "s", "fp", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdempotentRequestTarget(ctx, "s", "fp", "outcome", now); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetIdempotentRequest(ctx, "s", "fp")
	if err != nil || rec.State != models.RequestStatePending || rec.TargetID != "outcome" {
		t.Fatalf("after set = %+v, %v", rec, err)
	}
	// A pending row with a target still blocks a second claimer, which now
	// sees the result.
	again, acquired, err := st.ClaimIdempotentRequest(ctx, "s", "fp", now, time.Hour)
	if err != nil || acquired || again.TargetID != "outcome" {
		t.Fatalf("second claim = %+v %v %v", again, acquired, err)
	}
	if err := st.CompleteIdempotentRequest(ctx, "s", "fp", "outcome", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	// A ready row is final: setting a target no longer applies.
	if err := st.SetIdempotentRequestTarget(ctx, "s", "fp", "late", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set on a ready row = %v, want ErrNotFound", err)
	}
	if err := st.SetIdempotentRequestTarget(ctx, "s", "missing", "x", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set on a missing row = %v", err)
	}
	_ = st.Close()
	if err := st.SetIdempotentRequestTarget(ctx, "s", "fp", "x", now); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("closed store = %v", fmt.Sprint(err))
	}
}
