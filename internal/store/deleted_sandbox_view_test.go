package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDeletedSandboxViewStore(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	// Missing → ErrNotFound.
	if _, err := st.GetDeletedSandboxView(ctx, "sb-x", models.FacadeRunloop); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing get = %v, want ErrNotFound", err)
	}

	// Put then get, with no foreign key to a sandbox row (it has none).
	if err := st.PutDeletedSandboxView(ctx, "sb-x", models.FacadeRunloop, "acme", `{"v":1}`, now); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.GetDeletedSandboxView(ctx, "sb-x", models.FacadeRunloop)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.OwnerRef != "acme" || got.ViewJSON != `{"v":1}` {
		t.Fatalf("got = %+v", got)
	}

	// Upsert replaces the view and owner.
	if err := st.PutDeletedSandboxView(ctx, "sb-x", models.FacadeRunloop, "globex", `{"v":2}`, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ = st.GetDeletedSandboxView(ctx, "sb-x", models.FacadeRunloop)
	if got.OwnerRef != "globex" || got.ViewJSON != `{"v":2}` {
		t.Fatalf("after upsert = %+v", got)
	}
}

func TestDeleteExpiredDeletedSandboxViews(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	if err := st.PutDeletedSandboxView(ctx, "sb-old", models.FacadeRunloop, "", `{}`, now.Add(-time.Hour)); err != nil {
		t.Fatalf("put old: %v", err)
	}
	if err := st.PutDeletedSandboxView(ctx, "sb-new", models.FacadeRunloop, "", `{}`, now); err != nil {
		t.Fatalf("put new: %v", err)
	}

	// limit 0 deletes nothing.
	if n, err := st.DeleteExpiredDeletedSandboxViews(ctx, now, 0); err != nil || n != 0 {
		t.Fatalf("limit 0 = %d %v", n, err)
	}

	n, err := st.DeleteExpiredDeletedSandboxViews(ctx, now.Add(-time.Minute), 100)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d, want 1", n)
	}
	if _, err := st.GetDeletedSandboxView(ctx, "sb-old", models.FacadeRunloop); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old survived: %v", err)
	}
	if _, err := st.GetDeletedSandboxView(ctx, "sb-new", models.FacadeRunloop); err != nil {
		t.Fatalf("new was swept: %v", err)
	}

	// A closed DB surfaces errors on each path rather than panicking.
	st.Close()
	if err := st.PutDeletedSandboxView(ctx, "sb-z", models.FacadeRunloop, "", `{}`, now); err == nil {
		t.Fatal("put on closed store returned no error")
	}
	if _, err := st.GetDeletedSandboxView(ctx, "sb-new", models.FacadeRunloop); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("get on closed store returned no query error")
	}
	if _, err := st.DeleteExpiredDeletedSandboxViews(ctx, now, 100); err == nil {
		t.Fatal("sweep on closed store returned no error")
	}
}
