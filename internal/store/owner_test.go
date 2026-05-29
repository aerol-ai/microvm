package store

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestOwnerRefRoundTripAndListByOwner(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	acmeA := sampleSandbox("sb-acme-a")
	acmeA.OwnerRef = "acme"
	acmeB := sampleSandbox("sb-acme-b")
	acmeB.OwnerRef = "acme"
	globex := sampleSandbox("sb-globex")
	globex.OwnerRef = "globex"
	operator := sampleSandbox("sb-operator") // owner-less (PAT-created)

	for _, sb := range []*models.Sandbox{acmeA, acmeB, globex, operator} {
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create(%s): %v", sb.ID, err)
		}
	}

	// owner_ref survives the round-trip.
	got, err := st.Get(ctx, "sb-acme-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.OwnerRef != "acme" {
		t.Fatalf("owner_ref = %q, want acme", got.OwnerRef)
	}

	// ListByOwner returns only the owner's sandboxes.
	acme, err := st.ListByOwner(ctx, "acme")
	if err != nil {
		t.Fatalf("ListByOwner(acme): %v", err)
	}
	if len(acme) != 2 {
		t.Fatalf("ListByOwner(acme) = %d, want 2", len(acme))
	}
	for _, sb := range acme {
		if sb.OwnerRef != "acme" {
			t.Fatalf("ListByOwner(acme) leaked %s (owner %q)", sb.ID, sb.OwnerRef)
		}
	}

	// Empty owner matches operator/PAT-created rows.
	ownerless, err := st.ListByOwner(ctx, "")
	if err != nil {
		t.Fatalf("ListByOwner(\"\"): %v", err)
	}
	if len(ownerless) != 1 || ownerless[0].ID != "sb-operator" {
		t.Fatalf("ListByOwner(\"\") = %+v, want [sb-operator]", ownerless)
	}
}

func TestSetFleetSuspended(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	sb := sampleSandbox("sb-fs")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := st.SetFleetSuspended(ctx, "sb-fs", true); err != nil {
		t.Fatalf("SetFleetSuspended(true): %v", err)
	}
	got, err := st.Get(ctx, "sb-fs")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.FleetSuspended {
		t.Fatalf("FleetSuspended = false, want true")
	}

	// Idempotent clear.
	if err := st.SetFleetSuspended(ctx, "sb-fs", false); err != nil {
		t.Fatalf("SetFleetSuspended(false): %v", err)
	}
	got, _ = st.Get(ctx, "sb-fs")
	if got.FleetSuspended {
		t.Fatalf("FleetSuspended = true after clear, want false")
	}

	// Missing row reads as ErrNotFound (caller treats as already-converged).
	if err := st.SetFleetSuspended(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetFleetSuspended(missing) = %v, want ErrNotFound", err)
	}
}

func TestUpsertAccountMapping(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	if err := st.UpsertAccountMapping(ctx, "acme", "ext-1"); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	var external string
	var first, last string
	if err := st.db.QueryRowContext(ctx,
		`SELECT external_id, first_seen, last_seen FROM account_mappings WHERE owner_ref = ?`, "acme").
		Scan(&external, &first, &last); err != nil {
		t.Fatalf("read mapping: %v", err)
	}
	if external != "ext-1" {
		t.Fatalf("external_id = %q, want ext-1", external)
	}

	// Second upsert refreshes external_id but preserves first_seen.
	if err := st.UpsertAccountMapping(ctx, "acme", "ext-2"); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	var external2, first2 string
	if err := st.db.QueryRowContext(ctx,
		`SELECT external_id, first_seen FROM account_mappings WHERE owner_ref = ?`, "acme").
		Scan(&external2, &first2); err != nil {
		t.Fatalf("read mapping 2: %v", err)
	}
	if external2 != "ext-2" {
		t.Fatalf("external_id = %q, want ext-2", external2)
	}
	if first2 != first {
		t.Fatalf("first_seen changed across upsert: %q -> %q", first, first2)
	}

	// Empty owner_ref is rejected.
	if err := st.UpsertAccountMapping(ctx, "", "x"); err == nil {
		t.Fatalf("empty owner_ref should error")
	}
}
