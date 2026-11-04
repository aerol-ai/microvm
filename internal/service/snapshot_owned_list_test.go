package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ListOwnedSnapshots must return exactly the caller's snapshots, across the
// store page boundary, and must never read another tenant's rows (the D9 fix:
// the old ListSnapshots loaded every tenant's rows and filtered in Go). The
// 250-row owner set crosses the 200-row scan batch, proving the accumulator
// pages correctly.
func TestListOwnedSnapshots(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()

	const acmeCount = 250 // > snapshotOwnedScanBatch (200): forces multiple pages
	for i := 0; i < acmeCount; i++ {
		src := ""
		if i < 3 {
			src = "sb-acme-1"
		}
		if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
			Name:            fmt.Sprintf("acme-snap-%03d", i),
			Image:           "img:acme",
			OwnerRef:        "acme",
			SourceSandboxID: src,
			CreatedAt:       now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("seed acme snapshot %d: %v", i, err)
		}
	}
	for i := 0; i < 10; i++ {
		if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{
			Name:      fmt.Sprintf("globex-snap-%03d", i),
			Image:     "img:globex",
			OwnerRef:  "globex",
			CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed globex snapshot %d: %v", i, err)
		}
	}

	acme := userCtx("acme")

	// Owner isolation + batch paging: all 250 acme rows, no globex row.
	rows, err := svc.ListOwnedSnapshots(acme, "", "")
	if err != nil {
		t.Fatalf("ListOwnedSnapshots(acme): %v", err)
	}
	if len(rows) != acmeCount {
		t.Fatalf("acme rows = %d, want %d", len(rows), acmeCount)
	}
	for _, row := range rows {
		if row.Snapshot.OwnerRef != "acme" {
			t.Fatalf("leaked a non-acme snapshot: %+v", row.Snapshot)
		}
	}

	// Source-sandbox filter is pushed into the store scan.
	filtered, err := svc.ListOwnedSnapshots(acme, "sb-acme-1", "")
	if err != nil {
		t.Fatalf("ListOwnedSnapshots(acme, sb-acme-1): %v", err)
	}
	if len(filtered) != 3 {
		t.Fatalf("source-filtered rows = %d, want 3", len(filtered))
	}

	// A different owner sees only its own rows.
	gx, err := svc.ListOwnedSnapshots(userCtx("globex"), "", "")
	if err != nil {
		t.Fatalf("ListOwnedSnapshots(globex): %v", err)
	}
	if len(gx) != 10 {
		t.Fatalf("globex rows = %d, want 10", len(gx))
	}

	// Alias join: only the named facade's alias comes back on the row.
	if err := svc.UpsertSnapshotAlias(acme, models.SnapshotAlias{
		Alias:        "e2b-alias-1",
		SnapshotName: "acme-snap-000",
		Facade:       models.FacadeE2B,
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("UpsertSnapshotAlias: %v", err)
	}
	joined, err := svc.ListOwnedSnapshots(acme, "", models.FacadeE2B)
	if err != nil {
		t.Fatalf("ListOwnedSnapshots(acme, e2b): %v", err)
	}
	aliased := 0
	for _, row := range joined {
		if row.Alias != nil {
			aliased++
			if row.Alias.Alias != "e2b-alias-1" || row.Snapshot.Name != "acme-snap-000" {
				t.Fatalf("unexpected alias join: %+v on %+v", row.Alias, row.Snapshot)
			}
		}
	}
	if aliased != 1 {
		t.Fatalf("alias-joined rows = %d, want 1", aliased)
	}

	// An unscoped (operator) caller sees every tenant's rows.
	all, err := svc.ListOwnedSnapshots(operatorCtx(), "", "")
	if err != nil {
		t.Fatalf("ListOwnedSnapshots(operator): %v", err)
	}
	if len(all) != acmeCount+10 {
		t.Fatalf("operator rows = %d, want %d", len(all), acmeCount+10)
	}
}
