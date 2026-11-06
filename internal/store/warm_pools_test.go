package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWarmPoolCRUD(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	p, changed, err := st.PutWarmPool(ctx, models.WarmPool{Image: "python:3.12", Depth: 2}, now)
	if err != nil || !changed || p.Generation != 1 || p.Depth != 2 || !p.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("create = %+v %v %v", p, changed, err)
	}
	// The same body again is a no-op: a retried PUT keeps the generation.
	if p, changed, err = st.PutWarmPool(ctx, models.WarmPool{Image: "python:3.12", Depth: 2}, now.Add(time.Second)); err != nil || changed || p.Generation != 1 {
		t.Fatalf("same body = %+v %v %v", p, changed, err)
	}
	if p, changed, _ = st.PutWarmPool(ctx, models.WarmPool{Image: "python:3.12", Depth: 5}, now.Add(time.Second)); !changed || p.Generation != 2 || p.Depth != 5 || !p.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("update = %+v %v", p, changed)
	}
	got, err := st.GetWarmPool(ctx, "python:3.12")
	if err != nil || got.Depth != 5 || got.Generation != 2 {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := st.GetWarmPool(ctx, "node:22"); !errors.Is(err, ErrWarmPoolNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if _, _, err := st.PutWarmPool(ctx, models.WarmPool{Image: "alpine:3.20", Depth: 1}, now); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListWarmPools(ctx)
	if err != nil || len(list) != 2 || list[0].Image != "alpine:3.20" || list[1].Image != "python:3.12" {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := st.DeleteWarmPool(ctx, "python:3.12"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteWarmPool(ctx, "python:3.12"); err != nil {
		t.Fatalf("a repeated delete must succeed: %v", err)
	}
	if list, _ := st.ListWarmPools(ctx); len(list) != 1 {
		t.Fatalf("after delete = %+v", list)
	}
	empty := newTestStore(t)
	if list, err := empty.ListWarmPools(ctx); err != nil || list == nil || len(list) != 0 {
		t.Fatalf("an empty store lists [] (not null): %#v %v", list, err)
	}
}

// TestWarmPoolLimitUnderConcurrentCreates: the limit is checked in the
// insert's transaction, so racing creates past it never all land, and an
// update of an existing entry is never refused by it.
func TestWarmPoolLimitUnderConcurrentCreates(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < models.MaxWarmPools-1; i++ {
		if _, _, err := st.PutWarmPool(ctx, models.WarmPool{Image: fmt.Sprintf("img-%02d", i), Depth: 1}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, errs[i] = st.PutWarmPool(ctx, models.WarmPool{Image: fmt.Sprintf("race-%d", i), Depth: 1}, time.Now())
		}(i)
	}
	wg.Wait()
	ok, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrWarmPoolLimit):
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || refused != 7 {
		t.Fatalf("ok=%d refused=%d, want exactly one create past the limit", ok, refused)
	}
	if _, changed, err := st.PutWarmPool(ctx, models.WarmPool{Image: "img-00", Depth: 9}, time.Now()); err != nil || !changed {
		t.Fatalf("updating an entry at the limit: %v %v", changed, err)
	}
}

func TestWarmPoolClosedStore(t *testing.T) {
	st := newTestStore(t)
	_ = st.Close()
	ctx := context.Background()
	if _, _, err := st.PutWarmPool(ctx, models.WarmPool{Image: "a", Depth: 1}, time.Now()); err == nil {
		t.Fatal("put on a closed store must fail")
	}
	if _, err := st.GetWarmPool(ctx, "a"); err == nil || errors.Is(err, ErrWarmPoolNotFound) {
		t.Fatalf("get on a closed store = %v", err)
	}
	if _, err := st.ListWarmPools(ctx); err == nil {
		t.Fatal("list on a closed store must fail")
	}
	if err := st.DeleteWarmPool(ctx, "a"); err == nil {
		t.Fatal("delete on a closed store must fail")
	}
}

// TestWarmPoolDemandRange (W2): min_depth and max_depth round-trip, and a
// change to either is a change (a new generation), not a no-op.
func TestWarmPoolDemandRange(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	in := models.WarmPool{Image: "python:3.12", MinDepth: 0, MaxDepth: 4}
	if p, changed, err := st.PutWarmPool(ctx, in, now); err != nil || !changed || p.MaxDepth != 4 {
		t.Fatalf("create = %+v %v %v", p, changed, err)
	}
	if _, changed, _ := st.PutWarmPool(ctx, in, now); changed {
		t.Fatal("the same range again must be a no-op")
	}
	for i, next := range []models.WarmPool{
		{Image: "python:3.12", MinDepth: 1, MaxDepth: 4},
		{Image: "python:3.12", MinDepth: 1, MaxDepth: 6},
		{Image: "python:3.12", Depth: 2},
	} {
		p, changed, err := st.PutWarmPool(ctx, next, now)
		if err != nil || !changed || p.Generation != int64(i+2) {
			t.Fatalf("change %d = %+v %v %v", i, p, changed, err)
		}
	}
	got, err := st.GetWarmPool(ctx, "python:3.12")
	if err != nil || got.Depth != 2 || got.MinDepth != 0 || got.MaxDepth != 0 {
		t.Fatalf("back to a fixed depth = %+v %v", got, err)
	}
	if _, _, err := st.PutWarmPool(ctx, models.WarmPool{Image: "node:22", MinDepth: 2, MaxDepth: 3}, now); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListWarmPools(ctx)
	if len(list) != 2 || list[0].Image != "node:22" || list[0].MinDepth != 2 || list[0].MaxDepth != 3 {
		t.Fatalf("list = %+v", list)
	}
}

// TestWarmPoolUpgradeAddsDemandColumns: a database written before W2 (no
// min_depth/max_depth) opens, gains the columns, and its rows read as the
// fixed depths they were.
func TestWarmPoolUpgradeAddsDemandColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	raw, err := sql.Open("sqlite3", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE warm_pools (
		image TEXT PRIMARY KEY, depth INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL);
		INSERT INTO warm_pools (image, depth, generation, created_at, updated_at) VALUES ('python:3.12', 3, 2, '2026-11-01 00:00:00', '2026-11-01 00:00:00');`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a pre-W2 database: %v", err)
	}
	defer st.Close()
	got, err := st.GetWarmPool(context.Background(), "python:3.12")
	if err != nil || got.Depth != 3 || got.MinDepth != 0 || got.MaxDepth != 0 || got.Generation != 2 {
		t.Fatalf("old row = %+v %v", got, err)
	}
}
