package store

import (
	"context"
	"errors"
	"fmt"
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
