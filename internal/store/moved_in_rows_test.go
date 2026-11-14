package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A moved-in row survives a reopen of the store (an agent restart between a
// move's import and its start, review N4), a second import replaces it, and
// a delete is idempotent.
func TestMovedInRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sandboxd.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_800_000_000, 5).UTC()
	if err := st.PutMovedInRow(ctx, "sb-b", []byte("sealed-b"), at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := st.PutMovedInRow(ctx, "sb-a", []byte("sealed-a1"), at); err != nil {
		t.Fatal(err)
	}
	if err := st.PutMovedInRow(ctx, "sb-a", []byte("sealed-a2"), at); err != nil {
		t.Fatalf("a second import of the same sandbox: %v", err)
	}
	if err := st.PutMovedInRow(ctx, "", []byte("x"), at); err == nil {
		t.Fatal("a row without an id was stored")
	}
	if err := st.PutMovedInRow(ctx, "sb-c", nil, at); err == nil {
		t.Fatal("a row without a blob was stored")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	got, err := st.GetMovedInRow(ctx, "sb-a")
	if err != nil || !bytes.Equal(got.Sealed, []byte("sealed-a2")) || !got.ImportedAt.Equal(at) || got.SandboxID != "sb-a" {
		t.Fatalf("after a reopen: %+v %v", got, err)
	}
	all, err := st.ListMovedInRows(ctx)
	if err != nil || len(all) != 2 || all[0].SandboxID != "sb-a" || all[1].SandboxID != "sb-b" {
		t.Fatalf("list = %+v %v, want sb-a then sb-b", all, err)
	}
	if err := st.DeleteMovedInRow(ctx, "sb-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteMovedInRow(ctx, "sb-a"); err != nil {
		t.Fatalf("a second delete: %v", err)
	}
	if _, err := st.GetMovedInRow(ctx, "sb-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after the delete: %v, want ErrNotFound", err)
	}
	// Closed: every call reports it.
	_ = st.Close()
	if _, err := st.ListMovedInRows(ctx); err == nil {
		t.Fatal("list on a closed store")
	}
	if _, err := st.GetMovedInRow(ctx, "sb-b"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("get on a closed store = %v", err)
	}
	if err := st.PutMovedInRow(ctx, "sb-d", []byte("x"), at); err == nil {
		t.Fatal("put on a closed store")
	}
	if err := st.DeleteMovedInRow(ctx, "sb-b"); err == nil {
		t.Fatal("delete on a closed store")
	}
}
