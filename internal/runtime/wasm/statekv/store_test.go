package statekv

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
)

func TestValidateKey(t *testing.T) {
	// valid key
	if err := ValidateKey("mykey"); err != nil {
		t.Fatalf("valid key: %v", err)
	}
	// empty key
	if err := ValidateKey(""); err == nil {
		t.Fatal("empty key should fail")
	}
	// whitespace only
	if err := ValidateKey("   "); err == nil {
		t.Fatal("whitespace key should fail")
	}
	// exactly 512 bytes — valid
	if err := ValidateKey(strings.Repeat("x", 512)); err != nil {
		t.Fatalf("512-byte key should be valid: %v", err)
	}
	// 513 bytes — too long
	if err := ValidateKey(strings.Repeat("x", 513)); err == nil {
		t.Fatal("513-byte key should fail")
	}
}

func TestValidateValue(t *testing.T) {
	// empty value is fine
	if err := ValidateValue(nil); err != nil {
		t.Fatalf("nil value: %v", err)
	}
	if err := ValidateValue([]byte{}); err != nil {
		t.Fatalf("empty value: %v", err)
	}
	// 4 MiB — valid
	if err := ValidateValue(make([]byte, 4<<20)); err != nil {
		t.Fatalf("4MiB value: %v", err)
	}
	// 4 MiB + 1 — too large
	if err := ValidateValue(make([]byte, 4<<20+1)); err == nil {
		t.Fatal("oversized value should fail")
	}
}

func TestSQLiteStoreNilReceiver(t *testing.T) {
	var s *SQLiteStore

	if _, _, err := s.Get(nil, "sb", "k"); err == nil { //nolint:staticcheck
		t.Fatal("nil store Get should error")
	}
	if err := s.Set(nil, "sb", "k", []byte("v")); err == nil { //nolint:staticcheck
		t.Fatal("nil store Set should error")
	}
	if err := s.Delete(nil, "sb", "k"); err == nil { //nolint:staticcheck
		t.Fatal("nil store Delete should error")
	}
	if _, err := s.ListKeys(nil, "sb"); err == nil { //nolint:staticcheck
		t.Fatal("nil store ListKeys should error")
	}
}

func TestSQLiteStoreNilInnerStore(t *testing.T) {
	s := &SQLiteStore{st: nil}

	if _, _, err := s.Get(nil, "sb", "k"); err == nil { //nolint:staticcheck
		t.Fatal("nil inner Get should error")
	}
	if err := s.Set(nil, "sb", "k", []byte("v")); err == nil { //nolint:staticcheck
		t.Fatal("nil inner Set should error")
	}
	if err := s.Delete(nil, "sb", "k"); err == nil { //nolint:staticcheck
		t.Fatal("nil inner Delete should error")
	}
	if _, err := s.ListKeys(nil, "sb"); err == nil { //nolint:staticcheck
		t.Fatal("nil inner ListKeys should error")
	}
}

func TestErrNotFound(t *testing.T) {
	if ErrNotFound == nil {
		t.Fatal("ErrNotFound should be non-nil")
	}
	if ErrNotFound.Error() == "" {
		t.Fatal("ErrNotFound should have a message")
	}
}

func TestSQLiteStore_CRUD(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	kv := NewSQLiteStore(st)
	const sandboxID = "sb-kv"

	if err := kv.Set(ctx, sandboxID, "counter", []byte("1")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := kv.Get(ctx, sandboxID, "counter")
	if err != nil || !ok || string(got) != "1" {
		t.Fatalf("Get = %q ok=%v err=%v", got, ok, err)
	}
	got, ok, err = kv.Get(ctx, sandboxID, "missing")
	if err != nil || ok {
		t.Fatalf("Get missing = %q ok=%v err=%v", got, ok, err)
	}
	if err := kv.Set(ctx, sandboxID, "other", []byte("x")); err != nil {
		t.Fatalf("Set other: %v", err)
	}
	keys, err := kv.ListKeys(ctx, sandboxID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListKeys = %v err=%v", keys, err)
	}
	if err := kv.Delete(ctx, sandboxID, "counter"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok, err = kv.Get(ctx, sandboxID, "counter")
	if err != nil || ok {
		t.Fatalf("Get after delete = ok=%v err=%v", ok, err)
	}
}

func TestNewSQLiteStore_Constructor(t *testing.T) {
	// NewSQLiteStore wraps a (possibly nil) store pointer; the important
	// invariant is that the returned *SQLiteStore is non-nil and that
	// calling any method on it with a nil inner store returns the
	// "not configured" sentinel error rather than panicking.
	s := NewSQLiteStore(nil)
	if s == nil {
		t.Fatal("NewSQLiteStore(nil) must return a non-nil *SQLiteStore")
	}
	if _, _, err := s.Get(nil, "sb", "k"); err == nil { //nolint:staticcheck
		t.Fatal("Get with nil inner store should return error")
	}
	if err := s.Set(nil, "sb", "k", []byte("v")); err == nil { //nolint:staticcheck
		t.Fatal("Set with nil inner store should return error")
	}
	if err := s.Delete(nil, "sb", "k"); err == nil { //nolint:staticcheck
		t.Fatal("Delete with nil inner store should return error")
	}
	if _, err := s.ListKeys(nil, "sb"); err == nil { //nolint:staticcheck
		t.Fatal("ListKeys with nil inner store should return error")
	}
}
