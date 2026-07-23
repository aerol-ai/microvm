package statekv

import (
	"strings"
	"testing"
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
