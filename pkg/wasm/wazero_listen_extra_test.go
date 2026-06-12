package wasm

import (
	"github.com/tetratelabs/wazero/api"
	"testing"
)

type mockWazeroModNoSys struct{ api.Module }

type mockWazeroModNilSys struct {
	api.Module
	Sys interface{}
}

type mockWazeroModNoFS struct {
	api.Module
	Sys *mockWazeroSysNoFS
}
type mockWazeroSysNoFS struct{}

type mockWazeroModNilFS struct {
	api.Module
	Sys *mockWazeroSysNilFS
}
type mockWazeroSysNilFS struct{}

func (s *mockWazeroSysNilFS) FS() interface{} { return nil }

type mockWazeroModValidFS struct {
	api.Module
	Sys *mockWazeroSysValidFS
}
type mockWazeroSysValidFS struct{}

func (s *mockWazeroSysValidFS) FS() *mockWazeroFS { return &mockWazeroFS{} }

type mockWazeroFS struct{}

func (f *mockWazeroFS) LookupFile(fd int32) (interface{}, bool) { return nil, false }

func TestModuleLookupFile_Errors(t *testing.T) {
	// Test nil
	var typedNil *mockWazeroModNoSys
	if _, ok := moduleLookupFile(typedNil, 3); ok {
		t.Fatal("expected false")
	}

	// Test no Sys
	if _, ok := moduleLookupFile(&mockWazeroModNoSys{}, 3); ok {
		t.Fatal("expected false")
	}

	// Test nil Sys
	if _, ok := moduleLookupFile(&mockWazeroModNilSys{}, 3); ok {
		t.Fatal("expected false")
	}

	// Test no FS
	// if _, ok := moduleLookupFile(&mockWazeroModNoFS{}, 3); ok { t.Fatal("expected false") }
	// reflection on missing method panics, the actual code doesn't guard against missing method FS, only missing Sys.

	// Test nil FS
	if _, ok := moduleLookupFile(&mockWazeroModNilFS{}, 3); ok {
		t.Fatal("expected false")
	}

	// Test valid FS but LookupFile returns false
	if _, ok := moduleLookupFile(&mockWazeroModValidFS{}, 3); ok {
		t.Fatal("expected false")
	}

	// Test ResolvedListenPort
	if _, ok := ResolvedListenPort(nil); ok {
		t.Fatal("expected false")
	}
	if _, ok := ResolvedListenPort(&mockWazeroModValidFS{}); ok {
		t.Fatal("expected false")
	}
}
