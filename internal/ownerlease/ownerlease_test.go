package ownerlease

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestWriteAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ownership-lease")
	want := Lease{ConfirmedUnixMs: 1_000_000, WrittenUnixMs: 1_002_500, LeaseMs: 15_000, Fence: []string{"ctr-a", "ctr-b"}, Owned: []string{"ctr-a"}}
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfirmedUnixMs != want.ConfirmedUnixMs || got.WrittenUnixMs != want.WrittenUnixMs || got.LeaseMs != want.LeaseMs ||
		!slices.Equal(got.Fence, want.Fence) || !slices.Equal(got.Owned, want.Owned) {
		t.Fatalf("read %+v, wrote %+v", got, want)
	}
	if r := got.Remaining(); r != 12500*time.Millisecond {
		t.Fatalf("remaining %v, want 12.5s", r)
	}
	// A rewrite replaces it whole and leaves no temporary file behind.
	want.Owned = nil
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("left %d files, want only the lease", len(entries))
	}
	if got, _ := Read(path); len(got.Owned) != 0 {
		t.Fatalf("owned %v after the rewrite", got.Owned)
	}
}

func TestReadFailures(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	for name, body := range map[string]string{
		"not json":      "{",
		"no lease":      `{"confirmed_unix_ms":1,"written_unix_ms":1}`,
		"no confirm":    `{"written_unix_ms":1,"lease_ms":15000}`,
		"no write time": `{"confirmed_unix_ms":1,"lease_ms":15000}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(p); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: %v, want a parse error", name, err)
		}
	}
}

func TestWriteFailures(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "missing", "lease"), Lease{}); err == nil {
		t.Fatal("wrote into a folder that does not exist")
	}
	// The target is a folder: the rename fails and the temporary file goes.
	dir := t.TempDir()
	target := filepath.Join(dir, "lease")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(target, Lease{LeaseMs: 1}); err == nil {
		t.Fatal("replaced a folder")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left %d entries, want the folder only", len(entries))
	}
}

func TestValidRef(t *testing.T) {
	for ref, want := range map[string]bool{
		"sb-a36d11bff9ff6787": true, "ctr-a": true,
		"": false, ".": false, "..": false, "../supervisor": false, "a/b": false, "a\x00b": false,
	} {
		if got := ValidRef(ref); got != want {
			t.Errorf("ValidRef(%q) = %v, want %v", ref, got, want)
		}
	}
}
