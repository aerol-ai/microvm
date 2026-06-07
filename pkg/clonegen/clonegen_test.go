package clonegen

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGeneration_InitWritesStableToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "clone-generation")
	c := New(path, nil)

	token, resumedAt := c.Current()
	if token == "" {
		t.Fatal("initial token is empty")
	}
	if resumedAt != 0 {
		t.Errorf("initial resumedAt = %d, want 0 (never resumed)", resumedAt)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read clone-generation file: %v", err)
	}
	if strings.TrimSpace(string(got)) != token {
		t.Errorf("file token = %q, want %q", strings.TrimSpace(string(got)), token)
	}
}

func TestGeneration_BumpChangesTokenAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clone-generation")
	c := New(path, nil)
	before, _ := c.Current()

	c.Bump(1700000000000000000)

	after, resumedAt := c.Current()
	if after == before {
		t.Errorf("token unchanged after bump: %q", after)
	}
	if resumedAt != 1700000000000000000 {
		t.Errorf("resumedAt = %d, want 1700000000000000000", resumedAt)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read clone-generation file: %v", err)
	}
	if strings.TrimSpace(string(got)) != after {
		t.Errorf("file token = %q, want %q", strings.TrimSpace(string(got)), after)
	}
}

func TestGeneration_BumpPublishesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clone-generation")
	c := New(path, nil)
	before, _ := c.Current()

	c.Bump(1700000000000000000)

	after, _ := c.Current()
	if after == before {
		t.Fatalf("token unchanged after bump: %q", after)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read clone-generation file: %v", err)
	}
	fileToken := strings.TrimSpace(string(got))
	if fileToken != before && fileToken != after {
		t.Fatalf("file token = %q, want old %q or new %q", fileToken, before, after)
	}
}

func TestGeneration_MissingDirIsNonFatal(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(filepath.Join(file, "clone-generation"), nil)
	if token, _ := c.Current(); token == "" {
		t.Error("token should still be served from memory when file write fails")
	}
	c.Bump(1)
}

func TestGeneration_ConcurrentReadWrite(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "clone-generation"), nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func(n int) { defer wg.Done(); c.Bump(int64(n)) }(i)
		go func() { defer wg.Done(); _, _ = c.Current() }()
	}
	wg.Wait()
}

func TestGeneration_NilReceiverIsSafe(t *testing.T) {
	var cg *Generation

	token, resumedAt := cg.Current()
	if token != "" || resumedAt != 0 {
		t.Errorf("nil Current() = (%q, %d), want (\"\", 0)", token, resumedAt)
	}
	cg.Bump(123)
}

func TestRandomTokenFallbackUsesResumeTimestamp(t *testing.T) {
	oldRandRead := RandRead
	RandRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	defer func() { RandRead = oldRandRead }()

	a := randomToken(111)
	b := randomToken(222)
	if a == b {
		t.Fatalf("fallback token collision: %q", a)
	}
	if !strings.Contains(a, "fallback-111-") {
		t.Fatalf("fallback token %q does not include resume timestamp", a)
	}
	if !strings.Contains(b, "fallback-222-") {
		t.Fatalf("fallback token %q does not include resume timestamp", b)
	}
}
