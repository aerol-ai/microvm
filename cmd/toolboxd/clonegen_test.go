package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestCloneGeneration_InitWritesStableToken asserts the constructor seeds a
// token and persists it, and that current() matches the file — the baseline
// an in-guest reader records before any clone.
func TestCloneGeneration_InitWritesStableToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "clone-generation")
	c := newCloneGeneration(path, nil)

	token, resumedAt := c.current()
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

// TestCloneGeneration_BumpChangesTokenAndPersists asserts bump rotates the
// token, records the resume time, and rewrites the file — the signal an
// in-guest process keys off to reseed.
func TestCloneGeneration_BumpChangesTokenAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clone-generation")
	c := newCloneGeneration(path, nil)
	before, _ := c.current()

	c.bump(1700000000000000000)

	after, resumedAt := c.current()
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

// TestCloneGeneration_MissingDirIsNonFatal asserts an unwritable path never
// panics or blocks — the HTTP endpoint stays the source of truth even when
// /run is read-only. The token is still served from memory.
func TestCloneGeneration_MissingDirIsNonFatal(t *testing.T) {
	// A path under a file (not a dir) makes MkdirAll fail.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := newCloneGeneration(filepath.Join(file, "clone-generation"), nil)
	if token, _ := c.current(); token == "" {
		t.Error("token should still be served from memory when file write fails")
	}
	c.bump(1) // must not panic
}

// TestCloneGeneration_ConcurrentReadWrite is a race-detector smoke test:
// concurrent bumps and reads must not data-race.
func TestCloneGeneration_ConcurrentReadWrite(t *testing.T) {
	c := newCloneGeneration(filepath.Join(t.TempDir(), "clone-generation"), nil)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func(n int) { defer wg.Done(); c.bump(int64(n)) }(i)
		go func() { defer wg.Done(); _, _ = c.current() }()
	}
	wg.Wait()
}

// TestCloneGenerationRoute_ReturnsToken asserts GET /clone-generation is
// unauthenticated (like /health) and returns the current token + resume time.
func TestCloneGenerationRoute_ReturnsToken(t *testing.T) {
	cg := newCloneGeneration(filepath.Join(t.TempDir(), "clone-generation"), nil)
	cg.bump(1700000000000000000)
	s := &server{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		sandboxID:    "sb-test",
		authToken:    "token-123",
		allowedPorts: map[int]struct{}{},
		cloneGen:     cg,
	}

	rr := httptest.NewRecorder()
	s.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/clone-generation", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unauthenticated)", rr.Code)
	}

	var body struct {
		Generation string `json:"generation"`
		ResumedAt  int64  `json:"resumed_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	wantToken, wantResumedAt := cg.current()
	if body.Generation != wantToken {
		t.Errorf("generation = %q, want %q", body.Generation, wantToken)
	}
	if body.ResumedAt != wantResumedAt {
		t.Errorf("resumed_at = %d, want %d", body.ResumedAt, wantResumedAt)
	}
}

// TestQuiesceHandler_PostResume_BumpsCloneGeneration asserts the post_resume
// handler rotates the clone-generation token — the wiring that lets an
// in-guest process detect the clone and reseed its userspace PRNGs.
func TestQuiesceHandler_PostResume_BumpsCloneGeneration(t *testing.T) {
	cg := newCloneGeneration(filepath.Join(t.TempDir(), "clone-generation"), nil)
	before, _ := cg.current()

	h := newQuiesceHandler(nil, nil, cg)
	h.quiesce = &fakeQuiesceOps{}

	if err := h.OnPostResume(context.Background(),
		json.RawMessage(`{"wallclock_unix_ns":1700000000000000000}`)); err != nil {
		t.Fatalf("OnPostResume: %v", err)
	}

	after, resumedAt := cg.current()
	if after == before {
		t.Error("clone generation token was not bumped on post_resume")
	}
	if resumedAt != 1700000000000000000 {
		t.Errorf("resumedAt = %d, want 1700000000000000000", resumedAt)
	}
}

// TestCloneGeneration_NilReceiverIsSafe pins the cheap hardening that the
// /clone-generation route relies on: a nil *cloneGeneration (a partial
// server in a test, or future code that skips newCloneGeneration) must
// report the baseline "never cloned" state instead of panicking. bump on a
// nil receiver is likewise a no-op.
func TestCloneGeneration_NilReceiverIsSafe(t *testing.T) {
	var cg *cloneGeneration // nil

	token, resumedAt := cg.current()
	if token != "" || resumedAt != 0 {
		t.Errorf("nil current() = (%q, %d), want (\"\", 0)", token, resumedAt)
	}
	// Must not panic.
	cg.bump(123)
}
