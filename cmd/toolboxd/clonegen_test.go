package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/clonegen"
)

func TestCloneGenerationRoute_ReturnsToken(t *testing.T) {
	cg := clonegen.New(filepath.Join(t.TempDir(), "clone-generation"), nil)
	cg.Bump(1700000000000000000)
	s := &server{
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
	wantToken, wantResumedAt := cg.Current()
	if body.Generation != wantToken {
		t.Errorf("generation = %q, want %q", body.Generation, wantToken)
	}
	if body.ResumedAt != wantResumedAt {
		t.Errorf("resumed_at = %d, want %d", body.ResumedAt, wantResumedAt)
	}
}

func TestQuiesceHandler_PostResume_BumpsCloneGeneration(t *testing.T) {
	cg := clonegen.New(filepath.Join(t.TempDir(), "clone-generation"), nil)
	before, _ := cg.Current()

	h := newQuiesceHandler(nil, nil, cg)
	h.quiesce = &fakeQuiesceOps{}

	if err := h.OnPostResume(context.Background(),
		json.RawMessage(`{"wallclock_unix_ns":1700000000000000000}`)); err != nil {
		t.Fatalf("OnPostResume: %v", err)
	}

	after, resumedAt := cg.Current()
	if after == before {
		t.Error("clone generation token was not bumped on post_resume")
	}
	if resumedAt != 1700000000000000000 {
		t.Errorf("resumedAt = %d, want 1700000000000000000", resumedAt)
	}
}
