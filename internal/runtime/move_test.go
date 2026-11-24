package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestMoveMarks(t *testing.T) {
	ctx := context.Background()
	if CheckpointRequested(ctx) || RestoreRequested(ctx) {
		t.Fatal("a plain context asks for a move")
	}
	if c := WithCheckpoint(ctx); !CheckpointRequested(c) || RestoreRequested(c) {
		t.Fatal("WithCheckpoint marks the wrong call")
	}
	if c := WithRestore(ctx); !RestoreRequested(c) || CheckpointRequested(c) {
		t.Fatal("WithRestore marks the wrong call")
	}
}

// A refusal for good keeps its own text, and errors.Is reads it as
// ErrNotMovable through any wrapping; a plain error is not one.
func TestNotMovable(t *testing.T) {
	err := NotMovable("a sandbox from the warm pool moves by recreate only")
	for _, tc := range []struct {
		name    string
		err     error
		forGood bool
	}{
		{"the refusal", err, true},
		{"wrapped", fmt.Errorf("stop sb-1: %w", err), true},
		{"a plain error", errors.New("a sandbox from the warm pool moves by recreate only"), false},
		{"nil", nil, false},
	} {
		if got := errors.Is(tc.err, ErrNotMovable); got != tc.forGood {
			t.Errorf("%s: for good %v, want %v", tc.name, got, tc.forGood)
		}
	}
	if err.Error() != "a sandbox from the warm pool moves by recreate only" {
		t.Fatalf("text %q", err.Error())
	}
	if !errors.Is(err, err) {
		t.Fatal("a refusal is not itself")
	}
}
