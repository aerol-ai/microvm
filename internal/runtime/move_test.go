package runtime

import (
	"context"
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
