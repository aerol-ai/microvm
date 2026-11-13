package runtime

import "context"

// A gVisor sandbox moves to another worker with its memory (C21,
// plans/kubernetes-v2-architecture.md §10.5) through the service's usual
// stop on the source and its usual recreate on the target; these mark the
// two calls that are part of a move, so the runtime saves the memory on the
// stop and resumes from it on the create. Neither changes anything for a
// runtime that does not move sandboxes this way.

type checkpointKey struct{}

type restoreKey struct{}

// WithCheckpoint marks a Stop that saves the sandbox's memory before the
// sandbox ends, for a move.
func WithCheckpoint(ctx context.Context) context.Context {
	return context.WithValue(ctx, checkpointKey{}, true)
}

// CheckpointRequested reports whether ctx carries WithCheckpoint.
func CheckpointRequested(ctx context.Context) bool {
	v, _ := ctx.Value(checkpointKey{}).(bool)
	return v
}

// WithRestore marks a Create that resumes the sandbox from the memory a
// move staged on this worker, instead of booting it.
func WithRestore(ctx context.Context) context.Context {
	return context.WithValue(ctx, restoreKey{}, true)
}

// RestoreRequested reports whether ctx carries WithRestore.
func RestoreRequested(ctx context.Context) bool {
	v, _ := ctx.Value(restoreKey{}).(bool)
	return v
}
