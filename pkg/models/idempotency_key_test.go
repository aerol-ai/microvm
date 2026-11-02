package models

import (
	"errors"
	"fmt"
	"testing"
)

func TestIdempotencyKeyReusedError(t *testing.T) {
	tests := []struct {
		name string
		err  *IdempotencyKeyReusedError
		want string
	}{
		{name: "named", err: &IdempotencyKeyReusedError{Key: "job-42"}, want: `Idempotency-Key "job-42" was already used with a different request`},
		{name: "unnamed", err: &IdempotencyKeyReusedError{}, want: "Idempotency-Key was already used with a different request"},
		{name: "nil", err: nil, want: "Idempotency-Key was already used with a different request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
	wrapped := fmt.Errorf("create: %w", &IdempotencyKeyReusedError{Key: "k"})
	if !errors.Is(wrapped, ErrIdempotencyKeyReused) || errors.Is(wrapped, ErrSandboxExists) {
		t.Fatal("the error does not match exactly ErrIdempotencyKeyReused")
	}
}
