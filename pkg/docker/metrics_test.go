package docker

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClassifyImagePullError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: ""},
		{name: "context_canceled_sentinel", err: context.Canceled, want: "canceled"},
		{name: "context_deadline_exceeded_sentinel", err: context.DeadlineExceeded, want: "timeout"},
		{name: "wrapped_context_canceled", err: fmt.Errorf("op failed: %w", context.Canceled), want: "canceled"},
		{name: "string_context_canceled", err: errors.New("context canceled"), want: "canceled"},
		{name: "string_deadline_exceeded", err: errors.New("deadline exceeded"), want: "timeout"},
		{name: "string_timeout", err: errors.New("i/o timeout"), want: "timeout"},
		{name: "string_timed_out", err: errors.New("connection timed out"), want: "timeout"},
		{name: "string_unauthorized", err: errors.New("unauthorized"), want: "auth"},
		{name: "string_authentication_required", err: errors.New("authentication required"), want: "auth"},
		{name: "string_denied", err: errors.New("access denied"), want: "auth"},
		{name: "string_manifest_unknown", err: errors.New("manifest unknown"), want: "not_found"},
		{name: "string_not_found", err: errors.New("image not found"), want: "not_found"},
		{name: "string_no_such_image", err: errors.New("no such image"), want: "not_found"},
		{name: "string_too_many_requests", err: errors.New("too many requests"), want: "rate_limited"},
		{name: "string_rate_limit", err: errors.New("rate limit exceeded"), want: "rate_limited"},
		{name: "string_backoff", err: errors.New("pull backoff"), want: "backoff"},
		{name: "unknown_error", err: errors.New("some unexpected failure"), want: "error"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyImagePullError(tc.err)
			if got != tc.want {
				t.Fatalf("classifyImagePullError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
