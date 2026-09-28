package docker

import (
	"context"
	"errors"
	"testing"
)

// A zero-value Client has no HTTP transport. Several callers run on detached
// janitor goroutines (built-image GC, image GC, the events stream), so a nil
// dereference there does not fail one sweep — it SIGSEGVs the daemon. The
// request layer must return an error instead.
func TestZeroValueClientReturnsErrorInsteadOfPanicking(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"ListBuiltImages", func() error { _, err := (&Client{}).ListBuiltImages(ctx); return err }},
		{"nil receiver doRequest", func() error {
			_, err := (*Client)(nil).doRequest(ctx, "GET", "/_ping", nil, nil, nil)
			return err
		}},
		{"zero-value doRequest", func() error {
			_, err := (&Client{}).doRequest(ctx, "GET", "/_ping", nil, nil, nil)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			if err := tc.call(); !errors.Is(err, ErrClientNotConfigured) {
				t.Fatalf("err = %v, want ErrClientNotConfigured", err)
			}
		})
	}
}
