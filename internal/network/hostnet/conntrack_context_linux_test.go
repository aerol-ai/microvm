//go:build linux

package hostnet

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// TestFlushConntrackContext: both directions, as FlushConntrackForIP, and
// no run starts once the call's context has ended.
func TestFlushConntrackContext(t *testing.T) {
	var calls [][]string
	orig := execConntrackContext
	execConntrackContext = func(_ context.Context, args ...string) error {
		calls = append(calls, args)
		return errors.New("nothing matched")
	}
	t.Cleanup(func() { execConntrackContext = orig })
	if err := FlushConntrackContext(context.Background(), " 10.88.0.5 "); err != nil {
		t.Fatalf("a best-effort flush failed: %v", err)
	}
	if len(calls) != 2 || !slices.Equal(calls[0], []string{"-D", "-s", "10.88.0.5"}) || !slices.Equal(calls[1], []string{"-D", "-d", "10.88.0.5"}) {
		t.Fatalf("calls %v", calls)
	}
	calls = nil
	if err := FlushConntrackContext(context.Background(), ""); err != nil || calls != nil {
		t.Fatalf("no address: %v %v", err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := FlushConntrackContext(ctx, "10.88.0.5"); !errors.Is(err, context.Canceled) || calls != nil {
		t.Fatalf("an ended call: %v, ran %v", err, calls)
	}
	// The real run, through a process group: conntrack may be absent, and
	// the flush is best-effort either way.
	execConntrackContext = orig
	if err := FlushConntrackContext(context.Background(), "10.88.0.5"); err != nil {
		t.Fatal(err)
	}
}
