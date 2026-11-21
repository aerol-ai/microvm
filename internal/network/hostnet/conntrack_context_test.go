//go:build !linux

package hostnet

import (
	"context"
	"testing"
)

func TestFlushConntrackContextElsewhere(t *testing.T) {
	if err := FlushConntrackContext(context.Background(), "10.88.0.5"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := FlushConntrackContext(ctx, "10.88.0.5"); err == nil {
		t.Fatal("an ended call reported success")
	}
}
