package wasm

import (
	"context"
	"testing"
	"time"
)

func TestCoverage97RunReturnsWhenPoolIsClosed(t *testing.T) {
	pool := New(t.TempDir(), nil)
	if drained := pool.Close(); drained != 0 {
		t.Fatalf("drained = %d", drained)
	}
	done := make(chan struct{})
	go func() {
		pool.Run(context.Background(), RefillConfig{RefillInterval: time.Second}, &fakeSpawner{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("closed pool refill did not return")
	}
}
