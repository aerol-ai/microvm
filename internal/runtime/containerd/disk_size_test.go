package containerd

import (
	"context"
	"testing"
)

// TestWritableLayerBytesNeedsAClient: without a connected client the size is
// an error, never a zero that reads as "within its disk".
func TestWritableLayerBytesNeedsAClient(t *testing.T) {
	d := New(Config{}, nil, nil)
	if _, err := d.WritableLayerBytes(context.Background(), "ctr"); err == nil {
		t.Fatal("no client: want an error")
	}
}
