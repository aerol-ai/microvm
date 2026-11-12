package containerd

import (
	"context"
	"testing"
)

// PrepareImage is the create path's pull, run ahead (C9): it pulls from the
// registry once, and an image already here costs nothing.
func TestPrepareImage(t *testing.T) {
	reg := newFakeAOCR(t)
	patPath := writeClusterPAT(t, "pat")
	d := newTestDriver(t)
	d.ConfigureAOCRPullAuth([]string{reg.host()}, "c1", patPath)
	d.SetClient(NewTestClient("aerolvm", resolvingTransport()))
	ref := reg.host() + "/cluster/c1/snapshots/s:latest--ttl-1h"
	if err := d.PrepareImage(context.Background(), ref); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := d.PrepareImage(context.Background(), ref); err != nil {
		t.Fatalf("prepare again: %v", err)
	}
	if err := d.PrepareImage(context.Background(), " "); err == nil {
		t.Fatal("empty ref accepted")
	}
}
