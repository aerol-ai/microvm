package firecracker

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/firecracker"
)

func TestFirecrackerRESTSnapshotLoad_NetworkOverride(t *testing.T) {
	client := newFakeClient()
	if err := client.LoadSnapshot(context.Background(), firecracker.SnapshotLoad{
		SnapshotPath: "state",
		MemBackend:   &firecracker.MemoryBackend{BackendType: "File", BackendPath: "mem"},
		NetworkOverrides: []firecracker.NetworkOverride{{
			IfaceID: primaryIfaceID, HostDevName: "tap-test",
		}},
	}); err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if client.snapshotLoad.NetworkOverrides[0].HostDevName != "tap-test" {
		t.Fatalf("override = %+v", client.snapshotLoad.NetworkOverrides)
	}
}
