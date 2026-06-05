package firecracker

import (
	"context"
	"strings"
	"testing"
)

func TestWarmSpawn_ExtraCoverage(t *testing.T) {
	d := &Driver{
		cfg: Config{
			KernelImage: "/some/kernel",
		},
	}

	// Missing slot ID
	if _, err := d.WarmSpawn(context.Background(), WarmSpawnRequest{
		SnapshotMemoryPath: "/mem", SnapshotStatePath: "/state", VsockCID: 3,
	}); err == nil || !strings.Contains(err.Error(), "slot id is empty") {
		t.Errorf("expected slot ID error, got %v", err)
	}

	// Invalid SandboxID (SlotID)
	if _, err := d.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "bad/id", SnapshotMemoryPath: "/mem", SnapshotStatePath: "/state", VsockCID: 3,
	}); err == nil || !strings.Contains(err.Error(), "invalid character '/'") {
		t.Errorf("expected invalid sandbox ID error, got %v", err)
	}

	// Missing paths
	if _, err := d.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot1", VsockCID: 3,
	}); err == nil || !strings.Contains(err.Error(), "snapshot paths are required") {
		t.Errorf("expected missing paths error, got %v", err)
	}

	// Invalid CID
	if _, err := d.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot1", SnapshotMemoryPath: "/mem", SnapshotStatePath: "/state", VsockCID: 2,
	}); err == nil || !strings.Contains(err.Error(), "VsockCID=2 is reserved") {
		t.Errorf("expected invalid CID error, got %v", err)
	}
}

func TestWarmHandle_Pid(t *testing.T) {
	fakeH := &fakeVMM{}
	wh := &warmHandle{handle: fakeH}
	if wh.Pid() != 0 {
		t.Errorf("expected 0, got %v", wh.Pid())
	}
}
