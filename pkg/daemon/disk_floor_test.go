package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDiskFloorPath(t *testing.T) {
	has := func(dirs ...string) func(string) bool {
		return func(p string) bool {
			for _, d := range dirs {
				if d == p {
					return true
				}
			}
			return false
		}
	}
	for _, tc := range []struct {
		name   string
		cfg    config.Config
		exists func(string) bool
		want   string
	}{
		{name: "the operator's path wins", cfg: config.Config{DiskFloorPath: "/data", ContainerEngine: models.ContainerEngineContainerd}, exists: has(), want: "/data"},
		{name: "containerd's data folder", cfg: config.Config{ContainerEngine: models.ContainerEngineContainerd}, exists: has("/var/lib/containerd", "/var/lib/docker"), want: "/var/lib/containerd"},
		{name: "docker's data folder", cfg: config.Config{ContainerEngine: models.ContainerEngineDocker}, exists: has("/var/lib/containerd", "/var/lib/docker"), want: "/var/lib/docker"},
		{name: "no data folder yet", cfg: config.Config{ContainerEngine: models.ContainerEngineContainerd}, exists: has("/var/lib/docker"), want: "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := diskFloorPath(tc.cfg, tc.exists); got != tc.want {
				t.Fatalf("diskFloorPath = %q, want %q", got, tc.want)
			}
		})
	}
}

type stubDisk struct {
	total, free uint64
	err         error
}

func (d stubDisk) DiskUsage() (uint64, uint64, error) { return d.total, d.free, d.err }

func TestWireDiskFloor(t *testing.T) {
	const gib = uint64(1) << 30
	boom := errors.New("statfs boom")
	for _, tc := range []struct {
		name      string
		ratio     float64
		disk      stubDisk
		wantErr   bool
		wantProbe bool
		admits    bool
	}{
		{name: "floor set, volume under it", ratio: 0.10, disk: stubDisk{total: 100 * gib, free: 2 * gib}, wantProbe: true},
		{name: "floor set, volume fine", ratio: 0.10, disk: stubDisk{total: 100 * gib, free: 60 * gib}, wantProbe: true, admits: true},
		{name: "floor set, volume unreadable refuses the boot", ratio: 0.10, disk: stubDisk{err: boom}, wantErr: true},
		{name: "no floor: gauges only", disk: stubDisk{total: 100 * gib, free: 2 * gib}, wantProbe: true, admits: true},
		{name: "no floor, volume unreadable: warn and go on", disk: stubDisk{err: boom}, admits: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{DiskFloorRatio: tc.ratio, DiskFloorPath: "/data"}
			admitter := capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 8192}, capacity.Limits{DiskFloorRatio: tc.ratio}, nil)
			var gotPath string
			err := wireDiskFloor(quietLogger(), cfg, admitter, func(p string) capacity.DiskProbe { gotPath = p; return tc.disk })
			if gotPath != "/data" {
				t.Fatalf("probe built for %q, want /data", gotPath)
			}
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "SB_DISK_FLOOR_PATH") || !errors.Is(err, boom) {
					t.Fatalf("err = %v, want a boot refusal naming SB_DISK_FLOOR_PATH", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("wireDiskFloor: %v", err)
			}
			snap := admitter.Snapshot()
			if got := snap.SandboxDiskTotalMB > 0; got != tc.wantProbe {
				t.Fatalf("probe installed = %v, want %v", got, tc.wantProbe)
			}
			if err := admitter.Admit("sb-1", capacity.Request{CPU: 1}); (err == nil) != tc.admits {
				t.Fatalf("Admit = %v, want admitted %v", err, tc.admits)
			}
		})
	}
}
