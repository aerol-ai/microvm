package daemon

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// diskFloorPath is the volume the disk floor and its gauges read: the
// operator's SB_DISK_FLOOR_PATH, else the container engine's data folder,
// where image layers and sandbox writable layers live, else "/".
func diskFloorPath(cfg config.Config, exists func(string) bool) string {
	if cfg.DiskFloorPath != "" {
		return cfg.DiskFloorPath
	}
	engineDir := "/var/lib/docker"
	if cfg.ContainerEngine == models.ContainerEngineContainerd {
		engineDir = "/var/lib/containerd"
	}
	if exists(engineDir) {
		return engineDir
	}
	return "/"
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// wireDiskFloor gives the admitter its sandbox volume reader (C27). With a
// floor set, a volume that cannot be read refuses the boot: the operator
// asked for the floor, and a node that silently ran without it is the
// failure the floor exists to stop. Without one, the reader still feeds
// the 80%-used alert, so a read error only warns.
func wireDiskFloor(logger *slog.Logger, cfg config.Config, admitter *capacity.Admitter, newProbe func(string) capacity.DiskProbe) error {
	path := diskFloorPath(cfg, pathExists)
	probe := newProbe(path)
	total, free, err := probe.DiskUsage()
	if err != nil {
		if cfg.DiskFloorRatio > 0 {
			return fmt.Errorf("SB_DISK_FLOOR_RATIO is set but the sandbox volume cannot be read (set SB_DISK_FLOOR_PATH): %w", err)
		}
		logger.Warn("sandbox volume unreadable; no disk gauges", "path", path, "error", err)
		return nil
	}
	admitter.SetDiskProbe(probe)
	logger.Info("sandbox volume",
		"path", path,
		"disk_floor_ratio", cfg.DiskFloorRatio,
		"total_mb", total>>20,
		"free_mb", free>>20,
	)
	return nil
}
