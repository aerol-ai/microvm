package adapters

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Rclone mounts any rclone-supported remote using the user-supplied
// rclone.conf as a credentials file. The config is unlinked after the mount
// becomes ready; rclone keeps it in memory.
type Rclone struct{}

func (Rclone) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (Plan, error) {
	conf := spec.Credentials["rclone_conf"]
	if conf == "" {
		return Plan{}, errors.New("rclone requires credentials.rclone_conf")
	}

	credFile := filepath.Join(credDir, fmt.Sprintf("%s-%d.rclone.conf", sandboxID, index))

	argv := []string{
		"rclone", "mount",
		"--config", credFile,
		"--vfs-cache-mode", valueOr(spec.Options["vfs_cache_mode"], "writes"),
		spec.Source, hostTarget,
	}
	if spec.ReadOnly {
		argv = append(argv, "--read-only")
	}

	return Plan{
		Argv:       argv,
		CredFile:   credFile,
		CredBody:   []byte(conf),
		UnlinkCred: true,
	}, nil
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
