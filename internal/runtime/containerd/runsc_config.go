package containerd

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const runscConfigRelPath = "runsc/config.toml"

var runscConfigOnce sync.Once

// ensureRunscConfig writes a host-local runsc config pinning --host-uds=open
// for UC-96* readiness socket attribution (mirrors install.sh runtimeArgs).
func (d *Driver) ensureRunscConfig() (string, error) {
	if d == nil {
		return "", fmt.Errorf("driver is nil")
	}
	runDir := d.cfg.RunDir
	if runDir == "" {
		runDir = "/var/lib/aerolvm/containerd"
	}
	path := filepath.Join(runDir, runscConfigRelPath)
	var initErr error
	runscConfigOnce.Do(func() {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			initErr = err
			return
		}
		body := []byte("# Managed by AerolVM containerd driver (do not edit).\n[runscflags]\n  host-uds = \"open\"\n")
		if err := os.WriteFile(path, body, 0o644); err != nil {
			initErr = err
		}
	})
	if initErr != nil {
		return "", initErr
	}
	return path, nil
}
