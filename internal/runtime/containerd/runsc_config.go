package containerd

import (
	"fmt"
	"os"
	"path/filepath"
)

const runscConfigRelPath = "runsc/config.toml"

// ensureRunscConfig writes a host-local runsc config pinning --host-uds=open
// for UC-96* readiness socket attribution (mirrors install.sh runtimeArgs).
// Idempotent per path — no package-level Once, so tests (and a corrected
// RunDir) are not stranded on the first call's directory.
func (d *Driver) ensureRunscConfig() (string, error) {
	if d == nil {
		return "", fmt.Errorf("driver is nil")
	}
	runDir := d.cfg.RunDir
	if runDir == "" {
		runDir = "/var/lib/aerolvm/containerd"
	}
	path := filepath.Join(runDir, runscConfigRelPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	body := []byte("# Managed by AerolVM containerd driver (do not edit).\n[runscflags]\n  host-uds = \"open\"\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
