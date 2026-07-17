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
	// [runsc_config] is the section the runsc shim's toml Config actually
	// decodes into runsc flags — the previous [runscflags] name was silently
	// ignored, so host-uds never reached runsc and the in-guest toolboxd could
	// not dial the bind-mounted readiness socket (create then stalls to its
	// deadline). Compare CONTENT, not existence: a stat-only check strands
	// nodes upgraded from the old format on the stale file forever (caught
	// live on cluster-3-mixed-gvisor).
	body := []byte("# Managed by AerolVM containerd driver (do not edit).\n[runsc_config]\n  host-uds = \"open\"\n")
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == string(body) {
			return path, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
