package containerd

import (
	"fmt"
	"os"
	"path/filepath"
)

const runscConfigRelPath = "runsc/config.toml"

// runscFlagsSection is the runsc flags every gVisor sandbox gets, restored
// or not (runsc checks a restore against the flags the sandbox was saved
// with). [runsc_config] is the section the runsc shim's toml Config
// actually decodes into runsc flags — the previous [runscflags] name was
// silently ignored, so host-uds never reached runsc and the in-guest
// toolboxd could not dial the bind-mounted readiness socket (create then
// stalls to its deadline).
const runscFlagsSection = "[runsc_config]\n  host-uds = \"open\"\n"

// ensureRunscConfig writes a host-local runsc config pinning --host-uds=open
// for UC-96* readiness socket attribution (mirrors install.sh runtimeArgs).
// Idempotent per path — no package-level Once, so tests (and a corrected
// RunDir) are not stranded on the first call's directory.
func (d *Driver) ensureRunscConfig() (string, error) {
	return d.ensureRunscFile(runscConfigRelPath, "# Managed by AerolVM containerd driver (do not edit).\n"+runscFlagsSection)
}

// ensureRunscFile writes body at rel under the run dir unless it is there.
// Compare CONTENT, not existence: a stat-only check strands nodes upgraded
// from an old format on the stale file forever (caught live on
// cluster-3-mixed-gvisor).
func (d *Driver) ensureRunscFile(rel, body string) (string, error) {
	if d == nil {
		return "", fmt.Errorf("driver is nil")
	}
	path := filepath.Join(d.runDir(), rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if existing, err := os.ReadFile(path); err == nil {
		if string(existing) == body {
			return path, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
