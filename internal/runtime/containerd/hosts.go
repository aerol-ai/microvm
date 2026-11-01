package containerd

import (
	"os"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
)

// A container's host files (resolv.conf, hosts, hostname) live in
// <RunDir>/hosts/<container id>, and the container's OCI spec bind-mounts
// them from there. The spec is written once, at NewContainer, and every task
// start re-reads it, so the directory must sit at that path for as long as
// the container exists: it belongs to the container, not to whichever
// sandbox holds the container. For a cold create the container id is the
// sandbox id. For a warm-pool container it stays the park slot id
// (park-<hex>) after a sandbox adopts it, since adoption relabels the
// container and never renames it. Destroy removes the directory by the
// container id (destroyParked by the slot id, which is the same string).
//
// Adoption used to rename the directory to the sandbox id. The running task
// didn't notice (a bind mount holds the inode, not the path), but the next
// start re-created the task from a spec that still named the park path, and
// runc failed: "open .../hosts/park-<id>/resolv.conf: no such file or
// directory".
type sandboxHostFiles struct {
	Dir        string
	ResolvConf string
	Hosts      string
	Hostname   string
}

func hostFilesDir(runDir, containerID string) string {
	return filepath.Join(runDir, "hosts", containerID)
}

func prepareSandboxHostFiles(runDir, sandboxID string) (*sandboxHostFiles, error) {
	dir := hostFilesDir(runDir, sandboxID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	resolvBody, err := resolvconf.Generate(resolvconf.HostPath)
	if err != nil {
		return nil, err
	}
	resolvPath := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte(resolvBody), 0o644); err != nil {
		return nil, err
	}
	hostsPath := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n"), 0o644); err != nil {
		return nil, err
	}
	hostnamePath := filepath.Join(dir, "hostname")
	if err := os.WriteFile(hostnamePath, []byte(sandboxID+"\n"), 0o644); err != nil {
		return nil, err
	}
	return &sandboxHostFiles{
		Dir:        dir,
		ResolvConf: resolvPath,
		Hosts:      hostsPath,
		Hostname:   hostnamePath,
	}, nil
}

// ensureSpecHostFiles puts back a host-files directory the container's spec
// mounts but the host no longer has, before a start hands that spec to runc.
// The one way it goes missing is a warm-pool container adopted by a build
// that renamed the directory to the sandbox id (see sandboxHostFiles): that
// directory is moved back to the path the spec names. With nothing to move,
// the files are generated again, as the park or create did. Either way the
// start goes ahead; without this, such a sandbox could never start again.
// A spec whose mounts are all present costs one stat per host-file mount.
func (d *Driver) ensureSpecHostFiles(spec *specs.Spec, sandboxID string) error {
	if spec == nil {
		return nil
	}
	root := filepath.Join(d.cfg.RunDir, "hosts")
	for _, m := range spec.Mounts {
		if m.Type != "bind" || filepath.Dir(filepath.Dir(m.Source)) != root {
			continue
		}
		if _, err := os.Stat(m.Source); err == nil {
			continue
		}
		dir := filepath.Dir(m.Source)
		owner := filepath.Base(dir)
		if validateSandboxID(owner) != nil {
			continue
		}
		// A sandbox has one container, so a directory under its own id here
		// can only be that container's, renamed.
		if sandboxID != owner && validateSandboxID(sandboxID) == nil {
			legacy := hostFilesDir(d.cfg.RunDir, sandboxID)
			if _, err := os.Stat(legacy); err == nil {
				_ = os.RemoveAll(dir)
				if err := os.Rename(legacy, dir); err != nil {
					return err
				}
				if d.logger != nil {
					d.logger.Warn("containerd start: moved a renamed host-files directory back to the path its container mounts",
						"container_id", owner, "sandbox_id", sandboxID)
				}
				continue
			}
		}
		if _, err := prepareSandboxHostFiles(d.cfg.RunDir, owner); err != nil {
			return err
		}
		if d.logger != nil {
			d.logger.Warn("containerd start: regenerated a container's missing host files",
				"container_id", owner, "missing", m.Source)
		}
	}
	return nil
}
