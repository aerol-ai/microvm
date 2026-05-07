package adapters

import (
	"github.com/aerol-ai/microvm/pkg/models"
)

// NFS uses the kernel mount(2) syscall via /bin/mount; there is no long-running
// user-space process to supervise. The manager runs `mount -t nfs ...` once,
// waits for it to exit (it returns immediately on success), then registers a
// periodic health check via findmnt.
type NFS struct{}

func (NFS) Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (Plan, error) {
	opts := spec.Options["opts"]
	if opts == "" {
		if spec.ReadOnly {
			opts = "ro"
		} else {
			opts = "rw"
		}
	} else if spec.ReadOnly {
		opts = opts + ",ro"
	}

	argv := []string{"mount", "-t", "nfs", "-o", opts, spec.Source, hostTarget}

	return Plan{
		Argv:          argv,
		IsKernelMount: true,
	}, nil
}
