package adapters

import (
	"github.com/aerol-ai/microvm/pkg/models"
)

// NFS uses the kernel mount(2) syscall via /bin/mount; there is no long-running
// user-space process to supervise. The manager runs `mount -t nfs ...` once,
// waits for it to exit (it returns immediately on success), then registers a
// periodic health check via findmnt.
type NFS struct{}

// nfsForcedOptions end every -o list, after the caller's options, so they
// win over an earlier suid or dev (mount takes the last of a pair). Without
// them a set-uid binary or a device node on the share would act as one on
// the host, where the share is mounted as root, and in the sandbox, which
// gets a bind of it with the same flags. This holds for every spec,
// including one stored before MountSpec.ValidateToolOptions refused suid
// and dev. noexec is not forced: a share used as a workspace runs its own
// scripts and tools.
const nfsForcedOptions = "nosuid,nodev"

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
	opts += "," + nfsForcedOptions

	// "--" keeps source positional even if it ever starts with '-'.
	argv := []string{"mount", "-t", "nfs", "-o", opts, "--", spec.Source, hostTarget}

	return Plan{
		Argv:          argv,
		IsKernelMount: true,
	}, nil
}
