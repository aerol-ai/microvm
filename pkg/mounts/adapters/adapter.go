// Package adapters describes how to invoke external mount tools on the host
// for each supported storage protocol. The adapters are pure: they translate a
// MountSpec into a Plan describing what to run. The mounts.Manager owns
// process spawning, credential-file lifecycle, and supervision.
package adapters

import (
	"github.com/aerol-ai/microvm/pkg/models"
)

// Plan tells the manager exactly what to run on the host for one mount entry.
// It does not actually spawn anything; that is the manager's job.
type Plan struct {
	// Argv is the full command line, beginning with the binary path or name.
	Argv []string
	// Env is the environment for the spawned process. Empty means inherit
	// sandboxd's env.
	Env []string
	// CredFile is the absolute path the manager should write CredBody to with
	// mode 0600 before spawning. Empty means no credentials file.
	CredFile string
	// CredBody is the bytes the manager should write to CredFile.
	CredBody []byte
	// UnlinkCred indicates whether the manager should unlink CredFile after
	// the mount becomes ready. FUSE tools typically read credentials once at
	// startup and keep them in memory; sshfs may re-read on reconnect, so
	// that adapter sets UnlinkCred=false.
	UnlinkCred bool
	// IsKernelMount reports whether this mount type uses a kernel mount(2)
	// (no long-running user-space process). Manager skips supervision for
	// these and falls back to periodic health checks.
	IsKernelMount bool
}

// Adapter is the interface every supported mount type implements.
type Adapter interface {
	// Build produces a Plan from a user-supplied MountSpec, given the host
	// path the mount should land on. sandboxID and index are passed in so
	// the adapter can place its credentials file at a stable, per-mount path.
	Build(sandboxID string, index int, spec models.MountSpec, hostTarget, credDir string) (Plan, error)
}

// Adapters returns the default adapter map keyed by mount type.
func Adapters() map[models.MountType]Adapter {
	return map[models.MountType]Adapter{
		models.MountTypeS3:     S3{},
		models.MountTypeNFS:    NFS{},
		models.MountTypeSSHFS:  SSHFS{},
		models.MountTypeRclone: Rclone{},
	}
}
