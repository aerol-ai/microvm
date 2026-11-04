package mounts

import "fmt"

// ContainerBind is the daemon-internal description of a host→container bind
// mount produced by the mount manager. The docker client converts each one
// into a HostConfig.Binds entry at container create time.
type ContainerBind struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
	// Tmpfs mounts a small private tmpfs (TmpfsSize bytes, mode 1777) at
	// ContainerPath instead of binding HostPath: scratch space the sandbox
	// can write whatever user it runs as, without touching the host's disk.
	Tmpfs     bool
	TmpfsSize int64
}

// TmpfsOptions returns the mount options for a Tmpfs bind.
func (b ContainerBind) TmpfsOptions() []string {
	size := b.TmpfsSize
	if size <= 0 {
		size = 1 << 20
	}
	return []string{"nosuid", "nodev", "noexec", "mode=1777", fmt.Sprintf("size=%d", size)}
}
