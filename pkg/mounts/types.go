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
	// RootOnly marks an s3 or rclone mount whose tool lets only root in: it
	// was started for no consumer (Consumer), for instance by a sandboxd
	// from before WASM workers dropped their privileges and taken over as
	// it was. A WASM sandbox with one keeps a root worker until it is
	// recreated: a live mount is never restarted under it, since rclone may
	// hold writes it has not flushed.
	RootOnly bool
	// Lent marks a mount point the root helper keeps (privilege mode
	// split, NewRemote): sandboxd cannot reach it, so a WASM worker is lent
	// it by the helper, never passed it by sandboxd (pkg/wasm/worker
	// lend.go). A container's runtime binds it as any other.
	Lent bool
}

// TmpfsOptions returns the mount options for a Tmpfs bind.
func (b ContainerBind) TmpfsOptions() []string {
	size := b.TmpfsSize
	if size <= 0 {
		size = 1 << 20
	}
	return []string{"nosuid", "nodev", "noexec", "mode=1777", fmt.Sprintf("size=%d", size)}
}
