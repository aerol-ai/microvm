package mounts

// ContainerBind is the daemon-internal description of a host→container bind
// mount produced by the mount manager. The docker client converts each one
// into a HostConfig.Binds entry at container create time.
type ContainerBind struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}
