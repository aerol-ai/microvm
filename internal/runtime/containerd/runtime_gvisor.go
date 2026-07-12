package containerd

import (
	cntr "github.com/containerd/containerd"
	"github.com/containerd/typeurl/v2"
)

// runscShimName is the containerd runtime handler for gVisor (runsc).
const runscShimName = "io.containerd.runsc.v1"

func containerdRuntimeName(ociRuntime string) string {
	if ociRuntime == "runsc" {
		return runscShimName
	}
	return ociRuntime
}

// runscShimOptions mirrors the runsc containerd shim Options proto without a
// gVisor module dependency. Type URL must match the shim's registered decoder.
type runscShimOptions struct {
	ConfigPath string `json:"config_path,omitempty"`
}

func init() {
	typeurl.Register(&runscShimOptions{}, "github.com/google/gvisor/runsc/cmd/containerd-shim-runsc-v1/options", "Options")
}

// runscRuntimeOpts returns per-container runsc shim options with host-uds=open.
func (d *Driver) runscRuntimeOpts() (interface{}, error) {
	path, err := d.ensureRunscConfig()
	if err != nil {
		return nil, err
	}
	return &runscShimOptions{ConfigPath: path}, nil
}

func (d *Driver) runtimeContainerOpt(ociRuntime string) (cntr.NewContainerOpts, error) {
	name := containerdRuntimeName(ociRuntime)
	if ociRuntime != "runsc" {
		if name == "" {
			return nil, nil
		}
		return cntr.WithRuntime(name, nil), nil
	}
	opts, err := d.runscRuntimeOpts()
	if err != nil {
		return nil, err
	}
	return cntr.WithRuntime(name, opts), nil
}
