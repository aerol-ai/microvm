package containerd

import (
	"context"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
)

// runscShimName is the containerd runtime handler for gVisor (runsc).
const runscShimName = "io.containerd.runsc.v1"

// runscOptionsTypeUrl is the discriminator the runsc shim requires INSIDE
// runtimeoptions.Options (its TypeUrl field, not the protobuf Any URL); the
// shim rejects any other value with "unsupported option type".
const runscOptionsTypeUrl = "io.containerd.runsc.v1.options"

func containerdRuntimeName(ociRuntime string) string {
	if ociRuntime == "runsc" {
		return runscShimName
	}
	return ociRuntime
}

// runscRuntimeOpts returns per-container shim options pointing at our
// host-local runsc.toml (host-uds=open). The wire type MUST be containerd's
// well-known runtimeoptions.v1 Options: the shim typeurl-unmarshals
// r.Options against its own proto registry, so a custom-registered Go type
// fails task create with "type with url ...: not found" — caught live by the
// first cluster-3-mixed-gvisor bench run; client-side-only tests can't see it.
func (d *Driver) runscRuntimeOpts() (interface{}, error) {
	path, err := d.ensureRunscConfig()
	if err != nil {
		return nil, err
	}
	return &runtimeoptions.Options{
		TypeUrl:    runscOptionsTypeUrl,
		ConfigPath: path,
	}, nil
}

// criSandboxAnnotation marks the container as a CRI pod-sandbox for the runsc
// shim. The shim classifies containers by this annotation
// (specutils.SpecContainerType); WITHOUT it the container is treated as a
// pod SUB-container: the shim runs `runsc create` with its output captured
// into buffer pipes (cmdOutput), runsc boots a standalone sandbox anyway,
// donates those pipes to the long-lived sandbox process as its stdio, and the
// shim then waits forever for pipe EOF — task create deadlocks (caught live
// by the first cluster-3-mixed-gvisor bench; reproduces with plain ctr too).
// Every AerolVM sandbox is one container == one gvisor sandbox, so declaring
// it a sandbox container is semantically exact.
const criContainerTypeAnnotation = "io.kubernetes.cri.container-type"
const criContainerTypeSandbox = "sandbox"

// runscSandboxAnnotationOpt returns the spec opt every runsc container needs.
func runscSandboxAnnotationOpt() oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		if s.Annotations == nil {
			s.Annotations = map[string]string{}
		}
		s.Annotations[criContainerTypeAnnotation] = criContainerTypeSandbox
		return nil
	}
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
