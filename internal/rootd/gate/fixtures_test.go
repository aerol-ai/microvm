package gate

import (
	"context"
	"encoding/json"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	"github.com/containerd/containerd/api/types"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

const testID = "sb-1"

// goodSpec is shaped like the agent's runc sandbox spec. The real
// builder's output is checked against rootpolicy in
// internal/runtime/containerd; here it only has to be one the gate passes.
func goodSpec(t testing.TB) *specs.Spec {
	t.Helper()
	ctx := namespaces.WithNamespace(context.Background(), testNS)
	s, err := oci.GenerateSpecWithPlatform(ctx, nil, "linux", &containers.Container{ID: testID},
		oci.WithProcessArgs("/.aerol/toolboxd", "sleep", "inf"),
		oci.WithHostname(testID),
		seccomp.WithDefaultProfile(),
		oci.WithAddedCapabilities(rootpolicy.SandboxCapabilities()),
		oci.WithDroppedCapabilities(rootpolicy.DroppedCapabilities()),
		oci.WithMaskedPaths(rootpolicy.MaskedPaths()),
		oci.WithReadonlyPaths(rootpolicy.ReadonlyPaths()),
		oci.WithNoNewPrivileges,
		oci.WithMemoryLimit(512<<20),
		oci.WithPidsLimit(4096),
		oci.WithCPUCFS(100000, 100000),
		func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
			for i, ns := range s.Linux.Namespaces {
				if ns.Type == specs.NetworkNamespace {
					s.Linux.Namespaces[i].Path = "/run/netns/" + testID
				}
			}
			return nil
		},
		oci.WithMounts([]specs.Mount{
			{Type: "bind", Source: testToolbox, Destination: "/.aerol/toolboxd", Options: []string{"rbind", "ro"}},
			{Type: "bind", Source: testRunDir + "/hosts/" + testID + "/resolv.conf", Destination: "/etc/resolv.conf", Options: []string{"rbind", "ro"}},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func specAny(t testing.TB, s *specs.Spec) *anypb.Any {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return &anypb.Any{TypeUrl: rootpolicy.SpecTypeURL, Value: b}
}

func protoAny(t testing.TB, url string, m proto.Message) *anypb.Any {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return &anypb.Any{TypeUrl: url, Value: b}
}

// goodContainer is a runc container record the gate passes.
func goodContainer(t testing.TB) *containersapi.Container {
	return &containersapi.Container{
		ID:          testID,
		Labels:      map[string]string{"aerolvm.managed": "true"},
		Image:       "docker.io/library/alpine:3.20",
		Runtime:     &containersapi.Container_Runtime{Name: rootpolicy.RuntimeRunc},
		Spec:        specAny(t, goodSpec(t)),
		Snapshotter: "overlayfs",
		SnapshotKey: testID,
	}
}

// goodRunscContainer is goodContainer on gVisor with the helper's config.
func goodRunscContainer(t testing.TB) *containersapi.Container {
	c := goodContainer(t)
	s := goodSpec(t)
	s.Annotations = map[string]string{rootpolicy.CRIContainerTypeAnnotation: rootpolicy.CRIContainerTypeSandbox}
	c.Spec = specAny(t, s)
	c.Runtime = &containersapi.Container_Runtime{
		Name:    rootpolicy.RuntimeRunsc,
		Options: protoAny(t, "runtimeoptions.v1.Options", &runtimeoptions.Options{TypeUrl: rootpolicy.RunscOptionsTypeURL, ConfigPath: testRunscCfg}),
	}
	return c
}

// overlayRootfs is the overlayfs snapshotter's mounts for an active
// snapshot with two layers below it.
func overlayRootfs() []*types.Mount {
	return []*types.Mount{{Type: "overlay", Source: "overlay", Options: []string{
		"index=off",
		"workdir=" + testLayers + "/9/work",
		"upperdir=" + testLayers + "/9/fs",
		"lowerdir=" + testLayers + "/2/fs:" + testLayers + "/1/fs",
	}}}
}
