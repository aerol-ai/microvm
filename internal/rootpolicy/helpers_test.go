package rootpolicy

import (
	"context"
	"encoding/json"
	"testing"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

const (
	testID       = "sb-1"
	testRunDir   = "/var/lib/sandboxd/containerd"
	testToolbox  = "/usr/local/lib/aerolvm/toolboxd"
	testReady    = "/run/sandboxd/docker/ready"
	testMounts   = "/var/lib/sandboxd/mounts"
	testSnapRoot = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"
	testFIFO     = "/run/aerolvm/fifo"
	testMoves    = testRunDir + "/moves"
	testRunscCfg = testRunDir + "/runsc/config.toml"
	testRestore  = testRunDir + "/runsc/restore.toml"
	// The root helper's own folders of per-container files.
	testHelperHosts = "/var/lib/aerolvm-rootd/hosts"
	testHelperReady = "/run/aerolvm-rootd/ready"
)

// testPolicy is the helper's policy for an agent with the default paths.
func testPolicy() Policy {
	return Policy{
		Namespace:        "aerolvm",
		Snapshotter:      "overlayfs",
		SnapshotterRoot:  testSnapRoot,
		NetnsDir:         "/run/netns",
		BindRoots:        []string{testRunDir + "/hosts", testReady, testMounts},
		BindFiles:        []string{testToolbox},
		HelperFileRoots:  []string{testHelperHosts, testHelperReady},
		ForbiddenRoots:   []string{"/run/aerolvm/sock", "/run/containerd"},
		MovesDir:         testMoves,
		FIFODir:          testFIFO,
		RunscConfigPaths: []string{testRunscCfg, testRestore},
		Limits:           Limits{MemoryBytes: 1 << 30, Pids: 8192, CPUs: 2},
	}
}

// baselineSpec is a spec shaped like the agent's: containerd's default
// Linux spec plus the options internal/runtime/containerd adds for a runc
// sandbox in a pooled network namespace with a ready socket. The real
// builder's output is checked in that package (rootpolicy_conformance_test).
func baselineSpec(t testing.TB) *specs.Spec {
	t.Helper()
	ctx := namespaces.WithNamespace(context.Background(), "aerolvm")
	c := &containers.Container{ID: testID}
	pids := int64(4096)
	s, err := oci.GenerateSpecWithPlatform(ctx, nil, "linux", c,
		oci.WithProcessArgs("/.aerol/toolboxd", "sleep", "inf"),
		oci.WithHostname(testID),
		seccomp.WithDefaultProfile(),
		oci.WithAddedCapabilities(SandboxCapabilities()),
		oci.WithDroppedCapabilities(DroppedCapabilities()),
		oci.WithMaskedPaths(MaskedPaths()),
		oci.WithReadonlyPaths(ReadonlyPaths()),
		oci.WithNoNewPrivileges,
		oci.WithPidsLimit(pids),
		oci.WithMemoryLimit(512<<20),
		oci.WithCPUCFS(150000, 100000),
		func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
			for i, ns := range s.Linux.Namespaces {
				if ns.Type == specs.NetworkNamespace {
					s.Linux.Namespaces[i].Path = "/run/netns/" + testID
				}
			}
			s.Linux.Sysctl = map[string]string{hostnet.SysctlAllDisableIPv6: "1", hostnet.SysctlDefaultDisableIPv6: "1"}
			return nil
		},
		oci.WithEnv([]string{"SB_SANDBOX_ID=" + testID}),
		oci.WithMounts([]specs.Mount{
			{Type: "bind", Source: testToolbox, Destination: "/.aerol/toolboxd", Options: []string{"rbind", "ro"}},
			{Type: "bind", Source: testRunDir + "/hosts/" + testID + "/resolv.conf", Destination: "/etc/resolv.conf", Options: []string{"rbind", "ro"}},
			{Type: "bind", Source: testReady + "/" + testID + ".abc.sock", Destination: "/run/aerolvm/ready.sock", Options: []string{"rbind"}},
			{Type: "bind", Source: testMounts + "/" + testID + "/0", Destination: "/data", Options: []string{"rbind", "ro"}},
			{Type: "tmpfs", Source: "tmpfs", Destination: "/scratch", Options: []string{"nosuid", "nodev", "noexec", "mode=1777", "size=1048576"}},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// gvisorSpec is baselineSpec as a runsc sandbox restored from a move.
func gvisorSpec(t testing.TB) *specs.Spec {
	s := baselineSpec(t)
	s.Annotations = map[string]string{
		CRIContainerTypeAnnotation: CRIContainerTypeSandbox,
		RestoreAnnotation:          testMoves + "/in/" + testID,
	}
	s.Mounts = append(s.Mounts, specs.Mount{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"ro", "nosuid", "noexec", "nodev"}})
	return s
}

func specJSON(t testing.TB, s *specs.Spec) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runscRuntime(t testing.TB, o *runtimeoptions.Options) Runtime {
	t.Helper()
	b, err := proto.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return Runtime{Name: RuntimeRunsc, OptionsTypeURL: "runtimeoptions.v1.Options", Options: b}
}

// baselineContainer is a runc container around baselineSpec.
func baselineContainer(t testing.TB, s *specs.Spec) Container {
	t.Helper()
	return Container{
		ID:          testID,
		Labels:      map[string]string{"aerolvm.managed": "true", "aerolvm.sandbox_id": testID},
		Runtime:     Runtime{Name: RuntimeRunc},
		SpecTypeURL: SpecTypeURL,
		Spec:        specJSON(t, s),
		Snapshotter: "overlayfs",
		SnapshotKey: testID,
	}
}

func wantRule(t *testing.T, err error, rule Rule) {
	t.Helper()
	if got := RuleOf(err); got != rule {
		t.Fatalf("rule %q (err %v), want %q", got, err, rule)
	}
}
