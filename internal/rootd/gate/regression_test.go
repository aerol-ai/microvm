package gate

import (
	"context"
	"errors"
	"slices"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	diffapi "github.com/containerd/containerd/api/services/diff/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The tests below are the independent review's proofs of concept against
// c34de25, each a hostile request the gate forwarded then. Each must now
// be refused before containerd sees it.

const (
	cCreate = "/containerd.services.containers.v1.Containers/Create"
	tCreate = "/containerd.services.tasks.v1.Tasks/Create"
	tUpdate = "/containerd.services.tasks.v1.Tasks/Update"
	dApply  = "/containerd.services.diff.v1.Diff/Apply"
	dDiff   = "/containerd.services.diff.v1.Diff/Diff"
)

var layerDesc = &types.Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: "sha256:00", Size: 1}

// storedContainer makes the fake answer the gate's own read of the
// container a task create names.
func (r *rig) storedContainer(c *containersapi.Container) {
	r.fake.on("/containerd.services.containers.v1.Containers/Get", func(context.Context, proto.Message) ([]proto.Message, error) {
		return []proto.Message{&containersapi.GetContainerResponse{Container: c}}, nil
	})
}

// Finding 2: a second procfs outside /proc has neither masked nor read-only
// paths; the sandbox's root writes <dest>/sys/kernel/core_pattern.
func TestRegressionExtraProcfs(t *testing.T) {
	r := newRig(t, testPolicy())
	s := goodSpec(t)
	s.Mounts = append(s.Mounts, specs.Mount{Destination: "/p2", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}})
	s.Process.Args = []string{"/bin/sh", "-c", "echo '|/proc/%P/root/x' > /p2/sys/kernel/core_pattern"}
	c := goodContainer(t)
	c.Spec = specAny(t, s)
	_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c})
	r.wantRefused(err, cCreate, string(rootpolicy.RuleMount))
}

// Finding 1: a comma inside an overlay path value becomes more overlay
// options in the mount data containerd hands the kernel, here an upperdir
// of /etc that Diff.Apply then writes a layer into, as root.
func TestRegressionOverlayCommaDiffApply(t *testing.T) {
	r := newRig(t, testPolicy())
	m := &types.Mount{Type: "overlay", Source: "overlay", Options: []string{
		"index=off",
		"lowerdir=" + testLayers + "/1/fs,upperdir=/etc,workdir=/var/tmp",
	}}
	_, err := r.invoke(nsCtx(), dApply, &diffapi.ApplyRequest{Diff: layerDesc, Mounts: []*types.Mount{m}})
	r.wantRefused(err, dApply, string(rootpolicy.RuleSnapshotMount))
}

// Finding 1 on the read side: Diff.Diff over a comma-smuggled upperdir=/etc
// would put the host's /etc in a layer the agent can read.
func TestRegressionOverlayCommaDiffDiff(t *testing.T) {
	r := newRig(t, testPolicy())
	left := []*types.Mount{{Type: "bind", Source: testLayers + "/1/fs", Options: []string{"ro", "rbind"}}}
	right := []*types.Mount{{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=" + testLayers + "/1/fs,upperdir=/etc,workdir=/var/tmp"}}}
	_, err := r.invoke(nsCtx(), dDiff, &diffapi.DiffRequest{Left: left, Right: right})
	r.wantRefused(err, dDiff, string(rootpolicy.RuleSnapshotMount))
}

// Findings 1 and 4 in a task's rootfs: the root becomes host / through a
// comma, or through a symlink the sandbox left under its own snapshots/<n>/fs,
// or a whole snapshot folder.
func TestRegressionTaskRootfs(t *testing.T) {
	for name, rootfs := range map[string][]*types.Mount{
		"comma": {{Type: "overlay", Source: "overlay", Options: []string{
			"index=off", "workdir=" + testLayers + "/9/work", "upperdir=" + testLayers + "/9/fs",
			"lowerdir=" + testLayers + "/1/fs,upperdir=/etc,workdir=/var/tmp",
		}}},
		"symlink": {{Type: "bind", Source: testLayers + "/5/fs/h", Options: []string{"rbind", "rw"}}},
		"parent":  {{Type: "bind", Source: testLayers + "/5", Options: []string{"rbind", "rw"}}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, testPolicy())
			r.storedContainer(goodContainer(t))
			_, err := r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: rootfs})
			r.wantRefused(err, tCreate, string(rootpolicy.RuleSnapshotMount))
		})
	}
}

// Finding 4 through Diff.Apply's shortcut: with one overlay mount,
// containerd applies the layer straight into its upperdir as a host path,
// following a symlink there.
func TestRegressionDiffApplyUpperdirSymlink(t *testing.T) {
	r := newRig(t, testPolicy())
	m := &types.Mount{Type: "overlay", Source: "overlay", Options: []string{
		"upperdir=" + testLayers + "/5/fs/h", "workdir=" + testLayers + "/5/work", "lowerdir=" + testLayers + "/1/fs",
	}}
	_, err := r.invoke(nsCtx(), dApply, &diffapi.ApplyRequest{Diff: layerDesc, Mounts: []*types.Mount{m}})
	r.wantRefused(err, dApply, string(rootpolicy.RuleSnapshotMount))
}

// Finding 3: stdio paths were checked as text only. With the gate's own
// on-disk check (Linux: stdio_linux_test.go builds real links and FIFOs),
// a path that is not a FIFO root made is refused.
func TestRegressionStdioSymlinkPath(t *testing.T) {
	r := newRig(t, testPolicy(), func(c *Config) { c.Stdio = nil })
	r.storedContainer(goodContainer(t))
	_, err := r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs(),
		Stdin: testFIFO + "/a/link-to-etc-shadow", Stdout: testFIFO + "/a/link-to-etc-crontab"})
	r.wantRefused(err, tCreate, string(rootpolicy.RuleTaskIO))
}

// Finding 5: a live resize could lift every limit.
func TestRegressionTaskUpdateUnlimited(t *testing.T) {
	r := newRig(t, testPolicy())
	lim, pids, q := int64(-1), int64(-1), int64(-1)
	_, err := r.invoke(nsCtx(), tUpdate, &tasksapi.UpdateTaskRequest{ContainerID: testID, Resources: resourcesAny(t, specs.LinuxResources{
		Memory: &specs.LinuxMemory{Limit: &lim}, Pids: &specs.LinuxPids{Limit: &pids}, CPU: &specs.LinuxCPU{Quota: &q},
	})})
	r.wantRefused(err, tUpdate, string(rootpolicy.RuleResources))
}

// bindings is a NetnsBinding from netns name to the container it was made for.
type bindings struct {
	owner map[string]string
	err   error
}

func (b bindings) Bound(_ context.Context, netns, containerID string) (bool, error) {
	if b.err != nil {
		return false, b.err
	}
	owner, ok := b.owner[netns]
	return ok && owner == containerID, nil
}

// Finding 6: any well-formed name under /run/netns passes the form check,
// a CNI pod's included. Accepted until T2 (R9: a broken agent already
// reaches every sandbox on its node); with the helper's binding wired, it
// is refused.
func TestRegressionForeignNetns(t *testing.T) {
	foreign := func(t *testing.T) *containersapi.Container {
		s := goodSpec(t)
		for i, ns := range s.Linux.Namespaces {
			if ns.Type == specs.NetworkNamespace {
				s.Linux.Namespaces[i].Path = "/run/netns/cni-0b6f5c1e-2a8d-4f7e-9c11-3d5e7a9b0c2d"
			}
		}
		c := goodContainer(t)
		c.Spec = specAny(t, s)
		return c
	}
	t.Run("no binding yet: the form check alone passes it", func(t *testing.T) {
		r := newRig(t, testPolicy())
		if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: foreign(t)}); err != nil {
			t.Fatalf("err %v", err)
		}
	})
	withBinding := func(b NetnsBinding) func(*Config) { return func(c *Config) { c.NetnsBinding = b } }
	own := bindings{owner: map[string]string{testID: testID}}
	t.Run("bound: another namespace is refused", func(t *testing.T) {
		r := newRig(t, testPolicy(), withBinding(own))
		_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: foreign(t)})
		r.wantRefused(err, cCreate, string(rootpolicy.RuleHostNamespace))
	})
	t.Run("bound: its own namespace passes", func(t *testing.T) {
		r := newRig(t, testPolicy(), withBinding(own))
		if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: goodContainer(t)}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bound: a sandbox with a namespace of its own needs no binding", func(t *testing.T) {
		r := newRig(t, testPolicy(), withBinding(bindings{}))
		s := goodSpec(t)
		for i := range s.Linux.Namespaces {
			s.Linux.Namespaces[i].Path = ""
		}
		c := goodContainer(t)
		c.Spec = specAny(t, s)
		if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bound: the stored container is checked at task create", func(t *testing.T) {
		r := newRig(t, testPolicy(), withBinding(own))
		r.storedContainer(foreign(t))
		_, err := r.invoke(nsCtx(), tCreate, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs()})
		r.wantRefused(err, tCreate, string(rootpolicy.RuleHostNamespace))
	})
	t.Run("a binding that cannot answer fails closed, not as a refusal", func(t *testing.T) {
		r := newRig(t, testPolicy(), withBinding(bindings{err: errors.New("netns pool unavailable")}))
		_, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: goodContainer(t)})
		if err == nil || status.Code(err) == codes.PermissionDenied || len(r.refused()) != 0 {
			t.Fatalf("err %v, refusals %v", err, r.refused())
		}
		if slices.Contains(r.fake.methodsSeen(), cCreate) {
			t.Fatal("containerd saw the create")
		}
	})
}
