package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	contentapi "github.com/containerd/containerd/api/services/content/v1"
	diffapi "github.com/containerd/containerd/api/services/diff/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	leasesapi "github.com/containerd/containerd/api/services/leases/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	runcoptions "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthapi "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// invoke makes one call through the gate as a raw stream: it works for
// every method shape and for methods the gate does not know.
func (r *rig) invoke(ctx context.Context, name string, reqs ...proto.Message) ([]proto.Message, error) {
	r.t.Helper()
	newResp := func() proto.Message { return &emptypb.Empty{} }
	if m := methods[name]; m != nil {
		newResp = m.newResp
	}
	cs, err := r.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, name)
	if err != nil {
		return nil, err
	}
	for _, q := range reqs {
		if err := cs.SendMsg(q); err != nil {
			break
		}
	}
	_ = cs.CloseSend()
	var out []proto.Message
	for {
		resp := newResp()
		if err := cs.RecvMsg(resp); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		out = append(out, resp)
	}
}

func resourcesAny(t *testing.T, r specs.LinuxResources) *anypb.Any {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return &anypb.Any{TypeUrl: rootpolicy.ResourcesTypeURL, Value: raw}
}

// withUnknownField adds a field this build does not know to m, as a newer
// client would send it.
func withUnknownField[T proto.Message](m T) T {
	m.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 999, protowire.VarintType), 1))
	return m
}

// validRequests is a request the gate passes for every method on the
// allowlist, as the agent's client would send it.
func validRequests(t *testing.T) map[string][]proto.Message {
	limit := int64(1 << 30)
	return map[string][]proto.Message{
		"/containerd.services.version.v1.Version/Version":             {&emptypb.Empty{}},
		"/grpc.health.v1.Health/Check":                                {&healthapi.HealthCheckRequest{}},
		"/containerd.services.namespaces.v1.Namespaces/Get":           {&namespacesapi.GetNamespaceRequest{Name: testNS}},
		"/containerd.services.introspection.v1.Introspection/Plugins": {&introspectionapi.PluginsRequest{Filters: []string{"type==io.containerd.snapshotter.v1"}}},
		"/containerd.services.containers.v1.Containers/Get":           {&containersapi.GetContainerRequest{ID: testID}},
		"/containerd.services.containers.v1.Containers/List":          {&containersapi.ListContainersRequest{Filters: []string{"labels.aerolvm.managed"}}},
		"/containerd.services.containers.v1.Containers/ListStream":    {&containersapi.ListContainersRequest{}},
		"/containerd.services.tasks.v1.Tasks/Get":                     {&tasksapi.GetRequest{ContainerID: testID}},
		"/containerd.services.tasks.v1.Tasks/ListPids":                {&tasksapi.ListPidsRequest{ContainerID: testID}},
		"/containerd.services.tasks.v1.Tasks/Wait":                    {&tasksapi.WaitRequest{ContainerID: testID}},
		"/containerd.services.images.v1.Images/Get":                   {&imagesapi.GetImageRequest{Name: "docker.io/library/alpine:3.20"}},
		"/containerd.services.content.v1.Content/Info":                {&contentapi.InfoRequest{Digest: "sha256:abc"}},
		"/containerd.services.content.v1.Content/Read":                {&contentapi.ReadContentRequest{Digest: "sha256:abc"}},
		"/containerd.services.snapshots.v1.Snapshots/Stat":            {&snapshotsapi.StatSnapshotRequest{Snapshotter: "overlayfs", Key: testID}},
		"/containerd.services.snapshots.v1.Snapshots/Mounts":          {&snapshotsapi.MountsRequest{Snapshotter: "overlayfs", Key: testID}},
		"/containerd.services.snapshots.v1.Snapshots/Usage":           {&snapshotsapi.UsageRequest{Snapshotter: "overlayfs", Key: testID}},
		"/containerd.services.events.v1.Events/Subscribe":             {&eventsapi.SubscribeRequest{Filters: []string{`topic~="/tasks/"`}}},
		"/containerd.services.containers.v1.Containers/Create":        {&containersapi.CreateContainerRequest{Container: goodContainer(t)}},
		"/containerd.services.containers.v1.Containers/Update":        {&containersapi.UpdateContainerRequest{Container: &containersapi.Container{ID: testID, Labels: map[string]string{"aerolvm.sandbox_id": "sb-9"}}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels.aerolvm.sandbox_id"}}}},
		"/containerd.services.containers.v1.Containers/Delete":        {&containersapi.DeleteContainerRequest{ID: testID}},
		"/containerd.services.tasks.v1.Tasks/Create":                  {&tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs(), Stdout: testFIFO + "/1/" + testID + "-stdout", Stderr: testFIFO + "/1/" + testID + "-stderr"}},
		"/containerd.services.tasks.v1.Tasks/Start":                   {&tasksapi.StartRequest{ContainerID: testID}},
		"/containerd.services.tasks.v1.Tasks/Kill":                    {&tasksapi.KillRequest{ContainerID: testID, Signal: 15}},
		"/containerd.services.tasks.v1.Tasks/Delete":                  {&tasksapi.DeleteTaskRequest{ContainerID: testID}},
		"/containerd.services.tasks.v1.Tasks/Pause":                   {&tasksapi.PauseTaskRequest{ContainerID: testID}},
		"/containerd.services.tasks.v1.Tasks/Resume":                  {&tasksapi.ResumeTaskRequest{ContainerID: testID}},
		"/containerd.services.tasks.v1.Tasks/Update":                  {&tasksapi.UpdateTaskRequest{ContainerID: testID, Resources: resourcesAny(t, specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: &limit}})}},
		"/containerd.services.images.v1.Images/Create":                {&imagesapi.CreateImageRequest{Image: &imagesapi.Image{Name: "x:1", Target: &types.Descriptor{Digest: "sha256:abc"}}}},
		"/containerd.services.images.v1.Images/Update":                {&imagesapi.UpdateImageRequest{Image: &imagesapi.Image{Name: "x:1", Labels: map[string]string{"containerd.io/gc.root": "now"}}}},
		"/containerd.services.images.v1.Images/Delete":                {&imagesapi.DeleteImageRequest{Name: "x:1"}},
		"/containerd.services.content.v1.Content/Write":               {&contentapi.WriteContentRequest{Action: contentapi.WriteAction_STAT, Ref: "r"}, &contentapi.WriteContentRequest{Action: contentapi.WriteAction_WRITE, Ref: "r", Data: []byte("layer")}, &contentapi.WriteContentRequest{Action: contentapi.WriteAction_COMMIT, Ref: "r"}},
		"/containerd.services.content.v1.Content/Update":              {&contentapi.UpdateRequest{Info: &contentapi.Info{Digest: "sha256:abc", Labels: map[string]string{"containerd.io/distribution.source.docker.io": "library/alpine"}}}},
		"/containerd.services.snapshots.v1.Snapshots/Prepare":         {&snapshotsapi.PrepareSnapshotRequest{Snapshotter: "overlayfs", Key: testID, Parent: "sha256:p"}},
		"/containerd.services.snapshots.v1.Snapshots/View":            {&snapshotsapi.ViewSnapshotRequest{Snapshotter: "overlayfs", Key: "v", Parent: "sha256:p"}},
		"/containerd.services.snapshots.v1.Snapshots/Commit":          {&snapshotsapi.CommitSnapshotRequest{Snapshotter: "overlayfs", Name: "sha256:n", Key: "k"}},
		"/containerd.services.snapshots.v1.Snapshots/Remove":          {&snapshotsapi.RemoveSnapshotRequest{Snapshotter: "overlayfs", Key: testID}},
		"/containerd.services.diff.v1.Diff/Apply":                     {&diffapi.ApplyRequest{Diff: &types.Descriptor{Digest: "sha256:l"}, Mounts: overlayRootfs()}},
		"/containerd.services.diff.v1.Diff/Diff":                      {&diffapi.DiffRequest{Left: []*types.Mount{{Type: "bind", Source: testLayers + "/2/fs", Options: []string{"ro", "rbind"}}}, Right: overlayRootfs()}},
		"/containerd.services.leases.v1.Leases/Create":                {&leasesapi.CreateRequest{ID: "lease-1", Labels: map[string]string{"containerd.io/gc.expire": "x"}}},
		"/containerd.services.leases.v1.Leases/Delete":                {&leasesapi.DeleteRequest{ID: "lease-1"}},
		"/containerd.services.leases.v1.Leases/AddResource":           {&leasesapi.AddResourceRequest{ID: "lease-1", Resource: &leasesapi.Resource{ID: "sha256:abc", Type: "content"}}},
	}
}

// TestEveryAllowedMethodForwards: each method on the allowlist reaches
// containerd, in the agent's namespace, with nothing refused.
func TestEveryAllowedMethodForwards(t *testing.T) {
	valid := validRequests(t)
	if len(valid) != len(allowlist) {
		t.Fatalf("%d valid requests for %d allowed methods", len(valid), len(allowlist))
	}
	r := newRig(t, testPolicy())
	r.fake.on("/containerd.services.containers.v1.Containers/Get", func(context.Context, proto.Message) ([]proto.Message, error) {
		return []proto.Message{&containersapi.GetContainerResponse{Container: goodContainer(t)}}, nil
	})
	for _, m := range allowlist {
		t.Run(m.name, func(t *testing.T) {
			reqs, ok := valid[m.name]
			if !ok {
				t.Fatalf("no valid request for %s", m.name)
			}
			before := len(r.fake.seen())
			if _, err := r.invoke(nsCtx(), m.name, reqs...); err != nil {
				t.Fatalf("%s: %v", m.name, err)
			}
			got := r.fake.seen()[before:]
			want := len(reqs)
			if m.name == "/containerd.services.tasks.v1.Tasks/Create" {
				want++ // the gate reads the stored container first
			}
			if len(got) != want || got[len(got)-1].method != m.name {
				t.Fatalf("containerd saw %v", r.fake.methodsSeen()[before:])
			}
			for _, c := range got {
				if !slices.Equal(c.namespace, []string{testNS}) {
					t.Fatalf("namespace %v reached containerd", c.namespace)
				}
			}
		})
	}
	if refs := r.refused(); len(refs) != 0 {
		t.Fatalf("refusals: %+v", refs)
	}
	// The task create's stdio went to the on-disk check, both of them.
	if want := []string{testFIFO + "/1/" + testID + "-stdout", testFIFO + "/1/" + testID + "-stderr"}; !slices.Equal(r.stdio.seen, want) {
		t.Fatalf("stdio checked %v, want %v", r.stdio.seen, want)
	}
	// Each bind source, from its root, at create and again at task create.
	binds := [][2]string{
		{"/usr/local/lib/aerolvm", testToolbox},
		{testRunDir + "/hosts", testRunDir + "/hosts/" + testID + "/resolv.conf"},
	}
	if want := append(slices.Clone(binds), binds...); !slices.Equal(r.binds.seen, want) {
		t.Fatalf("binds checked %v, want %v", r.binds.seen, want)
	}
}

// refuseBinds is a bind check that finds every source on disk wrong.
type refuseBinds struct{}

func (refuseBinds) CheckBind(_, src string, _ bool) error { return bindViolation(src, "planted link") }

func TestBindCheckRefusals(t *testing.T) {
	r := newRig(t, testPolicy(), func(c *Config) { c.Binds = refuseBinds{} })
	const create = "/containerd.services.containers.v1.Containers/Create"
	_, err := r.invoke(nsCtx(), create, &containersapi.CreateContainerRequest{Container: goodContainer(t)})
	r.wantRefused(err, create, string(rootpolicy.RuleMount))
	const task = "/containerd.services.tasks.v1.Tasks/Create"
	r.storedContainer(goodContainer(t))
	_, err = r.invoke(nsCtx(), task, &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs()})
	r.wantRefused(err, task, string(rootpolicy.RuleMount))
	// A source outside every root never reaches the disk check.
	g := &Gate{policy: testPolicy(), binds: refuseBinds{}}
	c := policyContainer(goodContainer(t))
	if err := g.checkBinds(c); rootpolicy.RuleOf(err) != rootpolicy.RuleMount {
		t.Fatalf("err %v", err)
	}
	g.policy.BindRoots, g.policy.BindFiles = nil, nil
	if err := g.checkBinds(c); err == nil || rootpolicy.RuleOf(err) != rootpolicy.RuleMount {
		t.Fatalf("a source outside every root: %v", err)
	}
	c.Spec = []byte("{")
	if err := g.checkBinds(c); rootpolicy.RuleOf(err) != rootpolicy.RuleSpec {
		t.Fatalf("bad spec: %v", err)
	}
}

// TestUnlistedMethodsRefused: anything the agent does not call today is
// refused by name, before containerd hears of it.
func TestUnlistedMethodsRefused(t *testing.T) {
	r := newRig(t, testPolicy())
	for _, name := range []string{
		"/containerd.services.tasks.v1.Tasks/Exec",
		"/containerd.services.tasks.v1.Tasks/Checkpoint",
		"/containerd.services.tasks.v1.Tasks/List",
		"/containerd.services.tasks.v1.Tasks/Metrics",
		"/containerd.services.tasks.v1.Tasks/DeleteProcess",
		"/containerd.services.tasks.v1.Tasks/ResizePty",
		"/containerd.services.tasks.v1.Tasks/CloseIO",
		"/containerd.services.namespaces.v1.Namespaces/Create",
		"/containerd.services.namespaces.v1.Namespaces/Update",
		"/containerd.services.namespaces.v1.Namespaces/Delete",
		"/containerd.services.namespaces.v1.Namespaces/List",
		"/containerd.services.sandbox.v1.Store/Create",
		"/containerd.services.sandbox.v1.Controller/Create",
		"/containerd.services.sandbox.v1.Controller/Start",
		"/containerd.services.transfer.v1.Transfer/Transfer",
		"/containerd.services.streaming.v1.Streaming/Stream",
		"/containerd.services.mounts.v1.Mounts/Activate",
		"/containerd.services.events.v1.Events/Publish",
		"/containerd.services.events.v1.Events/Forward",
		"/containerd.services.content.v1.Content/Delete",
		"/containerd.services.content.v1.Content/Abort",
		"/containerd.services.images.v1.Images/List",
		"/containerd.services.snapshots.v1.Snapshots/Update",
		"/containerd.services.snapshots.v1.Snapshots/Cleanup",
		"/containerd.services.leases.v1.Leases/DeleteResource",
		"/containerd.services.introspection.v1.Introspection/Server",
		"/runtime.v1.RuntimeService/RunPodSandbox",
		"/grpc.health.v1.Health/Watch",
		"/no.such.Service/Method",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := r.invoke(nsCtx(), name, &emptypb.Empty{})
			r.wantRefused(err, name, ReasonMethod)
		})
	}
	if seen := r.fake.seen(); len(seen) != 0 {
		t.Fatalf("containerd saw %v", r.fake.methodsSeen())
	}
}

func TestNamespaceIsPinned(t *testing.T) {
	r := newRig(t, testPolicy())
	const list = "/containerd.services.containers.v1.Containers/List"
	for name, ctx := range map[string]context.Context{
		"no namespace":      context.Background(),
		"another namespace": metadata.AppendToOutgoingContext(context.Background(), namespaces.GRPCHeader, "k8s.io"),
		"two namespaces":    metadata.AppendToOutgoingContext(context.Background(), namespaces.GRPCHeader, testNS, namespaces.GRPCHeader, "k8s.io"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := r.invoke(ctx, list, &containersapi.ListContainersRequest{})
			r.wantRefused(err, list, ReasonNamespace)
		})
	}
	const get = "/containerd.services.namespaces.v1.Namespaces/Get"
	_, err := r.invoke(nsCtx(), get, &namespacesapi.GetNamespaceRequest{Name: "k8s.io"})
	r.wantRefused(err, get, string(rootpolicy.RuleNamespace))
}

// TestOnlyContainerdMetadataForwarded: the namespace and lease reach
// containerd; nothing else the agent puts on a call does.
func TestOnlyContainerdMetadataForwarded(t *testing.T) {
	r := newRig(t, testPolicy())
	ctx := metadata.AppendToOutgoingContext(nsCtx(), "containerd-lease", "lease-7", "x-impersonate", "root")
	if _, err := r.invoke(ctx, "/containerd.services.images.v1.Images/Get", &imagesapi.GetImageRequest{Name: "x"}); err != nil {
		t.Fatal(err)
	}
	c := r.fake.seen()[0]
	if !slices.Equal(c.lease, []string{"lease-7"}) || len(c.other) != 0 {
		t.Fatalf("lease %v, other metadata %v", c.lease, c.other)
	}
}

// TestBrokenAgentWrites is the "broken agent" suite for the gate
// (plans/security-gaps-m1-m4.md §3.6): a client that talks to the gate as a
// compromised agent would. Every hostile write is refused with the rule
// that caught it, and containerd never sees it.
func TestBrokenAgentWrites(t *testing.T) {
	withSpec := func(mutate func(*specs.Spec)) *containersapi.Container {
		c := goodContainer(t)
		s := goodSpec(t)
		mutate(s)
		c.Spec = specAny(t, s)
		return c
	}
	create := func(c *containersapi.Container) proto.Message {
		return &containersapi.CreateContainerRequest{Container: c}
	}
	runcOpts := func(o *runcoptions.Options) *containersapi.Container {
		c := goodContainer(t)
		c.Runtime.Options = protoAny(t, "containerd.runc.v1.Options", o)
		return c
	}
	runscAt := func(path string) *containersapi.Container {
		c := goodRunscContainer(t)
		c.Runtime.Options = protoAny(t, "runtimeoptions.v1.Options", &runtimeoptions.Options{TypeUrl: rootpolicy.RunscOptionsTypeURL, ConfigPath: path})
		return c
	}
	task := func(mutate func(*tasksapi.CreateTaskRequest)) proto.Message {
		r := &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs(), Stdout: testFIFO + "/1/out"}
		mutate(r)
		return r
	}
	update := func(c *containersapi.Container, paths ...string) proto.Message {
		r := &containersapi.UpdateContainerRequest{Container: c}
		if paths != nil {
			r.UpdateMask = &fieldmaskpb.FieldMask{Paths: paths}
		}
		return r
	}
	allowDevices := true
	const (
		cCreate = "/containerd.services.containers.v1.Containers/Create"
		cUpdate = "/containerd.services.containers.v1.Containers/Update"
		tCreate = "/containerd.services.tasks.v1.Tasks/Create"
		tUpdate = "/containerd.services.tasks.v1.Tasks/Update"
		apply   = "/containerd.services.diff.v1.Diff/Apply"
		diff    = "/containerd.services.diff.v1.Diff/Diff"
		prepare = "/containerd.services.snapshots.v1.Snapshots/Prepare"
	)
	for _, tc := range []struct {
		name   string
		method string
		req    proto.Message
		reason string
	}{
		{"privileged spec", cCreate, create(withSpec(func(s *specs.Spec) {
			s.Process.Capabilities.Bounding = append(s.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")
			s.Linux.Seccomp = nil
		})), string(rootpolicy.RuleCapability)},
		{"OCI hook", cCreate, create(withSpec(func(s *specs.Spec) { s.Hooks = &specs.Hooks{CreateRuntime: []specs.Hook{{Path: "/bin/sh"}}} })), string(rootpolicy.RuleHook)},
		{"bind of /", cCreate, create(withSpec(func(s *specs.Spec) {
			s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: "/", Destination: "/host", Options: []string{"rbind"}})
		})), string(rootpolicy.RuleMount)},
		{"bind of /proc", cCreate, create(withSpec(func(s *specs.Spec) {
			s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: "/proc", Destination: "/hp", Options: []string{"rbind"}})
		})), string(rootpolicy.RuleMount)},
		{"bind source outside the roots", cCreate, create(withSpec(func(s *specs.Spec) {
			s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: "/var/lib/kubelet", Destination: "/k", Options: []string{"rbind"}})
		})), string(rootpolicy.RuleMount)},
		{"device", cCreate, create(withSpec(func(s *specs.Spec) { s.Linux.Devices = []specs.LinuxDevice{{Path: "/dev/sda", Type: "b"}} })), string(rootpolicy.RuleDevice)},
		{"extra capability", cCreate, create(withSpec(func(s *specs.Spec) { s.Process.Capabilities.Effective = []string{"CAP_NET_ADMIN"} })), string(rootpolicy.RuleCapability)},
		{"missing seccomp", cCreate, create(withSpec(func(s *specs.Spec) { s.Linux.Seccomp = nil })), string(rootpolicy.RuleSeccomp)},
		{"NoNewPrivileges off", cCreate, create(withSpec(func(s *specs.Spec) { s.Process.NoNewPrivileges = false })), string(rootpolicy.RuleNoNewPrivileges)},
		{"netns path with ../", cCreate, create(withSpec(func(s *specs.Spec) {
			for i := range s.Linux.Namespaces {
				if s.Linux.Namespaces[i].Type == specs.NetworkNamespace {
					s.Linux.Namespaces[i].Path = "/run/netns/../../proc/1/ns/net"
				}
			}
		})), string(rootpolicy.RuleHostNamespace)},
		{"cgroup outside the parent", cCreate, create(withSpec(func(s *specs.Spec) { s.Linux.CgroupsPath = "/system.slice/kubelet.service" })), string(rootpolicy.RuleCgroup)},
		{"gVisor host network", cCreate, create(withSpec(func(s *specs.Spec) { s.Annotations = map[string]string{"dev.gvisor.flag.network": "host"} })), string(rootpolicy.RuleAnnotation)},
		{"runc BinaryName /bin/sh", cCreate, create(runcOpts(&runcoptions.Options{BinaryName: "/bin/sh"})), string(rootpolicy.RuleRuntimeOptions)},
		{"runc CRIU path", cCreate, create(runcOpts(&runcoptions.Options{CriuImagePath: "/etc"})), string(rootpolicy.RuleCheckpoint)},
		{"runsc ConfigPath elsewhere", cCreate, create(runscAt("/tmp/runsc.toml")), string(rootpolicy.RuleRuntimeOptions)},
		{"restart monitor label", cCreate, create(func() *containersapi.Container {
			c := goodContainer(t)
			c.Labels["containerd.io/restart.loguri"] = "binary:///bin/sh"
			return c
		}()), string(rootpolicy.RuleLabel)},
		{"containerd sandbox", cCreate, create(func() *containersapi.Container {
			c := goodContainer(t)
			c.Sandbox = "sbx"
			return c
		}()), string(rootpolicy.RuleRuntime)},
		{"container extensions", cCreate, create(func() *containersapi.Container {
			c := goodContainer(t)
			c.Extensions = map[string]*anypb.Any{"x": {TypeUrl: "x"}}
			return c
		}()), string(rootpolicy.RuleField)},
		{"unknown field in the container", cCreate, create(withUnknownField(goodContainer(t))), ReasonUnknownField},
		{"update replaces the spec", cUpdate, update(goodContainer(t), "spec"), string(rootpolicy.RuleUpdate)},
		{"update with no mask", cUpdate, update(&containersapi.Container{ID: testID, Labels: map[string]string{"a": "b"}}), string(rootpolicy.RuleUpdate)},
		{"update carrying a runtime", cUpdate, update(&containersapi.Container{ID: testID, Runtime: &containersapi.Container_Runtime{Name: "x"}}, "labels.a"), string(rootpolicy.RuleUpdate)},
		{"update setting a restart label", cUpdate, update(&containersapi.Container{ID: testID, Labels: map[string]string{"containerd.io/restart.status": "running"}}, "labels"), string(rootpolicy.RuleLabel)},
		{"update of a bad ID", cUpdate, update(&containersapi.Container{ID: "../x"}, "labels.a"), string(rootpolicy.RuleID)},
		{"rootfs source outside the snapshotter", tCreate, task(func(r *tasksapi.CreateTaskRequest) {
			r.Rootfs = []*types.Mount{{Type: "bind", Source: "/", Options: []string{"rbind", "rw"}}}
		}), string(rootpolicy.RuleSnapshotMount)},
		{"stdout runs a binary", tCreate, task(func(r *tasksapi.CreateTaskRequest) { r.Stdout = "binary:///bin/sh" }), string(rootpolicy.RuleTaskIO)},
		{"shim binary", tCreate, task(func(r *tasksapi.CreateTaskRequest) { r.RuntimePath = "/tmp/shim" }), string(rootpolicy.RuleRuntime)},
		{"restore from a checkpoint", tCreate, task(func(r *tasksapi.CreateTaskRequest) { r.Checkpoint = &types.Descriptor{Digest: "sha256:c"} }), string(rootpolicy.RuleCheckpoint)},
		{"blank checkpoint", tCreate, task(func(r *tasksapi.CreateTaskRequest) { r.Checkpoint = &types.Descriptor{MediaType: "x"} }), string(rootpolicy.RuleCheckpoint)},
		{"task runtime options", tCreate, task(func(r *tasksapi.CreateTaskRequest) { r.Options = &anypb.Any{Value: []byte{1}} }), string(rootpolicy.RuleRuntimeOptions)},
		{"resize opens devices", tUpdate, &tasksapi.UpdateTaskRequest{ContainerID: testID, Resources: resourcesAny(t, specs.LinuxResources{Devices: []specs.LinuxDeviceCgroup{{Allow: allowDevices, Access: "rwm"}}})}, string(rootpolicy.RuleDevice)},
		{"Diff.Apply into a host folder", apply, &diffapi.ApplyRequest{Mounts: []*types.Mount{{Type: "bind", Source: "/etc", Options: []string{"rw", "rbind"}}}}, string(rootpolicy.RuleSnapshotMount)},
		{"Diff.Apply with a stream processor", apply, &diffapi.ApplyRequest{Mounts: overlayRootfs(), Payloads: map[string]*anypb.Any{"x": {}}}, ReasonField},
		{"Diff.Diff reading the host's /", diff, &diffapi.DiffRequest{Left: overlayRootfs(), Right: []*types.Mount{{Type: "bind", Source: "/", Options: []string{"ro", "rbind"}}}}, string(rootpolicy.RuleSnapshotMount)},
		{"Diff.Diff left side", diff, &diffapi.DiffRequest{Left: []*types.Mount{{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=/root"}}}}, string(rootpolicy.RuleSnapshotMount)},
		{"another snapshotter", prepare, &snapshotsapi.PrepareSnapshotRequest{Snapshotter: "native", Key: "k"}, string(rootpolicy.RuleSnapshotter)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, testPolicy())
			_, err := r.invoke(nsCtx(), tc.method, tc.req)
			r.wantRefused(err, tc.method, tc.reason)
		})
	}
}

// TestTaskCreateChecksTheStoredContainer: a container stored before the
// gate existed (or under a wider policy) is checked again when its task
// is created.
func TestTaskCreateChecksTheStoredContainer(t *testing.T) {
	const tCreate = "/containerd.services.tasks.v1.Tasks/Create"
	req := &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs()}
	t.Run("a privileged container from before the gate", func(t *testing.T) {
		r := newRig(t, testPolicy())
		r.fake.on("/containerd.services.containers.v1.Containers/Get", func(context.Context, proto.Message) ([]proto.Message, error) {
			c := goodContainer(t)
			s := goodSpec(t)
			s.Linux.Seccomp = nil
			c.Spec = specAny(t, s)
			return []proto.Message{&containersapi.GetContainerResponse{Container: c}}, nil
		})
		_, err := r.invoke(nsCtx(), tCreate, req)
		r.wantRefused(err, tCreate, string(rootpolicy.RuleSeccomp))
	})
	t.Run("a gVisor container", func(t *testing.T) {
		r := newRig(t, testPolicy())
		r.fake.on("/containerd.services.containers.v1.Containers/Get", func(context.Context, proto.Message) ([]proto.Message, error) {
			return []proto.Message{&containersapi.GetContainerResponse{Container: goodRunscContainer(t)}}, nil
		})
		if _, err := r.invoke(nsCtx(), tCreate, req); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("containerd does not have it", func(t *testing.T) {
		r := newRig(t, testPolicy())
		r.fake.on("/containerd.services.containers.v1.Containers/Get", func(context.Context, proto.Message) ([]proto.Message, error) {
			return nil, status.Error(codes.NotFound, "container \"sb-1\": not found")
		})
		_, err := r.invoke(nsCtx(), tCreate, req)
		if status.Code(err) != codes.NotFound || len(r.refused()) != 0 {
			t.Fatalf("err %v, refusals %v: want containerd's NotFound and no refusal", err, r.refused())
		}
		if got := r.fake.methodsSeen(); slices.Contains(got, tCreate) {
			t.Fatalf("containerd saw %v", got)
		}
	})
}

func TestUpstreamErrorsPassThrough(t *testing.T) {
	r := newRig(t, testPolicy())
	const get = "/containerd.services.containers.v1.Containers/Get"
	r.fake.on(get, func(context.Context, proto.Message) ([]proto.Message, error) {
		return nil, status.Error(codes.NotFound, "container \"sb-x\": not found")
	})
	_, err := r.invoke(nsCtx(), get, &containersapi.GetContainerRequest{ID: "sb-x"})
	if st := status.Convert(err); st.Code() != codes.NotFound || st.Message() != "container \"sb-x\": not found" {
		t.Fatalf("err %v", err)
	}
	if len(r.refused()) != 0 {
		t.Fatal("a containerd error counted as a refusal")
	}
}

func TestStreams(t *testing.T) {
	t.Run("server stream", func(t *testing.T) {
		r := newRig(t, testPolicy())
		const read = "/containerd.services.content.v1.Content/Read"
		r.fake.on(read, func(context.Context, proto.Message) ([]proto.Message, error) {
			return []proto.Message{
				&contentapi.ReadContentResponse{Data: []byte("a")},
				&contentapi.ReadContentResponse{Offset: 1, Data: []byte("b")},
				&contentapi.ReadContentResponse{Offset: 2, Data: []byte("c")},
			}, nil
		})
		out, err := r.invoke(nsCtx(), read, &contentapi.ReadContentRequest{Digest: "sha256:abc"})
		if err != nil || len(out) != 3 || string(out[2].(*contentapi.ReadContentResponse).Data) != "c" {
			t.Fatalf("out %v, err %v", out, err)
		}
	})
	t.Run("bidi stream, every message checked", func(t *testing.T) {
		r := newRig(t, testPolicy())
		const write = "/containerd.services.content.v1.Content/Write"
		out, err := r.invoke(nsCtx(), write, validRequests(t)[write]...)
		if err != nil || len(out) != 3 {
			t.Fatalf("out %d, err %v", len(out), err)
		}
		if n := len(r.fake.seen()); n != 3 {
			t.Fatalf("containerd saw %d writes", n)
		}
	})
	t.Run("bidi stream refused mid-way", func(t *testing.T) {
		r := newRig(t, testPolicy())
		const write = "/containerd.services.content.v1.Content/Write"
		hostile := withUnknownField(&contentapi.WriteContentRequest{Action: contentapi.WriteAction_WRITE, Ref: "r"})
		_, err := r.invoke(nsCtx(), write, &contentapi.WriteContentRequest{Action: contentapi.WriteAction_STAT, Ref: "r"}, hostile, &contentapi.WriteContentRequest{Action: contentapi.WriteAction_COMMIT, Ref: "r"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("err %v", err)
		}
		if refs := r.refused(); len(refs) != 1 || refs[0].Reason != ReasonUnknownField {
			t.Fatalf("refusals %+v", refs)
		}
		// The first message was forwarded; the refusal cancels the call,
		// which may beat containerd to reading it. The hostile message and
		// the commit after it never reach containerd.
		for _, c := range r.fake.seen() {
			if w := c.req.(*contentapi.WriteContentRequest); w.GetAction() != contentapi.WriteAction_STAT {
				t.Fatalf("containerd saw %v", w)
			}
		}
	})
	t.Run("client closes without a message", func(t *testing.T) {
		r := newRig(t, testPolicy())
		out, err := r.invoke(nsCtx(), "/containerd.services.content.v1.Content/Write")
		if err != nil || len(out) != 0 || len(r.fake.seen()) != 0 {
			t.Fatalf("out %v, err %v, seen %v", out, err, r.fake.methodsSeen())
		}
	})
}

// TestCallsRunInParallel (eng review D11): the gate holds no lock across
// calls. Each call blocks in containerd until all of them have arrived, so
// a gate that ran them one at a time would never finish.
func TestCallsRunInParallel(t *testing.T) {
	const n = 32
	r := newRig(t, testPolicy())
	var arrived sync.WaitGroup
	arrived.Add(n)
	all := make(chan struct{})
	go func() { arrived.Wait(); close(all) }()
	const get = "/containerd.services.tasks.v1.Tasks/Get"
	r.fake.on(get, func(ctx context.Context, _ proto.Message) ([]proto.Message, error) {
		arrived.Done()
		select {
		case <-all:
			return []proto.Message{&tasksapi.GetResponse{}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	ctx, cancel := context.WithTimeout(nsCtx(), 10*time.Second)
	defer cancel()
	errs := make(chan error, n)
	for i := range n {
		go func() {
			_, err := r.invoke(ctx, get, &tasksapi.GetRequest{ContainerID: fmt.Sprintf("sb-%d", i)})
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("parallel call: %v", err)
		}
	}
}

func TestVerifyNamespace(t *testing.T) {
	const get = "/containerd.services.namespaces.v1.Namespaces/Get"
	for _, tc := range []struct {
		name   string
		answer responder
		want   string // "" means no error
	}{
		{"no labels", func(context.Context, proto.Message) ([]proto.Message, error) {
			return []proto.Message{&namespacesapi.GetNamespaceResponse{Namespace: &namespacesapi.Namespace{Name: testNS}}}, nil
		}, ""},
		{"not made yet", func(context.Context, proto.Message) ([]proto.Message, error) {
			return nil, status.Error(codes.NotFound, "namespace aerolvm: not found")
		}, ""},
		{"a default runtime", func(context.Context, proto.Message) ([]proto.Message, error) {
			return []proto.Message{&namespacesapi.GetNamespaceResponse{Namespace: &namespacesapi.Namespace{Name: testNS, Labels: map[string]string{"containerd.io/defaults/runtime": "io.containerd.kata.v2"}}}}, nil
		}, "sets a default"},
		{"containerd down", func(context.Context, proto.Message) ([]proto.Message, error) {
			return nil, status.Error(codes.Unavailable, "down")
		}, "read namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, testPolicy())
			r.fake.on(get, tc.answer)
			err := r.gate.VerifyNamespace(context.Background())
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if c := r.fake.seen(); len(c) != 1 || !slices.Equal(c[0].namespace, []string{testNS}) {
				t.Fatalf("calls %+v", c)
			}
		})
	}
}

func TestNew(t *testing.T) {
	bad := testPolicy()
	bad.BindRoots = []string{"/"}
	if _, err := New(Config{Policy: bad, Upstream: &grpc.ClientConn{}}); err == nil {
		t.Fatal("a policy binding / was accepted")
	}
	if _, err := New(Config{Policy: testPolicy()}); err == nil {
		t.Fatal("no upstream was accepted")
	}
	// Round 2 finding 2: a gate never runs without resource bounds.
	unbounded := testPolicy()
	unbounded.Limits = rootpolicy.Limits{}
	if _, err := New(Config{Policy: unbounded, Upstream: &grpc.ClientConn{}}); err == nil {
		t.Fatal("a policy with no limits was accepted")
	}
	if g, err := New(Config{Policy: testPolicy(), Upstream: &grpc.ClientConn{}}); err != nil || g.onRefusal != nil {
		t.Fatalf("gate %v, err %v", g, err)
	}
}

func TestAllowedMethods(t *testing.T) {
	got := AllowedMethods()
	if len(got) != len(allowlist) {
		t.Fatalf("%d methods", len(got))
	}
	writes := 0
	for _, m := range got {
		if m.Why == "" {
			t.Errorf("%s has no reason", m.Name)
		}
		if m.Write {
			writes++
		}
	}
	if writes != 24 || len(got)-writes != 17 {
		t.Fatalf("%d writes, %d reads", writes, len(got)-writes)
	}
}

// noMethodStream is a server stream whose context names no method.
type noMethodStream struct{ grpc.ServerStream }

func (noMethodStream) Context() context.Context { return context.Background() }

func TestHandleWithoutAMethod(t *testing.T) {
	g, err := New(Config{Policy: testPolicy(), Upstream: &grpc.ClientConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Handle(nil, noMethodStream{}); status.Code(err) != codes.Internal {
		t.Fatalf("err %v", err)
	}
}

func TestRefusalWithoutCallback(t *testing.T) {
	g, err := New(Config{Policy: testPolicy(), Upstream: &grpc.ClientConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.refuse(context.Background(), "/m", ReasonMethod, "x"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err %v", err)
	}
}
