package gate

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	leasesapi "github.com/containerd/containerd/api/services/leases/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	"github.com/containerd/containerd/api/types"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	tasktypes "github.com/containerd/containerd/api/types/task"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthapi "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// statefulContainerd gives the fake enough memory (containers, one task's
// state) for containerd's own client library to run its flows against it.
func statefulContainerd(r *rig) {
	var mu sync.Mutex
	stored := map[string]*containersapi.Container{}
	taskStatus := map[string]tasktypes.Status{}
	one := func(m proto.Message) ([]proto.Message, error) { return []proto.Message{m}, nil }
	f := r.fake
	f.on("/containerd.services.version.v1.Version/Version", func(context.Context, proto.Message) ([]proto.Message, error) {
		return one(&versionapi.VersionResponse{Version: "2.1.4", Revision: "fake"})
	})
	f.on("/grpc.health.v1.Health/Check", func(context.Context, proto.Message) ([]proto.Message, error) {
		return one(&healthapi.HealthCheckResponse{Status: healthapi.HealthCheckResponse_SERVING})
	})
	f.on("/containerd.services.namespaces.v1.Namespaces/Get", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		return one(&namespacesapi.GetNamespaceResponse{Namespace: &namespacesapi.Namespace{Name: q.(*namespacesapi.GetNamespaceRequest).GetName()}})
	})
	f.on("/containerd.services.leases.v1.Leases/Create", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		id := q.(*leasesapi.CreateRequest).GetID()
		return one(&leasesapi.CreateResponse{Lease: &leasesapi.Lease{ID: id}})
	})
	f.on("/containerd.services.containers.v1.Containers/Create", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		c := q.(*containersapi.CreateContainerRequest).GetContainer()
		mu.Lock()
		stored[c.GetID()] = c
		mu.Unlock()
		return one(&containersapi.CreateContainerResponse{Container: c})
	})
	f.on("/containerd.services.containers.v1.Containers/Get", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		mu.Lock()
		defer mu.Unlock()
		c, ok := stored[q.(*containersapi.GetContainerRequest).GetID()]
		if !ok {
			return nil, status.Error(codes.NotFound, "container not found")
		}
		return one(&containersapi.GetContainerResponse{Container: c})
	})
	f.on("/containerd.services.containers.v1.Containers/Update", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		u := q.(*containersapi.UpdateContainerRequest).GetContainer()
		mu.Lock()
		defer mu.Unlock()
		c := proto.Clone(stored[u.GetID()]).(*containersapi.Container)
		for k, v := range u.GetLabels() {
			c.Labels[k] = v
		}
		stored[u.GetID()] = c
		return one(&containersapi.UpdateContainerResponse{Container: c})
	})
	f.on("/containerd.services.containers.v1.Containers/ListStream", func(context.Context, proto.Message) ([]proto.Message, error) {
		mu.Lock()
		defer mu.Unlock()
		var out []proto.Message
		for _, c := range stored {
			out = append(out, &containersapi.ListContainerMessage{Container: c})
		}
		return out, nil
	})
	f.on("/containerd.services.containers.v1.Containers/Delete", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		mu.Lock()
		delete(stored, q.(*containersapi.DeleteContainerRequest).GetID())
		mu.Unlock()
		return one(&containersapi.DeleteContainerRequest{})
	})
	f.on("/containerd.services.snapshots.v1.Snapshots/Mounts", func(context.Context, proto.Message) ([]proto.Message, error) {
		return one(&snapshotsapi.MountsResponse{Mounts: overlayRootfs()})
	})
	setTask := func(id string, s tasktypes.Status) {
		mu.Lock()
		taskStatus[id] = s
		mu.Unlock()
	}
	f.on("/containerd.services.tasks.v1.Tasks/Create", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		setTask(q.(*tasksapi.CreateTaskRequest).GetContainerID(), tasktypes.Status_CREATED)
		return one(&tasksapi.CreateTaskResponse{ContainerID: testID, Pid: 42})
	})
	f.on("/containerd.services.tasks.v1.Tasks/Start", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		setTask(q.(*tasksapi.StartRequest).GetContainerID(), tasktypes.Status_RUNNING)
		return one(&tasksapi.StartResponse{Pid: 42})
	})
	f.on("/containerd.services.tasks.v1.Tasks/Kill", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		setTask(q.(*tasksapi.KillRequest).GetContainerID(), tasktypes.Status_STOPPED)
		return one(&tasksapi.KillRequest{})
	})
	f.on("/containerd.services.tasks.v1.Tasks/Get", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		id := q.(*tasksapi.GetRequest).GetContainerID()
		mu.Lock()
		s, ok := taskStatus[id]
		mu.Unlock()
		if !ok {
			return nil, status.Error(codes.NotFound, "no task")
		}
		return one(&tasksapi.GetResponse{Process: &tasktypes.Process{ID: id, ContainerID: id, Pid: 42, Status: s}})
	})
	f.on("/containerd.services.tasks.v1.Tasks/Wait", func(context.Context, proto.Message) ([]proto.Message, error) {
		return one(&tasksapi.WaitResponse{ExitStatus: 137})
	})
	f.on("/containerd.services.tasks.v1.Tasks/Delete", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		id := q.(*tasksapi.DeleteTaskRequest).GetContainerID()
		mu.Lock()
		delete(taskStatus, id)
		mu.Unlock()
		return one(&tasksapi.DeleteResponse{ID: id, Pid: 42, ExitStatus: 137})
	})
	f.on("/containerd.services.tasks.v1.Tasks/ListPids", func(context.Context, proto.Message) ([]proto.Message, error) {
		return one(&tasksapi.ListPidsResponse{Processes: []*tasktypes.ProcessInfo{{Pid: 42}}})
	})
	f.on("/containerd.services.images.v1.Images/Get", func(_ context.Context, q proto.Message) ([]proto.Message, error) {
		return one(&imagesapi.GetImageResponse{Image: &imagesapi.Image{Name: q.(*imagesapi.GetImageRequest).GetName(), Target: &types.Descriptor{MediaType: "application/vnd.oci.image.index.v1+json", Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Size: 1}}})
	})
	f.on("/containerd.services.events.v1.Events/Subscribe", func(context.Context, proto.Message) ([]proto.Message, error) {
		return []proto.Message{&types.Envelope{Namespace: testNS, Topic: "/tasks/exit"}}, nil
	})
}

// agentClient is the containerd client library the agent uses, dialing the
// gate as it will dial the helper's socket.
func agentClient(t *testing.T, r *rig) (*cntr.Client, context.Context) {
	t.Helper()
	client, err := cntr.New("/run/aerolvm/root.sock", cntr.WithDefaultNamespace(testNS), cntr.WithDialOpts([]grpc.DialOption{
		grpc.WithContextDialer(r.dial), grpc.WithTransportCredentials(insecure.NewCredentials()),
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(namespaces.WithNamespace(context.Background(), testNS), 20*time.Second)
	t.Cleanup(cancel)
	return client, ctx
}

func withSnapshot(_ context.Context, _ *cntr.Client, c *containers.Container) error {
	c.Snapshotter, c.SnapshotKey = "overlayfs", c.ID
	return nil
}

// TestAgentFlowsThroughTheGate runs the containerd client library's own
// code for the agent's main flows against the gate. Each call it makes
// must be on the allowlist and pass: this is what proves the traced
// allowlist matches the library, not only the list of names.
func TestAgentFlowsThroughTheGate(t *testing.T) { agentFlows(t, newRig) }

// rigMaker builds the agent's view of a gate: newRig in memory, or
// newSocketRig through the root helper's socket (socket_test.go).
type rigMaker func(t *testing.T, p rootpolicy.Policy, opts ...func(*Config)) *rig

// agentFlows is TestAgentFlowsThroughTheGate's body, for any rig.
func agentFlows(t *testing.T, newRig rigMaker) {
	for _, rt := range []struct {
		name string
		opt  cntr.NewContainerOpts
		spec func(*specs.Spec)
	}{
		{"runc", cntr.WithRuntime(rootpolicy.RuntimeRunc, nil), func(*specs.Spec) {}},
		{"gvisor", cntr.WithRuntime(rootpolicy.RuntimeRunsc, &runtimeoptions.Options{TypeUrl: rootpolicy.RunscOptionsTypeURL, ConfigPath: testRunscCfg}), func(s *specs.Spec) {
			s.Annotations = map[string]string{rootpolicy.CRIContainerTypeAnnotation: rootpolicy.CRIContainerTypeSandbox}
		}},
	} {
		t.Run(rt.name, func(t *testing.T) {
			r := newRig(t, testPolicy())
			statefulContainerd(r)
			client, ctx := agentClient(t, r)

			if v, err := client.Version(ctx); err != nil || v.Version != "2.1.4" {
				t.Fatalf("version %v, %v", v, err)
			}
			if ok, err := client.IsServing(ctx); err != nil || !ok {
				t.Fatalf("serving %v, %v", ok, err)
			}
			spec := goodSpec(t)
			rt.spec(spec)
			c, err := client.NewContainer(ctx, testID, cntr.WithSpec(spec), rt.opt, withSnapshot,
				cntr.WithContainerLabels(map[string]string{"aerolvm.managed": "true"}))
			if err != nil {
				t.Fatalf("NewContainer: %v", err)
			}
			if _, err := c.SetLabels(ctx, map[string]string{"aerolvm.sandbox_id": "sb-9"}); err != nil {
				t.Fatalf("SetLabels: %v", err)
			}
			task, err := c.NewTask(ctx, cio.NullIO)
			if err != nil {
				t.Fatalf("NewTask: %v", err)
			}
			if err := task.Start(ctx); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if pids, err := task.Pids(ctx); err != nil || len(pids) != 1 {
				t.Fatalf("Pids %v, %v", pids, err)
			}
			if err := task.Pause(ctx); err != nil {
				t.Fatalf("Pause: %v", err)
			}
			if err := task.Resume(ctx); err != nil {
				t.Fatalf("Resume: %v", err)
			}
			limit := int64(1 << 30)
			if err := task.Update(ctx, cntr.WithResources(&specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: &limit}})); err != nil {
				t.Fatalf("Update: %v", err)
			}
			if st, err := task.Status(ctx); err != nil || st.Status != cntr.Running {
				t.Fatalf("Status %v, %v", st, err)
			}
			if _, err := task.Delete(ctx, cntr.WithProcessKill); err != nil {
				t.Fatalf("task Delete: %v", err)
			}
			if list, err := client.Containers(ctx, "labels.aerolvm.managed"); err != nil || len(list) != 1 {
				t.Fatalf("Containers %v, %v", list, err)
			}
			if err := c.Delete(ctx, cntr.WithSnapshotCleanup); err != nil {
				t.Fatalf("container Delete: %v", err)
			}
			if _, err := client.GetImage(ctx, "docker.io/library/alpine:3.20"); err != nil {
				t.Fatalf("GetImage: %v", err)
			}
			if err := client.ImageService().Delete(ctx, "docker.io/library/alpine:3.20"); err != nil {
				t.Fatalf("image Delete: %v", err)
			}
			ls := client.LeasesService()
			l, err := ls.Create(ctx, leases.WithID("img-lease"), leases.WithExpiration(time.Hour))
			if err != nil {
				t.Fatalf("lease Create: %v", err)
			}
			if err := ls.AddResource(ctx, l, leases.Resource{ID: "sha256:abc", Type: "content"}); err != nil {
				t.Fatalf("lease AddResource: %v", err)
			}
			if err := ls.Delete(ctx, l); err != nil {
				t.Fatalf("lease Delete: %v", err)
			}
			envs, errs := client.EventService().Subscribe(ctx, `topic~="/tasks/"`)
			select {
			case e := <-envs:
				if e.Topic != "/tasks/exit" {
					t.Fatalf("event %+v", e)
				}
			case err := <-errs:
				t.Fatalf("Subscribe: %v", err)
			}

			if refs := r.refused(); len(refs) != 0 {
				t.Fatalf("the gate refused the agent's own flow: %+v", refs)
			}
			for _, want := range []string{
				"/containerd.services.leases.v1.Leases/Create",
				"/containerd.services.namespaces.v1.Namespaces/Get",
				"/containerd.services.containers.v1.Containers/Create",
				"/containerd.services.containers.v1.Containers/Update",
				"/containerd.services.snapshots.v1.Snapshots/Mounts",
				"/containerd.services.tasks.v1.Tasks/Create",
				"/containerd.services.tasks.v1.Tasks/Wait",
				"/containerd.services.containers.v1.Containers/ListStream",
				"/containerd.services.snapshots.v1.Snapshots/Remove",
				"/containerd.services.containers.v1.Containers/Delete",
				"/containerd.services.events.v1.Events/Subscribe",
			} {
				if !slices.Contains(r.fake.methodsSeen(), want) {
					t.Errorf("the flow never reached %s", want)
				}
			}
		})
	}
}

// TestAgentClientSeesRefusals: a hostile create through the real client
// fails with permission denied and containerd never stores it.
func TestAgentClientSeesRefusals(t *testing.T) { agentRefusals(t, newRig) }

// agentRefusals is TestAgentClientSeesRefusals's body, for any rig.
func agentRefusals(t *testing.T, newRig rigMaker) {
	r := newRig(t, testPolicy())
	statefulContainerd(r)
	client, ctx := agentClient(t, r)
	spec := goodSpec(t)
	spec.Process.Capabilities.Bounding = append(spec.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")
	_, err := client.NewContainer(ctx, testID, cntr.WithSpec(spec), cntr.WithRuntime(rootpolicy.RuntimeRunc, nil), withSnapshot)
	if !errdefs.IsPermissionDenied(err) {
		t.Fatalf("err %v, want permission denied", err)
	}
	if slices.Contains(r.fake.methodsSeen(), "/containerd.services.containers.v1.Containers/Create") {
		t.Fatal("containerd stored the hostile container")
	}
	// The agent's client could reach for Exec; the gate refuses it.
	if _, err := client.TaskService().Exec(ctx, &tasksapi.ExecProcessRequest{ContainerID: testID, ExecID: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("exec: %v", err)
	}
	if n := len(r.refused()); n != 2 {
		t.Fatalf("%d refusals, want 2", n)
	}
}
