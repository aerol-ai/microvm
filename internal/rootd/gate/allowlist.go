package gate

import (
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
	versionapi "github.com/containerd/containerd/api/services/version/v1"
	"github.com/containerd/containerd/api/types"
	healthapi "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// method is one containerd gRPC method the gate passes.
type method struct {
	name string
	// write: the request is walked field by field (fields.go) and refused
	// on any field without a decision or with unknown bytes. Reads pass
	// through as they are.
	write bool
	// check, when set, runs the method's rootpolicy checks on a request
	// that passed the walk.
	check checkFunc
	// ended, when set, runs once a forwarded call has ended, whatever its
	// outcome, with its first request.
	ended        func(g *Gate, req any)
	clientStream bool
	serverStream bool
	newReq       func() proto.Message
	newResp      func() proto.Message
	// why is the agent code that needs the method (eng review D6: only
	// what the agent calls today passes).
	why string
}

func req[T any, PT interface {
	*T
	proto.Message
}]() func() proto.Message {
	return func() proto.Message { return PT(new(T)) }
}

// allowlist is every containerd method the agent calls today, traced from
// internal/runtime/containerd through the containerd v2.4.2 client library
// it uses (nothing else in the repo dials containerd). Everything not here
// is refused: among others Tasks.Exec, Tasks.Checkpoint, Namespaces
// Create/Update/Delete, Events.Publish/Forward, Content.Delete, the
// Transfer, Streaming and Mounts services, and containerd 2's sandbox API.
var allowlist = []method{
	// --- Reads: pass through, in the agent's namespace only. ---
	{name: "/containerd.services.version.v1.Version/Version", newReq: req[emptypb.Empty](), newResp: req[versionapi.VersionResponse](),
		why: "client.go Connect: refuses a containerd outside the supported versions"},
	{name: "/grpc.health.v1.Health/Check", newReq: req[healthapi.HealthCheckRequest](), newResp: req[healthapi.HealthCheckResponse](),
		why: "Driver.Ping: the containerd client's IsServing"},
	{name: "/containerd.services.namespaces.v1.Namespaces/Get", check: checkNamespaceGet, newReq: req[namespacesapi.GetNamespaceRequest](), newResp: req[namespacesapi.GetNamespaceResponse](),
		why: "the client reads the namespace's default runtime and snapshotter labels on NewContainer and Pull"},
	{name: "/containerd.services.introspection.v1.Introspection/Plugins", newReq: req[introspectionapi.PluginsRequest](), newResp: req[introspectionapi.PluginsResponse](),
		why: "Pull with unpack asks the snapshotter's capabilities and platforms"},
	{name: "/containerd.services.containers.v1.Containers/Get", newReq: req[containersapi.GetContainerRequest](), newResp: req[containersapi.GetContainerResponse](),
		why: "LoadContainer, and a container's Info, Labels and Spec (Inspect, start, adopt, move, resize)"},
	{name: "/containerd.services.containers.v1.Containers/List", newReq: req[containersapi.ListContainersRequest](), newResp: req[containersapi.ListContainersResponse](),
		why: "ListContainers (ListManaged, PurgeParkedContainers, lookup by sandbox label) when ListStream is unimplemented"},
	{name: "/containerd.services.containers.v1.Containers/ListStream", serverStream: true, newReq: req[containersapi.ListContainersRequest](), newResp: req[containersapi.ListContainerMessage](),
		why: "ListContainers: the client tries the stream first"},
	{name: "/containerd.services.tasks.v1.Tasks/Get", newReq: req[tasksapi.GetRequest](), newResp: req[tasksapi.GetResponse](),
		why: "container.Task and task.Status (Inspect, stop, freeze, reattaching a task's log)"},
	{name: "/containerd.services.tasks.v1.Tasks/ListPids", newReq: req[tasksapi.ListPidsRequest](), newResp: req[tasksapi.ListPidsResponse](),
		why: "task.Pids: the sandbox's address probe and the gVisor process count"},
	{name: "/containerd.services.tasks.v1.Tasks/Wait", newReq: req[tasksapi.WaitRequest](), newResp: req[tasksapi.WaitResponse](),
		why: "task.Delete(WithProcessKill) waits for the killed task to exit"},
	{name: "/containerd.services.images.v1.Images/Get", newReq: req[imagesapi.GetImageRequest](), newResp: req[imagesapi.GetImageResponse](),
		why: "GetImage (ensureImage, ImageExists, PoolImageID), snapshot commit and export"},
	{name: "/containerd.services.content.v1.Content/Info", newReq: req[contentapi.InfoRequest](), newResp: req[contentapi.InfoResponse](),
		why: "reading an image's config and manifest, and Pull's already-have-it check"},
	{name: "/containerd.services.content.v1.Content/Read", serverStream: true, newReq: req[contentapi.ReadContentRequest](), newResp: req[contentapi.ReadContentResponse](),
		why: "reading image config, manifests and layers (create, push, export, snapshot diff IDs)"},
	{name: "/containerd.services.snapshots.v1.Snapshots/Stat", newReq: req[snapshotsapi.StatSnapshotRequest](), newResp: req[snapshotsapi.StatSnapshotResponse](),
		why: "Pull's unpack and the snapshot commit's diff (rootfs.CreateDiff)"},
	{name: "/containerd.services.snapshots.v1.Snapshots/Mounts", newReq: req[snapshotsapi.MountsRequest](), newResp: req[snapshotsapi.MountsResponse](),
		why: "NewTask's rootfs, the disk limit's writable layer, image user lookup, snapshot commit"},
	{name: "/containerd.services.snapshots.v1.Snapshots/Usage", newReq: req[snapshotsapi.UsageRequest](), newResp: req[snapshotsapi.UsageResponse](),
		why: "WritableLayerBytes: the disk usage metric"},
	{name: "/containerd.services.events.v1.Events/Subscribe", serverStream: true, newReq: req[eventsapi.SubscribeRequest](), newResp: req[types.Envelope](),
		why: "the task exit and container delete event stream (events.go)"},

	// --- Writes: walked field by field, then checked against rootpolicy. ---
	{name: "/containerd.services.containers.v1.Containers/Create", write: true, check: checkContainerCreate, newReq: req[containersapi.CreateContainerRequest](), newResp: req[containersapi.CreateContainerResponse](),
		why: "NewContainer: every create and warm-pool park"},
	{name: "/containerd.services.containers.v1.Containers/Update", write: true, check: checkContainerUpdate, newReq: req[containersapi.UpdateContainerRequest](), newResp: req[containersapi.UpdateContainerResponse](),
		why: "container.SetLabels: warm-pool adoption relabels the parked container"},
	{name: "/containerd.services.containers.v1.Containers/Delete", write: true, check: checkContainerDelete, ended: containerDeleteEnded, newReq: req[containersapi.DeleteContainerRequest](), newResp: req[emptypb.Empty](),
		why: "container.Delete: destroy, failed-create undo, parked slot teardown"},
	{name: "/containerd.services.tasks.v1.Tasks/Create", write: true, check: checkTaskCreate, newReq: req[tasksapi.CreateTaskRequest](), newResp: req[tasksapi.CreateTaskResponse](),
		why: "container.NewTask: create, start, park"},
	{name: "/containerd.services.tasks.v1.Tasks/Start", write: true, newReq: req[tasksapi.StartRequest](), newResp: req[tasksapi.StartResponse](),
		why: "task.Start"},
	{name: "/containerd.services.tasks.v1.Tasks/Kill", write: true, newReq: req[tasksapi.KillRequest](), newResp: req[emptypb.Empty](),
		why: "task.Kill: stop, destroy, undo"},
	{name: "/containerd.services.tasks.v1.Tasks/Delete", write: true, newReq: req[tasksapi.DeleteTaskRequest](), newResp: req[tasksapi.DeleteResponse](),
		why: "task.Delete: stop, destroy, restart"},
	{name: "/containerd.services.tasks.v1.Tasks/Pause", write: true, newReq: req[tasksapi.PauseTaskRequest](), newResp: req[emptypb.Empty](),
		why: "Freeze (the cluster ownership fence) and snapshot commit"},
	{name: "/containerd.services.tasks.v1.Tasks/Resume", write: true, newReq: req[tasksapi.ResumeTaskRequest](), newResp: req[emptypb.Empty](),
		why: "Thaw, and resuming after a snapshot commit"},
	{name: "/containerd.services.tasks.v1.Tasks/Update", write: true, check: checkTaskUpdate, newReq: req[tasksapi.UpdateTaskRequest](), newResp: req[emptypb.Empty](),
		why: "Resize: memory and CPU limits of a running sandbox"},
	{name: "/containerd.services.images.v1.Images/Create", write: true, newReq: req[imagesapi.CreateImageRequest](), newResp: req[imagesapi.CreateImageResponse](),
		why: "Pull, snapshot commit, rootfs image import"},
	{name: "/containerd.services.images.v1.Images/Update", write: true, newReq: req[imagesapi.UpdateImageRequest](), newResp: req[imagesapi.UpdateImageResponse](),
		why: "Pull of an image that exists, rootfs image import"},
	{name: "/containerd.services.images.v1.Images/Delete", write: true, newReq: req[imagesapi.DeleteImageRequest](), newResp: req[emptypb.Empty](),
		why: "RemoveImage, and a failed snapshot commit's undo"},
	{name: "/containerd.services.content.v1.Content/Write", write: true, clientStream: true, serverStream: true, newReq: req[contentapi.WriteContentRequest](), newResp: req[contentapi.WriteContentResponse](),
		why: "Pull's layer fetch, snapshot commit's config and manifest, rootfs image import"},
	{name: "/containerd.services.content.v1.Content/Update", write: true, newReq: req[contentapi.UpdateRequest](), newResp: req[contentapi.UpdateResponse](),
		why: "Pull's labels on content (distribution source, uncompressed digest, GC refs)"},
	{name: "/containerd.services.snapshots.v1.Snapshots/Prepare", write: true, check: checkSnapshotter, newReq: req[snapshotsapi.PrepareSnapshotRequest](), newResp: req[snapshotsapi.PrepareSnapshotResponse](),
		why: "NewContainer's WithNewSnapshot, and Pull's unpack of each layer"},
	{name: "/containerd.services.snapshots.v1.Snapshots/View", write: true, check: checkSnapshotter, newReq: req[snapshotsapi.ViewSnapshotRequest](), newResp: req[snapshotsapi.ViewSnapshotResponse](),
		why: "snapshot commit: a read-only view of the parent layer (rootfs.CreateDiff)"},
	{name: "/containerd.services.snapshots.v1.Snapshots/Commit", write: true, check: checkSnapshotter, newReq: req[snapshotsapi.CommitSnapshotRequest](), newResp: req[emptypb.Empty](),
		why: "Pull's unpack commits each layer"},
	{name: "/containerd.services.snapshots.v1.Snapshots/Remove", write: true, check: checkSnapshotter, newReq: req[snapshotsapi.RemoveSnapshotRequest](), newResp: req[emptypb.Empty](),
		why: "container.Delete(WithSnapshotCleanup), the orphan snapshot sweep, unpack and diff cleanup"},
	{name: "/containerd.services.diff.v1.Diff/Apply", write: true, check: checkDiffApply, newReq: req[diffapi.ApplyRequest](), newResp: req[diffapi.ApplyResponse](),
		why: "Pull's unpack: containerd, as root, writes a layer into the snapshot mounts the request names"},
	{name: "/containerd.services.diff.v1.Diff/Diff", write: true, check: checkDiffDiff, newReq: req[diffapi.DiffRequest](), newResp: req[diffapi.DiffResponse](),
		why: "snapshot commit: containerd, as root, reads the request's mounts into a new layer"},
	{name: "/containerd.services.leases.v1.Leases/Create", write: true, newReq: req[leasesapi.CreateRequest](), newResp: req[leasesapi.CreateResponse](),
		why: "the image lease each sandbox pins, and the client's own lease around NewContainer, Pull and import"},
	{name: "/containerd.services.leases.v1.Leases/Delete", write: true, newReq: req[leasesapi.DeleteRequest](), newResp: req[emptypb.Empty](),
		why: "releasing those leases"},
	{name: "/containerd.services.leases.v1.Leases/AddResource", write: true, newReq: req[leasesapi.AddResourceRequest](), newResp: req[emptypb.Empty](),
		why: "pinImageLease adds the image's content to the sandbox's lease"},
}

// methods is allowlist by full method name.
var methods = func() map[string]*method {
	m := make(map[string]*method, len(allowlist))
	for i := range allowlist {
		m[allowlist[i].name] = &allowlist[i]
	}
	return m
}()

// AllowedMethods lists the methods the gate passes and why the agent needs
// each, for the evidence a buyer reads.
func AllowedMethods() []AllowedMethod {
	out := make([]AllowedMethod, 0, len(allowlist))
	for _, m := range allowlist {
		out = append(out, AllowedMethod{Name: m.name, Write: m.write, Why: m.why})
	}
	return out
}

// AllowedMethod describes one method the gate passes.
type AllowedMethod struct {
	Name  string
	Write bool
	Why   string
}
