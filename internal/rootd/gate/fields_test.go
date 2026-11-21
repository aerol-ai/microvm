package gate

import (
	"errors"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

// pinnedFields is every field of every request message the gate passes,
// nested messages included, as the containerd API this build links has
// them. TestFieldPins fails when a containerd bump adds, renames or drops
// one, so the bump cannot ship until someone has decided what the gate does
// with the change (eng review D6): for a write, a fieldDecisions entry.
var pinnedFields = map[string][]string{
	// Writes.
	"containerd.services.containers.v1.Container":              {"id", "labels", "image", "runtime", "spec", "snapshotter", "snapshot_key", "created_at", "updated_at", "extensions", "sandbox"},
	"containerd.services.containers.v1.Container.Runtime":      {"name", "options"},
	"containerd.services.containers.v1.CreateContainerRequest": {"container"},
	"containerd.services.containers.v1.DeleteContainerRequest": {"id"},
	"containerd.services.containers.v1.UpdateContainerRequest": {"container", "update_mask"},
	"containerd.services.content.v1.Info":                      {"digest", "size", "created_at", "updated_at", "labels"},
	"containerd.services.content.v1.UpdateRequest":             {"info", "update_mask"},
	"containerd.services.content.v1.WriteContentRequest":       {"action", "ref", "total", "expected", "offset", "data", "labels"},
	"containerd.services.diff.v1.ApplyRequest":                 {"diff", "mounts", "payloads", "sync_fs"},
	"containerd.services.diff.v1.DiffRequest":                  {"left", "right", "media_type", "ref", "labels", "source_date_epoch"},
	"containerd.services.images.v1.CreateImageRequest":         {"image", "source_date_epoch"},
	"containerd.services.images.v1.DeleteImageRequest":         {"name", "sync", "target"},
	"containerd.services.images.v1.Image":                      {"name", "labels", "target", "created_at", "updated_at"},
	"containerd.services.images.v1.UpdateImageRequest":         {"image", "update_mask", "source_date_epoch"},
	"containerd.services.leases.v1.AddResourceRequest":         {"id", "resource"},
	"containerd.services.leases.v1.CreateRequest":              {"id", "labels"},
	"containerd.services.leases.v1.DeleteRequest":              {"id", "sync"},
	"containerd.services.leases.v1.Resource":                   {"id", "type"},
	"containerd.services.snapshots.v1.CommitSnapshotRequest":   {"snapshotter", "name", "key", "labels", "parent"},
	"containerd.services.snapshots.v1.PrepareSnapshotRequest":  {"snapshotter", "key", "parent", "labels"},
	"containerd.services.snapshots.v1.RemoveSnapshotRequest":   {"snapshotter", "key"},
	"containerd.services.snapshots.v1.ViewSnapshotRequest":     {"snapshotter", "key", "parent", "labels"},
	"containerd.services.tasks.v1.CreateTaskRequest":           {"container_id", "rootfs", "stdin", "stdout", "stderr", "terminal", "checkpoint", "options", "runtime_path", "task_api_address", "task_api_version"},
	"containerd.services.tasks.v1.DeleteTaskRequest":           {"container_id"},
	"containerd.services.tasks.v1.KillRequest":                 {"container_id", "exec_id", "signal", "all"},
	"containerd.services.tasks.v1.PauseTaskRequest":            {"container_id"},
	"containerd.services.tasks.v1.ResumeTaskRequest":           {"container_id"},
	"containerd.services.tasks.v1.StartRequest":                {"container_id", "exec_id"},
	"containerd.services.tasks.v1.UpdateTaskRequest":           {"container_id", "resources", "annotations"},
	"containerd.types.Descriptor":                              {"media_type", "digest", "size", "annotations"},
	"containerd.types.Mount":                                   {"type", "source", "target", "options"},
	"google.protobuf.Any":                                      {"type_url", "value"},
	"google.protobuf.FieldMask":                                {"paths"},
	"google.protobuf.Timestamp":                                {"seconds", "nanos"},
	// Reads.
	"containerd.services.containers.v1.GetContainerRequest":   {"id"},
	"containerd.services.containers.v1.ListContainersRequest": {"filters"},
	"containerd.services.content.v1.InfoRequest":              {"digest"},
	"containerd.services.content.v1.ReadContentRequest":       {"digest", "offset", "size"},
	"containerd.services.events.v1.SubscribeRequest":          {"filters"},
	"containerd.services.images.v1.GetImageRequest":           {"name"},
	"containerd.services.introspection.v1.PluginsRequest":     {"filters"},
	"containerd.services.namespaces.v1.GetNamespaceRequest":   {"name"},
	"containerd.services.snapshots.v1.MountsRequest":          {"snapshotter", "key"},
	"containerd.services.snapshots.v1.StatSnapshotRequest":    {"snapshotter", "key"},
	"containerd.services.snapshots.v1.UsageRequest":           {"snapshotter", "key"},
	"containerd.services.tasks.v1.GetRequest":                 {"container_id", "exec_id"},
	"containerd.services.tasks.v1.ListPidsRequest":            {"container_id"},
	"containerd.services.tasks.v1.WaitRequest":                {"container_id", "exec_id"},
	"google.protobuf.Empty":                                   {},
	"grpc.health.v1.HealthCheckRequest":                       {"service"},
}

// reachable lists the fields of md and of every message reachable from it.
func reachable(md protoreflect.MessageDescriptor, out map[string][]string) {
	name := string(md.FullName())
	if _, ok := out[name]; ok {
		return
	}
	out[name] = []string{}
	fs := md.Fields()
	for i := range fs.Len() {
		fd := fs.Get(i)
		out[name] = append(out[name], string(fd.Name()))
		switch {
		case fd.IsMap():
			if v := fd.MapValue().Message(); v != nil {
				reachable(v, out)
			}
		case fd.Message() != nil:
			reachable(fd.Message(), out)
		}
	}
}

// TestFieldPins is the containerd-bump tripwire: the request messages of
// every allowed method still have exactly the fields this gate was written
// against.
func TestFieldPins(t *testing.T) {
	got := map[string][]string{}
	for _, m := range allowlist {
		reachable(m.newReq().ProtoReflect().Descriptor(), got)
	}
	var diffs []string
	for _, name := range slices.Sorted(maps.Keys(got)) {
		if want, ok := pinnedFields[name]; !ok {
			diffs = append(diffs, name+": not pinned, has "+strings.Join(got[name], ","))
		} else if !slices.Equal(got[name], want) {
			diffs = append(diffs, name+": has "+strings.Join(got[name], ",")+", pinned "+strings.Join(want, ","))
		}
	}
	for name := range pinnedFields {
		if _, ok := got[name]; !ok {
			diffs = append(diffs, name+": pinned but no allowed request carries it any more")
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Fatalf("containerd's request messages changed; decide what the gate does with each change (fieldDecisions), then re-pin:\n%s", strings.Join(diffs, "\n"))
	}
}

// TestEveryWriteFieldHasADecision: the walk fails closed on a field with no
// decision, so a missing entry would refuse the agent's own writes.
func TestEveryWriteFieldHasADecision(t *testing.T) {
	got := map[string][]string{}
	for _, m := range allowlist {
		if m.write {
			reachable(m.newReq().ProtoReflect().Descriptor(), got)
		}
	}
	for name, fields := range got {
		d, ok := fieldDecisions[protoreflect.FullName(name)]
		if !ok {
			t.Errorf("%s: no decisions", name)
			continue
		}
		for _, f := range fields {
			if d[protoreflect.Name(f)] == 0 {
				t.Errorf("%s.%s: no decision", name, f)
			}
		}
		if len(d) != len(fields) {
			t.Errorf("%s: %d decisions for %d fields", name, len(d), len(fields))
		}
	}
	if len(got) != len(fieldDecisions) {
		t.Errorf("%d messages reachable from writes, %d with decisions", len(got), len(fieldDecisions))
	}
}

func TestWalkFailsClosed(t *testing.T) {
	t.Run("a nested message without decisions", func(t *testing.T) {
		saved := fieldDecisions["containerd.types.Descriptor"]
		delete(fieldDecisions, "containerd.types.Descriptor")
		t.Cleanup(func() { fieldDecisions["containerd.types.Descriptor"] = saved })
		err := walk((&imagesapi.DeleteImageRequest{Name: "x", Target: &types.Descriptor{Digest: "d"}}).ProtoReflect())
		var fe *fieldError
		if !errors.As(err, &fe) || fe.reason != ReasonField || !strings.Contains(fe.Error(), "has no field decisions") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("a field without a decision", func(t *testing.T) {
		saved := fieldDecisions["containerd.services.images.v1.DeleteImageRequest"]
		fieldDecisions["containerd.services.images.v1.DeleteImageRequest"] = map[protoreflect.Name]decision{"name": free}
		t.Cleanup(func() { fieldDecisions["containerd.services.images.v1.DeleteImageRequest"] = saved })
		err := walk((&imagesapi.DeleteImageRequest{Name: "x", Sync: true}).ProtoReflect())
		if err == nil || !strings.Contains(err.Error(), "sync has no decision") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("unknown bytes in a list element", func(t *testing.T) {
		err := walk((&tasksapi.CreateTaskRequest{ContainerID: "c", Rootfs: []*types.Mount{withUnknownField(&types.Mount{Type: "bind"})}}).ProtoReflect())
		var fe *fieldError
		if !errors.As(err, &fe) || fe.reason != ReasonUnknownField {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("unknown bytes in a map value", func(t *testing.T) {
		c := &containersapi.Container{ID: "c", Extensions: map[string]*anypb.Any{"x": withUnknownField(&anypb.Any{TypeUrl: "x"})}}
		err := walk((&containersapi.CreateContainerRequest{Container: c}).ProtoReflect())
		var fe *fieldError
		if !errors.As(err, &fe) || fe.reason != ReasonUnknownField {
			t.Fatalf("err %v", err)
		}
	})
}
