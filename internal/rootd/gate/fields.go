package gate

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// decision is what the gate does with one field of a write request.
type decision int

const (
	// free: forwarded as sent. Names, keys, labels and content that only
	// mean something inside containerd's own store.
	free decision = iota + 1
	// checked: forwarded once the method's rootpolicy check has read it.
	checked
	// empty: the agent never sets it, and it means something to root.
	empty
)

// fieldDecisions has a decision for every field of every message a write
// request can carry, nested ones included. The walk refuses a set field
// with no decision, so a field containerd adds is refused at run time until
// someone decides about it; TestFieldPins fails the build first.
var fieldDecisions = map[protoreflect.FullName]map[protoreflect.Name]decision{
	"containerd.services.containers.v1.CreateContainerRequest": {"container": checked},
	"containerd.services.containers.v1.UpdateContainerRequest": {"container": checked, "update_mask": checked},
	"containerd.services.containers.v1.DeleteContainerRequest": {"id": free},
	"containerd.services.containers.v1.Container": {
		"id": checked, "labels": checked, "image": free, "runtime": checked, "spec": checked,
		"snapshotter": checked, "snapshot_key": free, "created_at": free, "updated_at": free,
		"extensions": checked, "sandbox": checked,
	},
	"containerd.services.containers.v1.Container.Runtime": {"name": checked, "options": checked},

	"containerd.services.tasks.v1.CreateTaskRequest": {
		"container_id": checked, "rootfs": checked, "stdin": checked, "stdout": checked, "stderr": checked,
		"terminal": checked, "checkpoint": checked, "options": checked, "runtime_path": checked,
		"task_api_address": checked, "task_api_version": checked,
	},
	"containerd.services.tasks.v1.StartRequest":      {"container_id": free, "exec_id": free},
	"containerd.services.tasks.v1.KillRequest":       {"container_id": free, "exec_id": free, "signal": free, "all": free},
	"containerd.services.tasks.v1.DeleteTaskRequest": {"container_id": free},
	"containerd.services.tasks.v1.PauseTaskRequest":  {"container_id": free},
	"containerd.services.tasks.v1.ResumeTaskRequest": {"container_id": free},
	"containerd.services.tasks.v1.UpdateTaskRequest": {"container_id": free, "resources": checked, "annotations": checked},

	"containerd.services.images.v1.CreateImageRequest": {"image": free, "source_date_epoch": free},
	"containerd.services.images.v1.UpdateImageRequest": {"image": free, "update_mask": free, "source_date_epoch": free},
	"containerd.services.images.v1.DeleteImageRequest": {"name": free, "sync": free, "target": free},
	"containerd.services.images.v1.Image":              {"name": free, "labels": free, "target": free, "created_at": free, "updated_at": free},

	"containerd.services.content.v1.WriteContentRequest": {
		"action": free, "ref": free, "total": free, "expected": free, "offset": free, "data": free, "labels": free,
	},
	"containerd.services.content.v1.UpdateRequest": {"info": free, "update_mask": free},
	"containerd.services.content.v1.Info":          {"digest": free, "size": free, "created_at": free, "updated_at": free, "labels": free},

	"containerd.services.snapshots.v1.PrepareSnapshotRequest": {"snapshotter": checked, "key": free, "parent": free, "labels": free},
	"containerd.services.snapshots.v1.ViewSnapshotRequest":    {"snapshotter": checked, "key": free, "parent": free, "labels": free},
	"containerd.services.snapshots.v1.CommitSnapshotRequest":  {"snapshotter": checked, "name": free, "key": free, "labels": free, "parent": free},
	"containerd.services.snapshots.v1.RemoveSnapshotRequest":  {"snapshotter": checked, "key": free},

	// payloads configure containerd's stream processors, which the agent's
	// unpack never asks for.
	"containerd.services.diff.v1.ApplyRequest": {"diff": free, "mounts": checked, "payloads": empty, "sync_fs": free},
	"containerd.services.diff.v1.DiffRequest": {
		"left": checked, "right": checked, "media_type": free, "ref": free, "labels": free, "source_date_epoch": free,
	},

	"containerd.services.leases.v1.CreateRequest":      {"id": free, "labels": free},
	"containerd.services.leases.v1.DeleteRequest":      {"id": free, "sync": free},
	"containerd.services.leases.v1.AddResourceRequest": {"id": free, "resource": free},
	"containerd.services.leases.v1.Resource":           {"id": free, "type": free},

	// Mounts appear only in Tasks.Create's rootfs and the Diff calls, where
	// rootpolicy.CheckSnapshotMounts reads every field.
	"containerd.types.Mount":      {"type": checked, "source": checked, "target": checked, "options": checked},
	"containerd.types.Descriptor": {"media_type": free, "digest": free, "size": free, "annotations": free},
	"google.protobuf.Any":         {"type_url": free, "value": free},
	"google.protobuf.FieldMask":   {"paths": free},
	"google.protobuf.Timestamp":   {"seconds": free, "nanos": free},
}

// fieldError is a write request the walk refused.
type fieldError struct {
	reason string
	detail string
}

func (e *fieldError) Error() string { return e.detail }

// walk refuses a write request that carries unknown field bytes anywhere
// (a newer client's field this build cannot see, so cannot check), or a
// set field that has no decision or must be empty.
func walk(m protoreflect.Message) error {
	md := m.Descriptor()
	if len(m.GetUnknown()) > 0 {
		return &fieldError{ReasonUnknownField, fmt.Sprintf("%s carries fields this gate does not know", md.FullName())}
	}
	decisions, ok := fieldDecisions[md.FullName()]
	if !ok {
		return &fieldError{ReasonField, fmt.Sprintf("%s has no field decisions", md.FullName())}
	}
	var err error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch decisions[fd.Name()] {
		case free, checked:
		case empty:
			err = &fieldError{ReasonField, fmt.Sprintf("%s.%s is set; the agent never sets it", md.FullName(), fd.Name())}
			return false
		default:
			err = &fieldError{ReasonField, fmt.Sprintf("%s.%s has no decision in the gate", md.FullName(), fd.Name())}
			return false
		}
		err = walkValue(fd, v)
		return err == nil
	})
	return err
}

func walkValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) error {
	switch {
	case fd.IsMap():
		if fd.MapValue().Message() == nil {
			return nil
		}
		var err error
		v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
			err = walk(mv.Message())
			return err == nil
		})
		return err
	case fd.Message() == nil:
		return nil
	case fd.IsList():
		l := v.List()
		for i := range l.Len() {
			if err := walk(l.Get(i).Message()); err != nil {
				return err
			}
		}
		return nil
	default:
		return walk(v.Message())
	}
}
