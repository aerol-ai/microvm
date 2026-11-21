package gate

import (
	"context"
	"fmt"
	"sort"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	diffapi "github.com/containerd/containerd/api/services/diff/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// checkFunc runs a method's rootpolicy checks on a request. A
// rootpolicy.Violation becomes a refusal; any other error is returned to
// the caller as it is.
type checkFunc func(ctx context.Context, g *Gate, req proto.Message) error

func checkNamespaceGet(_ context.Context, g *Gate, req proto.Message) error {
	return rootpolicy.CheckNamespace(g.policy, req.(*namespacesapi.GetNamespaceRequest).GetName())
}

func checkContainerCreate(ctx context.Context, g *Gate, req proto.Message) error {
	return g.checkContainer(ctx, policyContainer(req.(*containersapi.CreateContainerRequest).GetContainer()))
}

// checkContainer runs every check on a container record: the rules, its
// bind sources on disk, and its network namespace's owner.
func (g *Gate) checkContainer(ctx context.Context, c rootpolicy.Container) error {
	if err := rootpolicy.CheckContainer(g.policy, c); err != nil {
		return err
	}
	if err := g.checkBinds(c); err != nil {
		return err
	}
	return g.checkNetns(ctx, c)
}

// checkContainerUpdate allows a relabel and nothing else. The field mask
// already limits what containerd applies; a request that carries a spec or
// runtime anyway is still not one the agent builds.
func checkContainerUpdate(_ context.Context, _ *Gate, req proto.Message) error {
	r := req.(*containersapi.UpdateContainerRequest)
	if err := rootpolicy.CheckContainerUpdate(r.GetUpdateMask().GetPaths()); err != nil {
		return err
	}
	c := r.GetContainer()
	if err := rootpolicy.ValidateID(c.GetID()); err != nil {
		return err
	}
	if err := rootpolicy.CheckContainerLabels(c.GetLabels()); err != nil {
		return err
	}
	// The client always sends a runtime message, empty on a relabel
	// (containerd's containerToProto), so an empty message counts as unset.
	var extra protoreflect.Name
	c.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		n := fd.Name()
		if n == "id" || n == "labels" || (fd.Message() != nil && !fd.IsMap() && !fd.IsList() && proto.Size(v.Message().Interface()) == 0) {
			return true
		}
		extra = n
		return false
	})
	if extra != "" {
		return &rootpolicy.Violation{Rule: rootpolicy.RuleUpdate, Detail: fmt.Sprintf("container update carries %s; the agent sends only labels", extra)}
	}
	return nil
}

// checkTaskCreate checks the request, then the container containerd will
// build the task from. A container stored before the gate existed, or
// under a wider policy, must not start through it.
func checkTaskCreate(ctx context.Context, g *Gate, req proto.Message) error {
	r := req.(*tasksapi.CreateTaskRequest)
	t := rootpolicy.TaskCreate{
		ContainerID:    r.GetContainerID(),
		Rootfs:         policyMounts(r.GetRootfs()),
		Stdin:          r.GetStdin(),
		Stdout:         r.GetStdout(),
		Stderr:         r.GetStderr(),
		Terminal:       r.GetTerminal(),
		RuntimePath:    r.GetRuntimePath(),
		TaskAPIAddress: r.GetTaskApiAddress(),
		TaskAPIVersion: r.GetTaskApiVersion(),
	}
	if c := r.GetCheckpoint(); c != nil {
		t.Checkpoint = nonEmpty(c.GetDigest())
	}
	if o := r.GetOptions(); o != nil {
		t.OptionsTypeURL = nonEmpty(o.GetTypeUrl())
	}
	if err := rootpolicy.CheckTaskCreate(g.policy, t); err != nil {
		return err
	}
	for _, p := range []string{t.Stdin, t.Stdout, t.Stderr} {
		if p == "" {
			continue
		}
		if err := g.stdio.CheckStdio(p); err != nil {
			return err
		}
	}
	resp, err := containersapi.NewContainersClient(g.upstream).Get(g.upstreamContext(ctx), &containersapi.GetContainerRequest{ID: r.GetContainerID()})
	if err != nil {
		return err
	}
	// runc mounts the binds at task create, so this walk is the one
	// closest to the mount.
	return g.checkContainer(ctx, policyContainer(resp.GetContainer()))
}

// nonEmpty keeps a set but blank field visible to the check as set.
func nonEmpty(s string) string {
	if s == "" {
		return "(set, blank)"
	}
	return s
}

func checkTaskUpdate(_ context.Context, g *Gate, req proto.Message) error {
	r := req.(*tasksapi.UpdateTaskRequest)
	res := r.GetResources()
	return rootpolicy.CheckTaskUpdate(g.policy, res.GetTypeUrl(), res.GetValue(), r.GetAnnotations())
}

func checkSnapshotter(_ context.Context, g *Gate, req proto.Message) error {
	return rootpolicy.CheckSnapshotter(g.policy, req.(interface{ GetSnapshotter() string }).GetSnapshotter())
}

// checkDiffApply: containerd, as root, writes a layer into these mounts.
func checkDiffApply(_ context.Context, g *Gate, req proto.Message) error {
	return rootpolicy.CheckSnapshotMounts(g.policy, policyMounts(req.(*diffapi.ApplyRequest).GetMounts()))
}

// checkDiffDiff: containerd, as root, reads these mounts into a layer the
// agent can then read back from the content store.
func checkDiffDiff(_ context.Context, g *Gate, req proto.Message) error {
	r := req.(*diffapi.DiffRequest)
	if err := rootpolicy.CheckSnapshotMounts(g.policy, policyMounts(r.GetLeft())); err != nil {
		return err
	}
	return rootpolicy.CheckSnapshotMounts(g.policy, policyMounts(r.GetRight()))
}

func policyMounts(in []*types.Mount) []rootpolicy.Mount {
	out := make([]rootpolicy.Mount, 0, len(in))
	for _, m := range in {
		out = append(out, rootpolicy.Mount{Type: m.GetType(), Source: m.GetSource(), Target: m.GetTarget(), Options: m.GetOptions()})
	}
	return out
}

// policyContainer is a container record as rootpolicy reads it.
func policyContainer(c *containersapi.Container) rootpolicy.Container {
	out := rootpolicy.Container{
		ID:          c.GetID(),
		Labels:      c.GetLabels(),
		Snapshotter: c.GetSnapshotter(),
		SnapshotKey: c.GetSnapshotKey(),
		Sandbox:     c.GetSandbox(),
		SpecTypeURL: c.GetSpec().GetTypeUrl(),
		Spec:        c.GetSpec().GetValue(),
		Runtime: rootpolicy.Runtime{
			Name:           c.GetRuntime().GetName(),
			OptionsTypeURL: c.GetRuntime().GetOptions().GetTypeUrl(),
			Options:        c.GetRuntime().GetOptions().GetValue(),
		},
	}
	for k := range c.GetExtensions() {
		out.Extensions = append(out.Extensions, k)
	}
	sort.Strings(out.Extensions)
	return out
}
