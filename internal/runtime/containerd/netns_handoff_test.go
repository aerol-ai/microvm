package containerd

import (
	"context"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

type fakeNetnsHandoff struct {
	path, ip string
	provErr  error
	relErr   error
	relCalls int
}

func (f *fakeNetnsHandoff) Provision(ctx context.Context, sandboxID string) (string, string, error) {
	_ = ctx
	_ = sandboxID
	if f.provErr != nil {
		return "", "", f.provErr
	}
	return f.path, f.ip, nil
}

func (f *fakeNetnsHandoff) Release(ctx context.Context, sandboxID string) error {
	_ = ctx
	_ = sandboxID
	f.relCalls++
	return f.relErr
}

func (f *fakeNetnsHandoff) ReassignOwner(context.Context, string, string) error { return nil }

func TestWithNetworkNamespaceSetsPath(t *testing.T) {
	spec := &specs.Spec{Linux: &specs.Linux{}}
	opt := withNetworkNamespace("/run/netns/sb-1")
	if err := opt(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace && ns.Path == "/run/netns/sb-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("namespaces=%+v", spec.Linux.Namespaces)
	}
}

func TestWithNetworkNamespaceOverridesExisting(t *testing.T) {
	spec := &specs.Spec{Linux: &specs.Linux{
		Namespaces: []specs.LinuxNamespace{{Type: specs.NetworkNamespace, Path: "/old"}},
	}}
	opt := withNetworkNamespace("/new")
	if err := opt(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	if spec.Linux.Namespaces[0].Path != "/new" {
		t.Fatalf("path=%q", spec.Linux.Namespaces[0].Path)
	}
}

func TestWithNetworkNamespaceEmptyNoOp(t *testing.T) {
	spec := &specs.Spec{}
	if err := withNetworkNamespace("")(context.Background(), nil, nil, spec); err != nil {
		t.Fatal(err)
	}
	if spec.Linux != nil && len(spec.Linux.Namespaces) != 0 {
		t.Fatal("unexpected namespace mutation")
	}
}

func TestRuntimeStateAfterStartUsesIPHint(t *testing.T) {
	d := New(Config{}, nil, nil)
	// No task — ipHint must carry the prepaid pool IP on platforms where
	// netlink PID lookup is unavailable in unit tests.
	state, err := d.runtimeStateAfterStart(context.Background(), nil, nil, "sb-1", "10.88.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if state.ContainerIP != "10.88.0.5" {
		t.Fatalf("ip=%q", state.ContainerIP)
	}
}

func TestSetNetnsHandoff(t *testing.T) {
	d := New(Config{}, nil, nil)
	f := &fakeNetnsHandoff{path: "/n", ip: "10.0.0.1"}
	d.SetNetnsHandoff(f)
	if d.netns == nil {
		t.Fatal("handoff not wired")
	}
}
