package containerd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	versionapi "github.com/containerd/containerd/api/services/version/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeHelper is the root helper as the driver sees it in split mode.
type fakeHelper struct {
	socket string
	addrs  map[string][]string
	err    error
	asked  []string
}

func (h *fakeHelper) Socket() string                { return h.socket }
func (h *fakeHelper) ContainerdOptions() []cntr.Opt { return nil }
func (h *fakeHelper) NetnsAddrs(_ context.Context, name string) (bool, []string, error) {
	h.asked = append(h.asked, name)
	a, ok := h.addrs[name]
	return ok, a, h.err
}

// TestSplitReachesContainerdThroughTheHelper: in split mode the driver's
// containerd connection goes to the helper's socket, never containerd's.
func TestSplitReachesContainerdThroughTheHelper(t *testing.T) {
	origFn, origHelper := connectFn, connectHelperFn
	t.Cleanup(func() { connectFn, connectHelperFn = origFn, origHelper })
	connectFn = func(string, string) (*Client, error) {
		t.Fatal("split mode dialed containerd's own socket")
		return nil, nil
	}
	h := &fakeHelper{socket: "/run/aerolvm-rootd/sock/root.sock"}
	var via RootHelper
	connectHelperFn = func(got RootHelper, ns string) (*Client, error) {
		via = got
		return NewTestClient(ns, newFakeTransport()), nil
	}
	d := New(Config{Socket: "/run/containerd/containerd.sock", Namespace: "aerolvm"}, nil, nil)
	d.SetRootHelper(h)
	if c, err := d.ensureClient(); err != nil || c == nil || via != h {
		t.Fatalf("ensureClient = %v, %v (via %v)", c, err, via)
	}
}

type versionServer struct {
	versionapi.UnimplementedVersionServer
}

func (versionServer) Version(context.Context, *emptypb.Empty) (*versionapi.VersionResponse, error) {
	return &versionapi.VersionResponse{Version: "2.1.4", Revision: "test"}, nil
}

// TestConnectThroughTheHelperSocket: the real dialer, against a socket
// that answers containerd's version as the gate passes it on.
func TestConnectThroughTheHelperSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ctdh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "root.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	versionapi.RegisterVersionServer(srv, versionServer{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	c, err := connectHelperFn(&fakeHelper{socket: sock}, "aerolvm")
	if err != nil || c.Namespace() != "aerolvm" {
		t.Fatalf("connect = %v, %v", c, err)
	}
	_ = c.Close()
	if _, err := connectHelperFn(&fakeHelper{socket: filepath.Join(dir, "none.sock")}, "aerolvm"); err == nil {
		t.Fatal("a missing socket connected")
	}
}

// specTask is a task whose spec pins a network namespace (or none).
type specTask struct {
	fakeTask
	netns   string
	specErr error
}

func (t *specTask) Spec(context.Context) (*oci.Spec, error) {
	if t.specErr != nil {
		return nil, t.specErr
	}
	s := &oci.Spec{Linux: &specs.Linux{}}
	if t.netns != "" {
		s.Linux.Namespaces = []specs.LinuxNamespace{{Type: specs.NetworkNamespace, Path: t.netns}}
	}
	return s, nil
}

// TestSplitTaskAddress: in split mode a task's address is the helper's
// read of its pool namespace; single mode keeps the in-process probe.
func TestSplitTaskAddress(t *testing.T) {
	orig := containerIPv4FromTaskFn
	t.Cleanup(func() { containerIPv4FromTaskFn = orig })
	probed := 0
	containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) {
		probed++
		return "10.88.0.7", nil
	}
	ctx := context.Background()
	d := newTestDriver(t)
	if ip, err := d.taskAddress(ctx, &specTask{netns: "/run/netns/sb-1"}); err != nil || ip != "10.88.0.7" || probed != 1 {
		t.Fatalf("single mode = %q, %v (probed %d)", ip, err, probed)
	}

	h := &fakeHelper{addrs: map[string][]string{"aerol-netns-4": {"10.88.0.9", "10.88.0.10"}, "gvisor": {}}}
	d.SetRootHelper(h)
	if ip, err := d.taskAddress(ctx, &specTask{netns: "/run/netns/aerol-netns-4"}); err != nil || ip != "10.88.0.9" {
		t.Fatalf("split = %q, %v", ip, err)
	}
	if probed != 1 || len(h.asked) != 1 || h.asked[0] != "aerol-netns-4" {
		t.Fatalf("probed %d in process, asked the helper %v", probed, h.asked)
	}
	for name, tc := range map[string]struct {
		task cntr.Task
		want string
	}{
		"no namespace in the spec": {&specTask{}, "no pool network namespace"},
		"the spec cannot be read":  {&specTask{specErr: errors.New("gone")}, "gone"},
		"no task":                  {nil, "nil"},
		"gVisor took the address":  {&specTask{netns: "/run/netns/gvisor"}, "no container IPv4"},
	} {
		if _, err := d.taskAddress(ctx, tc.task); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	h.err = errors.New("helper unavailable")
	if _, err := d.taskAddress(ctx, &specTask{netns: "/run/netns/aerol-netns-4"}); err == nil {
		t.Fatal("a helper error was swallowed")
	}
	// A create knows its slot's address, the one the helper gave it, and
	// asks nothing more of the helper; without one (a start, an inspect,
	// an adoption) the address is read through the helper, and a failed
	// read falls back as before.
	h.err = nil
	asked := len(h.asked)
	state, err := d.runtimeStateAfterStart(ctx, nil, &specTask{netns: "/run/netns/aerol-netns-4"}, "sb", "10.88.0.44")
	if err != nil || state.ContainerIP != "10.88.0.44" || len(h.asked) != asked {
		t.Fatalf("a create: state %+v, %v; helper asked %v", state, err, h.asked[asked:])
	}
	state, err = d.runtimeStateAfterStart(ctx, nil, &specTask{netns: "/run/netns/aerol-netns-4"}, "sb", "")
	if err != nil || state.ContainerIP != "10.88.0.9" || len(h.asked) != asked+1 {
		t.Fatalf("a start: state %+v, %v", state, err)
	}
	if _, err := d.runtimeStateAfterStart(ctx, nil, &specTask{netns: "/run/netns/gvisor"}, "sb", ""); err == nil {
		t.Fatal("a gVisor start with no address and no hint got one")
	}
}

// TestSplitCreateAndStartNameTheirGaps: in split mode a create and a start
// fail at once with a privmode.Gap (501) naming the root work the helper
// does not do yet, before any of it is tried, and never as root.
func TestSplitCreateAndStartNameTheirGaps(t *testing.T) {
	origFn := connectFn
	t.Cleanup(func() { connectFn = origFn })
	connectFn = func(string, string) (*Client, error) {
		t.Fatal("a refused create reached containerd")
		return nil, nil
	}
	ctx := context.Background()
	d := newTestDriver(t)
	d.SetRootHelper(&fakeHelper{})
	_, err := d.Create(ctx, models.CreateSandboxRequest{Image: "alpine"}, "sb-1", "tok", nil)
	if !errors.Is(err, privmode.ErrGap) || !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("Create = %v, want a Gap", err)
	}
	var g *privmode.Gap
	if !errors.As(err, &g) || len(g.Steps) != 2 {
		t.Fatalf("steps %+v", g)
	}
	d.cfg.CgroupParent, d.cfg.DiskQuota = "/kubepods/pod1/sandboxes", true
	_, err = d.Create(ctx, models.CreateSandboxRequest{Image: "alpine", DiskGB: 5}, "sb-1", "tok", nil)
	if !errors.As(err, &g) || len(g.Steps) != 4 || !strings.Contains(err.Error(), "disk quota") || !strings.Contains(err.Error(), "out-of-memory") {
		t.Fatalf("Create = %v", err)
	}
	// The ID is still checked first: a hostile one never reaches the gap.
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "alpine"}, "../etc", "tok", nil); errors.Is(err, privmode.ErrGap) {
		t.Fatalf("a bad ID passed its check: %v", err)
	}
	for _, start := range []func() error{
		func() error { _, err := d.Start(ctx, "sb-1"); return err },
		func() error { _, err := d.StartWithIdentityEnv(ctx, "sb-1", "sb-1", "tok", nil); return err },
	} {
		if err := start(); !errors.As(err, &g) || !strings.Contains(err.Error(), "start a sandbox") || len(g.Steps) != 2 {
			t.Fatalf("Start = %v", err)
		}
	}
	d.cfg.CgroupParent = ""
	if _, err := d.Start(ctx, "sb-1"); !errors.As(err, &g) || len(g.Steps) != 1 {
		t.Fatalf("Start = %v", err)
	}
}
