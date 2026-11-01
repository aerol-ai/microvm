package containerd

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func hostIPv6(t *testing.T, has bool) {
	t.Helper()
	orig := sandboxIPv6Sysctls
	sandboxIPv6Sysctls = func() map[string]string {
		if !has {
			return nil
		}
		return map[string]string{hostnet.SysctlAllDisableIPv6: "1", hostnet.SysctlDefaultDisableIPv6: "1"}
	}
	t.Cleanup(func() { sandboxIPv6Sysctls = orig })
}

// captureSpecs records the spec every NewContainer would get: each option
// that needs no live client is applied to a blank spec (WithImageConfig and
// friends read the content store and are skipped).
type specCapture struct {
	mu    sync.Mutex
	specs []*specs.Spec
}

func (c *specCapture) install(t *testing.T) {
	t.Helper()
	orig := withNewSpec
	withNewSpec = func(opts ...oci.SpecOpts) cntr.NewContainerOpts {
		spec := &specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}}, Linux: &specs.Linux{}}
		for _, o := range opts {
			func() {
				defer func() { _ = recover() }()
				_ = o(context.Background(), nil, &containers.Container{}, spec)
			}()
		}
		c.mu.Lock()
		c.specs = append(c.specs, spec)
		c.mu.Unlock()
		return func(context.Context, *cntr.Client, *containers.Container) error { return nil }
	}
	t.Cleanup(func() { withNewSpec = orig })
}

func (c *specCapture) last(t *testing.T) *specs.Spec {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.specs) == 0 {
		t.Fatal("no spec was generated")
	}
	return c.specs[len(c.specs)-1]
}

func wantIPv6Off(t *testing.T, spec *specs.Spec) {
	t.Helper()
	if spec.Linux == nil || spec.Linux.Sysctl[hostnet.SysctlAllDisableIPv6] != "1" || spec.Linux.Sysctl[hostnet.SysctlDefaultDisableIPv6] != "1" {
		t.Fatalf("spec sysctls = %+v, want IPv6 off (all and default)", spec.Linux)
	}
}

func TestWithSandboxIPv6Off(t *testing.T) {
	t.Run("nil_linux_section", func(t *testing.T) {
		hostIPv6(t, true)
		spec := &specs.Spec{}
		if err := withSandboxIPv6Off()(context.Background(), nil, nil, spec); err != nil {
			t.Fatal(err)
		}
		wantIPv6Off(t, spec)
	})
	t.Run("keeps_other_sysctls", func(t *testing.T) {
		hostIPv6(t, true)
		spec := &specs.Spec{Linux: &specs.Linux{Sysctl: map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}}}
		if err := withSandboxIPv6Off()(context.Background(), nil, nil, spec); err != nil {
			t.Fatal(err)
		}
		wantIPv6Off(t, spec)
		if spec.Linux.Sysctl["net.ipv4.ip_unprivileged_port_start"] != "0" {
			t.Fatalf("an existing sysctl was dropped: %v", spec.Linux.Sysctl)
		}
	})
	t.Run("host_without_ipv6", func(t *testing.T) {
		// runc fails a create on a sysctl with no /proc/sys entry.
		hostIPv6(t, false)
		spec := &specs.Spec{}
		if err := withSandboxIPv6Off()(context.Background(), nil, nil, spec); err != nil {
			t.Fatal(err)
		}
		if spec.Linux != nil {
			t.Fatalf("host without IPv6 got sysctls: %+v", spec.Linux)
		}
	})
}

// TestCreateSpecTurnsIPv6Off is the regression test for the containerd
// side of the link-local hole: a cold create, runc or gVisor, pooled netns
// or a fresh one, starts the sandbox with IPv6 off. For runsc the sysctl in
// the spec is what keeps IPv6 out of gVisor's own network stack.
func TestCreateSpecTurnsIPv6Off(t *testing.T) {
	for _, tc := range []struct {
		name    string
		runtime string
		pool    bool
	}{
		{"runc_pooled_netns", models.RuntimeDocker, true},
		{"gvisor_pooled_netns", models.RuntimeGvisor, true},
		{"runc_fresh_netns", models.RuntimeDocker, false},
		{"gvisor_fresh_netns", models.RuntimeGvisor, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubToolboxProbe(t)
			hostIPv6(t, true)
			cap := &specCapture{}
			cap.install(t)
			d := newTestDriver(t)
			if !tc.pool {
				d.SetNetnsHandoff(nil)
				d.cfg.NativeNetnsPool = false
			}
			if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}, Runtime: tc.runtime,
			}, "sb-v6-"+tc.name, "tok", nil); err != nil {
				t.Fatal(err)
			}
			spec := cap.last(t)
			wantIPv6Off(t, spec)
			if tc.runtime == models.RuntimeGvisor && spec.Annotations[criContainerTypeAnnotation] != criContainerTypeSandbox {
				t.Fatalf("runsc annotations lost: %v", spec.Annotations)
			}
		})
	}
}

// A privileged node still starts sandboxes with IPv6 off: it is the
// starting state, not a security option a privileged sandbox opts out of.
func TestCreateSpecTurnsIPv6OffPrivileged(t *testing.T) {
	stubToolboxProbe(t)
	hostIPv6(t, true)
	cap := &specCapture{}
	cap.install(t)
	d := newTestDriver(t)
	d.cfg.Privileged = true
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"},
	}, "sb-v6-priv", "tok", nil); err != nil {
		t.Fatal(err)
	}
	wantIPv6Off(t, cap.last(t))
}

// Parked warm containers are adopted as sandboxes, so they get it too.
func TestParkSpecTurnsIPv6Off(t *testing.T) {
	for _, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor} {
		t.Run(rt, func(t *testing.T) {
			stubToolboxProbe(t)
			hostIPv6(t, true)
			origWait := parkReadyWaitFn
			parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
			t.Cleanup(func() { parkReadyWaitFn = origWait })
			cap := &specCapture{}
			cap.install(t)

			provider, img := newTestImageProvider(t)
			tr := newFakeTransport()
			tr.provider = provider
			tr.image = img
			tmp := t.TempDir()
			toolbox := filepath.Join(tmp, "toolboxd")
			if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
				t.Fatal(err)
			}
			d := New(Config{
				ToolboxBinaryPath:  toolbox,
				ToolboxMountPath:   "/.aerol/toolboxd",
				ToolboxPort:        2280,
				ToolboxWaitTimeout: 2 * time.Second,
				LogDir:             filepath.Join(tmp, "logs"),
				RunDir:             filepath.Join(tmp, "run"),
				ReadyEnabled:       true,
				ReadyDir:           shortReadyDir(t),
				NativeNetnsPool:    true,
			}, nil, nil)
			d.SetClient(NewTestClient("aerolvm", tr))
			d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park-v6", ip: "10.88.0.79"})
			if _, err := d.parkContainer(context.Background(), "park-v6-"+rt, containerdpool.Key{Image: "cfg:test", Runtime: rt}); err != nil {
				t.Fatal(err)
			}
			wantIPv6Off(t, cap.last(t))
		})
	}
}
