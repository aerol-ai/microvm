package containerd

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/runscwrap"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// conformanceRig records every container the driver asks containerd for,
// as containerd would store it: containerd's default spec for the
// container with the driver's spec options on top, the runtime and its
// options, the labels. Only what needs a live containerd is left out (the
// image config's env, args and user, and the snapshot WithNewSnapshot
// prepares), none of which the envelope reads.
type conformanceRig struct {
	t   *testing.T
	d   *Driver
	tr  *fakeTransport
	tmp string

	mu      sync.Mutex
	created []containers.Container
}

func newConformanceRig(t *testing.T, mutate func(*Config)) *conformanceRig {
	t.Helper()
	stubToolboxProbe(t)
	hostIPv6(t, true)
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Namespace:          "aerolvm",
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		NativeNetnsPool:    true,
		PidsLimit:          4096,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	r := &conformanceRig{t: t, tr: newFakeTransport(), tmp: tmp}
	r.tr.provider, r.tr.image = newTestImageProvider(t) // a warm park reads the image's command
	r.d = New(cfg, nil, nil)
	r.d.SetClient(NewTestClient("aerolvm", r.tr))
	r.d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"})

	origSpec, origReady, origPark := withNewSpec, createReadyWaitFn, parkReadyWaitFn
	withNewSpec = func(opts ...oci.SpecOpts) cntr.NewContainerOpts {
		return func(_ context.Context, _ *cntr.Client, c *containers.Container) error {
			ctx := namespaces.WithNamespace(context.Background(), "aerolvm")
			// A sandbox is always a Linux container, whatever runs the test.
			spec, err := oci.GenerateSpecWithPlatform(ctx, nil, "linux", c)
			if err != nil {
				t.Errorf("containerd default spec: %v", err)
				return err
			}
			for _, o := range opts {
				func() {
					defer func() { _ = recover() }() // WithImageConfig needs a live content store
					_ = o(ctx, nil, c, spec)
				}()
			}
			c.Spec, err = typeurl.MarshalAny(spec)
			return err
		}
	}
	createReadyWaitFn = func(context.Context, *dockerpkg.ReadyListener) error { return nil }
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
	r.tr.newContainerFn = r.newContainer
	t.Cleanup(func() { withNewSpec, createReadyWaitFn, parkReadyWaitFn = origSpec, origReady, origPark })
	return r
}

func (r *conformanceRig) newContainer(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
	// containerd's client starts every record on its default runtime.
	rec := containers.Container{ID: id, Runtime: containers.RuntimeInfo{Name: rootpolicy.RuntimeRunc}}
	for _, o := range opts {
		func() {
			defer func() { _ = recover() }() // WithNewSnapshot needs a live client
			_ = o(ctx, nil, &rec)
		}()
	}
	rec.Snapshotter, rec.SnapshotKey = "overlayfs", id // what WithNewSnapshot records
	r.mu.Lock()
	r.created = append(r.created, rec)
	r.mu.Unlock()
	r.tr.mu.Lock()
	defer r.tr.mu.Unlock()
	if _, exists := r.tr.containers[id]; exists {
		return nil, errdefs.ErrAlreadyExists
	}
	c := &fakeContainer{id: id, runtime: rec.Runtime}
	r.tr.containers[id] = c
	return c, nil
}

// policy is the root helper's policy for this driver's config: what the
// helper will be configured with once it serves this agent.
func (r *conformanceRig) policy() rootpolicy.Policy {
	r.t.Helper()
	cfg := r.d.cfg
	p := rootpolicy.Policy{
		Namespace:       "aerolvm",
		Snapshotter:     "overlayfs",
		SnapshotterRoot: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
		NetnsDir:        "/run/netns",
		CgroupParent:    cfg.CgroupParent,
		BindRoots:       []string{r.mountsRoot(), r.egressCADir()},
		// The host files sit where the helper's will (<root>/<id>/<name>)
		// and are bound read-only, so they meet the rule for the helper's
		// own files already. The ready sockets are still the agent's flat
		// names; T4 moves them into the helper's folder, read-only too.
		HelperFileRoots: []string{filepath.Join(cfg.RunDir, "hosts")},
		BindFiles:       []string{cfg.ToolboxBinaryPath},
		ForbiddenRoots:  []string{"/run/aerolvm", "/run/containerd"},
		MovesDir:        filepath.Join(cfg.RunDir, movesDirName),
		FIFODir:         "/run/containerd/fifo",
		RunscConfigPaths: []string{
			filepath.Join(cfg.RunDir, runscConfigRelPath),
			filepath.Join(cfg.RunDir, runscRestoreConfigRelPath),
		},
		Privileged: cfg.Privileged,
		// The node's bounds: room for gVisor's larger host pids limit
		// (pkg/gvisorpids) and the sizes below.
		Limits: rootpolicy.Limits{MemoryBytes: 64 << 30, Pids: 1 << 20, CPUs: 64},
	}
	if cfg.ReadyDir != "" {
		p.BindRoots = append(p.BindRoots, cfg.ReadyDir)
	}
	if err := p.Validate(); err != nil {
		r.t.Fatalf("policy: %v", err)
	}
	return p
}

func (r *conformanceRig) mountsRoot() string  { return filepath.Join(r.tmp, "mounts") }
func (r *conformanceRig) egressCADir() string { return filepath.Join(r.tmp, "egress") }

func (r *conformanceRig) containers() []containers.Container {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]containers.Container(nil), r.created...)
}

// policyContainer is how the gate sees a container record.
func policyContainer(c containers.Container) rootpolicy.Container {
	out := rootpolicy.Container{
		ID:          c.ID,
		Labels:      c.Labels,
		Snapshotter: c.Snapshotter,
		SnapshotKey: c.SnapshotKey,
		Sandbox:     c.SandboxID,
		Runtime:     rootpolicy.Runtime{Name: c.Runtime.Name},
	}
	if c.Spec != nil {
		out.SpecTypeURL, out.Spec = c.Spec.GetTypeUrl(), c.Spec.GetValue()
	}
	if c.Runtime.Options != nil {
		out.Runtime.OptionsTypeURL, out.Runtime.Options = c.Runtime.Options.GetTypeUrl(), c.Runtime.Options.GetValue()
	}
	for k := range c.Extensions {
		out.Extensions = append(out.Extensions, k)
	}
	sort.Strings(out.Extensions)
	return out
}

// TestBuilderOutputPassesRootPolicy is the drift test the root split rests
// on (plans/security-gaps-m1-m4.md §3.3): every container shape this driver
// asks containerd for passes the checks the root helper's gate will run on
// it. A builder change the gate would refuse fails here, not on a worker.
func TestBuilderOutputPassesRootPolicy(t *testing.T) {
	type tc struct {
		name    string
		cfg     func(*Config)
		setup   func(*testing.T, *conformanceRig)
		req     models.CreateSandboxRequest
		binds   func(*conformanceRig) []mounts.ContainerBind
		restore bool
		park    bool
		// teeth narrows the policy so that this shape's own feature is
		// refused, with rule: proof the shape reaches the check, rather
		// than passing because nothing looked at it.
		teeth func(*rootpolicy.Policy)
		rule  rootpolicy.Rule
	}
	// Requests as the service hands them to the driver: normalizeCreateRequest
	// fills in the default CPU and memory.
	gvisor := models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeGvisor, ContainerCommand: []string{"sleep", "inf"},
		CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB}
	runc := models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker, ContainerCommand: []string{"sleep", "inf"},
		CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB}
	freshNetns := func(c *Config) { c.NativeNetnsPool = false }
	readySocket := func(c *Config) { c.ReadyEnabled, c.ReadyDir = true, shortReadyDir(t) }
	sized := runc
	sized.MemoryMB, sized.CPU = 512, 1.5
	quota := runc
	quota.DiskGB = 2
	// policy() lists the bind roots as: mounts, egress CA, ready sockets.
	// Each keepRoots(n) drops the ones from n on.
	keepRoots := func(n int) func(*rootpolicy.Policy) {
		return func(p *rootpolicy.Policy) { p.BindRoots = p.BindRoots[:n] }
	}
	noHelperRoots := func(p *rootpolicy.Policy) { p.HelperFileRoots = nil }
	otherNetnsDir := func(p *rootpolicy.Policy) { p.NetnsDir = "/var/run/netns" }
	noRunscConfig := func(p *rootpolicy.Policy) { p.RunscConfigPaths = nil }
	otherParent := func(p *rootpolicy.Policy) { p.CgroupParent = "/elsewhere" }
	for _, c := range []tc{
		{name: "runc pooled netns", req: runc, teeth: otherNetnsDir, rule: rootpolicy.RuleHostNamespace},
		{name: "runc fresh netns", cfg: freshNetns, req: runc, teeth: noHelperRoots, rule: rootpolicy.RuleMount},
		{name: "gvisor pooled netns", req: gvisor, teeth: noRunscConfig, rule: rootpolicy.RuleRuntimeOptions},
		{name: "gvisor fresh netns", cfg: freshNetns, req: gvisor, teeth: noRunscConfig, rule: rootpolicy.RuleRuntimeOptions},
		{name: "runc memory and cpu", req: sized, teeth: func(p *rootpolicy.Policy) { p.Snapshotter = "native" }, rule: rootpolicy.RuleSnapshotter},
		{name: "runc external mounts", req: runc, teeth: keepRoots(0), rule: rootpolicy.RuleMount, binds: func(r *conformanceRig) []mounts.ContainerBind {
			return []mounts.ContainerBind{
				{HostPath: filepath.Join(r.mountsRoot(), "sb", "0"), ContainerPath: "/data"},
				{HostPath: filepath.Join(r.mountsRoot(), "sb", "1"), ContainerPath: "/ro", ReadOnly: true},
				{ContainerPath: "/scratch", Tmpfs: true, TmpfsSize: 64 << 20},
			}
		}},
		{name: "gvisor external mounts", req: gvisor, teeth: keepRoots(0), rule: rootpolicy.RuleMount, binds: func(r *conformanceRig) []mounts.ContainerBind {
			return []mounts.ContainerBind{{HostPath: filepath.Join(r.mountsRoot(), "sb", "0"), ContainerPath: "/data"}}
		}},
		{name: "runc egress CA", req: runc, teeth: keepRoots(1), rule: rootpolicy.RuleMount, binds: func(r *conformanceRig) []mounts.ContainerBind {
			// internal/service/egress_inspect.go: the CA, read-only, and a
			// tmpfs for the bundle toolboxd assembles.
			return []mounts.ContainerBind{
				{HostPath: filepath.Join(r.egressCADir(), "ca.pem"), ContainerPath: "/etc/aerolvm/egress-ca.pem", ReadOnly: true},
				{ContainerPath: "/etc/aerolvm/egress-bundle", Tmpfs: true},
			}
		}},
		{name: "runc ready socket", cfg: readySocket, req: runc, teeth: keepRoots(2), rule: rootpolicy.RuleMount},
		{name: "gvisor ready socket", cfg: readySocket, req: gvisor, teeth: keepRoots(2), rule: rootpolicy.RuleMount},
		{name: "runc disk quota", cfg: func(c *Config) { c.DiskQuota = true }, req: quota, teeth: otherParent, rule: rootpolicy.RuleCgroup, setup: func(t *testing.T, _ *conformanceRig) {
			withDiskQuotaFakes(t, fakeSnapshots{numbers: map[string]int{"sb-conf": 42}})
		}},
		{name: "runc cgroup parent", cfg: func(c *Config) { c.CgroupParent = "/kubepods/aerolvm" }, req: runc, teeth: otherParent, rule: rootpolicy.RuleCgroup, setup: func(t *testing.T, _ *conformanceRig) {
			fakeOOMTree(t, map[string][]int{"kubepods/aerolvm/sb-conf": nil}, nil)
		}},
		{name: "gvisor cgroup parent", cfg: func(c *Config) { c.CgroupParent = "/kubepods/aerolvm" }, req: gvisor, teeth: otherParent, rule: rootpolicy.RuleCgroup, setup: func(t *testing.T, _ *conformanceRig) {
			fakeOOMTree(t, map[string][]int{"kubepods/aerolvm/sb-conf": nil}, nil)
		}},
		{name: "gvisor restore from a move", req: gvisor, restore: true, teeth: func(p *rootpolicy.Policy) { p.MovesDir = "/var/lib/elsewhere" }, rule: rootpolicy.RuleCheckpoint},
		{name: "runc warm pool park", cfg: readySocket, req: runc, park: true, teeth: keepRoots(2), rule: rootpolicy.RuleMount},
		{name: "gvisor warm pool park", cfg: readySocket, req: gvisor, park: true, teeth: noRunscConfig, rule: rootpolicy.RuleRuntimeOptions},
		{name: "gvisor warm pool park with cgroup parent", cfg: func(c *Config) {
			readySocket(c)
			c.CgroupParent = "/kubepods/aerolvm"
		}, req: gvisor, park: true, teeth: otherParent, rule: rootpolicy.RuleCgroup, setup: func(t *testing.T, _ *conformanceRig) {
			fakeOOMTree(t, map[string][]int{"kubepods/aerolvm/park-conf": nil}, nil)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newConformanceRig(t, c.cfg)
			if c.cfg != nil && !r.d.cfg.NativeNetnsPool {
				r.d.SetNetnsHandoff(nil)
			}
			if c.setup != nil {
				c.setup(t, r)
			}
			ctx := context.Background()
			switch {
			case c.park:
				if _, err := r.d.parkContainer(ctx, "park-conf", containerdpool.Key{Image: c.req.Image, Runtime: c.req.Runtime}); err != nil {
					t.Fatalf("park: %v", err)
				}
			default:
				if c.restore {
					ctx = sbruntime.WithRestore(ctx)
					dir := mustMoveDir(t, r.d, moveIn, "sb-conf")
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, runscwrap.CheckpointFile), []byte("x"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				var binds []mounts.ContainerBind
				if c.binds != nil {
					binds = c.binds(r)
				}
				if _, err := r.d.Create(ctx, c.req, "sb-conf", "tok", binds); err != nil {
					t.Fatalf("create: %v", err)
				}
			}
			made := r.containers()
			if len(made) != 1 {
				t.Fatalf("the driver made %d containers, want 1", len(made))
			}
			p := r.policy()
			if err := rootpolicy.CheckContainer(p, policyContainer(made[0])); err != nil {
				t.Fatalf("the gate would refuse the driver's own container (%s): %v", rootpolicy.RuleOf(err), err)
			}
			c.teeth(&p)
			err := rootpolicy.CheckContainer(p, policyContainer(made[0]))
			if got := rootpolicy.RuleOf(err); got != c.rule {
				t.Fatalf("narrowed policy: rule %q (%v), want %q", got, err, c.rule)
			}
		})
	}
}

// TestPrivilegedBuilderOutputNeedsThePolicy: with SB_CONTAINER_PRIVILEGED
// the builder skips the envelope, and the gate lets that through only when
// its own config says so. Nothing in the request can.
func TestPrivilegedBuilderOutputNeedsThePolicy(t *testing.T) {
	r := newConformanceRig(t, func(c *Config) { c.Privileged = true })
	req := models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker, ContainerCommand: []string{"sleep", "inf"},
		CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB}
	if _, err := r.d.Create(context.Background(), req, "sb-priv", "tok", nil); err != nil {
		t.Fatal(err)
	}
	made := policyContainer(r.containers()[0])
	p := r.policy()
	if err := rootpolicy.CheckContainer(p, made); err != nil {
		t.Fatalf("privileged policy refused the privileged builder output: %v", err)
	}
	p.Privileged = false
	err := rootpolicy.CheckContainer(p, made)
	if got := rootpolicy.RuleOf(err); got == "" {
		t.Fatal("a non-privileged policy let the privileged builder output through")
	}
}

// TestLimitsOffBuilderOutputRefused: the gate fails closed on resources, so
// SB_RESOURCE_LIMITS_OFF, which builds a spec with no limits, cannot run
// behind it. Split mode needs limits on.
func TestLimitsOffBuilderOutputRefused(t *testing.T) {
	r := newConformanceRig(t, func(c *Config) { c.ResourceLimitsOff = true })
	req := models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeDocker, ContainerCommand: []string{"sleep", "inf"},
		CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB}
	if _, err := r.d.Create(context.Background(), req, "sb-nolim", "tok", nil); err != nil {
		t.Fatal(err)
	}
	err := rootpolicy.CheckContainer(r.policy(), policyContainer(r.containers()[0]))
	if got := rootpolicy.RuleOf(err); got != rootpolicy.RuleResources {
		t.Fatalf("rule %q (%v), want %q", got, err, rootpolicy.RuleResources)
	}
}
