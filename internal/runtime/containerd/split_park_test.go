package containerd

import (
	"context"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// parkHelper is the root helper with container parts that also names park
// sockets (M1 PR 13), as the real one lays them out: <dir>/<slot>/
// ready.sock, beside the container's other files, and its toolbox and
// runsc config in folders of their own. Here that name is a link to the
// agent's socket, so a test's guest can dial it, and the files part makes
// every file it names, so runc's mount check (fakeContainer.mountCheck)
// finds them.
type parkHelper struct {
	*partsHelper
	agentReady     string
	toolbox, runsc string

	mu      sync.Mutex
	parks   []string
	parkErr error
	// answer, when set, is the path EnsureReadySocket answers.
	answer func(id string) string
}

func newParkHelper(t *testing.T, agentReady string) *parkHelper {
	t.Helper()
	// Short: a guest dials the link, and macOS caps a socket path at 104
	// bytes.
	base, err := os.MkdirTemp("/tmp", "ph")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	h := &parkHelper{partsHelper: &partsHelper{fakeHelper: &fakeHelper{}, fakeParts: &fakeParts{dir: filepath.Join(base, "f")}}, agentReady: agentReady,
		toolbox: filepath.Join(base, "t", "toolboxd"), runsc: filepath.Join(base, "r", "config.toml")}
	for _, d := range []string{h.dir, filepath.Dir(h.toolbox), filepath.Dir(h.runsc)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(h.toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *parkHelper) PrepareSandbox(ctx context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	resp, err := h.fakeParts.PrepareSandbox(ctx, req)
	if err != nil {
		return nil, err
	}
	f := resp.GetFiles()
	if f != nil {
		f.ToolboxPath = h.toolbox
		if f.RunscConfigPath != "" {
			f.RunscConfigPath = h.runsc
		}
	}
	for _, p := range []string{f.GetHostnamePath(), f.GetHostsPath(), f.GetResolvConfPath()} {
		if p != "" {
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				return nil, err
			}
		}
	}
	return resp, nil
}

func (h *parkHelper) EnsureReadySocket(_ context.Context, id, nonce string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.parks = append(h.parks, id+"|"+nonce)
	if h.parkErr != nil {
		return "", h.parkErr
	}
	if nonce != "" {
		return "", errors.New("test helper: the warm pool names park sockets only")
	}
	dir := filepath.Join(h.dir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, rootpolicy.ParkSocketFile)
	_ = os.Remove(p)
	if err := os.Symlink(filepath.Join(h.agentReady, id+".sock"), p); err != nil {
		return "", err
	}
	if h.answer != nil {
		return h.answer(id), nil
	}
	return p, nil
}

func (h *parkHelper) asked() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.parks)
}

// splitRestartRig is restartRig in privilege mode split: its driver's root
// helper is a parkHelper, its snapshots are prepared by the agent
// (fakeSplitSnapshot), and its containers keep their snapshot key.
func splitRestartRig(t *testing.T) (*restartRig, *parkHelper, *fakeSplitSnapshot, *removedSnapshots) {
	t.Helper()
	noHostNaming(t)
	r := newRestartRig(t)
	h := newParkHelper(t, r.cfg.ReadyDir)
	snap, removed := &fakeSplitSnapshot{}, &removedSnapshots{}
	snap.install(t)
	removed.install(t)
	inner := r.tr.newContainerFn
	r.tr.newContainerFn = func(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
		c, err := inner(ctx, id, opts...)
		if err == nil {
			rec := &containers.Container{}
			for _, o := range opts {
				func() {
					defer func() { _ = recover() }()
					_ = o(ctx, nil, rec)
				}()
			}
			c.(*fakeContainer).snapshotKey = rec.SnapshotKey
		}
		return c, err
	}
	r.d.SetRootHelper(h)
	return r, h, snap, removed
}

func mountsByDest(s *specs.Spec) map[string]specs.Mount {
	out := map[string]specs.Mount{}
	for _, m := range s.Mounts {
		out[m.Destination] = m
	}
	return out
}

// TestSplitParkMakesTheSlotThroughTheHelper (M1 PR 13): a split park is a
// split create's one helper call (the files, with no ready nonce, and the
// image's user) plus the helper's name for the slot's park socket, and the
// slot's spec takes everything root opens from the helper: its host files,
// toolbox, runsc config and its park socket's name, bound read-only. The
// agent writes no host file and binds the park socket in its own folder.
func TestSplitParkMakesTheSlotThroughTheHelper(t *testing.T) {
	for _, tc := range []struct {
		runtime string
		runsc   rootdpb.RunscConfig
	}{
		{models.RuntimeDocker, rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED},
		{models.RuntimeGvisor, rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT},
	} {
		t.Run(tc.runtime, func(t *testing.T) {
			r, h, snap, _ := splitRestartRig(t)
			slot, err := (&PoolSpawner{Driver: r.d}).Park(context.Background(), "park-s1", containerdpool.Key{Image: "cfg:test", Runtime: tc.runtime})
			if err != nil {
				t.Fatal(err)
			}
			want := &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles, rootdpb.PartImageUser}, ContainerId: "park-s1",
				Setup: &rootdpb.ContainerSetup{Naming: &rootdpb.HostNaming{Hostname: "park-s1", Hosts: localhostEntries, Nameservers: []string{"10.0.0.2"}},
					TaskFifos: true, RunscConfig: tc.runsc, Toolbox: true},
				ImageUser: &rootdpb.ImageUser{}}
			if len(h.prepares) != 1 || !proto.Equal(h.prepares[0], want) {
				t.Fatalf("asked %v, want %v", h.prepares, want)
			}
			if got := h.asked(); !slices.Equal(got, []string{"park-s1|"}) {
				t.Fatalf("park sockets asked %v", got)
			}
			if !slices.Equal(snap.prepared, []string{"park-s1"}) || snap.ended != 1 {
				t.Fatalf("snapshots %v, leases ended %d", snap.prepared, snap.ended)
			}
			r.mu.Lock()
			spec := r.pending
			r.mu.Unlock()
			byDest := mountsByDest(spec)
			if m := byDest[dockerpkg.GuestReadySocketPath]; m.Source != filepath.Join(h.dir, "park-s1", rootpolicy.ParkSocketFile) || !slices.Contains(m.Options, "ro") {
				t.Fatalf("park socket bound as %+v", m)
			}
			if m := byDest[r.cfg.ToolboxMountPath]; m.Source != h.toolbox {
				t.Fatalf("toolbox bound from %q", m.Source)
			}
			if m := byDest["/etc/resolv.conf"]; m.Source != filepath.Join(h.dir, "park-s1", "resolv.conf") {
				t.Fatalf("resolv.conf bound from %q", m.Source)
			}
			if u := spec.Process.User; u.UID != 1000 || u.GID != 1000 {
				t.Fatalf("user %+v, want the helper's answer", u)
			}
			if _, err := os.Stat(filepath.Join(r.cfg.RunDir, "hosts")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a split park wrote host files of its own: %v", err)
			}
			if fi, err := os.Stat(filepath.Join(r.cfg.ReadyDir, "park-s1.sock")); err != nil || fi.Mode()&os.ModeSocket == 0 {
				t.Fatalf("the agent's park socket: %v %v", fi, err)
			}
			if slot.ContainerIP != "10.88.0.9" || slot.Handle == nil {
				t.Fatalf("slot %+v", slot)
			}
			// The same image again: the agent's cache answers its user.
			if _, err := (&PoolSpawner{Driver: r.d}).Park(context.Background(), "park-s2", containerdpool.Key{Image: "cfg:test", Runtime: tc.runtime}); err != nil {
				t.Fatal(err)
			}
			if got := h.prepares[1].GetParts(); !slices.Equal(got, []string{rootdpb.PartFiles}) {
				t.Fatalf("second park asked %v", got)
			}
		})
	}
}

// TestSplitParkPassesTheGate: the split park's container, as containerd
// stores it, passes the checks the helper's gate runs on it with the
// helper's own folders as its file roots, and the park socket's bind is
// what the rule for the helper's files checks.
func TestSplitParkPassesTheGate(t *testing.T) {
	for _, runtime := range []string{models.RuntimeDocker, models.RuntimeGvisor} {
		t.Run(runtime, func(t *testing.T) {
			noHostNaming(t)
			r := newConformanceRig(t, func(c *Config) { c.ReadyEnabled, c.ReadyDir = true, shortReadyDir(t) })
			h := newParkHelper(t, r.d.cfg.ReadyDir)
			(&fakeSplitSnapshot{}).install(t)
			(&removedSnapshots{}).install(t)
			r.d.SetRootHelper(h)
			if _, err := r.d.parkContainer(context.Background(), "park-conf", containerdpool.Key{Image: "alpine:3.20", Runtime: runtime}); err != nil {
				t.Fatalf("park: %v", err)
			}
			made := r.containers()
			if len(made) != 1 {
				t.Fatalf("made %d containers", len(made))
			}
			p := r.policy()
			p.HelperFileRoots = []string{h.dir}
			p.BindFiles = []string{h.toolbox}
			p.BindRoots = []string{r.mountsRoot()}
			p.RunscConfigPaths = []string{h.runsc}
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			if err := rootpolicy.CheckContainer(p, policyContainer(made[0])); err != nil {
				t.Fatalf("the gate would refuse the split park (%s): %v", rootpolicy.RuleOf(err), err)
			}
			p.HelperFileRoots = nil
			if got := rootpolicy.RuleOf(rootpolicy.CheckContainer(p, policyContainer(made[0]))); got != rootpolicy.RuleMount {
				t.Fatalf("with no helper file roots: rule %q, want %q", got, rootpolicy.RuleMount)
			}
		})
	}
}

// TestSplitParkUndo: a split park that fails at any step leaves nothing of
// its own: the helper's files (and with them its name for the park socket)
// are released, the snapshot is removed while no container holds it, the
// snapshot's lease ends, and the agent's park socket goes.
func TestSplitParkUndo(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*restartRig, *parkHelper)
		want string
		// removed: the snapshot had no container yet.
		removed bool
	}{
		{"the park socket is refused", func(_ *restartRig, h *parkHelper) {
			h.parkErr = errors.New("root helper refused the call (not_agent_socket)")
		}, "not_agent_socket", true},
		{"the helper names another slot's socket", func(_ *restartRig, h *parkHelper) {
			h.answer = func(string) string { return filepath.Join(h.dir, "park-other", rootpolicy.ParkSocketFile) }
		}, "not slot park-u1's park socket", true},
		{"the helper names a file that is no park socket", func(_ *restartRig, h *parkHelper) {
			h.answer = func(id string) string { return filepath.Join(h.dir, id, "ab12.sock") }
		}, "not slot park-u1's park socket", true},
		{"the files part fails", func(_ *restartRig, h *parkHelper) { h.prepareErr = errors.New("disk full") }, "disk full", true},
		{"the container cannot be made", func(r *restartRig, _ *parkHelper) {
			r.tr.newContainerFn = func(context.Context, string, ...cntr.NewContainerOpts) (cntr.Container, error) {
				return nil, errors.New("gate refused the call (mount)")
			}
		}, "park create", true},
		{"the task cannot start", func(r *restartRig, _ *parkHelper) {
			inner := r.tr.newContainerFn
			r.tr.newContainerFn = func(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
				c, err := inner(ctx, id, opts...)
				if err == nil {
					c.(*fakeContainer).newTaskErr = errors.New("runc: no such file")
				}
				return c, err
			}
		}, "park task", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, h, snap, removed := splitRestartRig(t)
			tc.set(r, h)
			netns := &harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"}
			r.d.SetNetnsHandoff(netns)
			_, err := (&PoolSpawner{Driver: r.d}).Park(context.Background(), "park-u1", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeDocker})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if !slices.Equal(h.released(), []string{"park-u1"}) || snap.ended != 1 || !netns.released {
				t.Fatalf("released %v, leases ended %d, netns released %v", h.released(), snap.ended, netns.released)
			}
			if got := slices.Equal(removed.keys, []string{"park-u1"}); got != tc.removed {
				t.Fatalf("removed snapshots %v, want removed=%v", removed.keys, tc.removed)
			}
			if _, err := os.Stat(filepath.Join(r.cfg.ReadyDir, "park-u1.sock")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the agent's park socket stayed: %v", err)
			}
		})
	}
	t.Run("a helper with no park socket call", func(t *testing.T) {
		r, h, _, _ := splitRestartRig(t)
		r.d.SetRootHelper(h.partsHelper)
		_, err := (&PoolSpawner{Driver: r.d}).Park(context.Background(), "park-u2", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeDocker})
		if err == nil || !strings.Contains(err.Error(), "EnsureReadySocket") {
			t.Fatalf("err %v", err)
		}
		if !slices.Equal(h.released(), []string{"park-u2"}) {
			t.Fatalf("released %v", h.released())
		}
	})
}

// TestSplitWarmClaimRestartAndTeardown: a split warm claim carries the env
// in the adopt frame on the agent's own socket and asks the helper only
// for the request's disk limit (its disk_quota part, alone, as a
// resize's); a start of the adopted container binds the park socket again
// and has the helper make the container's files and name the socket
// again, and the toolbox is adopted again with the env; a teardown
// releases the helper's files by both keys.
func TestSplitWarmClaimRestartAndTeardown(t *testing.T) {
	r, h, _, _ := splitRestartRig(t)
	r.d.cfg.DiskQuota = true
	q := &recordingQuota{}
	installQuota(t, q)
	ctx := context.Background()
	slot := r.park("park-c1")
	pool := containerdpool.New(nil)
	pool.RecordLoaded(slot)
	r.d.SetWarmPool(pool)
	env := map[string]string{"GREETING": "hello"}
	// The claim reads containerd once, a list: it loads no container
	// (splitClaimRead).
	var loaded []string
	r.tr.loadContainerFn = func(_ context.Context, id string) (cntr.Container, error) {
		loaded = append(loaded, id)
		r.tr.mu.Lock()
		defer r.tr.mu.Unlock()
		if c, ok := r.tr.containers[id]; ok {
			return c, nil
		}
		return nil, errdefs.ErrNotFound
	}
	state, err := r.d.Create(ctx, models.CreateSandboxRequest{Image: "cfg:test", Runtime: models.RuntimeDocker, Env: env, DiskGB: 4}, "sb-c1", "sb-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 0 {
		t.Fatalf("the split claim loaded %v", loaded)
	}
	r.tr.loadContainerFn = nil
	r.d.SetWarmPool(nil)
	if state.AdoptedParkID != "park-c1" || state.ContainerID != "park-c1" {
		t.Fatalf("state %+v", state)
	}
	if got := r.lastAdopt(); got.SandboxID != "sb-c1" || got.Token != "sb-token" || got.Env["GREETING"] != "hello" {
		t.Fatalf("adopt frame %+v", got)
	}
	// The park's call, then the claim's disk limit alone; no quota of the
	// agent's own.
	if len(h.prepares) != 2 || !slices.Equal(h.prepares[1].GetParts(), []string{rootdpb.PartDiskQuota}) ||
		h.prepares[1].GetContainerId() != "park-c1" || h.prepares[1].GetDiskQuota().GetBytes() != 4<<30 || len(q.calls) != 0 {
		t.Fatalf("asked %v, own quota calls %v", h.prepares, q.calls)
	}

	if err := r.d.Stop(ctx, "park-c1"); err != nil {
		t.Fatal(err)
	}
	loader := &envLoader{env: env}
	if _, err := r.d.StartWithIdentityEnv(ctx, "park-c1", "sb-c1", "sb-token", loader.load); err != nil {
		t.Fatalf("start of a split warm-adopted sandbox: %v", err)
	}
	if got := r.lastAdopt(); got.SandboxID != "sb-c1" || got.Env["GREETING"] != "hello" {
		t.Fatalf("re-adopt frame %+v", got)
	}
	start := h.prepares[len(h.prepares)-1]
	if start.GetContainerId() != "park-c1" || !slices.Equal(start.GetParts(), []string{rootdpb.PartFiles}) || start.GetSetup().GetReadyNonce() != "" ||
		!start.GetSetup().GetTaskFifos() {
		t.Fatalf("the start asked %v", start)
	}
	if got := h.asked(); !slices.Equal(got, []string{"park-c1|", "park-c1|"}) {
		t.Fatalf("park sockets asked %v", got)
	}

	if err := r.d.Destroy(ctx, &models.Sandbox{ID: "sb-c1", ContainerID: "park-c1"}); err != nil {
		t.Fatal(err)
	}
	if got := h.released(); !slices.Contains(got, "sb-c1") || !slices.Contains(got, "park-c1") {
		t.Fatalf("released %v", got)
	}
	// A parked slot's teardown (an evict, the drain, the boot purge)
	// releases its helper files too.
	parked := r.park("park-c2")
	if err := r.d.destroyParked(ctx, parked); err != nil {
		t.Fatal(err)
	}
	if got := h.released(); got[len(got)-1] != "park-c2" {
		t.Fatalf("released %v", got)
	}
}

// TestSplitWarmRestartRefusesAMismatch: a split start of an adopted
// container whose helper answers another name for its park socket than its
// spec binds starts nothing.
func TestSplitWarmRestartRefusesAMismatch(t *testing.T) {
	r, h, _, _ := splitRestartRig(t)
	ctx := context.Background()
	r.adopt("park-m1", "sb-m1", "tok")
	if err := r.d.Stop(ctx, "park-m1"); err != nil {
		t.Fatal(err)
	}
	h.answer = func(string) string { return filepath.Join(h.dir, "park-zz", rootpolicy.ParkSocketFile) }
	if _, err := r.d.StartWithIdentity(ctx, "park-m1", "sb-m1", "tok"); err == nil || !strings.Contains(err.Error(), "not slot park-m1's park socket") {
		t.Fatalf("err %v", err)
	}
	h.answer = func(string) string { return filepath.Join(filepath.Dir(h.dir), "park-m1", rootpolicy.ParkSocketFile) }
	if _, err := r.d.StartWithIdentity(ctx, "park-m1", "sb-m1", "tok"); err == nil || !strings.Contains(err.Error(), "spec binds") {
		t.Fatalf("err %v", err)
	}
	h.answer, h.parkErr = nil, errors.New("unavailable")
	if _, err := r.d.StartWithIdentity(ctx, "park-m1", "sb-m1", "tok"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("err %v", err)
	}
	h.parkErr, h.prepareErr = nil, errors.New("files refused")
	if _, err := r.d.StartWithIdentity(ctx, "park-m1", "sb-m1", "tok"); err == nil || !strings.Contains(err.Error(), "files refused") {
		t.Fatalf("err %v", err)
	}
}

// TestSplitParkedRestartListener: in split mode a start re-adopts over a
// park socket only when its spec binds the helper's name for the
// container's own slot.
func TestSplitParkedRestartListener(t *testing.T) {
	d := newTestDriver(t)
	ready := shortReadyDir(t)
	d.cfg.ReadyDir = ready
	d.SetRootHelper(&fakeHelper{})
	env := []string{"SB_POOL_PARKED=1", "SB_TOOLBOX_TOKEN=boot", "SB_READY_NONCE=ab12"}
	spec := func(source string) *specs.Spec {
		return &specs.Spec{Process: &specs.Process{Env: env}, Mounts: []specs.Mount{readyMountAt(source)}}
	}
	for _, tc := range []struct {
		name, source, ref, want string
	}{
		{"its own slot", "/run/aerolvm-rootd/ready/park-a/ready.sock", "park-a", ""},
		{"another slot's socket", "/run/aerolvm-rootd/ready/park-b/ready.sock", "park-a", "no park socket of its own"},
		{"a create's ready socket", "/run/aerolvm-rootd/ready/park-a/ab12.sock", "park-a", "no park socket of its own"},
		{"single mode's flat name", filepath.Join(ready, "park-a.sock"), "park-a", "no park socket of its own"},
		{"a slot name that is no slot", "/run/aerolvm-rootd/ready/sb-1/ready.sock", "sb-1", "no park socket of its own"},
		{"a slot name with a bad character", "/run/aerolvm-rootd/ready/park-a b/ready.sock", "park-a b", "no park socket of its own"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pl, err := d.parkedRestartListener(spec(tc.source), tc.ref, "sb-1", "tok")
			if tc.want == "" {
				if err != nil || pl == nil || pl.HostSocketPath() != filepath.Join(ready, tc.ref+".sock") {
					t.Fatalf("= %v, %v", pl, err)
				}
				_ = pl.Close()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	d.cfg.ReadyDir = ""
	if _, err := d.parkedRestartListener(spec("/run/aerolvm-rootd/ready/park-a/ready.sock"), "park-a", "sb-1", "tok"); err == nil {
		t.Fatal("no ready dir, yet a listener")
	}
}

// TestSplitParkSocketThroughTheRealHelper: the real helper, through the
// agent's real client, names the socket a park listener bound in the
// agent's ready folder in its own folder, as one more name for the same
// socket; and refuses, as a broken agent's, what is no socket of the
// agent's.
func TestSplitParkSocketThroughTheRealHelper(t *testing.T) {
	var agentReady, helperReady string
	client := startHelperWith(t, func(c *rootd.Config, _ *rootd.Options) {
		agentReady, helperReady = c.Files.AgentReady, c.Files.Ready
	})
	if err := os.MkdirAll(agentReady, 0o700); err != nil {
		t.Fatal(err)
	}
	d := newTestDriver(t)
	d.cfg.ReadyDir = agentReady
	d.SetRootHelper(&realParkHelper{fakeHelper: &fakeHelper{}, ParkSockets: client})
	pl, err := dockerpkg.NewParkedListener(agentReady, "park-r1", "boot", "ab12")
	if err != nil {
		t.Skipf("no socket in %s: %v", agentReady, err)
	}
	defer func() { _ = pl.Close() }()
	got, err := d.parkSocketName(context.Background(), "park-r1")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(helperReady, "park-r1", rootpolicy.ParkSocketFile) {
		t.Fatalf("named %q", got)
	}
	a, errA := os.Lstat(got)
	b, errB := os.Lstat(pl.HostSocketPath())
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		t.Fatalf("the helper's name is not the agent's socket: %v %v", errA, errB)
	}
	// A broken agent puts a plain file where its park socket goes.
	if err := os.WriteFile(filepath.Join(agentReady, "park-r2.sock"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.parkSocketName(context.Background(), "park-r2"); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("a plain file was named: %v", err)
	}
	// And a link to another socket.
	other := filepath.Join(agentReady, "x.sock")
	ln, err := net.Listen("unix", other)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Symlink(other, filepath.Join(agentReady, "park-r3.sock")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.parkSocketName(context.Background(), "park-r3"); err == nil {
		t.Fatal("a link was named")
	}
	// A hostile slot name never names a file.
	if _, err := d.parkSocketName(context.Background(), "../park-r1"); err == nil {
		t.Fatal("a slot name with ../ was named")
	}
}

// realParkHelper is a split helper whose park socket call is the real
// client's.
type realParkHelper struct {
	*fakeHelper
	ParkSockets
}

// TestSplitClaimReadsOnce: a split claim reads containerd once, a list,
// and gets single mode's answers from it for every shape of containerd's
// records: the claimed slot's record, and whether a container of the
// sandbox is there already. No container is loaded.
func TestSplitClaimReadsOnce(t *testing.T) {
	park := map[string]string{poolParkLabelKey: poolParkLabelValue}
	adopted := func(sb string) map[string]string { return map[string]string{sandboxIDLabelKey: sb} }
	slot := func(labels map[string]string) *fakeContainer {
		return &fakeContainer{id: "park-a", labels: labels, snapshotKey: "park-a"}
	}
	for _, tc := range []struct {
		name   string
		cs     []*fakeContainer
		exists bool
	}{
		{"only parked slots", []*fakeContainer{slot(park), {id: "park-c", labels: park}}, false},
		{"a cold container of the sandbox", []*fakeContainer{slot(park), {id: "sb-1", labels: adopted("sb-1")}}, true},
		{"a container named after it, unlabelled", []*fakeContainer{slot(park), {id: "sb-1"}}, true},
		{"a parked slot named after it", []*fakeContainer{slot(park), {id: "sb-1", labels: park}}, false},
		{"another slot adopted for it", []*fakeContainer{slot(park), {id: "park-b", labels: adopted("sb-1")}}, true},
		{"the claimed slot itself, adopted for it already", []*fakeContainer{slot(adopted("sb-1"))}, false},
		{"another sandbox's container", []*fakeContainer{slot(park), {id: "sb-2", labels: adopted("sb-2")}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newFakeTransport()
			for _, c := range tc.cs {
				tr.containers[c.id] = c
			}
			client := NewTestClient("aerolvm", tr)
			d := newTestDriver(t)
			single := d.assertSandboxNotExists(context.Background(), client, "sb-1", "park-a")
			want, err := loadClaimedSlot(context.Background(), client, "park-a")
			if err != nil {
				t.Fatal(err)
			}
			tr.loadContainerFn = func(context.Context, string) (cntr.Container, error) {
				t.Fatal("the split claim loaded a container")
				return nil, nil
			}
			read, err := splitClaimRead(context.Background(), client, "sb-1", "park-a")
			if err != nil {
				t.Fatal(err)
			}
			if (read.exists != nil) != tc.exists || (single != nil) != tc.exists {
				t.Fatalf("split %v, single %v; want exists=%v", read.exists, single, tc.exists)
			}
			if tc.exists && !errors.Is(read.exists, dockerpkg.ErrSandboxContainerExists) {
				t.Fatalf("split %v", read.exists)
			}
			if read.container.ID() != "park-a" || read.info.SnapshotKey != want.info.SnapshotKey || !maps.Equal(read.info.Labels, want.info.Labels) {
				t.Fatalf("split read the slot as %+v, single as %+v", read.info, want.info)
			}
		})
	}
	tr := newFakeTransport()
	client := NewTestClient("aerolvm", tr)
	if _, err := splitClaimRead(context.Background(), client, "sb-1", "park-a"); !errdefs.IsNotFound(err) {
		t.Fatalf("a slot containerd does not have: %v", err)
	}
	tr.listErr = errors.New("gate refused the call")
	if _, err := splitClaimRead(context.Background(), client, "sb-1", "park-a"); err == nil {
		t.Fatal("a failed list passed")
	}
	tr = newFakeTransport()
	tr.containers["park-a"] = &fakeContainer{id: "park-a", infoErr: errors.New("gone")}
	if _, err := splitClaimRead(context.Background(), NewTestClient("aerolvm", tr), "sb-1", "park-a"); err == nil {
		t.Fatal("an unreadable record passed")
	}
	if _, err := loadClaimedSlot(context.Background(), NewTestClient("aerolvm", tr), "park-a"); err == nil {
		t.Fatal("single mode's read of an unreadable record passed")
	}
}

// TestSplitClaimRefusesAnExistingSandbox: a split claim for a sandbox that
// has a container already adopts nothing, and says so.
func TestSplitClaimRefusesAnExistingSandbox(t *testing.T) {
	r, _, _, _ := splitRestartRig(t)
	slot := r.park("park-x1")
	r.tr.containers["sb-x1"] = &fakeContainer{id: "sb-x1", labels: map[string]string{sandboxIDLabelKey: "sb-x1"}}
	_, err := r.d.adoptParked(context.Background(), models.CreateSandboxRequest{Image: "cfg:test"}, "sb-x1", "tok", slot)
	if !errors.Is(err, dockerpkg.ErrSandboxContainerExists) {
		t.Fatalf("err %v", err)
	}
	if got := r.lastAdopt(); got.SandboxID != "" {
		t.Fatalf("the toolbox was adopted: %+v", got)
	}
	delete(r.tr.containers, "park-x1")
	if _, err := r.d.adoptParked(context.Background(), models.CreateSandboxRequest{Image: "cfg:test"}, "sb-x2", "tok", slot); !errdefs.IsNotFound(err) {
		t.Fatalf("a slot that is gone: %v", err)
	}
}

// claimFirewall is splitFirewall with a hook at the start of a lift and
// errors to give back; the relabel is recorded in the same list, so a test
// reads the order of both trips.
type claimFirewall struct {
	*splitFirewall
	onLift   func()
	liftErr  error
	blockErr error
}

func (f *claimFirewall) LiftBlockAllEgress(ip string) error {
	if f.onLift != nil {
		f.onLift()
	}
	_ = f.rec("lift %s", ip)
	return f.liftErr
}

func (f *claimFirewall) BlockAllEgress(ip string) error {
	_ = f.rec("block %s", ip)
	return f.blockErr
}

// ownerNetns records the netns slot owner moves a claim makes.
type ownerNetns struct {
	harnessNetns
	mu    sync.Mutex
	moves []string
}

func (n *ownerNetns) ReassignOwner(_ context.Context, from, to string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.moves = append(n.moves, from+">"+to)
	return nil
}

func (n *ownerNetns) moved() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.moves)
}

// claimHandle is a parked slot's handle that records the adopt frame.
type claimHandle struct {
	adopted atomic.Bool
	closed  atomic.Bool
}

func (h *claimHandle) Alive() bool { return !h.closed.Load() }
func (h *claimHandle) AdoptWithEnv(context.Context, string, string, string, map[string]string) error {
	h.adopted.Store(true)
	return nil
}
func (h *claimHandle) Adopt(ctx context.Context, sandboxID, token, nonce string) error {
	return h.AdoptWithEnv(ctx, sandboxID, token, nonce, nil)
}
func (h *claimHandle) Close() error { h.closed.Store(true); return nil }

const claimIP = "10.88.0.9"

// claimRig is a warm claim of slot park-a (claimIP) over the fake
// transport, in privilege mode split (split) or single.
type claimRig struct {
	d     *Driver
	tr    *fakeTransport
	c     *fakeContainer
	fw    *claimFirewall
	netns *ownerNetns
	h     *claimHandle
	slot  *containerdpool.ParkedSlot
}

func newClaimRig(t *testing.T, split bool) *claimRig {
	t.Helper()
	r := &claimRig{tr: newFakeTransport(), fw: &claimFirewall{splitFirewall: &splitFirewall{}}, h: &claimHandle{}}
	r.c = &fakeContainer{id: "park-a", labels: map[string]string{poolParkLabelKey: poolParkLabelValue}, snapshotKey: "park-a"}
	r.c.onDelete = func() {
		r.tr.mu.Lock()
		delete(r.tr.containers, "park-a")
		r.tr.mu.Unlock()
	}
	r.tr.containers["park-a"] = r.c
	r.d = newTestDriver(t)
	r.d.cfg.ReadyEnabled = true
	r.d.SetClient(NewTestClient("aerolvm", r.tr))
	r.netns = &ownerNetns{harnessNetns: harnessNetns{path: "/run/netns/sb", ip: claimIP}}
	r.d.SetNetnsHandoff(r.netns)
	r.d.SetHostFirewall(r.fw)
	if split {
		r.d.SetRootHelper(&fakeHelper{})
	}
	r.c.onSetLabels = func() { _ = r.fw.rec("relabel") }
	r.slot = &containerdpool.ParkedSlot{ID: "park-a", ContainerID: "park-a", ContainerIP: claimIP, Handle: r.h,
		Key: containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)}
	return r
}

// TestSplitClaimRelabelsAndPutsRulesOnAtOnce: a split claim's relabel
// (through the gate) and its rules (through the helper's firewall) are in
// flight at the same time, both after the toolbox took the sandbox's
// identity; the claim ends with both done and the netns slot moved to the
// sandbox. Each trip waits for the other to start: made one after the
// other, the first would wait out its bound.
func TestSplitClaimRelabelsAndPutsRulesOnAtOnce(t *testing.T) {
	r := newClaimRig(t, true)
	labelIn, liftIn := make(chan struct{}), make(chan struct{})
	waitFor := func(ch chan struct{}, what string) {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Errorf("%s did not start while the other trip was in flight", what)
		}
	}
	inner := r.c.onSetLabels
	r.c.onSetLabels = func() {
		if !r.h.adopted.Load() {
			t.Error("relabelled before the toolbox took the sandbox's identity")
		}
		inner()
		close(labelIn)
		waitFor(liftIn, "the rules trip")
	}
	r.fw.onLift = func() {
		if !r.h.adopted.Load() {
			t.Error("lifted the slot's block before the toolbox took the sandbox's identity")
		}
		close(liftIn)
		waitFor(labelIn, "the relabel")
	}
	state, err := r.d.adoptParked(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", r.slot)
	if err != nil {
		t.Fatal(err)
	}
	if state.SandboxID != "sb-a" || state.AdoptedParkID != "park-a" {
		t.Fatalf("state %+v", state)
	}
	if r.c.labels[sandboxIDLabelKey] != "sb-a" || r.c.labels[poolParkLabelKey] != "" {
		t.Fatalf("labels %v", r.c.labels)
	}
	if got := r.netns.moved(); !slices.Equal(got, []string{"park-a>sb-a"}) {
		t.Fatalf("netns moves %v", got)
	}
	if got := r.fw.recorded(); len(got) != 2 || !slices.Contains(got, "relabel") || !slices.Contains(got, "lift "+claimIP) {
		t.Fatalf("calls %v", got)
	}
}

// TestSplitClaimFailurePutsTheBlockBack: a split claim whose relabel or
// rules fail puts the slot's egress block back before it returns, after
// the rules trip has ended (a slow lift still comes first), so the slot is
// blocked whatever the rules trip did. The netns slot moves only once the
// relabel is in, as in single mode.
func TestSplitClaimFailurePutsTheBlockBack(t *testing.T) {
	relabelErr, liftErr := errors.New("gate refused the relabel"), errors.New("helper unavailable")
	for _, tc := range []struct {
		name               string
		req                models.CreateSandboxRequest
		label, lift, block error
		want               []string
		calls              []string
		moved              bool
	}{
		{name: "the relabel fails", label: relabelErr, want: []string{"gate refused the relabel"},
			calls: []string{"relabel", "lift " + claimIP, "block " + claimIP}},
		{name: "the lift fails", lift: liftErr, want: []string{"helper unavailable"},
			calls: []string{"relabel", "lift " + claimIP, "block " + claimIP}, moved: true},
		{name: "both fail", label: relabelErr, lift: liftErr, want: []string{"gate refused the relabel", "helper unavailable"},
			calls: []string{"relabel", "lift " + claimIP, "block " + claimIP}},
		{name: "the block cannot go back", label: relabelErr, block: errors.New("no helper"),
			want: []string{"gate refused the relabel", "put the slot's egress block back: no helper"}, calls: []string{"relabel", "lift " + claimIP, "block " + claimIP}},
		{name: "an egress policy", req: models.CreateSandboxRequest{NetworkAllowOut: []string{"1.2.3.4/32"}}, label: relabelErr,
			want: []string{"gate refused the relabel"}, calls: []string{"relabel", "policy " + claimIP + " [1.2.3.4/32] []", "lift " + claimIP, "block " + claimIP}},
		{name: "a block-all create", req: models.CreateSandboxRequest{NetworkBlockAll: true}, label: relabelErr,
			want: []string{"gate refused the relabel"}, calls: []string{"relabel", "block " + claimIP, "block " + claimIP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newClaimRig(t, true)
			r.c.setLabelsErr = tc.label
			r.fw.liftErr, r.fw.blockErr = tc.lift, tc.block
			// The rules trip ends after the relabel: the block that goes
			// back must still come after it.
			r.fw.onLift = func() { time.Sleep(30 * time.Millisecond) }
			req := tc.req
			req.Image = "alpine:3.20"
			_, err := r.d.adoptParked(context.Background(), req, "sb-a", "tok", r.slot)
			if err == nil {
				t.Fatal("the claim passed")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("err %q, want %q in it", err, w)
				}
			}
			if tc.label != nil && !errors.Is(err, tc.label) || tc.lift != nil && !errors.Is(err, tc.lift) {
				t.Fatalf("err %v does not wrap the trips' errors", err)
			}
			// The relabel and the rules trip run at once, so only these
			// orders are fixed: the rules in their own order, and the
			// block that goes back last of all.
			got := r.fw.recorded()
			if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(tc.calls))) || got[len(got)-1] != "block "+claimIP {
				t.Fatalf("calls %v, want %v with the block back last", got, tc.calls)
			}
			rules := slices.DeleteFunc(slices.Clone(got), func(c string) bool { return c == "relabel" })
			want := slices.DeleteFunc(slices.Clone(tc.calls), func(c string) bool { return c == "relabel" })
			if !slices.Equal(rules, want) {
				t.Fatalf("rule calls %v, want %v", rules, want)
			}
			if moved := len(r.netns.moved()) > 0; moved != tc.moved {
				t.Fatalf("netns moves %v, want moved=%v", r.netns.moved(), tc.moved)
			}
		})
	}
}

// TestSplitClaimFailureDestroysABlockedSlot: through the pool, a split
// claim that fails part way is destroyed with its block back on: the
// block goes back before the teardown, and the create goes cold. The
// teardown's clear is the slot's release in split (the helper clears every
// rule of the address, CreateRules.ClearsOnRelease), so the driver makes
// none of its own (give_back.go).
func TestSplitClaimFailureDestroysABlockedSlot(t *testing.T) {
	r := newClaimRig(t, true)
	pool := containerdpool.New(nil)
	pool.RecordLoaded(r.slot)
	r.d.SetWarmPool(pool)
	r.c.setLabelsErr = errors.New("gate refused the relabel")
	_, err := r.d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", nil, models.RuntimeDocker)
	if err == nil || !strings.Contains(err.Error(), "warm adopt failed") {
		t.Fatalf("err %v", err)
	}
	r.tr.mu.Lock()
	_, left := r.tr.containers["park-a"]
	r.tr.mu.Unlock()
	if left {
		t.Fatal("the slot was not destroyed")
	}
	got := r.fw.recorded()
	lift, block := slices.Index(got, "lift "+claimIP), slices.Index(got, "block "+claimIP)
	if lift < 0 || block < lift {
		t.Fatalf("calls %v: want the lift, then the block back", got)
	}
	for _, c := range got[block:] {
		if strings.HasPrefix(c, "clear-") {
			t.Fatalf("calls %v: the driver cleared %q itself; in split the slot's release does", got, c)
		}
	}
}

// TestSingleClaimRelabelsFirst: single mode's claim is as before: the
// relabel, then the rules, one after the other; a failed relabel makes no
// rule call (the slot's park block is still on) and puts nothing back.
func TestSingleClaimRelabelsFirst(t *testing.T) {
	r := newClaimRig(t, false)
	if _, err := r.d.adoptParked(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", r.slot); err != nil {
		t.Fatal(err)
	}
	if got := r.fw.recorded(); !slices.Equal(got, []string{"relabel", "lift " + claimIP}) {
		t.Fatalf("calls %v", got)
	}
	r = newClaimRig(t, false)
	r.c.setLabelsErr = errors.New("containerd unavailable")
	if _, err := r.d.adoptParked(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-a", "tok", r.slot); err == nil {
		t.Fatal("the claim passed")
	}
	if got := r.fw.recorded(); !slices.Equal(got, []string{"relabel"}) || len(r.netns.moved()) != 0 {
		t.Fatalf("calls %v, moves %v", got, r.netns.moved())
	}
}
