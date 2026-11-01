package containerd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// restartRig is a containerd driver over the fake transport that models what
// a warm-pool restart depends on: each container keeps the OCI spec it was
// created with, every task start fails (as runc does) when a bind mount in
// that spec names a host path that is gone, and every task start runs a
// guest that plays toolboxd: a parked spec dials its park socket, sends the
// parked hello and waits to be adopted, as the real agent does.
type restartRig struct {
	t   *testing.T
	tr  *fakeTransport
	d   *Driver
	cfg Config

	mu      sync.Mutex
	pending *specs.Spec
	adopted []readyproto.AdoptFrame
	// silent guests never say hello (a toolbox that cannot boot).
	silent bool
}

func newRestartRig(t *testing.T) *restartRig {
	t.Helper()
	stubToolboxProbe(t)
	provider, img := newTestImageProvider(t)
	r := &restartRig{t: t, tr: newFakeTransport()}
	r.tr.provider = provider
	r.tr.image = img
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	r.cfg = Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		ReadyEnabled:       true,
		ReadyDir:           shortReadyDir(t),
		NativeNetnsPool:    true,
	}
	r.d = r.newDriver()

	origSpec := withNewSpec
	withNewSpec = func(opts ...oci.SpecOpts) cntr.NewContainerOpts {
		spec := &specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}}, Linux: &specs.Linux{}}
		for _, o := range opts {
			func() {
				defer func() { _ = recover() }() // WithImageConfig needs a live content store
				_ = o(context.Background(), nil, &containers.Container{}, spec)
			}()
		}
		r.mu.Lock()
		r.pending = spec
		r.mu.Unlock()
		return func(context.Context, *cntr.Client, *containers.Container) error { return nil }
	}
	r.tr.newContainerFn = r.newContainer
	origGrace, origPoll := stopGraceTimeout, stopPollInterval
	stopGraceTimeout, stopPollInterval = 20*time.Millisecond, 5*time.Millisecond
	// The guest only plays the parked handshake; a cold create's ready wait
	// is not what these tests are about.
	origReady := createReadyWaitFn
	createReadyWaitFn = func(context.Context, *dockerpkg.ReadyListener) error { return nil }
	t.Cleanup(func() {
		withNewSpec = origSpec
		stopGraceTimeout, stopPollInterval = origGrace, origPoll
		createReadyWaitFn = origReady
	})
	return r
}

// newDriver is a sandboxd process: a fresh driver over the same containerd.
func (r *restartRig) newDriver() *Driver {
	d := New(r.cfg, nil, nil)
	d.SetClient(NewTestClient("aerolvm", r.tr))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/sb", ip: "10.88.0.9"})
	return d
}

func (r *restartRig) newContainer(_ context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
	rec := &containers.Container{ID: id}
	for _, o := range opts {
		func() {
			defer func() { _ = recover() }() // WithNewSnapshot needs a live client
			_ = o(context.Background(), nil, rec)
		}()
	}
	r.mu.Lock()
	spec := r.pending
	r.mu.Unlock()
	r.tr.mu.Lock()
	defer r.tr.mu.Unlock()
	if _, exists := r.tr.containers[id]; exists {
		return nil, errdefs.ErrAlreadyExists
	}
	labels := map[string]string{}
	for k, v := range rec.Labels {
		labels[k] = v
	}
	c := &fakeContainer{id: id, labels: labels, specOverride: spec, mountCheck: true, onTaskStart: r.guest}
	c.onDelete = func() {
		r.tr.mu.Lock()
		delete(r.tr.containers, id)
		r.tr.mu.Unlock()
	}
	r.tr.containers[id] = c
	return c, nil
}

// guest plays a container's toolboxd at task start.
func (r *restartRig) guest(spec *specs.Spec) {
	var token, nonce, socket string
	parked := false
	for _, kv := range spec.Process.Env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "SB_POOL_PARKED":
			parked = v == "1"
		case "SB_TOOLBOX_TOKEN":
			token = v
		case "SB_READY_NONCE":
			nonce = v
		}
	}
	for _, m := range spec.Mounts {
		if m.Destination == dockerpkg.GuestReadySocketPath {
			socket = m.Source
		}
	}
	r.mu.Lock()
	silent := r.silent
	r.mu.Unlock()
	if !parked || socket == "" || silent {
		return
	}
	var conn net.Conn
	var err error
	for range 200 {
		if conn, err = net.Dial("unix", socket); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		return
	}
	defer conn.Close()
	if readyproto.EncodeParked(conn, readyproto.ParkedSignal{Event: readyproto.EventParked, Token: token, Nonce: nonce}) != nil {
		return
	}
	frame, err := readyproto.DecodeAdopt(bufio.NewReader(conn))
	if err != nil {
		return
	}
	r.mu.Lock()
	r.adopted = append(r.adopted, frame)
	r.mu.Unlock()
	_ = readyproto.Encode(conn, readyproto.ReadySignal{Event: readyproto.EventReady, SandboxID: frame.SandboxID, Token: frame.Token, Nonce: frame.Nonce})
}

func (r *restartRig) lastAdopt() readyproto.AdoptFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.adopted) == 0 {
		return readyproto.AdoptFrame{}
	}
	return r.adopted[len(r.adopted)-1]
}

// park parks a slot and loads it into a fresh pool on the rig's driver.
func (r *restartRig) park(slotID string) *containerdpool.ParkedSlot {
	r.t.Helper()
	key := containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeDocker}
	slot, err := (&PoolSpawner{Driver: r.d}).Park(context.Background(), slotID, key)
	if err != nil {
		r.t.Fatalf("park %s: %v", slotID, err)
	}
	return slot
}

// adopt parks slotID and creates sandboxID from it.
func (r *restartRig) adopt(slotID, sandboxID, token string) *models.SandboxRuntimeState {
	r.t.Helper()
	slot := r.park(slotID)
	pool := containerdpool.New(nil)
	pool.RecordLoaded(slot)
	r.d.SetWarmPool(pool)
	defer r.d.SetWarmPool(nil)
	state, err := r.d.Create(context.Background(), models.CreateSandboxRequest{Image: "cfg:test", Runtime: models.RuntimeDocker}, sandboxID, token, nil)
	if err != nil {
		r.t.Fatalf("create %s: %v", sandboxID, err)
	}
	if state.AdoptedParkID != slotID || state.ContainerID != slotID {
		r.t.Fatalf("create %s did not adopt %s: %+v", sandboxID, slotID, state)
	}
	if got := r.lastAdopt(); got.SandboxID != sandboxID || got.Token != token {
		r.t.Fatalf("adopt handed the toolbox %+v, want %s and its token", got, sandboxID)
	}
	return state
}

// startAgain starts a stopped sandbox the way the service does: with its
// identity when the driver takes one (looked up dynamically, so this file
// also shows the failure on a tree without it).
func startAgain(d *Driver, containerRef, sandboxID, token string) (*models.SandboxRuntimeState, error) {
	type identityStarter interface {
		StartWithIdentity(ctx context.Context, containerRef, sandboxID, toolboxToken string) (*models.SandboxRuntimeState, error)
	}
	if is, ok := any(d).(identityStarter); ok {
		return is.StartWithIdentity(context.Background(), containerRef, sandboxID, token)
	}
	return d.Start(context.Background(), containerRef)
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// The live failure (cluster-mixed-benchmark-with-obs, SB_CONTAINERD_POOL_ENABLED
// on): a sandbox adopted from the pool, stopped, could not start again —
// "open .../hosts/park-<id>/resolv.conf: no such file or directory" — because
// adoption renamed the park's host files away from the path the container's
// spec mounts. It must start again, and its toolboxd must be adopted again
// with the sandbox's own identity, or it boots parked and serves only 503s.
func TestWarmAdoptedSandboxStartsAgainAfterStop(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	r.adopt("park-r1", "sb-r1", "sandbox-token")

	if err := r.d.Stop(ctx, "park-r1"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	state, err := startAgain(r.d, "park-r1", "sb-r1", "sandbox-token")
	if err != nil {
		t.Fatalf("start of a stopped warm-adopted sandbox: %v", err)
	}
	if state.Status != models.SandboxStatusStarted || state.ContainerID != "park-r1" {
		t.Fatalf("state = %+v", state)
	}
	r.mu.Lock()
	n := len(r.adopted)
	r.mu.Unlock()
	if got := r.lastAdopt(); n != 2 || got.SandboxID != "sb-r1" || got.Token != "sandbox-token" || got.Nonce == "" {
		t.Fatalf("after the start the toolbox was adopted %d times, last with %+v; want twice, with the sandbox's identity", n, got)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.RunDir, "hosts", "park-r1", "resolv.conf")); err != nil {
		t.Fatalf("the container's resolv.conf left the path its spec mounts: %v", err)
	}

	// And again: each start takes its own handshake.
	if err := r.d.Stop(ctx, "park-r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := startAgain(r.d, "park-r1", "sb-r1", "sandbox-token"); err != nil {
		t.Fatalf("second start: %v", err)
	}
}

// A sandboxd restart: the driver is new, nothing of the park's listener is
// left in memory, and the boot sweep has removed every ready socket. The
// adopted sandbox still starts, from what its spec carries.
func TestWarmAdoptedSandboxStartsAfterSandboxdRestart(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	r.adopt("park-r2", "sb-r2", "tok-r2")
	if err := r.d.Stop(ctx, "park-r2"); err != nil {
		t.Fatal(err)
	}
	for _, name := range dirEntries(t, r.cfg.ReadyDir) {
		_ = os.Remove(filepath.Join(r.cfg.ReadyDir, name))
	}
	d2 := r.newDriver()
	if _, err := d2.StartWithIdentity(ctx, "park-r2", "sb-r2", "tok-r2"); err != nil {
		t.Fatalf("start after a sandboxd restart: %v", err)
	}
	if got := r.lastAdopt(); got.SandboxID != "sb-r2" || got.Token != "tok-r2" {
		t.Fatalf("adopted with %+v", got)
	}
	// A running adopted sandbox found by the new process is left alone.
	if _, err := d2.StartWithIdentity(ctx, "park-r2", "sb-r2", "tok-r2"); err != nil {
		t.Fatalf("start of a running sandbox: %v", err)
	}
	if err := d2.Destroy(ctx, &models.Sandbox{ID: "sb-r2", ContainerID: "park-r2"}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(r.cfg.RunDir, "hosts"), r.cfg.LogDir, r.cfg.ReadyDir} {
		if left := dirEntries(t, dir); len(left) > 0 {
			t.Fatalf("%s holds %v after the destroy", dir, left)
		}
	}
}

// Adoption closes the park's listener: its socket file is gone and nothing
// is left accepting on it, so a later start's listener is the only one.
func TestAdoptClosesTheParkListener(t *testing.T) {
	r := newRestartRig(t)
	r.adopt("park-r3", "sb-r3", "tok")
	if _, err := os.Stat(filepath.Join(r.cfg.ReadyDir, "park-r3.sock")); !os.IsNotExist(err) {
		t.Fatalf("park socket still on disk after adopt: %v", err)
	}
	if _, err := net.Dial("unix", filepath.Join(r.cfg.ReadyDir, "park-r3.sock")); err == nil {
		t.Fatal("something still accepts on the park socket after adopt")
	}
}

// A restarted pool container whose toolbox never says hello is not left
// running parked behind a start that failed: the task is killed and the
// start reports the re-adopt failure.
func TestStartWithIdentityFailsClosedWhenTheToolboxIsNotAdopted(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	r.adopt("park-r4", "sb-r4", "tok")
	if err := r.d.Stop(ctx, "park-r4"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.silent = true
	r.mu.Unlock()
	r.d.cfg.ToolboxWaitTimeout = 100 * time.Millisecond
	_, err := r.d.StartWithIdentity(ctx, "park-r4", "sb-r4", "tok")
	if err == nil || !strings.Contains(err.Error(), "re-adopt warm-pool container") {
		t.Fatalf("StartWithIdentity = %v, want a re-adopt failure", err)
	}
	c := r.tr.containers["park-r4"]
	if c.task.status != cntr.Stopped || c.task.killed == 0 {
		t.Fatalf("task after the failed start: status %v, kills %d; want killed and stopped", c.task.status, c.task.killed)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.ReadyDir, "park-r4.sock")); !os.IsNotExist(err) {
		t.Fatal("the start's park listener outlived it")
	}

	// The same start with a stubbed handshake error takes the same branch.
	orig := readoptParkedFn
	readoptParkedFn = func(context.Context, *dockerpkg.ParkedListener, string, string) error { return errors.New("boom") }
	t.Cleanup(func() { readoptParkedFn = orig })
	if _, err := r.d.StartWithIdentity(ctx, "park-r4", "sb-r4", "tok"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

// Start without an identity can't adopt a pool container's toolbox, so it
// refuses rather than leave it booted parked; a cold container is unaffected.
func TestStartWithoutIdentityRefusesAPoolContainer(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	r.adopt("park-r5", "sb-r5", "tok")
	if err := r.d.Stop(ctx, "park-r5"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.d.Start(ctx, "park-r5"); err == nil || !strings.Contains(err.Error(), "needs the sandbox's identity") {
		t.Fatalf("Start = %v, want a refusal", err)
	}

	if _, err := r.d.Create(ctx, models.CreateSandboxRequest{Image: "cfg:test", ContainerCommand: []string{"sleep"}}, "sb-cold", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Stop(ctx, "sb-cold"); err != nil {
		t.Fatal(err)
	}
	for _, start := range []func() error{
		func() error { _, err := r.d.Start(ctx, "sb-cold"); return err },
		func() error { _, err := r.d.StartWithIdentity(ctx, "sb-cold", "sb-cold", "tok"); return err },
	} {
		if err := start(); err != nil {
			t.Fatalf("cold restart: %v", err)
		}
		if err := r.d.Stop(ctx, "sb-cold"); err != nil {
			t.Fatal(err)
		}
	}
}

// Start fails before it creates a task when it can't read the container's
// spec, or can't put back the host files that spec mounts.
func TestStartTaskSpecAndHostFileErrors(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	tr.containers["sb-spec"] = &fakeContainer{id: "sb-spec", specErr: errors.New("spec gone")}
	resolv := filepath.Join(d.cfg.RunDir, "hosts", "sb-hosts", "resolv.conf")
	tr.containers["sb-hosts"] = &fakeContainer{id: "sb-hosts", specOverride: &specs.Spec{Mounts: []specs.Mount{
		{Type: "bind", Source: resolv, Destination: "/etc/resolv.conf"},
	}}}
	d.SetClient(NewTestClient("aerolvm", tr))
	if _, err := d.Start(context.Background(), "sb-spec"); err == nil || !strings.Contains(err.Error(), "spec gone") {
		t.Fatalf("err = %v", err)
	}
	if err := os.MkdirAll(d.cfg.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.cfg.RunDir, "hosts"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Start(context.Background(), "sb-hosts"); err == nil || !strings.Contains(err.Error(), "container host files") {
		t.Fatalf("err = %v", err)
	}
}

func TestParkedRestartListener(t *testing.T) {
	ready := shortReadyDir(t)
	d := &Driver{cfg: Config{ReadyDir: ready}}
	parkedEnv := []string{"SB_POOL_PARKED=1", "SB_TOOLBOX_TOKEN=boot", "SB_READY_NONCE=n1"}
	mount := func(src string) []specs.Mount {
		return []specs.Mount{{Type: "bind", Source: src, Destination: dockerpkg.GuestReadySocketPath}}
	}
	for _, tc := range []struct {
		name     string
		spec     *specs.Spec
		id, tok  string
		want     string // "" = a listener, "nil" = none, else an error substring
		readyDir string
	}{
		{name: "nil spec", spec: nil, want: "nil"},
		{name: "no process", spec: &specs.Spec{}, want: "nil"},
		{name: "cold container", spec: &specs.Spec{Process: &specs.Process{Env: []string{"SB_TOOLBOX_TOKEN=t"}}, Mounts: mount(filepath.Join(ready, "sb.n.sock"))}, want: "nil"},
		{name: "no identity", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}, Mounts: mount(filepath.Join(ready, "park-a.sock"))}, want: "needs the sandbox's identity"},
		{name: "no ready mount", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}}, id: "sb", tok: "t", want: "no park socket"},
		{name: "outside ready dir", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}, Mounts: mount("/etc/park-a.sock")}, id: "sb", tok: "t", want: "no park socket"},
		{name: "nested under ready dir", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}, Mounts: mount(filepath.Join(ready, "x", "park-a.sock"))}, id: "sb", tok: "t", want: "no park socket"},
		{name: "not a park name", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}, Mounts: mount(filepath.Join(ready, "sb-1.n.sock"))}, id: "sb", tok: "t", want: "no park socket"},
		{name: "bad id chars", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}, Mounts: mount(filepath.Join(ready, "park-a b.sock"))}, id: "sb", tok: "t", want: "no park socket"},
		{name: "no ready dir configured", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}, Mounts: mount(filepath.Join(ready, "park-a.sock"))}, id: "sb", tok: "t", want: "no park socket", readyDir: "-"},
		{name: "listens", spec: &specs.Spec{Process: &specs.Process{Env: parkedEnv}, Mounts: mount(filepath.Join(ready, "park-a.sock"))}, id: "sb", tok: "t", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.cfg.ReadyDir = ready
			if tc.readyDir == "-" {
				d.cfg.ReadyDir = ""
			}
			pl, err := d.parkedRestartListener(tc.spec, tc.id, tc.tok)
			switch tc.want {
			case "nil":
				if pl != nil || err != nil {
					t.Fatalf("= %v, %v; want none", pl, err)
				}
			case "":
				if err != nil || pl == nil || pl.HostSocketPath() != filepath.Join(ready, "park-a.sock") {
					t.Fatalf("= %v, %v", pl, err)
				}
				_ = pl.Close()
			default:
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("err = %v, want %q", err, tc.want)
				}
			}
		})
	}
}

func TestEnsureSpecHostFiles(t *testing.T) {
	newD := func(t *testing.T) (*Driver, string) {
		run := t.TempDir()
		return &Driver{cfg: Config{RunDir: run}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, run
	}
	specFor := func(run, owner string) *specs.Spec {
		dir := filepath.Join(run, "hosts", owner)
		return &specs.Spec{Mounts: []specs.Mount{
			{Type: "bind", Source: "/opt/toolboxd", Destination: "/.aerol/toolboxd"},
			{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
			{Type: "bind", Source: filepath.Join(dir, "resolv.conf"), Destination: "/etc/resolv.conf"},
			{Type: "bind", Source: filepath.Join(dir, "hosts"), Destination: "/etc/hosts"},
		}}
	}
	read := func(t *testing.T, p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("present files are left alone", func(t *testing.T) {
		d, run := newD(t)
		if _, err := prepareSandboxHostFiles(run, "park-p"); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(run, "hosts", "park-p", "resolv.conf")
		if err := os.WriteFile(marker, []byte("nameserver 192.0.2.53\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := d.ensureSpecHostFiles(specFor(run, "park-p"), "sb-p"); err != nil {
			t.Fatal(err)
		}
		if got := read(t, marker); got != "nameserver 192.0.2.53\n" {
			t.Fatalf("resolv.conf rewritten: %q", got)
		}
	})
	t.Run("a directory an older build renamed is moved back", func(t *testing.T) {
		d, run := newD(t)
		if _, err := prepareSandboxHostFiles(run, "sb-legacy"); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(run, "hosts", "sb-legacy", "resolv.conf")
		if err := os.WriteFile(marker, []byte("nameserver 192.0.2.54\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := d.ensureSpecHostFiles(specFor(run, "park-l"), "sb-legacy"); err != nil {
			t.Fatal(err)
		}
		if got := read(t, filepath.Join(run, "hosts", "park-l", "resolv.conf")); got != "nameserver 192.0.2.54\n" {
			t.Fatalf("moved-back resolv.conf = %q, want the park's own", got)
		}
		if _, err := os.Stat(filepath.Join(run, "hosts", "sb-legacy")); !os.IsNotExist(err) {
			t.Fatal("the renamed directory was copied, not moved")
		}
	})
	t.Run("missing files are generated for the container", func(t *testing.T) {
		d, run := newD(t)
		if err := d.ensureSpecHostFiles(specFor(run, "park-m"), ""); err != nil {
			t.Fatal(err)
		}
		if got := read(t, filepath.Join(run, "hosts", "park-m", "hostname")); got != "park-m\n" {
			t.Fatalf("hostname = %q, want the container id (its spec hostname)", got)
		}
		if read(t, filepath.Join(run, "hosts", "park-m", "resolv.conf")) == "" {
			t.Fatal("empty resolv.conf")
		}
	})
	t.Run("only the hosts root, only valid ids, nil spec", func(t *testing.T) {
		d, run := newD(t)
		spec := &specs.Spec{Mounts: []specs.Mount{
			{Type: "bind", Source: filepath.Join(run, "elsewhere", "x", "resolv.conf"), Destination: "/etc/resolv.conf"},
			{Type: "bind", Source: filepath.Join(run, "hosts", "bad id", "resolv.conf"), Destination: "/etc/resolv.conf"},
		}}
		if err := d.ensureSpecHostFiles(spec, "sb"); err != nil {
			t.Fatal(err)
		}
		if left := dirEntries(t, filepath.Join(run, "hosts")); len(left) > 0 {
			t.Fatalf("created %v for mounts it doesn't own", left)
		}
		if err := d.ensureSpecHostFiles(nil, "sb"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("an unwritable run dir fails the start", func(t *testing.T) {
		d, run := newD(t)
		if err := os.WriteFile(filepath.Join(run, "hosts"), nil, 0o644); err != nil { // a file where the dir goes
			t.Fatal(err)
		}
		if err := d.ensureSpecHostFiles(specFor(run, "park-u"), ""); err == nil {
			t.Fatal("want an error")
		}
	})
}

// Destroy removes every file a sandbox's container keeps under its id:
// the park id for an adopted one (host files, task log, park socket), and
// the sandbox id (which also covers files an older build renamed to it).
func TestDestroyRemovesTheContainersFiles(t *testing.T) {
	d := newTestDriver(t)
	d.cfg.ReadyDir = shortReadyDir(t)
	for _, key := range []string{"park-d1", "sb-d1"} {
		if _, err := prepareSandboxHostFiles(d.cfg.RunDir, key); err != nil {
			t.Fatal(err)
		}
		logPath, err := d.taskLogPath(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(logPath, []byte("log"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d.cfg.ReadyDir, "park-d1.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-d1", ContainerID: "park-d1"}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(d.cfg.RunDir, "hosts"), d.cfg.LogDir, d.cfg.ReadyDir} {
		if left := dirEntries(t, dir); len(left) > 0 {
			t.Fatalf("%s holds %v after the destroy", dir, left)
		}
	}
}

// A container id that isn't a valid id builds no path.
func TestRemoveContainerFilesRefusesBadKeys(t *testing.T) {
	d := newTestDriver(t)
	keep := filepath.Join(d.cfg.RunDir, "keep")
	if err := os.MkdirAll(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"", "  ", "../keep", "..", "a/b"} {
		d.removeContainerFiles(key)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-x", ContainerID: "../keep"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("a bad key reached the filesystem: %v", err)
	}
}

// Churn: parks adopted, restarted and destroyed; parks torn down unadopted;
// parks left by a crashed process and purged at boot. Nothing keyed by a
// container may outlive it: no host-files directory, task log or socket.
func TestWarmPoolChurnLeavesNoContainerFiles(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	const cycles = 20
	for i := range cycles {
		parkID, sbID := fmt.Sprintf("park-c%02d", i), fmt.Sprintf("sb-c%02d", i)
		r.adopt(parkID, sbID, "tok")
		if err := r.d.Stop(ctx, parkID); err != nil {
			t.Fatal(err)
		}
		if _, err := r.d.StartWithIdentity(ctx, parkID, sbID, "tok"); err != nil {
			t.Fatalf("cycle %d start: %v", i, err)
		}
		if err := r.d.Destroy(ctx, &models.Sandbox{ID: sbID, ContainerID: parkID}); err != nil {
			t.Fatal(err)
		}

		// A slot evicted, reaped or drained unadopted.
		slot := r.park(fmt.Sprintf("park-e%02d", i))
		if err := (&PoolSpawner{Driver: r.d}).DestroyParked(ctx, slot); err != nil {
			t.Fatal(err)
		}

		// A slot whose sandboxd died: its listener goes with the process
		// (the socket file stays), and the next boot purges by container id.
		crashed := r.park(fmt.Sprintf("park-x%02d", i))
		_ = crashed.Handle.Close()
		if err := os.WriteFile(filepath.Join(r.cfg.ReadyDir, crashed.ID+".sock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		r.d = r.newDriver()
		if n, err := r.d.PurgeParkedContainers(ctx); err != nil || n != 1 {
			t.Fatalf("cycle %d purge = %d, %v; want the one parked container", i, n, err)
		}
	}
	for _, dir := range []string{filepath.Join(r.cfg.RunDir, "hosts"), r.cfg.LogDir, r.cfg.ReadyDir} {
		if left := dirEntries(t, dir); len(left) > 0 {
			t.Fatalf("after %d cycles %s holds %v", cycles, dir, left)
		}
	}
	if n := len(r.tr.containers); n != 0 {
		t.Fatalf("%d containers left", n)
	}
}

// Two starts of one stopped pool sandbox at once (a retried SDK call, the
// CLI's exec-starts-it racing a start): both succeed with the same state,
// and the agent is adopted once, not raced over one socket path.
func TestConcurrentStartsOfOneSandbox(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	r.adopt("park-cc", "sb-cc", "tok")
	if err := r.d.Stop(ctx, "park-cc"); err != nil {
		t.Fatal(err)
	}
	const n = 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	states := make([]*models.SandboxRuntimeState, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			states[i], errs[i] = r.d.StartWithIdentity(ctx, "park-cc", "sb-cc", "tok")
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || states[i].Status != models.SandboxStatusStarted || states[i].ContainerID != "park-cc" {
			t.Fatalf("start %d = %+v, %v", i, states[i], errs[i])
		}
	}
	r.mu.Lock()
	adopts := len(r.adopted)
	r.mu.Unlock()
	if adopts != 2 { // the create's, and one start's
		t.Fatalf("the agent was adopted %d times, want 2", adopts)
	}
	r.d.startMu.Lock()
	left := len(r.d.startLocks)
	r.d.startMu.Unlock()
	if left != 0 {
		t.Fatalf("%d start locks outlived their starts", left)
	}
}
