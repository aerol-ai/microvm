package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakePool is the minimal TapPool used by the Create integration tests.
// Records every call so we can assert the allocate-then-release sequence
// on the error path — the load-bearing cleanup contract.
type fakePool struct {
	mu        sync.Mutex
	slots     map[string]*TapSlot
	alloc     int
	release   int
	get       int
	nextErr   error // injected on next Allocate
	relErr    error // injected on next Release
	getErr    error // injected on next Get
	lastAlloc string
}

func newFakePool() *fakePool {
	return &fakePool{slots: map[string]*TapSlot{}}
}

func (p *fakePool) Allocate(_ context.Context, sandboxID string, _ time.Time) (*TapSlot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.alloc++
	if p.nextErr != nil {
		err := p.nextErr
		p.nextErr = nil
		return nil, err
	}
	slot := &TapSlot{
		TapName:  "fctap-test",
		CIDR:     "172.16.0.0/30",
		HostIP:   "172.16.0.1",
		GuestIP:  "172.16.0.2",
		VsockCID: 3,
	}
	p.slots[sandboxID] = slot
	p.lastAlloc = sandboxID
	return slot, nil
}

func (p *fakePool) Release(_ context.Context, sandboxID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.release++
	if p.relErr != nil {
		err := p.relErr
		p.relErr = nil
		return err
	}
	delete(p.slots, sandboxID)
	return nil
}

func (p *fakePool) Get(_ context.Context, sandboxID string) (*TapSlot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.get++
	if p.getErr != nil {
		err := p.getErr
		p.getErr = nil
		return nil, err
	}
	if s, ok := p.slots[sandboxID]; ok {
		return s, nil
	}
	return nil, nil
}

// fakeRootfs is a no-subprocess RootfsBuilder for tests. Touches the
// requested OutPath so the driver sees a file at the path it later
// passes to PutDrive; that's the only invariant Create depends on.
type fakeRootfs struct {
	mu         sync.Mutex
	builds     int
	cleanups   int
	nextErr    error
	lastOutput string
}

func (b *fakeRootfs) Build(_ context.Context, req RootfsBuildRequest) (*RootfsResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.builds++
	if b.nextErr != nil {
		err := b.nextErr
		b.nextErr = nil
		return nil, err
	}
	if err := os.WriteFile(req.OutPath, []byte("fake ext4"), 0o644); err != nil {
		return nil, err
	}
	b.lastOutput = req.OutPath
	return NewRootfsResult(req.OutPath, filepath.Dir(req.OutPath)+"-staging", 4096, func() error {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.cleanups++
		return nil
	}), nil
}

// fakeTapHost records Ensure/Remove calls. The pool's allocate-then-
// release contract has a host-side mirror: every successful Ensure on a
// Create error path must be followed by a Remove.
type fakeTapHost struct {
	mu          sync.Mutex
	ensureCalls int
	removeCalls int
	ensureErr   error
	removeErr   error
	lastTap     string
}

func (h *fakeTapHost) Ensure(_ context.Context, slot TapSlot) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ensureCalls++
	h.lastTap = slot.TapName
	if h.ensureErr != nil {
		err := h.ensureErr
		h.ensureErr = nil
		return err
	}
	return nil
}

func (h *fakeTapHost) Remove(_ context.Context, tapName string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.removeCalls++
	if h.removeErr != nil {
		err := h.removeErr
		h.removeErr = nil
		return err
	}
	_ = tapName
	return nil
}

// fakeVsockDialer returns an in-memory io.ReadWriteCloser pair seeded
// with the Ok response the toolbox would send. The dialer fakes the
// guest side of the protocol entirely.
type fakeVsockDialer struct {
	mu          sync.Mutex
	dials       int
	err         error
	guestRespOk bool
	guestError  string
	// lastCID captures the CID the driver dialed on the most recent
	// attempt. The snapshot-load path dials the template's reserved CID
	// rather than the per-sandbox slot CID; without this we can't tell
	// the driver actually routed the handshake to the right place.
	lastCID        uint32
	lastSocketPath string
	// retryUntil >0 means return err for the first `retryUntil-1` Dial
	// calls (simulating the post-InstanceStart race) and succeed on
	// the `retryUntil`th. Lets us assert the driver's retry loop.
	retryUntil int
	// writes records every line written through any returned conn, so
	// post_resume payload-shape assertions can grep the captured JSON.
	writes [][]byte
	// errOnDialIdx >0 makes Dial fail on the Nth call (1-based) only.
	// Post-boot/post-resume sends are best-effort, so tests use this
	// to assert Create does not fail when that follow-up dial fails.
	errOnDialIdx int
}

func newFakeVsockDialer() *fakeVsockDialer {
	return &fakeVsockDialer{guestRespOk: true}
}

func (d *fakeVsockDialer) Dial(_ context.Context, socketPath string, cid, _ uint32) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	d.dials++
	d.lastCID = cid
	d.lastSocketPath = socketPath
	if d.retryUntil > 0 && d.dials < d.retryUntil {
		d.mu.Unlock()
		return nil, errors.New("vsock: connection refused (fake)")
	}
	if d.errOnDialIdx > 0 && d.dials == d.errOnDialIdx {
		d.mu.Unlock()
		return nil, errors.New("vsock: dial fail (fake)")
	}
	if d.err != nil {
		d.mu.Unlock()
		return nil, d.err
	}
	rwc := newFakeVsockConn(d.guestRespOk, d.guestError)
	rwc.parent = d
	d.mu.Unlock()
	return rwc, nil
}

func (d *fakeVsockDialer) recordWrite(p []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	d.writes = append(d.writes, cp)
}

func (d *fakeVsockDialer) snapshotWrites() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.writes))
	copy(out, d.writes)
	return out
}

// fakeVsockConn is a one-shot connection that, on read, returns either
// {"ok":true} or {"error":"..."} followed by a newline. Mirrors the
// toolbox's response wire shape.
type fakeVsockConn struct {
	reply  []byte
	pos    int
	closed bool
	parent *fakeVsockDialer
}

func newFakeVsockConn(ok bool, errMsg string) *fakeVsockConn {
	if ok {
		return &fakeVsockConn{reply: []byte(`{"ok":true}` + "\n")}
	}
	return &fakeVsockConn{reply: []byte(`{"error":"` + errMsg + `"}` + "\n")}
}

func (c *fakeVsockConn) Read(p []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}
	if c.pos >= len(c.reply) {
		return 0, io.EOF
	}
	n := copy(p, c.reply[c.pos:])
	c.pos += n
	return n, nil
}

func (c *fakeVsockConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	if c.parent != nil {
		c.parent.recordWrite(p)
	}
	return len(p), nil
}

func (c *fakeVsockConn) Close() error { c.closed = true; return nil }

// fakeVMM is the test handle returned by the fake spawner. Records
// Start / WaitSocket / Shutdown / Cleanup so the test asserts ordering.
type fakeVMM struct {
	id          string
	runDir      string
	apiSocket   string
	pid         int
	startErr    error
	waitErr     error
	shutdownErr error
	cleanupErr  error

	started  bool
	waited   bool
	shutdown bool
	cleaned  bool
	stderrTl string
}

func (v *fakeVMM) APISocket() string             { return v.apiSocket }
func (v *fakeVMM) RunDir() string                { return v.runDir }
func (v *fakeVMM) Pid() int                      { return v.pid }
func (v *fakeVMM) StderrTail() string            { return v.stderrTl }
func (v *fakeVMM) Start(_ context.Context) error { v.started = true; return v.startErr }
func (v *fakeVMM) WaitSocket(_ context.Context, _ time.Duration) error {
	v.waited = true
	return v.waitErr
}
func (v *fakeVMM) Shutdown(_ context.Context, _ time.Duration) error {
	v.shutdown = true
	return v.shutdownErr
}
func (v *fakeVMM) Kill() error { v.shutdown = true; return nil }
func (v *fakeVMM) Cleanup() error {
	v.cleaned = true
	return v.cleanupErr
}

// fakeClient records every REST call. Returns whatever per-call error
// is injected; default is success on every method.
type fakeClient struct {
	mu sync.Mutex

	mc       *firecracker.MachineConfig
	bs       *firecracker.BootSource
	drives   map[string]firecracker.Drive
	nics     map[string]firecracker.NetworkInterface
	vsock    *firecracker.Vsock
	actions  []string
	vmStates []string
	instance *firecracker.InstanceInfo

	snapshotCreate   *firecracker.SnapshotCreate
	snapshotLoad     *firecracker.SnapshotLoad
	snapshotBase     string
	loadSnapshotHook func() error

	// drivePatches records each PatchDrive call (snapshot-load + overlay
	// path swap). Keyed by drive_id so a test can assert the post-load
	// backing path is the per-sandbox overlay file and not the template
	// placeholder.
	drivePatches   map[string]firecracker.DrivePatch
	networkPatches map[string]firecracker.NetworkInterfacePatch

	// restOrder captures every PUT / Action / PatchVM / Snapshot call in the order
	// the driver issued them. Order is load-bearing for firecracker:
	// machine-config + boot-source MUST land before drives + nics, and
	// CreateSnapshot is only valid after PATCH /vm Paused. The snapshot
	// test asserts the full sequence; the cold-boot tests usually just
	// assert end-state, but the slice is cheap and harmless to share.
	restOrder []string

	machineErr        error
	bootErr           error
	driveErr          error
	drivePatchErr     error
	networkPatchErr   error
	nicErr            error
	vsockErr          error
	actionErr         error
	patchVMErr        error
	snapshotCreateErr error
	snapshotLoadErr   error
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		drives:         map[string]firecracker.Drive{},
		drivePatches:   map[string]firecracker.DrivePatch{},
		networkPatches: map[string]firecracker.NetworkInterfacePatch{},
		nics:           map[string]firecracker.NetworkInterface{},
		instance:       &firecracker.InstanceInfo{State: "Running"},
	}
}

func (c *fakeClient) PutMachineConfig(_ context.Context, cfg firecracker.MachineConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mc = &cfg
	c.restOrder = append(c.restOrder, "PutMachineConfig")
	return c.machineErr
}

func (c *fakeClient) PutBootSource(_ context.Context, src firecracker.BootSource) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bs = &src
	c.restOrder = append(c.restOrder, "PutBootSource")
	return c.bootErr
}

func (c *fakeClient) PutDrive(_ context.Context, id string, drv firecracker.Drive) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drives[id] = drv
	c.restOrder = append(c.restOrder, "PutDrive:"+id)
	return c.driveErr
}

func (c *fakeClient) PutNetworkInterface(_ context.Context, id string, iface firecracker.NetworkInterface) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nics[id] = iface
	c.restOrder = append(c.restOrder, "PutNetworkInterface:"+id)
	return c.nicErr
}

func (c *fakeClient) PutVsock(_ context.Context, v firecracker.Vsock) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vsock = &v
	c.restOrder = append(c.restOrder, "PutVsock")
	return c.vsockErr
}

func (c *fakeClient) Action(_ context.Context, a firecracker.Action) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actions = append(c.actions, a.ActionType)
	c.restOrder = append(c.restOrder, "Action:"+a.ActionType)
	return c.actionErr
}

func (c *fakeClient) PatchVM(_ context.Context, vm firecracker.VM) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vmStates = append(c.vmStates, vm.State)
	c.restOrder = append(c.restOrder, "PatchVM:"+vm.State)
	return c.patchVMErr
}

func (c *fakeClient) InstanceInfo(_ context.Context) (*firecracker.InstanceInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.instance, nil
}

func (c *fakeClient) CreateSnapshot(_ context.Context, req firecracker.SnapshotCreate) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshotCreate = &req
	c.restOrder = append(c.restOrder, "CreateSnapshot")
	// Touch the output files so the SnapshotTemplate post-pass that
	// hashes them finds something to read. Failure to write is fatal
	// here — the test depends on the artifacts existing.
	if c.snapshotCreateErr == nil {
		for _, path := range []string{req.SnapshotPath, req.MemFilePath} {
			if path == "" {
				continue
			}
			if !filepath.IsAbs(path) && c.snapshotBase != "" {
				path = filepath.Join(c.snapshotBase, path)
			}
			if err := os.WriteFile(path, []byte("fake-snapshot-"+filepath.Base(path)), 0o600); err != nil {
				return err
			}
		}
	}
	return c.snapshotCreateErr
}

func (c *fakeClient) LoadSnapshot(_ context.Context, req firecracker.SnapshotLoad) error {
	c.mu.Lock()
	c.snapshotLoad = &req
	c.restOrder = append(c.restOrder, "LoadSnapshot")
	err := c.snapshotLoadErr
	hook := c.loadSnapshotHook
	c.mu.Unlock()
	if hook != nil {
		if hErr := hook(); hErr != nil {
			return hErr
		}
	}
	return err
}

func (c *fakeClient) PatchDrive(_ context.Context, id string, patch firecracker.DrivePatch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drivePatches[id] = patch
	c.restOrder = append(c.restOrder, "PatchDrive:"+id)
	return c.drivePatchErr
}

func (c *fakeClient) PatchNetworkInterface(_ context.Context, id string, patch firecracker.NetworkInterfacePatch) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.networkPatches[id] = patch
	c.restOrder = append(c.restOrder, "PatchNetworkInterface:"+id)
	return c.networkPatchErr
}

// driverFixture is the standard test setup: a Driver wired with all
// seam fakes ready for happy-path Create. Tests opt out of fakes by
// overwriting their error field directly.
type driverFixture struct {
	driver  *Driver
	pool    *fakePool
	rootfs  *fakeRootfs
	tapHost *fakeTapHost
	vsock   *fakeVsockDialer
	vmm     *fakeVMM
	client  *fakeClient
	kernel  string
	runDir  string
}

func newDriverFixture(t *testing.T) *driverFixture {
	t.Helper()
	tmp := t.TempDir()
	kernel := filepath.Join(tmp, "vmlinux")
	if err := os.WriteFile(kernel, []byte{0}, 0o644); err != nil {
		t.Fatalf("write kernel: %v", err)
	}
	runDir := filepath.Join(tmp, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir runDir: %v", err)
	}

	pool := newFakePool()
	rootfs := &fakeRootfs{}
	tap := &fakeTapHost{}
	vsock := newFakeVsockDialer()
	client := newFakeClient()
	vmm := &fakeVMM{}

	d := New(Config{
		KernelImage:       kernel,
		RunDir:            runDir,
		OverlayEnabled:    true,
		PostResumeTimeout: 20 * time.Millisecond,
	}, nil)
	d.SetPool(pool)
	d.SetRootfsBuilder(rootfs)
	d.SetTapHost(tap)
	d.SetVsockDialer(vsock)
	d.SetSpawner(func(cfg Config, sandboxID string) (VMMHandle, error) {
		sandboxRun := filepath.Join(cfg.RunDir, sandboxID)
		_ = os.MkdirAll(sandboxRun, 0o755)
		vmm.id = sandboxID
		vmm.runDir = sandboxRun
		vmm.apiSocket = filepath.Join(sandboxRun, "api.sock")
		client.snapshotBase = sandboxRun
		return vmm, nil
	})
	d.SetClientFactory(func(_ string) VMMClient { return client })

	return &driverFixture{
		driver:  d,
		pool:    pool,
		rootfs:  rootfs,
		tapHost: tap,
		vsock:   vsock,
		vmm:     vmm,
		client:  client,
		kernel:  kernel,
		runDir:  runDir,
	}
}

// TestCreate_HappyPath exercises the full Create sequence and asserts
// every seam was visited in the right order. This is the canonical
// Phase 1 integration test for the driver.
func TestCreate_HappyPath(t *testing.T) {
	f := newDriverFixture(t)
	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1.5,
		MemoryMB: 256,
		DiskGB:   1,
	}, "sb-happy", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Output state must surface what the service layer needs.
	if state.SandboxID != "sb-happy" {
		t.Errorf("SandboxID = %q, want sb-happy", state.SandboxID)
	}
	if state.ContainerIP != "172.16.0.2" {
		t.Errorf("ContainerIP = %q, want guest IP", state.ContainerIP)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Errorf("Status = %q, want started", state.Status)
	}
	// Pool allocate ran, no release (slot now owned by the sandbox).
	if f.pool.alloc != 1 || f.pool.release != 0 {
		t.Errorf("pool counts alloc=%d release=%d, want 1/0", f.pool.alloc, f.pool.release)
	}
	// Rootfs build ran.
	if f.rootfs.builds != 1 {
		t.Errorf("rootfs builds = %d, want 1", f.rootfs.builds)
	}
	// Host TAP brought up, not torn down.
	if f.tapHost.ensureCalls != 1 || f.tapHost.removeCalls != 0 {
		t.Errorf("tap ensure=%d remove=%d, want 1/0", f.tapHost.ensureCalls, f.tapHost.removeCalls)
	}
	// VMM started, socket waited, NOT shut down.
	if !f.vmm.started || !f.vmm.waited || f.vmm.shutdown {
		t.Errorf("vmm started=%v waited=%v shutdown=%v; want true/true/false", f.vmm.started, f.vmm.waited, f.vmm.shutdown)
	}
	// Vsock handshake plus best-effort post-boot network reconfigure.
	if f.vsock.dials != 2 {
		t.Errorf("vsock dials = %d, want 2", f.vsock.dials)
	}
	// REST: machine config, boot source, drive, nic, vsock, action all set.
	if f.client.mc == nil || f.client.mc.VcpuCount != 2 || f.client.mc.MemSizeMib != 256 {
		t.Errorf("MachineConfig wrong: %+v", f.client.mc)
	}
	if f.client.bs == nil || f.client.bs.KernelImagePath != f.kernel {
		t.Errorf("BootSource wrong: %+v", f.client.bs)
	}
	if d, ok := f.client.drives[rootDriveID]; !ok || !d.IsRootDevice {
		t.Errorf("root drive wrong: %+v", d)
	}
	if nic, ok := f.client.nics[primaryIfaceID]; !ok || nic.HostDevName != "fctap-test" {
		t.Errorf("nic wrong: %+v", nic)
	}
	if f.client.vsock == nil || f.client.vsock.GuestCID != 3 {
		t.Errorf("vsock wrong: %+v", f.client.vsock)
	}
	if len(f.client.actions) != 1 || f.client.actions[0] != firecracker.ActionInstanceStart {
		t.Errorf("actions = %v, want [InstanceStart]", f.client.actions)
	}
}

// TestCreate_PoolRequired confirms Create rejects when no pool has been
// injected — that's a daemon-wiring bug (main.go forgot SetPool).
func TestCreate_PoolRequired(t *testing.T) {
	d := New(Config{KernelImage: "/anything"}, nil)
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{}, "id", "tok", nil)
	if err == nil {
		t.Fatal("expected error without pool")
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("err should wrap ErrRuntimeNotImplemented, got %v", err)
	}
}

// TestCreate_RootfsBuilderRequired confirms Create rejects when only
// the pool is wired. Distinct message per missing seam helps the
// operator pinpoint which adapter the daemon failed to register.
func TestCreate_RootfsBuilderRequired(t *testing.T) {
	d := New(Config{KernelImage: "/anything"}, nil)
	d.SetPool(newFakePool())
	_, err := d.Create(context.Background(), models.CreateSandboxRequest{}, "id", "tok", nil)
	if err == nil {
		t.Fatal("expected error without rootfs builder")
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("err should wrap ErrRuntimeNotImplemented, got %v", err)
	}
}

// TestCreate_KernelMissing confirms a missing kernel image fails fast,
// before touching the pool. Without this check, a misconfigured
// KernelImage would leak a TAP slot on every Create attempt.
func TestCreate_KernelMissing(t *testing.T) {
	f := newDriverFixture(t)
	// Replace the driver's kernel path with a bogus one. We can't
	// reconstruct the fixture's driver easily; just point at /no/such.
	d := New(Config{KernelImage: "/no/such/kernel"}, nil)
	d.SetPool(f.pool)
	d.SetRootfsBuilder(f.rootfs)
	d.SetTapHost(f.tapHost)
	d.SetVsockDialer(f.vsock)

	_, err := d.Create(context.Background(), models.CreateSandboxRequest{}, "id", "tok", nil)
	if err == nil {
		t.Fatal("expected error for missing kernel")
	}
	if f.pool.alloc != 0 || f.pool.release != 0 {
		t.Errorf("kernel check should run before pool ops; alloc=%d release=%d", f.pool.alloc, f.pool.release)
	}
}

// TestCreate_RootfsBuildFailureReleasesSlot is the cleanup contract:
// if the rootfs build fails, the pool slot must be released and the
// VMM cleaned up. Otherwise a flaky skopeo would slowly drain the pool.
func TestCreate_RootfsBuildFailureReleasesSlot(t *testing.T) {
	f := newDriverFixture(t)
	f.rootfs.nextErr = errors.New("skopeo: 401 unauthorized")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-rootfs-fail", "tok", nil)
	if err == nil {
		t.Fatal("expected rootfs error")
	}
	if f.pool.alloc != 1 || f.pool.release != 1 {
		t.Errorf("pool alloc=%d release=%d, want 1/1 (cleanup violated)", f.pool.alloc, f.pool.release)
	}
	if f.tapHost.ensureCalls != 0 {
		t.Errorf("tap should NOT have been ensured after rootfs failure; got %d", f.tapHost.ensureCalls)
	}
	if !f.vmm.cleaned {
		t.Error("vmm Cleanup should have been called after error")
	}
}

// TestCreate_TapEnsureFailureReleasesSlotAndVMM is the same contract on
// the next step in: an `ip link add` failure leaves nothing dangling.
func TestCreate_TapEnsureFailureReleasesSlotAndVMM(t *testing.T) {
	f := newDriverFixture(t)
	f.tapHost.ensureErr = errors.New("RTNETLINK: Operation not permitted")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-tap-fail", "tok", nil)
	if err == nil {
		t.Fatal("expected tap error")
	}
	if f.pool.release != 1 {
		t.Errorf("pool release = %d, want 1", f.pool.release)
	}
	// Tap Remove not called — Ensure failed, no device to remove.
	if f.tapHost.removeCalls != 0 {
		t.Errorf("tap Remove should NOT have been called when Ensure failed; got %d", f.tapHost.removeCalls)
	}
}

// TestCreate_VMMStartFailureRemovesTAPAndReleasesSlot covers the step
// after TAP-up: a failed firecracker spawn must walk back through the
// host TAP teardown and pool release.
func TestCreate_VMMStartFailureRemovesTAPAndReleasesSlot(t *testing.T) {
	f := newDriverFixture(t)
	// Stash the fake VMM error.
	f.vmm.startErr = errors.New("exec: firecracker: no such file")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-vmm-fail", "tok", nil)
	if err == nil {
		t.Fatal("expected vmm start error")
	}
	if f.tapHost.ensureCalls != 1 || f.tapHost.removeCalls != 1 {
		t.Errorf("tap ensure=%d remove=%d, want 1/1", f.tapHost.ensureCalls, f.tapHost.removeCalls)
	}
	if f.pool.release != 1 {
		t.Errorf("pool release = %d, want 1", f.pool.release)
	}
}

// TestCreate_RESTFailureUnwindsEverything is the regression test for
// pr-review.md §4 on the firecracker path: a REST error after
// InstanceStart must shut the VMM down, remove the TAP, and release
// the pool slot. Without all three, the host leaks a half-built sandbox.
func TestCreate_RESTFailureUnwindsEverything(t *testing.T) {
	f := newDriverFixture(t)
	f.client.bootErr = errors.New("firecracker: PUT /boot-source -> 400: invalid args")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-rest-fail", "tok", nil)
	if err == nil {
		t.Fatal("expected REST error")
	}
	if !f.vmm.shutdown {
		t.Error("vmm should have been shut down on REST failure")
	}
	if f.tapHost.removeCalls != 1 {
		t.Errorf("tap remove = %d, want 1", f.tapHost.removeCalls)
	}
	if f.pool.release != 1 {
		t.Errorf("pool release = %d, want 1", f.pool.release)
	}
}

// TestCreate_VsockHandshakeRetries confirms the driver tolerates a
// brief race where the in-guest toolbox isn't listening yet. The
// retry loop is the load-bearing piece for cold-boot reliability.
func TestCreate_VsockHandshakeRetries(t *testing.T) {
	f := newDriverFixture(t)
	f.vsock.retryUntil = 3 // succeed on the 3rd attempt
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-vsock-retry", "tok", nil)
	if err != nil {
		t.Fatalf("Create: expected retry to succeed, got %v", err)
	}
	if f.vsock.dials < 3 {
		t.Errorf("dials = %d, want >=3", f.vsock.dials)
	}
}

// TestCreate_VsockHandshakeRejectionFails is the inverse: an explicit
// "ok=false" reply from the guest fails the handshake even though
// connectivity was fine. The error message must include the guest's
// error string so the operator can diagnose.
func TestCreate_VsockHandshakeRejectionFails(t *testing.T) {
	f := newDriverFixture(t)
	f.vsock.guestRespOk = false
	f.vsock.guestError = "toolbox: init not ready"

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-vsock-rej", "tok", nil)
	if err == nil {
		t.Fatal("expected handshake rejection")
	}
	if !contains(err.Error(), "toolbox: init not ready") {
		t.Errorf("error should include guest message; got %v", err)
	}
	// And everything must still unwind.
	if !f.vmm.shutdown || f.pool.release != 1 || f.tapHost.removeCalls != 1 {
		t.Errorf("cleanup contract violated on handshake rejection: shutdown=%v release=%d remove=%d",
			f.vmm.shutdown, f.pool.release, f.tapHost.removeCalls)
	}
}

// TestCreate_RegistersHandleAndClient confirms a successful Create
// registers the VMM and REST client in the driver's in-memory map so
// Destroy/Inspect can find them.
func TestCreate_RegistersHandleAndClient(t *testing.T) {
	f := newDriverFixture(t)
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-register", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := f.driver.vmms["sb-register"]; !ok {
		t.Error("vmm not registered after Create")
	}
	if _, ok := f.driver.clients["sb-register"]; !ok {
		t.Error("client not registered after Create")
	}
}

// fakeTemplateResolver returns a pre-staged rootfs path (and optional
// snapshot artifact paths) for the Phase 2/3 template-hit paths. Tests
// inject this via SetTemplateResolver to exercise the template branches
// without standing up a real template service. resolveErr lets a test
// simulate a missing or non-ready template.
type fakeTemplateResolver struct {
	mu                 sync.Mutex
	calls              int
	lastID             string
	rootfsPath         string
	hasSnapshot        bool
	hasOverlay         bool
	snapshotMemoryPath string
	snapshotStatePath  string
	snapshotChecksum   string
	snapshotVsockCID   uint32
	resolveErr         error
}

func (r *fakeTemplateResolver) Resolve(_ context.Context, id string) (*TemplateResolution, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.lastID = id
	if r.resolveErr != nil {
		return nil, r.resolveErr
	}
	return &TemplateResolution{
		RootfsPath:         r.rootfsPath,
		HasSnapshot:        r.hasSnapshot,
		HasOverlay:         r.hasOverlay,
		SnapshotMemoryPath: r.snapshotMemoryPath,
		SnapshotStatePath:  r.snapshotStatePath,
		SnapshotChecksum:   r.snapshotChecksum,
		SnapshotVsockCID:   r.snapshotVsockCID,
	}, nil
}

// TestCreate_TemplateHit is the Phase 2 fast-path: req.TemplateID set,
// resolver returns a pre-built rootfs, the driver MUST NOT invoke the
// OCI pipeline. The drive that lands on the firecracker REST surface
// must point at the per-sandbox runDir copy (not the shared template
// file), so a future overlay layer can mutate per-sandbox state without
// corrupting the template.
func TestCreate_TemplateHit(t *testing.T) {
	f := newDriverFixture(t)

	// Pre-stage a "template" rootfs on the host. Hard-link into the per-
	// sandbox runDir is the production behavior; for the test we just
	// need a real file the resolver can point at.
	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("TEMPLATE-ROOTFS"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}

	resolver := &fakeTemplateResolver{rootfsPath: templateRootfs}
	f.driver.SetTemplateResolver(resolver)

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-prebuilt",
	}, "sb-tpl-hit", "tok", nil)
	if err != nil {
		t.Fatalf("Create with template: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Errorf("Status = %q, want started", state.Status)
	}
	// The OCI builder MUST NOT have run — that's the whole point of the
	// template fast path.
	if f.rootfs.builds != 0 {
		t.Errorf("rootfs.Build called %d times, want 0 on template hit", f.rootfs.builds)
	}
	if resolver.calls != 1 || resolver.lastID != "tpl-prebuilt" {
		t.Errorf("resolver calls=%d lastID=%q, want 1/tpl-prebuilt", resolver.calls, resolver.lastID)
	}
	// The drive the REST surface saw points at the per-sandbox runDir
	// rootfs (linkOrCopyRootfs staged it there), not the shared template
	// file. Guards against accidentally pointing Firecracker at the
	// template — a regression there would have multiple sandboxes
	// sharing writeable state.
	rootDrive, ok := f.client.drives[rootDriveID]
	if !ok {
		t.Fatal("no root drive registered")
	}
	if rootDrive.PathOnHost == templateRootfs {
		t.Errorf("drive pointed at template file %q; must point at per-sandbox copy", rootDrive.PathOnHost)
	}
	if filepath.Base(rootDrive.PathOnHost) != "rootfs.ext4" {
		t.Errorf("drive path basename = %q, want rootfs.ext4", filepath.Base(rootDrive.PathOnHost))
	}
	// HasSnapshot=false on the resolver MUST keep the cold-boot path:
	// LoadSnapshot is never called, the action is InstanceStart, and the
	// vsock handshake dials the per-sandbox slot CID. The contrast with
	// TestCreate_SnapshotLoadPath is the whole point of asserting these
	// inverses here.
	if f.client.snapshotLoad != nil {
		t.Errorf("LoadSnapshot called on cold-boot template hit: %+v", f.client.snapshotLoad)
	}
	if len(f.client.actions) != 1 || f.client.actions[0] != firecracker.ActionInstanceStart {
		t.Errorf("actions = %v, want [InstanceStart] on cold-boot template hit", f.client.actions)
	}
	if f.vsock.lastCID != 3 {
		t.Errorf("vsock dial CID = %d, want 3 (slot CID) on cold-boot path", f.vsock.lastCID)
	}
}

// TestCreate_TemplateRequiresResolver confirms a TemplateID-bearing
// request with no resolver wired is rejected with
// ErrRuntimeNotImplemented — distinguishes "operator hasn't set this
// node up for templates" from a generic 500.
func TestCreate_TemplateRequiresResolver(t *testing.T) {
	f := newDriverFixture(t)
	// Intentionally NOT calling SetTemplateResolver.
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-no-resolver",
	}, "sb-no-resolver", "tok", nil)
	if err == nil {
		t.Fatal("expected error without resolver")
	}
	if !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Errorf("err should wrap ErrRuntimeNotImplemented, got %v", err)
	}
	// Cleanup contract: no pool slot, no tap.
	if f.pool.release != f.pool.alloc {
		t.Errorf("pool alloc=%d release=%d; cleanup violated", f.pool.alloc, f.pool.release)
	}
}

// TestCreate_TemplateResolveErrorReleasesSlot mirrors the rootfs-
// build-failure cleanup contract for the template path: a resolver
// error (template not ready, deleted, etc.) must release the pool slot
// and clean up the VMM. Otherwise a flaky resolver drains the pool.
func TestCreate_TemplateResolveErrorReleasesSlot(t *testing.T) {
	f := newDriverFixture(t)
	resolver := &fakeTemplateResolver{resolveErr: errors.New("template tpl-x is pending, not ready")}
	f.driver.SetTemplateResolver(resolver)

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-x",
	}, "sb-tpl-bad", "tok", nil)
	if err == nil {
		t.Fatal("expected resolver error")
	}
	if f.pool.alloc != 1 || f.pool.release != 1 {
		t.Errorf("pool alloc=%d release=%d, want 1/1", f.pool.alloc, f.pool.release)
	}
	if f.rootfs.builds != 0 {
		t.Errorf("rootfs.Build called %d times on template error; want 0", f.rootfs.builds)
	}
}

// TestCreate_SnapshotLoadPath is the Phase 3 fast-boot regression test:
// resolver returns HasSnapshot=true, so the driver MUST skip
// configureVMM (no PutMachineConfig, no PutBootSource, no PutDrive,
// no PutNetworkInterface, no PutVsock) and instead issue LoadSnapshot
// + PATCH rebinding + PATCH /vm state=Resumed. The vsock handshake must dial the template's
// reserved CID (baked into the snapshot at build time), NOT the
// per-sandbox slot CID — a regression there silently hangs the
// handshake until deadline because the guest is listening on the
// template CID.
func TestCreate_SnapshotLoadPath(t *testing.T) {
	f := newDriverFixture(t)

	// Pre-stage template rootfs + snapshot artifact paths. The driver
	// does not read the snapshot files on this test (SnapshotVerifyOnLoad
	// is off by default in the fixture; the fakeClient's LoadSnapshot is
	// a no-op record), but the paths flow through to the LoadSnapshot
	// request body so we can assert they're wired correctly.
	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("TEMPLATE-ROOTFS"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	// Files do not need real content for the load-path assertions, but
	// touch them so any future "stat before load" check the driver might
	// adopt does not break the test.
	if err := os.WriteFile(snapMem, []byte("MEM"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("STATE"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}

	const templateCID uint32 = 200
	resolver := &fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		// Empty checksum so configureVMMForLoad skips verification
		// regardless of the SnapshotVerifyOnLoad config knob. The
		// verifySnapshotChecksum path has its own test seam.
		snapshotChecksum: "",
		snapshotVsockCID: templateCID,
	}
	f.driver.SetTemplateResolver(resolver)

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-snap",
	}, "sb-snap-load", "tok", nil)
	if err != nil {
		t.Fatalf("Create with snapshot template: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Errorf("Status = %q, want started", state.Status)
	}

	// LoadSnapshot MUST have been called with the template's artifact
	// paths and EnableDiffSnapshots true (the snapshot may be a base
	// for a future diff snapshot at sandbox-stop time).
	if f.client.snapshotLoad == nil {
		t.Fatal("LoadSnapshot was not called on snapshot-load path")
	}
	if f.client.snapshotLoad.SnapshotPath != snapState {
		t.Errorf("LoadSnapshot.SnapshotPath = %q, want %q", f.client.snapshotLoad.SnapshotPath, snapState)
	}
	if f.client.snapshotLoad.MemBackend == nil ||
		f.client.snapshotLoad.MemBackend.BackendPath != snapMem ||
		f.client.snapshotLoad.MemBackend.BackendType != "File" {
		t.Errorf("LoadSnapshot.MemBackend wrong: %+v", f.client.snapshotLoad.MemBackend)
	}
	if !f.client.snapshotLoad.EnableDiffSnapshots {
		t.Error("LoadSnapshot.EnableDiffSnapshots = false, want true")
	}
	if f.client.snapshotLoad.ResumeVM {
		t.Error("LoadSnapshot.ResumeVM = true; driver must Resume explicitly so PR-B can hook PATCH-then-Resume")
	}
	if got := f.client.snapshotLoad.NetworkOverrides; len(got) != 1 ||
		got[0].IfaceID != primaryIfaceID ||
		got[0].HostDevName != "fctap-test" {
		t.Errorf("LoadSnapshot.NetworkOverrides = %+v, want eth0 -> fctap-test", got)
	}

	// configureVMM MUST NOT have run — every one of its REST calls
	// must be absent. A regression here would re-do cold-boot setup
	// on top of a restored snapshot, either failing the firecracker
	// REST contract or silently double-configuring.
	if f.client.mc != nil {
		t.Errorf("PutMachineConfig was called on snapshot-load path: %+v", f.client.mc)
	}
	if f.client.bs != nil {
		t.Errorf("PutBootSource was called on snapshot-load path: %+v", f.client.bs)
	}
	if len(f.client.drives) != 0 {
		t.Errorf("PutDrive was called on snapshot-load path: %+v", f.client.drives)
	}
	if len(f.client.nics) != 0 {
		t.Errorf("PutNetworkInterface was called on snapshot-load path: %+v", f.client.nics)
	}
	if f.client.vsock != nil {
		t.Errorf("PutVsock was called on snapshot-load path: %+v", f.client.vsock)
	}
	if patch, ok := f.client.drivePatches[rootDriveID]; !ok || filepath.Base(patch.PathOnHost) != rootfsFileName {
		t.Errorf("PatchDrive rootfs = %+v, want staged rootfs path", f.client.drivePatches[rootDriveID])
	}
	if len(f.client.networkPatches) != 0 {
		t.Errorf("PatchNetworkInterface called on snapshot-load path: %+v", f.client.networkPatches)
	}

	// Resume only, never InstanceStart. PatchVM is the state-transition
	// wire trace; assert ordering and content.
	if len(f.client.vmStates) != 1 || f.client.vmStates[0] != firecracker.VMStateResumed {
		t.Errorf("vmStates = %v, want [Resumed] on snapshot-load path", f.client.vmStates)
	}
	if len(f.client.actions) != 0 {
		t.Errorf("actions = %v, want none on snapshot-load path", f.client.actions)
	}

	// The vsock handshake MUST dial the template's CID, not the
	// slot's CID. Dialing slot CID (3) would race a guest that's
	// listening on template CID (200) and hang the handshake.
	if f.vsock.lastCID != templateCID {
		t.Errorf("vsock dial CID = %d, want %d (template CID); slot CID = 3",
			f.vsock.lastCID, templateCID)
	}

	// Cleanup contract sanity: slot still owned by sandbox, TAP up,
	// VMM running. A snapshot-load Create has the same post-conditions
	// as a cold-boot Create.
	if f.pool.alloc != 1 || f.pool.release != 0 {
		t.Errorf("pool alloc=%d release=%d, want 1/0 on success", f.pool.alloc, f.pool.release)
	}
	if f.tapHost.ensureCalls != 1 || f.tapHost.removeCalls != 0 {
		t.Errorf("tap ensure=%d remove=%d, want 1/0 on success", f.tapHost.ensureCalls, f.tapHost.removeCalls)
	}
	if !f.vmm.started || f.vmm.shutdown {
		t.Errorf("vmm started=%v shutdown=%v, want true/false", f.vmm.started, f.vmm.shutdown)
	}
	if _, ok := f.driver.vmms["sb-snap-load"]; !ok {
		t.Error("vmm not registered after snapshot-load Create")
	}
}

// TestCreate_SnapshotLoadPath_VerifyMismatchRefusesLoad guards the
// integrity check: when SnapshotVerifyOnLoad is on and the persisted
// checksum doesn't match the on-disk bytes, the driver must refuse to
// call LoadSnapshot at all. A misorder that loads first and verifies
// after would let firecracker mmap corrupt memory.
func TestCreate_SnapshotLoadPath_VerifyMismatchRefusesLoad(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.SnapshotVerifyOnLoad = true

	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("TEMPLATE-ROOTFS"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	if err := os.WriteFile(snapMem, []byte("MEM-BYTES"), 0o600); err != nil {
		t.Fatalf("write snap mem: %v", err)
	}
	if err := os.WriteFile(snapState, []byte("STATE-BYTES"), 0o600); err != nil {
		t.Fatalf("write snap state: %v", err)
	}

	// Deliberately wrong checksum — the actual file SHA256 will differ.
	resolver := &fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		snapshotChecksum:   "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000" + "|sha256:" + "0000000000000000000000000000000000000000000000000000000000000000",
		snapshotVsockCID:   200,
	}
	f.driver.SetTemplateResolver(resolver)

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-bad-sum",
	}, "sb-bad-sum", "tok", nil)
	if err == nil {
		t.Fatal("expected integrity error")
	}
	if !contains(err.Error(), "snapshot integrity") {
		t.Errorf("error should mention snapshot integrity, got: %v", err)
	}
	// LoadSnapshot MUST NOT have been called — the whole point of
	// host-side verification is to refuse the load before firecracker
	// touches the artifacts.
	if f.client.snapshotLoad != nil {
		t.Errorf("LoadSnapshot was called despite checksum mismatch: %+v", f.client.snapshotLoad)
	}
	// And the cleanup contract still holds: pool slot released, TAP
	// removed, VMM shut down. The half-built sandbox does not leak.
	if f.pool.release != 1 {
		t.Errorf("pool release = %d, want 1 on integrity error", f.pool.release)
	}
	if f.tapHost.removeCalls != 1 {
		t.Errorf("tap remove = %d, want 1 on integrity error", f.tapHost.removeCalls)
	}
	if !f.vmm.shutdown {
		t.Error("vmm should have been shut down on integrity error")
	}
}

// TestCreate_ColdBoot_WithOverlay asserts that the cold-boot path
// attaches the per-sandbox overlay drive (PutDrive:overlay after
// PutDrive:rootfs) when OverlaySizeGB > 0, allocates the per-sandbox
// overlay.ext4 file in the runDir at the requested size, and never
// PATCHes the drive (PATCH is the snapshot-load tool, not the
// cold-boot tool — cold-boot's PutDrive runs before InstanceStart so
// the placeholder dance doesn't apply).
func TestCreate_ColdBoot_WithOverlay(t *testing.T) {
	f := newDriverFixture(t)

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		CPU:           1,
		MemoryMB:      128,
		DiskGB:        1,
		OverlaySizeGB: 4,
	}, "sb-overlay-cb", "tok", nil)
	if err != nil {
		t.Fatalf("Create cold-boot with overlay: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Errorf("Status = %q, want started", state.Status)
	}

	// Overlay drive must be present alongside rootfs.
	ov, ok := f.client.drives[overlayDriveID]
	if !ok {
		t.Fatalf("overlay drive not registered (drives=%v)", f.client.drives)
	}
	if ov.IsReadOnly {
		t.Errorf("overlay drive IsReadOnly=true, want false")
	}
	// File must exist on disk at OverlaySizeGB * 1 GiB.
	info, err := os.Stat(ov.PathOnHost)
	if err != nil {
		t.Fatalf("stat overlay file: %v", err)
	}
	if info.Size() != int64(4)<<30 {
		t.Errorf("overlay file size = %d, want %d", info.Size(), int64(4)<<30)
	}
	// PATCH must not have run — cold-boot uses PutDrive only.
	if len(f.client.drivePatches) != 0 {
		t.Errorf("PatchDrive called on cold-boot path: %+v", f.client.drivePatches)
	}
	// REST order: rootfs PutDrive must come before overlay PutDrive
	// (the snapshot-capture path bakes the same ordering into the
	// snapshot state — keeping the orderings consistent avoids
	// surprising the clone's PATCH).
	rootIdx, overlayIdx := -1, -1
	for i, op := range f.client.restOrder {
		if op == "PutDrive:"+rootDriveID {
			rootIdx = i
		}
		if op == "PutDrive:"+overlayDriveID {
			overlayIdx = i
		}
	}
	if rootIdx < 0 || overlayIdx < 0 || rootIdx >= overlayIdx {
		t.Errorf("expected PutDrive:rootfs before PutDrive:overlay in %v", f.client.restOrder)
	}
}

// TestCreate_ColdBoot_WithoutOverlay asserts that OverlaySizeGB=0 (the
// wire default) leaves the cold-boot path untouched — no extra
// PutDrive, no overlay file on disk. Pins the "PR-A behavior is
// preserved for callers who don't opt in" invariant.
func TestCreate_ColdBoot_WithoutOverlay(t *testing.T) {
	f := newDriverFixture(t)

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 128,
		DiskGB:   1,
	}, "sb-no-overlay", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := f.client.drives[overlayDriveID]; ok {
		t.Errorf("overlay drive registered without OverlaySizeGB request: %+v", f.client.drives)
	}
}

// TestCreate_SnapshotLoadPath_WithOverlay asserts that the
// snapshot-load path allocates a per-sandbox overlay file and
// PATCHes the overlay drive to that path between LoadSnapshot and
// PATCH /vm state=Resumed. The PATCH order matters: Firecracker accepts
// PathOnHost mutations on a loaded-but-paused VMM, but only before
// Resume. A regression that PATCHed after Resume would either be
// rejected by the API or be silently late (the guest's first write
// would hit the template placeholder).
func TestCreate_SnapshotLoadPath_WithOverlay(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("TEMPLATE-ROOTFS"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, "snapshot.memory")
	snapState := filepath.Join(tplDir, "snapshot.state")
	for _, p := range []string{snapMem, snapState} {
		if err := os.WriteFile(p, []byte("X"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	resolver := &fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		hasOverlay:         true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		snapshotVsockCID:   200,
	}
	f.driver.SetTemplateResolver(resolver)

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		CPU:           1,
		MemoryMB:      128,
		DiskGB:        1,
		TemplateID:    "tpl-snap-ov",
		OverlaySizeGB: 2,
	}, "sb-snap-ov", "tok", nil); err != nil {
		t.Fatalf("Create snapshot-load+overlay: %v", err)
	}

	// PatchDrive MUST have run for the overlay drive ID with a
	// path-on-host pointing at the freshly-allocated per-sandbox file.
	patch, ok := f.client.drivePatches[overlayDriveID]
	if !ok {
		t.Fatalf("PatchDrive overlay not called (patches=%+v)", f.client.drivePatches)
	}
	if filepath.Base(patch.PathOnHost) != overlayFileName {
		t.Errorf("PatchDrive.PathOnHost = %q, want basename %q", patch.PathOnHost, overlayFileName)
	}
	if info, err := os.Stat(patch.PathOnHost); err != nil {
		t.Errorf("overlay file at %q missing: %v", patch.PathOnHost, err)
	} else if info.Size() != int64(2)<<30 {
		t.Errorf("overlay file size = %d, want %d", info.Size(), int64(2)<<30)
	}

	// Order: LoadSnapshot -> PatchDrive -> Resume. Any rearrangement
	// here is an outage (PATCH-after-Resume is rejected;
	// Resume-before-PATCH silently corrupts).
	var loadIdx, patchIdx, resumeIdx int = -1, -1, -1
	for i, op := range f.client.restOrder {
		switch op {
		case "LoadSnapshot":
			loadIdx = i
		case "PatchDrive:" + overlayDriveID:
			patchIdx = i
		case "PatchVM:" + firecracker.VMStateResumed:
			resumeIdx = i
		}
	}
	if loadIdx < 0 || patchIdx < 0 || resumeIdx < 0 {
		t.Fatalf("missing one of LoadSnapshot/PatchDrive/Resume in %v", f.client.restOrder)
	}
	if !(loadIdx < patchIdx && patchIdx < resumeIdx) {
		t.Errorf("REST order = %v; want LoadSnapshot(%d) < PatchDrive(%d) < Resume(%d)",
			f.client.restOrder, loadIdx, patchIdx, resumeIdx)
	}
}

// TestCreate_SnapshotLoadPath_RejectsOverlayOnLegacyTemplate asserts
// that a snapshot-load request against a PR-A template (HasOverlay=
// false) with OverlaySizeGB > 0 is rejected up-front with a clear
// error pointing at template rebuild — and that the rejection comes
// BEFORE LoadSnapshot runs, so the cleanup contract isn't tested with
// a half-loaded VMM. Firecracker cannot add a virtio-blk drive after
// LoadSnapshot, only PATCH an existing one; the rejection is the
// only safe response.
func TestCreate_SnapshotLoadPath_RejectsOverlayOnLegacyTemplate(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("X"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	resolver := &fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		hasOverlay:         false, // PR-A template
		snapshotMemoryPath: filepath.Join(tplDir, "snap.memory"),
		snapshotStatePath:  filepath.Join(tplDir, "snap.state"),
		snapshotVsockCID:   200,
	}
	f.driver.SetTemplateResolver(resolver)

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		TemplateID:    "tpl-legacy",
		OverlaySizeGB: 1,
		MemoryMB:      128,
		CPU:           1,
		DiskGB:        1,
	}, "sb-legacy", "tok", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "no overlay drive") {
		t.Errorf("err = %v, want message about 'no overlay drive'", err)
	}
	// LoadSnapshot must not have been called — the reject is pre-load.
	if f.client.snapshotLoad != nil {
		t.Error("LoadSnapshot was invoked despite rejection")
	}
	// Pool slot must have been released so a follow-up retry doesn't
	// leak a TAP. The cleanup contract is the pr-review.md §4 line.
	if f.pool.alloc != 1 || f.pool.release != 1 {
		t.Errorf("pool alloc=%d release=%d, want 1/1", f.pool.alloc, f.pool.release)
	}
}

// TestCreate_OverlayDisabledByConfig asserts SB_FIRECRACKER_OVERLAY_
// ENABLED=false (cfg.OverlayEnabled=false) rejects any
// OverlaySizeGB > 0 request before pool allocation. Pure-config gate;
// flips to enable=false leave no on-disk state behind.
func TestCreate_OverlayDisabledByConfig(t *testing.T) {
	f := newDriverFixture(t)
	// New() captured an Config with OverlayEnabled=true via the
	// fixture; flip the live cfg pointer to off.
	f.driver.cfg.OverlayEnabled = false

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		OverlaySizeGB: 1,
		MemoryMB:      128,
		CPU:           1,
		DiskGB:        1,
	}, "sb-disabled", "tok", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "overlay drive disabled") {
		t.Errorf("err = %v, want 'overlay drive disabled'", err)
	}
	if f.pool.alloc != 0 {
		t.Errorf("pool alloc=%d, want 0 (reject pre-allocation)", f.pool.alloc)
	}
}

// TestCreate_SnapshotLoadPath_SendsPostResume asserts that after a
// successful snapshot-load + handshake, the driver sends a
// post_resume vsock op with a wall-clock payload. The second Dial is
// the post_resume dial; the first is the handshake. We assert the
// payload shape (op=post_resume, wallclock_unix_ns present and >0)
// because both the entropy reseed and the clock resync inside the
// guest depend on it.
func TestCreate_SnapshotLoadPath_SendsPostResume(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("X"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, "snap.memory")
	snapState := filepath.Join(tplDir, "snap.state")
	for _, p := range []string{snapMem, snapState} {
		if err := os.WriteFile(p, []byte("X"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	resolver := &fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		snapshotVsockCID:   200,
	}
	f.driver.SetTemplateResolver(resolver)

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		TemplateID: "tpl-snap-pr",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
	}, "sb-snap-pr", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Find the post_resume write. Vsock writes are recorded in dial
	// order: handshake's ping is first; post_resume is the second.
	var postLine []byte
	for _, w := range f.vsock.snapshotWrites() {
		if contains(string(w), "post_resume") {
			postLine = w
			break
		}
	}
	if postLine == nil {
		t.Fatalf("post_resume not sent; writes=%v", f.vsock.snapshotWrites())
	}
	var decoded struct {
		Op   string `json:"op"`
		Data struct {
			WallclockUnixNs int64 `json:"wallclock_unix_ns"`
			Network         struct {
				GuestIP   string `json:"guest_ip"`
				GatewayIP string `json:"gateway_ip"`
				Netmask   string `json:"netmask"`
				PrefixLen int    `json:"prefix_len"`
			} `json:"network"`
		} `json:"data"`
	}
	if err := json.Unmarshal(postLine, &decoded); err != nil {
		t.Fatalf("decode post_resume: %v (line=%s)", err, postLine)
	}
	if decoded.Op != "post_resume" {
		t.Errorf("Op = %q, want post_resume", decoded.Op)
	}
	if decoded.Data.WallclockUnixNs <= 0 {
		t.Errorf("WallclockUnixNs = %d, want > 0", decoded.Data.WallclockUnixNs)
	}
	if decoded.Data.Network.GuestIP != "172.16.0.2" ||
		decoded.Data.Network.GatewayIP != "172.16.0.1" ||
		decoded.Data.Network.Netmask != "255.255.255.252" ||
		decoded.Data.Network.PrefixLen != 30 {
		t.Errorf("post_resume network = %+v, want slot network", decoded.Data.Network)
	}
}

// TestCreate_SnapshotLoadPath_PostResumeFailureIsBestEffort asserts
// that a failed post_resume vsock send does not fail Create. The
// guest is already serving on the clone's TAP and vsock; the most
// telling regression here would be "post_resume timeout → Create
// returns 500 → caller retries → second VMM stuck because the first
// one wasn't cleaned up".
func TestCreate_SnapshotLoadPath_PostResumeFailureIsBestEffort(t *testing.T) {
	f := newDriverFixture(t)
	tplDir := t.TempDir()
	templateRootfs := filepath.Join(tplDir, "rootfs.ext4")
	if err := os.WriteFile(templateRootfs, []byte("X"), 0o644); err != nil {
		t.Fatalf("write template rootfs: %v", err)
	}
	snapMem := filepath.Join(tplDir, "snap.memory")
	snapState := filepath.Join(tplDir, "snap.state")
	for _, p := range []string{snapMem, snapState} {
		if err := os.WriteFile(p, []byte("X"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	resolver := &fakeTemplateResolver{
		rootfsPath:         templateRootfs,
		hasSnapshot:        true,
		snapshotMemoryPath: snapMem,
		snapshotStatePath:  snapState,
		snapshotVsockCID:   200,
	}
	f.driver.SetTemplateResolver(resolver)
	// Second Dial fails — that's the post_resume call (the first is
	// the handshake). retryUntil + errOnDialIdx are mutually
	// exclusive in our fake: we use errOnDialIdx only.
	f.vsock.errOnDialIdx = 2

	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		TemplateID: "tpl-pr-fail",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
	}, "sb-pr-fail", "tok", nil); err != nil {
		t.Fatalf("Create should not fail on post_resume error: %v", err)
	}
}

// contains is a tiny strings.Contains shim — pulling strings.Contains
// here would have to flow through the import block, and we already
// use this same helper in the host_test for the same reason.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
