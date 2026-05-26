package firecracker

import (
	"context"
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
	// retryUntil >0 means return err for the first `retryUntil-1` Dial
	// calls (simulating the post-InstanceStart race) and succeed on
	// the `retryUntil`th. Lets us assert the driver's retry loop.
	retryUntil int
}

func newFakeVsockDialer() *fakeVsockDialer {
	return &fakeVsockDialer{guestRespOk: true}
}

func (d *fakeVsockDialer) Dial(_ context.Context, _, _ uint32) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials++
	if d.retryUntil > 0 && d.dials < d.retryUntil {
		return nil, errors.New("vsock: connection refused (fake)")
	}
	if d.err != nil {
		return nil, d.err
	}
	rwc := newFakeVsockConn(d.guestRespOk, d.guestError)
	return rwc, nil
}

// fakeVsockConn is a one-shot connection that, on read, returns either
// {"ok":true} or {"error":"..."} followed by a newline. Mirrors the
// toolbox's response wire shape.
type fakeVsockConn struct {
	reply  []byte
	pos    int
	closed bool
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
	return len(p), nil
}

func (c *fakeVsockConn) Close() error { c.closed = true; return nil }

// fakeVMM is the test handle returned by the fake spawner. Records
// Start / WaitSocket / Shutdown / Cleanup so the test asserts ordering.
type fakeVMM struct {
	id          string
	runDir      string
	apiSocket   string
	startErr    error
	waitErr     error
	shutdownErr error

	started  bool
	waited   bool
	shutdown bool
	cleaned  bool
	stderrTl string
}

func (v *fakeVMM) APISocket() string             { return v.apiSocket }
func (v *fakeVMM) RunDir() string                { return v.runDir }
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
func (v *fakeVMM) Kill() error    { v.shutdown = true; return nil }
func (v *fakeVMM) Cleanup() error { v.cleaned = true; return nil }

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
	instance *firecracker.InstanceInfo

	machineErr error
	bootErr    error
	driveErr   error
	nicErr     error
	vsockErr   error
	actionErr  error
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		drives:   map[string]firecracker.Drive{},
		nics:     map[string]firecracker.NetworkInterface{},
		instance: &firecracker.InstanceInfo{State: "Running"},
	}
}

func (c *fakeClient) PutMachineConfig(_ context.Context, cfg firecracker.MachineConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mc = &cfg
	return c.machineErr
}

func (c *fakeClient) PutBootSource(_ context.Context, src firecracker.BootSource) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bs = &src
	return c.bootErr
}

func (c *fakeClient) PutDrive(_ context.Context, id string, drv firecracker.Drive) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drives[id] = drv
	return c.driveErr
}

func (c *fakeClient) PutNetworkInterface(_ context.Context, id string, iface firecracker.NetworkInterface) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nics[id] = iface
	return c.nicErr
}

func (c *fakeClient) PutVsock(_ context.Context, v firecracker.Vsock) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vsock = &v
	return c.vsockErr
}

func (c *fakeClient) Action(_ context.Context, a firecracker.Action) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actions = append(c.actions, a.ActionType)
	return c.actionErr
}

func (c *fakeClient) InstanceInfo(_ context.Context) (*firecracker.InstanceInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.instance, nil
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
		KernelImage: kernel,
		RunDir:      runDir,
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
	// Vsock handshake ran exactly once.
	if f.vsock.dials != 1 {
		t.Errorf("vsock dials = %d, want 1", f.vsock.dials)
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
