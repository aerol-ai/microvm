package firecracker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// withHostArch runs the test as if on arch, so the nested-virtualization
// CPU template applies (amd64) whatever the machine running the tests.
func withHostArch(t *testing.T, arch string) {
	t.Helper()
	old := hostArch
	hostArch = arch
	t.Cleanup(func() { hostArch = old })
}

// A cold boot on the Nitro backend is the KVM sequence with three changes,
// each one a setting Firecracker refuses at InstanceStart otherwise or a
// device the guest would not find: no dirty-page tracking, no CPU template,
// no pci=off; then PUT /enclave right before InstanceStart.
func TestCreate_NitroColdBoot(t *testing.T) {
	withHostArch(t, "amd64")
	for _, tc := range []struct {
		mode       string
		wantDirect bool
	}{{"direct", true}, {"confidential", false}} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newDriverFixture(t)
			f.driver.cfg.Backend = "nitro"
			f.driver.cfg.NitroMode = tc.mode
			if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro, CPU: 1, MemoryMB: 512, DiskGB: 1,
			}, "sb-nitro", "tok", nil); err != nil {
				t.Fatalf("Create: %v", err)
			}
			c := f.client
			if c.mc == nil || c.mc.TrackDirtyPages {
				t.Fatalf("machine config %+v: dirty-page tracking must be off on Nitro", c.mc)
			}
			if c.cpu != nil || slices.Contains(c.restOrder, "PutCPUConfig") {
				t.Fatalf("a CPU template was sent on Nitro: %v", c.restOrder)
			}
			if c.bs == nil || strings.Contains(c.bs.BootArgs, "pci=off") {
				t.Fatalf("boot args %q: a Nitro guest needs PCI", c.bs.BootArgs)
			}
			if !strings.Contains(c.bs.BootArgs, "init="+guestInitPath) && f.driver.cfg.ToolboxBinaryPath != "" {
				t.Fatalf("boot args lost the agent's init: %q", c.bs.BootArgs)
			}
			if c.enclave == nil || c.enclave.DirectMode != tc.wantDirect || !c.enclave.CPUOvercommit || c.enclave.DebugMode {
				t.Fatalf("enclave = %+v, want direct=%v overcommit, no debug", c.enclave, tc.wantDirect)
			}
			enc := slices.Index(c.restOrder, "PutEnclave")
			start := slices.Index(c.restOrder, "Action:"+firecracker.ActionInstanceStart)
			if enc < 0 || start < 0 || enc != start-1 {
				t.Fatalf("PUT /enclave must be the last call before InstanceStart: %v", c.restOrder)
			}
		})
	}
}

// The KVM backend, with the backend unset as on every node today, sends no
// enclave and keeps its dirty-page tracking, CPU template and boot line
// (pci=off on amd64).
func TestCreate_KVMColdBootUnchanged(t *testing.T) {
	withHostArch(t, "amd64")
	for _, backend := range []string{"", "kvm"} {
		f := newDriverFixture(t)
		f.driver.cfg.Backend = backend
		if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", Runtime: models.RuntimeFirecracker, CPU: 1, MemoryMB: 256, DiskGB: 1,
		}, "sb-kvm", "tok", nil); err != nil {
			t.Fatalf("backend %q: Create: %v", backend, err)
		}
		c := f.client
		if c.enclave != nil || slices.Contains(c.restOrder, "PutEnclave") {
			t.Fatalf("backend %q sent PUT /enclave: %v", backend, c.restOrder)
		}
		if c.mc == nil || !c.mc.TrackDirtyPages || c.cpu == nil {
			t.Fatalf("backend %q: machine config %+v cpu %+v; KVM keeps dirty pages and its CPU template", backend, c.mc, c.cpu)
		}
		if !strings.HasPrefix(c.bs.BootArgs, baseBootArgsFor(runtime.GOARCH)+" ") {
			t.Fatalf("backend %q boot args %q do not start with the KVM base %q", backend, c.bs.BootArgs, baseBootArgsFor(runtime.GOARCH))
		}
	}
}

// Each backend boots only its own runtime, and a Nitro node never starts
// from a template snapshot. Refused before a TAP slot or a disk is taken.
func TestCreate_RuntimeMustFitTheBackend(t *testing.T) {
	for _, tc := range []struct {
		name, backend string
		req           models.CreateSandboxRequest
		want          string
	}{
		{"kvm node, nitro create", "kvm", models.CreateSandboxRequest{Runtime: models.RuntimeFirecrackerNitro}, `this node runs "firecracker", not "firecracker-nitro"`},
		{"nitro node, kvm create", "nitro", models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker}, `this node runs "firecracker-nitro", not "firecracker"`},
		{"nitro node, template", "nitro", models.CreateSandboxRequest{TemplateID: "tpl-1"}, "cannot start from a template snapshot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDriverFixture(t)
			f.driver.cfg.Backend = tc.backend
			tc.req.Image = "alpine:3.20"
			_, err := f.driver.Create(context.Background(), tc.req, "sb-x", "tok", nil)
			if !errors.Is(err, models.ErrRuntimeNotImplemented) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one saying %q", err, tc.want)
			}
			if f.pool.alloc != 0 || f.rootfs.builds != 0 {
				t.Fatalf("refused create took a slot (%d) or built a disk (%d)", f.pool.alloc, f.rootfs.builds)
			}
		})
	}
}

// What a Nitro VM cannot do (no memory snapshots, no paused state) and what
// this build does not do yet answers 501 with the reason, before any work;
// a start without the env (StartWithIdentity) is refused, never handed a
// guest with no env; the cluster fence is told the VM cannot be frozen.
func TestNitroRefusals(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.Backend = "nitro"
	ctx := context.Background()
	const id = "sb-nitro"
	for name, call := range map[string]func() error{
		"start without env": func() error { _, err := f.driver.StartWithIdentity(ctx, id, id, "tok"); return err },
		"snapshot":          func() error { _, err := f.driver.CreateSnapshot(ctx, id, "img:1"); return err },
		"template": func() error {
			_, err := f.driver.SnapshotTemplate(ctx, TemplateSnapshotRequest{})
			return err
		},
		"export": func() error { return f.driver.ExportSandboxSnapshot(ctx, id, &bytes.Buffer{}) },
		"import": func() error { return f.driver.ImportSandboxSnapshot(ctx, id, &bytes.Buffer{}) },
	} {
		if err := call(); !errors.Is(err, models.ErrRuntimeNotImplemented) || !strings.Contains(err.Error(), models.RuntimeFirecrackerNitro) {
			t.Errorf("%s: err = %v, want a 501 naming %s", name, err, models.RuntimeFirecrackerNitro)
		}
	}
	if err := f.driver.Freeze(ctx, id); !errors.Is(err, sbruntime.ErrCannotFreeze) {
		t.Errorf("Freeze: err = %v, want ErrCannotFreeze", err)
	}
	if f.pool.alloc != 0 || f.vmm.started {
		t.Fatal("a refused operation did work")
	}
}

// A running Nitro VM still reports itself on Start: only a stopped one is
// refused.
func TestNitroStartReportsARunningVM(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.Backend = "nitro"
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro}, "sb-run", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	state, err := f.driver.StartWithIdentity(ctx, "sb-run", "sb-run", "tok")
	if err != nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("Start of a running Nitro VM = %+v, %v", state, err)
	}
}

// Health on the Nitro backend needs Firecracker 1.18 (the first with Nitro
// Sandboxes) and no vmgenid kernel config: a Nitro VM is never restored.
func TestRuntimeHealth_Nitro(t *testing.T) {
	for _, tc := range []struct {
		version, want string
	}{
		{"Firecracker v1.18.0", "ok"},
		{"Firecracker v1.15.1", "the Nitro backend requires Firecracker >= 1.18.0, found 1.15.1"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			dir := t.TempDir()
			bin := func(name, body string) string {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
				return p
			}
			d := New(Config{
				Backend:           "nitro",
				FirecrackerBinary: bin("firecracker", "#!/bin/sh\necho "+tc.version+"\n"),
				JailerBinary:      bin("jailer", "#!/bin/sh\n"),
				// No kernel config next to it: KVM would report vmgenid
				// unverifiable; Nitro does not ask.
				KernelImage: bin("bzImage", ""),
			}, nil)
			if got := d.RuntimeHealth(context.Background()); !strings.Contains(got, tc.want) {
				t.Fatalf("RuntimeHealth = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWithoutBootArg(t *testing.T) {
	if got := withoutBootArg("console=ttyS0 pci=off  quiet pci=offx", "pci=off"); got != "console=ttyS0 quiet pci=offx" {
		t.Fatalf("got %q", got)
	}
}

// A refused PUT /enclave (an old Firecracker, no Nitro device in the jail)
// fails the create before InstanceStart and gives back everything it took,
// as any other pre-boot REST failure does.
func TestCreate_NitroEnclaveRefusedUnwinds(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.Backend = "nitro"
	f.client.enclaveErr = errors.New("400 Bad Request: unknown request")
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro,
	}, "sb-noenclave", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "PutEnclave (SB_FIRECRACKER_BACKEND=nitro") {
		t.Fatalf("err = %v, want the PutEnclave failure", err)
	}
	if slices.Contains(f.client.restOrder, "Action:"+firecracker.ActionInstanceStart) {
		t.Fatalf("InstanceStart ran after a refused enclave: %v", f.client.restOrder)
	}
	if f.pool.release != 1 || !f.vmm.shutdown || f.tapHost.removeCalls != 1 {
		t.Fatalf("not unwound: release=%d shutdown=%v tap removes=%d", f.pool.release, f.vmm.shutdown, f.tapHost.removeCalls)
	}
}

// nitroStopped creates a Nitro sandbox and stops it, as a user would.
func nitroStopped(t *testing.T, f *driverFixture, id string) {
	t.Helper()
	f.driver.cfg.Backend = "nitro"
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro, CPU: 2, MemoryMB: 768,
	}, id, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.driver.Stop(ctx, id); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func opsWritten(f *driverFixture) string {
	var all []string
	for _, w := range f.vsock.snapshotWrites() {
		all = append(all, string(w))
	}
	return strings.Join(all, "\n")
}

// A Nitro Stop has no memory to save, so it keeps the disks and the VM's
// shape, and Start boots the VM again from them on the same TAP slot, with
// the sandbox's env handed over again and its token adopted. The kept disk
// is what the next VM boots, and the address is the sandbox's own.
func TestNitroStopKeepsTheDiskAndStartBootsItAgain(t *testing.T) {
	f := newDriverFixture(t)
	const id = "sb-cold"
	nitroStopped(t, f, id)

	if !f.vmm.shutdown || f.pool.release != 0 || f.tapHost.removeCalls != 1 {
		t.Fatalf("stop: shutdown=%v slot releases=%d tap removes=%d; want the VM ended, the slot kept, the TAP removed",
			f.vmm.shutdown, f.pool.release, f.tapHost.removeCalls)
	}
	if !strings.Contains(opsWritten(f), `"freeze_fs"`) {
		t.Fatal("stop did not freeze the guest's filesystem first")
	}
	m, err := f.driver.readSandboxSnapshotManifest(id)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if !m.Cold || m.VcpuCount != 2 || m.MemSizeMib != 768 || m.SnapshotChecksum != "" || m.GuestFlush != guestFlushDone {
		t.Fatalf("manifest = %+v; want cold, 2 vCPUs, 768 MiB, no memory checksum, flushed", m)
	}
	_, memPath, _, keptRootfs, _, _ := f.driver.sandboxSnapshotPaths(id)
	if _, err := os.Stat(memPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a Nitro stop wrote a memory file: %v", err)
	}
	if b, err := os.ReadFile(keptRootfs); err != nil || string(b) != "fake ext4" {
		t.Fatalf("kept rootfs = %q, %v", b, err)
	}
	// The stop is a no-op the second time.
	if err := f.driver.Stop(context.Background(), id); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	// Without the env, refused; with it, booted.
	if _, err := f.driver.StartWithIdentity(context.Background(), id, id, "tok"); !errors.Is(err, errNitroStartNeedsEnv) {
		t.Fatalf("StartWithIdentity on Nitro = %v, want errNitroStartNeedsEnv", err)
	}
	f.client.restOrder = nil
	f.client.enclave = nil
	before := len(f.vsock.snapshotWrites())
	loads := 0
	state, err := f.driver.StartWithIdentityEnv(context.Background(), id, id, "tok", func(context.Context) (map[string]string, error) {
		loads++
		return map[string]string{"GREETING": "hello"}, nil
	})
	if err != nil || state.Status != models.SandboxStatusStarted || state.ContainerIP != "172.16.0.2" {
		t.Fatalf("StartWithIdentityEnv = %+v, %v", state, err)
	}
	if loads != 1 {
		t.Fatalf("env loaded %d times, want once", loads)
	}
	c := f.client
	if c.mc == nil || c.mc.VcpuCount != 2 || c.mc.MemSizeMib != 768 || c.mc.TrackDirtyPages || c.enclave == nil {
		t.Fatalf("start booted %+v enclave %+v; want the stopped VM's shape on Nitro", c.mc, c.enclave)
	}
	if slices.Contains(c.restOrder, "LoadSnapshot") || !slices.Contains(c.restOrder, "Action:"+firecracker.ActionInstanceStart) {
		t.Fatalf("a Nitro start must cold-boot, not load a snapshot: %v", c.restOrder)
	}
	var after []string
	for _, w := range f.vsock.snapshotWrites()[before:] {
		after = append(after, string(w))
	}
	sent := strings.Join(after, "\n")
	envAt, adoptAt := strings.Index(sent, `"set_env"`), strings.Index(sent, `"adopt"`)
	if envAt < 0 || adoptAt < envAt || !strings.Contains(sent, "GREETING") {
		t.Fatalf("start must hand the env over, then adopt:\n%s", sent)
	}
	if f.tapHost.ensureCalls != 2 {
		t.Fatalf("tap ensures = %d, want the create's and the start's", f.tapHost.ensureCalls)
	}
	// Started again: a second start reports the running VM and loads nothing.
	if _, err := f.driver.StartWithIdentityEnv(context.Background(), id, id, "tok", func(context.Context) (map[string]string, error) {
		loads++
		return nil, nil
	}); err != nil || loads != 1 {
		t.Fatalf("start of a running VM: err %v, env loads %d", err, loads)
	}
}

// A Nitro stop whose guest did not flush is refused and the sandbox runs
// on: with no memory saved, its last writes would be lost. A stop that
// cannot read the VM's shape is refused too, and the guest thawed.
func TestNitroStopRefusedWithoutAFlushOrAShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *driverFixture)
		want  string
	}{
		{"freeze fails", func(f *driverFixture) {
			f.vsock.replyFor = func(op string) (bool, string) {
				if op == "freeze_fs" {
					return false, "freeze: device busy"
				}
				return true, ""
			}
		}, "the guest did not flush its disk"},
		{"no shape", func(f *driverFixture) { f.client.getMachineErr = errors.New("api down") }, "read the VM's shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDriverFixture(t)
			f.driver.cfg.Backend = "nitro"
			ctx := context.Background()
			if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro}, "sb-busy", "tok", nil); err != nil {
				t.Fatalf("Create: %v", err)
			}
			tc.setup(f)
			if err := f.driver.Stop(ctx, "sb-busy"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Stop = %v, want %q", err, tc.want)
			}
			if f.vmm.shutdown {
				t.Fatal("a refused stop ended the VM")
			}
			if !strings.Contains(opsWritten(f), `"thaw_fs"`) {
				t.Fatal("a refused stop left the guest frozen")
			}
			if _, err := f.driver.readSandboxSnapshotManifest("sb-busy"); err == nil {
				t.Fatal("a refused stop wrote a stopped folder")
			}
		})
	}
}

// Each backend starts only what its own Stop wrote: a KVM node does not
// try to restore memory a Nitro stop never kept, and a Nitro node does
// not boot from a KVM snapshot folder.
func TestStartRefusesTheOtherBackendsStop(t *testing.T) {
	f := newDriverFixture(t)
	nitroStopped(t, f, "sb-cross")
	f.driver.cfg.Backend = "kvm"
	if _, err := f.driver.StartWithIdentity(context.Background(), "sb-cross", "sb-cross", "tok"); err == nil || !strings.Contains(err.Error(), "stopped by a Nitro node") {
		t.Fatalf("KVM start of a Nitro stop = %v", err)
	}

	g := newDriverFixture(t)
	g.driver.cfg.Backend = "nitro"
	dir, _, _, rootfs, _, manifestPath := g.driver.sandboxSnapshotPaths("sb-kvm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(rootfs, []byte("x"), 0o644)
	_ = os.WriteFile(manifestPath, []byte(`{"version":1,"sandbox_id":"sb-kvm","vsock_cid":3,"snapshot_checksum":"x"}`), 0o600)
	_, err := g.driver.StartWithIdentityEnv(context.Background(), "sb-kvm", "sb-kvm", "tok", func(context.Context) (map[string]string, error) { return nil, nil })
	if err == nil || !strings.Contains(err.Error(), "not stopped by a Nitro node") {
		t.Fatalf("Nitro start of a KVM stop = %v", err)
	}
	if g.pool.alloc != 0 || g.vmm.started {
		t.Fatal("a refused start did work")
	}
}

// A Nitro start that fails after its VM began (the env cannot be loaded)
// ends that VM and removes its TAP, and keeps the stopped disks: the next
// start can try again.
func TestNitroStartFailureUnwindsAndKeepsTheDisk(t *testing.T) {
	f := newDriverFixture(t)
	nitroStopped(t, f, "sb-retry")
	f.vmm.shutdown = false
	removes := f.tapHost.removeCalls
	_, err := f.driver.StartWithIdentityEnv(context.Background(), "sb-retry", "sb-retry", "tok", func(context.Context) (map[string]string, error) {
		return nil, errors.New("store unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "load env") {
		t.Fatalf("start = %v, want the env load failure", err)
	}
	if !f.vmm.shutdown || f.tapHost.removeCalls != removes+1 {
		t.Fatalf("not unwound: shutdown=%v tap removes %d→%d", f.vmm.shutdown, removes, f.tapHost.removeCalls)
	}
	if _, err := f.driver.readSandboxSnapshotManifest("sb-retry"); err != nil {
		t.Fatalf("the kept disk is gone after a failed start: %v", err)
	}
	if _, ok := f.driver.vmms["sb-retry"]; ok {
		t.Fatal("a failed start registered the VM")
	}
}

// Every way a Nitro start can fail names its step, leaves no VM or TAP
// behind, and keeps the stopped disks for the next try.
func TestNitroStartFailures(t *testing.T) {
	failOp := func(f *driverFixture, bad string) {
		f.vsock.replyFor = func(op string) (bool, string) {
			if op == bad {
				return false, bad + " refused"
			}
			return true, ""
		}
	}
	for _, tc := range []struct {
		name  string
		token string
		setup func(t *testing.T, f *driverFixture)
		want  string
	}{
		{"no token", "", nil, errGuestTokenMissing.Error()},
		{"no stopped folder", "tok", func(t *testing.T, f *driverFixture) {
			dir, _, _, _, _, _ := f.driver.sandboxSnapshotPaths("sb-f")
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
		}, "read sandbox snapshot manifest"},
		{"kept rootfs gone", "tok", func(t *testing.T, f *driverFixture) {
			_, _, _, rootfs, _, _ := f.driver.sandboxSnapshotPaths("sb-f")
			_ = os.Remove(rootfs)
		}, "kept rootfs missing"},
		{"slot lookup", "tok", func(_ *testing.T, f *driverFixture) { f.pool.getErr = errors.New("db locked") }, "tap lookup"},
		{"spawn", "tok", func(_ *testing.T, f *driverFixture) {
			f.driver.SetSpawner(func(Config, string) (VMMHandle, error) { return nil, errors.New("no jailer") })
		}, "spawn handle"},
		{"tap", "tok", func(_ *testing.T, f *driverFixture) { f.tapHost.ensureErr = errors.New("ip: busy") }, "tap host ensure"},
		{"vmm start", "tok", func(_ *testing.T, f *driverFixture) { f.vmm.startErr = errors.New("exec") }, "vmm start"},
		{"api socket", "tok", func(_ *testing.T, f *driverFixture) { f.vmm.waitErr = errors.New("timeout") }, "wait api socket"},
		{"machine config", "tok", func(_ *testing.T, f *driverFixture) { f.client.machineErr = errors.New("400") }, "PutMachineConfig"},
		{"instance start", "tok", func(_ *testing.T, f *driverFixture) { f.client.actionErr = errors.New("400") }, "InstanceStart"},
		{"handshake", "tok", func(_ *testing.T, f *driverFixture) { failOp(f, "ping") }, "vsock handshake"},
		{"env push", "tok", func(_ *testing.T, f *driverFixture) { failOp(f, "set_env") }, "set_env"},
		{"adopt", "tok", func(_ *testing.T, f *driverFixture) { failOp(f, "adopt") }, "adopt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDriverFixture(t)
			nitroStopped(t, f, "sb-f")
			f.vmm.shutdown, f.vmm.started = false, false
			removes := f.tapHost.removeCalls
			if tc.setup != nil {
				tc.setup(t, f)
			}
			_, err := f.driver.StartWithIdentityEnv(context.Background(), "sb-f", "sb-f", tc.token, func(context.Context) (map[string]string, error) {
				return map[string]string{"K": "v"}, nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("start = %v, want %q", err, tc.want)
			}
			if _, ok := f.driver.vmms["sb-f"]; ok {
				t.Fatal("a failed start registered the VM")
			}
			if f.vmm.started && !f.vmm.shutdown {
				t.Fatal("a failed start left its VM running")
			}
			// A TAP that came up is removed again (one that failed to come
			// up has nothing to remove).
			if tapUp := f.tapHost.ensureCalls > 1 && tc.name != "tap"; tapUp && f.tapHost.removeCalls != removes+1 {
				t.Fatalf("a failed start left its TAP: removes %d→%d", removes, f.tapHost.removeCalls)
			}
		})
	}
}

// Stop's own refusals: nothing to stop; a slot it cannot look up; and,
// once the VM has ended, disks it cannot keep stay in the run folder for
// Destroy rather than be cleaned away.
func TestNitroStopFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("nothing to stop", func(t *testing.T) {
		f := newDriverFixture(t)
		f.driver.cfg.Backend = "nitro"
		if err := f.driver.Stop(ctx, "sb-none"); err == nil || !strings.Contains(err.Error(), "no stopped disk exists") {
			t.Fatalf("Stop = %v", err)
		}
	})
	create := func(t *testing.T) *driverFixture {
		f := newDriverFixture(t)
		f.driver.cfg.Backend = "nitro"
		if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro, MemoryMB: 256}, "sb-s", "tok", nil); err != nil {
			t.Fatalf("Create: %v", err)
		}
		return f
	}
	t.Run("slot lookup", func(t *testing.T) {
		f := create(t)
		f.pool.getErr = errors.New("db locked")
		if err := f.driver.Stop(ctx, "sb-s"); err == nil || !strings.Contains(err.Error(), "tap lookup") || f.vmm.shutdown {
			t.Fatalf("Stop = %v (VM ended: %v)", err, f.vmm.shutdown)
		}
	})
	t.Run("disks cannot be kept", func(t *testing.T) {
		f := create(t)
		base, err := f.driver.sandboxSnapshotBase()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(base, []byte("not a folder"), 0o644); err != nil {
			t.Fatal(err)
		}
		err = f.driver.Stop(ctx, "sb-s")
		if err == nil || !strings.Contains(err.Error(), "create snapshot base") {
			t.Fatalf("Stop = %v", err)
		}
		if !f.vmm.shutdown || f.vmm.cleaned {
			t.Fatalf("VM ended %v, run folder cleaned %v; want ended and kept", f.vmm.shutdown, f.vmm.cleaned)
		}
	})
}

// StartWithIdentityEnv checks the reference names the sandbox, on either
// backend, before any work.
func TestStartWithIdentityEnvChecksTheReference(t *testing.T) {
	for _, backend := range []string{"kvm", "nitro"} {
		f := newDriverFixture(t)
		f.driver.cfg.Backend = backend
		if _, err := f.driver.StartWithIdentityEnv(context.Background(), "sb-a", "sb-b", "tok", nil); err == nil || !strings.Contains(err.Error(), "does not name sandbox") {
			t.Fatalf("%s: err = %v", backend, err)
		}
	}
}
