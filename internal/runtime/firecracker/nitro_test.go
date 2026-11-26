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
// the cluster fence is told the VM cannot be frozen, so it stops it instead.
func TestNitroRefusals(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.Backend = "nitro"
	ctx := context.Background()
	const id = "sb-nitro"
	for name, call := range map[string]func() error{
		"stop":     func() error { return f.driver.Stop(ctx, id) },
		"start":    func() error { _, err := f.driver.StartWithIdentity(ctx, id, id, "tok"); return err },
		"snapshot": func() error { _, err := f.driver.CreateSnapshot(ctx, id, "img:1"); return err },
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
