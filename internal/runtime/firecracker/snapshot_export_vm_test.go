package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootfstar"
)

// exportGuest stands in for the helper VM a snapshot's disk is read in: its
// process, its API and its agent, which streams fill's tree as the files of
// the disk copy it was given.
type exportGuest struct {
	t    *testing.T
	fill func(t *testing.T, dir string)
	// ackErr is the agent's answer to export_rootfs when it refuses (the
	// disk copy would not mount).
	ackErr string
	// stream, when set, is sent after the ack instead of a tar of the tree.
	stream []byte
	// pingErr fails the boot handshake; exportDialErr the export's dial.
	pingErr error
	// failDial fails the helper's nth dial (1: the boot handshake, 2: the
	// export); ack replaces the export's ack line.
	failDial int
	ack      *string
	dials    int
	// vmHook and clientHook change the helper's VM and API client as they
	// are made, to break a step of its boot.
	vmHook     func(*fakeVMM)
	clientHook func(*fakeClient)

	mu        sync.Mutex
	vms       []*fakeVMM
	clients   []*fakeClient
	disks     [][]byte // each helper's disk copy, as the export was asked for
	mkfsCalls [][]string
	mkfsErr   error
}

type dialerFunc func(ctx context.Context, socketPath string, cid, port uint32) (io.ReadWriteCloser, error)

func (f dialerFunc) Dial(ctx context.Context, socketPath string, cid, port uint32) (io.ReadWriteCloser, error) {
	return f(ctx, socketPath, cid, port)
}

func isHelperPath(p string) bool {
	return strings.Contains(p, string(filepath.Separator)+exportHelperIDPrefix)
}

// install puts the helper stand-in in front of the fixture's VM seams and
// configures a toolbox binary and mkfs, which the stand-in "runs".
func (g *exportGuest) install(f *driverFixture) {
	g.t.Helper()
	bin := filepath.Join(g.t.TempDir(), "toolboxd")
	if err := os.WriteFile(bin, []byte("agent build 1"), 0o755); err != nil {
		g.t.Fatal(err)
	}
	f.driver.cfg.ToolboxBinaryPath, f.driver.cfg.Mkfs4Bin = bin, "/sbin/mkfs.ext4"
	savedMkfs := runHelperMkfs
	runHelperMkfs = func(_ context.Context, bin string, args ...string) ([]byte, error) {
		g.mu.Lock()
		g.mkfsCalls = append(g.mkfsCalls, append([]string{bin}, args...))
		err := g.mkfsErr
		g.mu.Unlock()
		if err != nil {
			return []byte("mkfs said no"), err
		}
		return nil, os.WriteFile(args[len(args)-2], []byte("helper image"), 0o644)
	}
	g.t.Cleanup(func() { runHelperMkfs = savedMkfs })

	spawn, newClient, inner := f.driver.spawn, f.driver.newClient, f.driver.vsockDial
	f.driver.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
		if !strings.HasPrefix(id, exportHelperIDPrefix) {
			return spawn(cfg, id)
		}
		runDir := filepath.Join(cfg.RunDir, id)
		vm := &fakeVMM{id: id, runDir: runDir, apiSocket: filepath.Join(runDir, "api.sock")}
		if g.vmHook != nil {
			g.vmHook(vm)
		}
		g.mu.Lock()
		g.vms = append(g.vms, vm)
		g.mu.Unlock()
		return &cleaningVMM{fakeVMM: vm}, nil
	})
	f.driver.SetClientFactory(func(socket string) VMMClient {
		if !isHelperPath(socket) {
			return newClient(socket)
		}
		c := newFakeClient()
		if g.clientHook != nil {
			g.clientHook(c)
		}
		g.mu.Lock()
		g.clients = append(g.clients, c)
		g.mu.Unlock()
		return c
	})
	f.driver.SetVsockDialer(dialerFunc(func(ctx context.Context, socket string, cid, port uint32) (io.ReadWriteCloser, error) {
		if !isHelperPath(socket) {
			return inner.Dial(ctx, socket, cid, port)
		}
		g.mu.Lock()
		g.dials++
		fail := g.dials == g.failDial
		g.mu.Unlock()
		if fail {
			return nil, errors.New("connection reset")
		}
		return &exportConn{guest: g}, nil
	}))
}

// cleaningVMM removes its run dir on Cleanup, as the real vmm does, so a
// test sees what an export leaves behind.
type cleaningVMM struct{ *fakeVMM }

func (v *cleaningVMM) Cleanup() error {
	if err := v.fakeVMM.Cleanup(); err != nil {
		return err
	}
	return os.RemoveAll(v.runDir)
}

func (g *exportGuest) lastClient() *fakeClient {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.clients) == 0 {
		return nil
	}
	return g.clients[len(g.clients)-1]
}

// exportConn answers one connection to the helper's agent.
type exportConn struct {
	guest *exportGuest
	out   bytes.Buffer
	wrote bool
}

func (c *exportConn) Write(p []byte) (int, error) {
	g := c.guest
	var msg struct {
		Op string `json:"op"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(p), &msg); err != nil {
		return 0, err
	}
	c.wrote = true
	switch msg.Op {
	case "ping":
		if g.pingErr != nil {
			return 0, g.pingErr
		}
		c.out.WriteString(`{"ok":true}` + "\n")
	case "export_rootfs":
		client := g.lastClient()
		disk, err := os.ReadFile(client.drives[exportDriveID].PathOnHost)
		if err != nil {
			g.t.Errorf("the helper's disk copy is unreadable: %v", err)
		}
		g.mu.Lock()
		g.disks = append(g.disks, disk)
		g.mu.Unlock()
		if g.ackErr != "" {
			resp, _ := json.Marshal(map[string]string{"error": g.ackErr})
			c.out.Write(append(resp, '\n'))
			break
		}
		if g.ack != nil {
			c.out.WriteString(*g.ack)
			break
		}
		c.out.WriteString(`{"ok":true}` + "\n")
		if g.stream != nil {
			c.out.Write(g.stream)
			break
		}
		tree := g.t.TempDir()
		if g.fill != nil {
			g.fill(g.t, tree)
		}
		if err := rootfstar.Write(&c.out, tree); err != nil {
			g.t.Errorf("tar the guest tree: %v", err)
		}
	default:
		c.out.WriteString(`{"error":"unknown op"}` + "\n")
	}
	return len(p), nil
}

func (c *exportConn) Read(p []byte) (int, error) { return c.out.Read(p) }
func (c *exportConn) Close() error               { return nil }

// helperSandbox is a stopped sandbox whose snapshot the helper stand-in
// reads, with an image store.
func helperSandbox(t *testing.T, id string) (*driverFixture, *recordingImageStore, *exportGuest) {
	t.Helper()
	f, store, guest := stoppedSandboxForSnapshot(t, id)
	return f, store, guest
}

// The helper VM is a small read-only image with toolboxd as init in export
// mode, the disk copy as a second drive, vsock and no network; it is stopped
// and its dir removed when the export is done.
func TestCreateSnapshotBootsAHelperVMOnTheCopy(t *testing.T) {
	f, _, guest := helperSandbox(t, "sb-helper")
	if _, err := f.driver.CreateSnapshot(context.Background(), "sb-helper", "aerolvm-snapshot/h:latest"); err != nil {
		t.Fatal(err)
	}
	client := guest.lastClient()
	if client.mc == nil || client.mc.VcpuCount != 1 || client.mc.MemSizeMib != exportHelperMemMiB {
		t.Fatalf("machine config = %+v", client.mc)
	}
	if client.bs == nil || !strings.HasSuffix(client.bs.BootArgs, " init=/toolboxd aerolvm_export=1") || client.bs.KernelImagePath != f.kernel {
		t.Fatalf("boot source = %+v", client.bs)
	}
	root, disk := client.drives[rootDriveID], client.drives[exportDriveID]
	if !root.IsRootDevice || !root.IsReadOnly || filepath.Dir(root.PathOnHost) != filepath.Join(f.runDir, exportHelperDirName) {
		t.Fatalf("root drive = %+v, want the shared helper image, read-only", root)
	}
	if disk.IsRootDevice || disk.IsReadOnly || filepath.Base(disk.PathOnHost) != exportDiskFileName {
		t.Fatalf("disk drive = %+v", disk)
	}
	if len(client.nics) != 0 {
		t.Fatal("the helper VM has a network")
	}
	if client.vsock == nil || client.vsock.GuestCID != exportHelperCID {
		t.Fatalf("vsock = %+v", client.vsock)
	}
	if len(client.actions) != 1 || client.actions[0] != "InstanceStart" {
		t.Fatalf("actions = %v", client.actions)
	}
	vm := guest.vms[0]
	if !vm.started || !vm.waited || !vm.shutdown || !vm.cleaned {
		t.Fatalf("helper VM lifecycle = %+v, want started, stopped and cleaned", vm)
	}
	if _, err := os.Stat(vm.runDir); !os.IsNotExist(err) {
		t.Fatal("the helper's dir is left")
	}
	if len(guest.mkfsCalls) != 1 || !strings.Contains(strings.Join(guest.mkfsCalls[0], " "), "-d ") {
		t.Fatalf("mkfs calls = %v", guest.mkfsCalls)
	}
}

// The helper image is built once per toolboxd build: reused while the binary
// is unchanged, rebuilt (and the old one removed) when it changes.
func TestExportHelperImageFollowsTheToolboxBuild(t *testing.T) {
	f, _, guest := helperSandbox(t, "sb-reuse")
	ctx := context.Background()
	first, err := f.driver.exportHelperRootfs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := f.driver.exportHelperRootfs(ctx); err != nil || again != first || len(guest.mkfsCalls) != 1 {
		t.Fatalf("second call = %q, %v, mkfs %d times", again, err, len(guest.mkfsCalls))
	}
	// A restarted daemon finds the image on disk without rebuilding it.
	f.driver.helperImages = exportHelperImages{}
	if again, err := f.driver.exportHelperRootfs(ctx); err != nil || again != first || len(guest.mkfsCalls) != 1 {
		t.Fatalf("after a restart = %q, %v, mkfs %d times", again, err, len(guest.mkfsCalls))
	}
	if err := os.WriteFile(f.driver.cfg.ToolboxBinaryPath, []byte("agent build 2, longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	second, err := f.driver.exportHelperRootfs(ctx)
	if err != nil || second == first || len(guest.mkfsCalls) != 2 {
		t.Fatalf("after an upgrade = %q, %v, mkfs %d times", second, err, len(guest.mkfsCalls))
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatal("the old build's image is left")
	}
	// The cache notices an image removed under it.
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	if third, err := f.driver.exportHelperRootfs(ctx); err != nil || third != second || len(guest.mkfsCalls) != 3 {
		t.Fatalf("after removal = %q, %v, mkfs %d times", third, err, len(guest.mkfsCalls))
	}
}

func TestExportHelperImageFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("not configured", func(t *testing.T) {
		f, _, _ := helperSandbox(t, "sb-nocfg")
		f.driver.cfg.Mkfs4Bin = ""
		if _, err := f.driver.CreateSnapshot(ctx, "sb-nocfg", "r:1"); err == nil || !strings.Contains(err.Error(), "mkfs.ext4 configured") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no toolbox binary", func(t *testing.T) {
		f, _, _ := helperSandbox(t, "sb-nobin")
		f.driver.cfg.ToolboxBinaryPath = filepath.Join(t.TempDir(), "missing")
		if _, err := f.driver.exportHelperRootfs(ctx); err == nil || !strings.Contains(err.Error(), "toolbox binary") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("mkfs fails", func(t *testing.T) {
		f, _, guest := helperSandbox(t, "sb-mkfs")
		guest.mkfsErr = errors.New("exit 1")
		if _, err := f.driver.exportHelperRootfs(ctx); err == nil || !strings.Contains(err.Error(), "mkfs said no") {
			t.Fatalf("err = %v", err)
		}
		dir := filepath.Join(f.runDir, exportHelperDirName)
		if left, _ := os.ReadDir(dir); len(left) != 0 {
			t.Fatalf("a failed build left %v", left)
		}
	})
	t.Run("the image dir cannot be made", func(t *testing.T) {
		f, _, _ := helperSandbox(t, "sb-dir")
		if err := os.WriteFile(filepath.Join(f.runDir, exportHelperDirName), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := f.driver.exportHelperRootfs(ctx); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no dir for saved sandboxes", func(t *testing.T) {
		f, _, _ := helperSandbox(t, "sb-nobase")
		f.driver.cfg.TemplatesDir, f.driver.cfg.RunDir = "", ""
		if _, err := f.driver.exportHelperRootfs(ctx); err == nil {
			t.Fatal("accepted")
		}
	})
}

// Each step of booting the helper can fail; every failure stops the helper
// (if it started) and removes its dir.
func TestExportHelperBootFailures(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name   string
		break_ func(f *driverFixture, g *exportGuest)
		want   string
	}{
		{"spawn", func(f *driverFixture, g *exportGuest) {
			spawn := f.driver.spawn
			f.driver.SetSpawner(func(cfg Config, id string) (VMMHandle, error) {
				if strings.HasPrefix(id, exportHelperIDPrefix) {
					return nil, boom
				}
				return spawn(cfg, id)
			})
		}, "export VM: boom"},
		{"start", func(_ *driverFixture, g *exportGuest) { g.vmHook = (func(vm *fakeVMM) { vm.startErr = boom }) }, "export VM: start"},
		{"api socket", func(_ *driverFixture, g *exportGuest) { g.vmHook = (func(vm *fakeVMM) { vm.waitErr = boom }) }, "wait api socket"},
		{"machine config", func(_ *driverFixture, g *exportGuest) { g.clientHook = (func(c *fakeClient) { c.machineErr = boom }) }, "machine config"},
		{"boot source", func(_ *driverFixture, g *exportGuest) { g.clientHook = (func(c *fakeClient) { c.bootErr = boom }) }, "boot source"},
		{"drives", func(_ *driverFixture, g *exportGuest) { g.clientHook = (func(c *fakeClient) { c.driveErr = boom }) }, "root drive"},
		{"vsock", func(_ *driverFixture, g *exportGuest) { g.clientHook = (func(c *fakeClient) { c.vsockErr = boom }) }, "export VM: vsock"},
		{"instance start", func(_ *driverFixture, g *exportGuest) { g.clientHook = (func(c *fakeClient) { c.actionErr = boom }) }, "start instance"},
		{"agent never up", func(_ *driverFixture, g *exportGuest) { g.pingErr = boom }, "agent not up"},
		{"the disk does not mount", func(_ *driverFixture, g *exportGuest) { g.ackErr = "mount the disk copy: invalid argument" }, "export VM: mount the disk copy"},
		{"a broken stream", func(_ *driverFixture, g *exportGuest) {
			g.stream = []byte("not a tar at all, and long enough to read a header from it...")
		}, "rootfs stream"},
		{"the export's dial", func(_ *driverFixture, g *exportGuest) { g.failDial = 2 }, "export VM: dial"},
		{"an ack that is not JSON", func(_ *driverFixture, g *exportGuest) { ack := "garbage\n"; g.ack = &ack }, "decode ack"},
		{"no ack at all", func(_ *driverFixture, g *exportGuest) { ack := ""; g.ack = &ack }, "read ack"},
		{"a stream larger than the disk could hold", func(_ *driverFixture, _ *exportGuest) {
			saved := exportStreamSlack
			exportStreamSlack = 0
			t.Cleanup(func() { exportStreamSlack = saved })
		}, "exceeds its size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, store, guest := helperSandbox(t, "sb-boot")
			tc.break_(f, guest)
			_, err := f.driver.CreateSnapshot(context.Background(), "sb-boot", "r:1")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if len(store.imported) != 0 {
				t.Fatal("an image was imported")
			}
			for _, vm := range guest.vms {
				if vm.started && !vm.shutdown {
					t.Fatal("a started helper was left running")
				}
				if !vm.cleaned {
					t.Fatal("a helper's dir was left")
				}
			}
			base, _ := f.driver.snapshotExportDir()
			if left, _ := os.ReadDir(base); len(left) != 0 {
				t.Fatalf("export work dir left: %v", left)
			}
		})
	}
}
