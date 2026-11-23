package wasm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestSplitWarmSlotRoutes: in privilege mode split a warm slot's worker is
// a helper host named by the slot's id, and a record names it by the
// helper's socket. Only a slot id's shape is a slot's: a sandbox's own
// worker never passes for one, and single mode's slot sockets are its own.
func TestSplitWarmSlotRoutes(t *testing.T) {
	d, _, _, _ := splitDriver(t)
	slot := wasmpool.NewSlotID()
	sock := d.helperSocket(rootpolicy.HostWasmWorker, slot)
	if id, ok := d.slotFromSocket(sock); !ok || id != slot {
		t.Fatalf("slot socket %s = %q %v", sock, id, ok)
	}
	singleSock := filepath.Join(wasmpool.SlotDirIn(d.cfg.RunDir, "deadbeef", slot), "worker.sock")
	for _, bad := range []string{
		d.workerSocketPath("sb-1"),                        // a sandbox's own worker
		d.helperSocket(rootpolicy.HostWasmResident, slot), // a resident host's socket
		"/elsewhere/w-" + slot + ".sock",
		helperSockets + "/w-" + slot + ".sockx",
		helperSockets + "/x-" + slot + ".sock",
		singleSock, // single mode's, not the helper's
	} {
		if _, ok := d.slotFromSocket(bad); ok {
			t.Errorf("%s read as a slot's", bad)
		}
	}
	for name, tc := range map[string]struct {
		rec  instanceRecord
		want bool
	}{
		"its warm slot":                {instanceRecord{Socket: sock, WarmPool: true, WorkerKey: slot}, true},
		"its warm slot, another key":   {instanceRecord{Socket: sock, WarmPool: true, WorkerKey: "pool-0000000000000000"}, false},
		"another sandbox's own worker": {instanceRecord{Socket: d.workerSocketPath("sb-2"), WarmPool: true, WorkerKey: "sb-2"}, false},
		"single mode's slot socket":    {instanceRecord{Socket: singleSock, WarmPool: true, WorkerKey: slot}, false},
	} {
		if got := d.recordRoutesValid("sb-1", tc.rec, false); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	single, _, _, _ := adoptDriver(t, false)
	if _, ok := single.slotFromSocket(sock); ok {
		t.Fatal("single mode read the helper's socket as a slot's")
	}
	if id, ok := single.slotFromSocket(filepath.Join(wasmpool.SlotDirIn(single.cfg.RunDir, "deadbeef", slot), "worker.sock")); !ok || id != slot {
		t.Fatal("single mode's own slot socket")
	}
}

// TestSplitWarmClaimAndDestroy: a create that takes a warm slot in split
// mode dials the helper's socket and keeps the slot's id as its worker
// key; its destroy stops the slot's host and removes the slot's own
// folder, never the helper's socket folder.
func TestSplitWarmClaimAndDestroy(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	sockets, other := shortSockets(t)
	runDir := filepath.Join(dir, "run")
	sup := &fakeSupervisor{}
	dialed := map[string]bool{}
	client := &recordingWorkerClient{}
	d := New(Config{RunDir: runDir, ModulesDir: dir, HelperSockets: sockets,
		Worker: worker.Confinement{UID: os.Getuid(), GID: shareGID()}}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef00112233"})
	d.SetWorkerSupervisor(sup)
	d.SetWorkerClientFactory(func(sock string) WorkerClient { dialed[sock] = true; return client })
	slotID := wasmpool.NewSlotID()
	slotDir := wasmpool.SlotDirIn(runDir, "deadbeef00112233", slotID)
	if err := os.MkdirAll(slotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := d.helperSocket(rootpolicy.HostWasmWorker, slotID)
	d.SetWarmPool(&fakeWarmPool{slot: &wasmpool.Slot{ID: slotID, ModuleDigest: "deadbeef00112233", ModulePath: modPath,
		SocketPath: sock, WorkerKey: slotID, MemoryMB: 256, Dir: slotDir}})
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-warm", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	inst, err := d.instance("sb-warm")
	if err != nil || inst.workerKey != slotID || inst.socketPath != sock || !inst.fromWarmPool || !dialed[sock] || sup.ensureCalls != 0 {
		t.Fatalf("instance %+v dialed %v ensure %d (%v)", inst, dialed, sup.ensureCalls, err)
	}
	rec, _, ok := d.readInstanceRecord("sb-warm")
	if !ok || rec.Socket != sock || !rec.WarmPool {
		t.Fatalf("record %+v %v", rec, ok)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-warm"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(slotDir); !os.IsNotExist(err) {
		t.Fatalf("slot folder left: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("the helper's socket folder was touched: %v", err)
	}
	if sup.stopCalls != 1 {
		t.Fatalf("stop calls %d", sup.stopCalls)
	}
	// An instance whose socket names no slot removes no folder.
	keep := filepath.Join(runDir, "keep")
	if err := os.MkdirAll(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := d.warmSlotFolder(&sandboxInstance{socketPath: d.workerSocketPath("sb-x"), moduleDigest: "deadbeef00112233"}); got != "" {
		t.Fatalf("a sandbox's own worker's slot folder %q", got)
	}
	if got := d.warmSlotFolder(&sandboxInstance{socketPath: sock}); got != "" {
		t.Fatalf("a slot with no digest %q", got)
	}
}

// shortSockets stands in for the helper's socket folder, short enough for
// a socket path on macOS, with another host's socket in it.
func shortSockets(t *testing.T) (string, string) {
	t.Helper()
	sockets, err := os.MkdirTemp("", "aws")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockets) })
	other := filepath.Join(sockets, "w-another.sock")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return sockets, other
}

// failingInstantiateClient fails every instantiate.
type failingInstantiateClient struct{ recordingWorkerClient }

func (*failingInstantiateClient) Instantiate(string, wasmengine.Capabilities) error {
	return errors.New("instantiate failed")
}

// TestSplitWarmClaimFailureRemovesTheSlotFolder: a create that took a
// warm slot and failed removes the slot's folder, not its socket's.
func TestSplitWarmClaimFailureRemovesTheSlotFolder(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	sockets, other := shortSockets(t)
	slotDir := filepath.Join(dir, "slot")
	if err := os.MkdirAll(slotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := New(Config{RunDir: filepath.Join(dir, "run"), ModulesDir: dir, HelperSockets: sockets,
		Worker: worker.Confinement{UID: os.Getuid(), GID: shareGID()}}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "deadbeef"})
	d.SetWorkerSupervisor(&fakeSupervisor{})
	d.SetWorkerClientFactory(func(string) WorkerClient { return &failingInstantiateClient{} })
	d.SetWarmPool(&fakeWarmPool{slot: &wasmpool.Slot{ID: "pool-0123456789abcdef", ModuleDigest: "deadbeef", ModulePath: modPath,
		SocketPath: filepath.Join(sockets, "w-pool-0123456789abcdef.sock"), WorkerKey: "pool-0123456789abcdef", MemoryMB: 256, Dir: slotDir}})
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "demo.wasm"}, "sb-warm", "tok", nil); err == nil {
		t.Fatal("create succeeded")
	}
	if _, err := os.Stat(slotDir); !os.IsNotExist(err) {
		t.Fatalf("slot folder left: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("the helper's socket folder was touched: %v", err)
	}
}
