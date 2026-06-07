package wasm

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// inProcessSupervisor runs worker.Server on a unix socket without a subprocess.
type inProcessSupervisor struct {
	mu      sync.Mutex
	workers map[string]*inProcessWorker
}

type inProcessWorker struct {
	ln   net.Listener
	stop chan struct{}
}

func newInProcessSupervisor() *inProcessSupervisor {
	return &inProcessSupervisor{workers: make(map[string]*inProcessWorker)}
}

func (s *inProcessSupervisor) Ensure(ctx context.Context, sandboxID, socketPath string) error {
	s.mu.Lock()
	if _, ok := s.workers[sandboxID]; ok {
		s.mu.Unlock()
		return nil
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	stop := make(chan struct{})
	s.workers[sandboxID] = &inProcessWorker{ln: ln, stop: stop}
	s.mu.Unlock()

	srv := &worker.Server{}
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			go func(c net.Conn) { _ = srv.Serve(c) }(conn)
		}
	}()

	client := worker.NewClient(socketPath)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.Ping(sandboxID); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return fmt.Errorf("worker not ready at %s", socketPath)
}

func (s *inProcessSupervisor) Stop(sandboxID string) error {
	s.mu.Lock()
	w, ok := s.workers[sandboxID]
	if ok {
		delete(s.workers, sandboxID)
	}
	s.mu.Unlock()
	if !ok {
		return nil
	}
	close(w.stop)
	return w.ln.Close()
}

func TestCheckpointRehydrateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// macOS sun_path is capped at 104 bytes — keep worker sockets under /tmp.
	runDir := filepath.Join(os.TempDir(), "aw")
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	modulesDir := filepath.Join(dir, "modules")
	if err := os.MkdirAll(modulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	modPath := wasmmod.WriteCheckpointWasm(t, modulesDir, "demo.wasm")

	sup := newInProcessSupervisor()
	t.Cleanup(func() {
		for id := range sup.workers {
			_ = sup.Stop(id)
		}
	})

	d := New(Config{RunDir: runDir, ModulesDir: modulesDir, DefaultMemoryMB: 64}, nil)
	d.SetModuleResolver(fakeResolver{path: modPath, digest: "abc123"})
	d.SetWorkerSupervisor(sup)

	sandboxID := "s1"
	ctx := context.Background()
	req := models.CreateSandboxRequest{
		Image:      "demo.wasm",
		Durability: models.DurabilityPassivatable,
		MemoryMB:   64,
	}
	state, err := d.Create(ctx, req, sandboxID, "", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state.Status != models.SandboxStatusStarted {
		t.Fatalf("status = %q, want started", state.Status)
	}

	managed, err := d.ListManaged(ctx)
	if err != nil {
		t.Fatalf("ListManaged: %v", err)
	}
	if len(managed) != 1 {
		t.Fatalf("managed count = %d, want 1", len(managed))
	}

	sb := &models.Sandbox{
		ID:           sandboxID,
		Durability:   models.DurabilityPassivatable,
		ModuleRef:    "demo.wasm",
		ModuleDigest: "abc123",
		MemoryMB:     64,
	}
	path, gen, err := d.CheckpointSandbox(ctx, sb)
	if err != nil {
		t.Fatalf("CheckpointSandbox: %v", err)
	}
	if path == "" || gen == "" {
		t.Fatalf("checkpoint path/gen empty: path=%q gen=%q", path, gen)
	}
	if !wasmengine.DirExists(path) {
		t.Fatalf("mem.snap missing at %s", path)
	}

	managed, err = d.ListManaged(ctx)
	if err != nil {
		t.Fatalf("ListManaged after checkpoint: %v", err)
	}
	if len(managed) != 0 {
		t.Fatalf("expected no live instances after checkpoint, got %d", len(managed))
	}

	sb.Status = models.SandboxStatusPassivated
	sb.CheckpointPath = path
	sb.CloneGeneration = gen
	state2, err := d.RehydrateSandbox(ctx, sb)
	if err != nil {
		t.Fatalf("RehydrateSandbox: %v", err)
	}
	if state2.Status != models.SandboxStatusStarted {
		t.Fatalf("rehydrated status = %q, want started", state2.Status)
	}

	managed, err = d.ListManaged(ctx)
	if err != nil {
		t.Fatalf("ListManaged after rehydrate: %v", err)
	}
	if len(managed) != 1 {
		t.Fatalf("expected one live instance after rehydrate, got %d", len(managed))
	}
}
