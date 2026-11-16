package wasm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// gatedStopClient is a streaming fake whose StopInstance and Checkpoint
// wait for the test, so the test can act while a stop is under way.
type gatedStopClient struct {
	*fakeStreamingClient
	entered chan struct{}
	gate    chan struct{}
}

func (c gatedStopClient) wait() {
	c.entered <- struct{}{}
	<-c.gate
}

func (c gatedStopClient) StopInstance(string) error { c.wait(); return nil }

func (c gatedStopClient) Checkpoint(context.Context, string, string, wasmengine.SnapshotConfig) error {
	c.wait()
	return nil
}

// gatedStartClient is a streaming fake whose StartExec waits for the test,
// so a start can be caught between its checks and its registration.
type gatedStartClient struct {
	*fakeStreamingClient
	entered chan struct{}
	gate    chan struct{}
}

func (c gatedStartClient) StartExec(ctx context.Context, id string, p worker.ExecStartPayload) (workerExecStream, error) {
	c.entered <- struct{}{}
	<-c.gate
	return c.fakeStreamingClient.StartExec(ctx, id, p)
}

func stoppingDriver(t *testing.T) (*Driver, *sandboxInstance) {
	t.Helper()
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWorkerSupervisor(&fakeSupervisor{})
	inst := &sandboxInstance{sandboxID: "sb", status: models.SandboxStatusStarted, socketPath: "/tmp/x.sock", workDir: t.TempDir(), workerKey: "sb"}
	d.byID["sb"] = inst
	return d, inst
}

// TestStopRefusesWorkThatArrivesDuringIt: Stop, and a checkpoint that
// passivates, mark the sandbox stopping before their kill pass. A request
// that arrives while they wait on the worker can no longer start a run,
// make a session set or make interpreter state, any of which would have
// outlived the stop (a run on a stopped sandbox, sessions and contexts
// that a restart would find).
func TestStopRefusesWorkThatArrivesDuringIt(t *testing.T) {
	for _, op := range []string{"stop", "passivate"} {
		t.Run(op, func(t *testing.T) {
			d, inst := stoppingDriver(t)
			fake := &fakeStreamingClient{}
			client := gatedStopClient{fakeStreamingClient: fake, entered: make(chan struct{}, 2), gate: make(chan struct{})}
			d.SetWorkerClientFactory(func(string) WorkerClient { return client })
			ctx := context.Background()
			done := make(chan error, 1)
			go func() {
				if op == "stop" {
					done <- d.Stop(ctx, "sb")
					return
				}
				_, _, err := d.CheckpointSandbox(ctx, &models.Sandbox{ID: "sb"})
				done <- err
			}()
			select {
			case <-client.entered: // past the kill pass, waiting on the worker
			case <-time.After(5 * time.Second):
				t.Fatal("the stop never reached the worker")
			}

			if _, err := d.StartStream(ctx, "sb", StreamSpec{Args: []string{"x"}}); !errors.Is(err, ErrSandboxNotRunning) {
				t.Errorf("StartStream during the %s = %v, want ErrSandboxNotRunning", op, err)
			}
			if err := (sandboxProcesses{driver: d, id: "sb"}).CanStart(); !errors.Is(err, toolhost.ErrSandboxNotRunning) {
				t.Errorf("CanStart during the %s = %v", op, err)
			}
			if _, err := d.sessionsFor("sb"); !errors.Is(err, toolhost.ErrSessionStopped) {
				t.Errorf("sessionsFor during the %s = %v, want ErrSessionStopped", op, err)
			}
			if st := d.interpreters("sb"); st != nil {
				t.Errorf("interpreter state made during the %s", op)
			}

			close(client.gate)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			d.mu.Lock()
			sessions, interp := inst.sessions, inst.interp
			d.mu.Unlock()
			if len(fake.starts) != 0 || sessions != nil || interp != nil {
				t.Fatalf("after the %s: %d starts, sessions %v, interpreter %v", op, len(fake.starts), sessions != nil, interp != nil)
			}
		})
	}
}

// TestStartStreamRacingAStopIsEnded: a start that passed its checks before
// Stop began, and reaches the worker only after Stop's kill pass, is not
// registered on the stopped sandbox: it is killed and closed, and its slot
// is given back.
func TestStartStreamRacingAStopIsEnded(t *testing.T) {
	d, inst := stoppingDriver(t)
	fake := &fakeStreamingClient{}
	client := gatedStartClient{fakeStreamingClient: fake, entered: make(chan struct{}, 1), gate: make(chan struct{})}
	d.SetWorkerClientFactory(func(string) WorkerClient { return client })
	ctx := context.Background()
	type result struct {
		st  *Stream
		err error
	}
	started := make(chan result, 1)
	go func() {
		st, err := d.StartStream(ctx, "sb", StreamSpec{Args: []string{"x"}, Stdin: true, NoDeadline: true})
		started <- result{st, err}
	}()
	<-client.entered
	if err := d.Stop(ctx, "sb"); err != nil {
		t.Fatal(err)
	}
	close(client.gate)
	res := <-started
	if !errors.Is(res.err, ErrSandboxNotRunning) || res.st != nil {
		t.Fatalf("start racing a stop = %v, %v; want ErrSandboxNotRunning", res.st, res.err)
	}
	fs := fake.streams[0]
	fs.mu.Lock()
	kills := fs.kills
	fs.mu.Unlock()
	select {
	case <-fs.closed:
	default:
		t.Fatal("the late run's connection was left open")
	}
	if kills != 1 || inst.streams.count() != 0 {
		t.Fatalf("late run: kills %d, slots held %d", kills, inst.streams.count())
	}
	// A stop that fails leaves the sandbox running and taking runs again.
	d2, _ := stoppingDriver(t)
	failing := &failingStopClient{fakeStreamingClient: &fakeStreamingClient{}}
	d2.SetWorkerClientFactory(func(string) WorkerClient { return failing })
	if err := d2.Stop(ctx, "sb"); err == nil {
		t.Fatal("Stop with a failing worker succeeded")
	}
	if _, err := d2.StartStream(ctx, "sb", StreamSpec{Args: []string{"x"}}); err != nil {
		t.Fatalf("StartStream after a failed stop = %v", err)
	}
}

// failingStopClient fails StopInstance.
type failingStopClient struct {
	*fakeStreamingClient
}

func (c failingStopClient) StopInstance(string) error { return errors.New("worker gone") }
