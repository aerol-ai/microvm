package worker

import (
	"context"
	"fmt"
	"net"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// Client talks to one worker over a Unix domain socket.
type Client struct {
	socketPath string
	dial       func(string) (net.Conn, error)
}

// NewClient dials socketPath for each request.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		dial: func(path string) (net.Conn, error) {
			return net.DialTimeout("unix", path, 2*time.Second)
		},
	}
}

func (c *Client) roundTrip(env Envelope) (Envelope, error) {
	dial := c.dial
	socketPath := c.socketPath
	conn, err := dial(socketPath)
	if err != nil {
		return Envelope{}, err
	}
	defer conn.Close()
	if err := writeFrame(conn, env); err != nil {
		return Envelope{}, err
	}
	reply, err := readFrame(conn)
	if err != nil {
		return Envelope{}, err
	}
	return reply, nil
}

func (c *Client) roundTripContext(ctx context.Context, env Envelope) (Envelope, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Avoid launching a dial goroutine for an already-cancelled request. Apart
	// from unnecessary work, a custom/test dialer could otherwise outlive the
	// call and retain resources after the caller has moved on.
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}
	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	done := make(chan struct{})
	// Capture immutable request dependencies before the goroutine starts. A
	// cancelled dial may outlive this call, and must not dereference Client
	// fields after the caller has returned.
	dial := c.dial
	socketPath := c.socketPath
	defer close(done)
	go func() {
		conn, err := dial(socketPath)
		select {
		case ch <- dialResult{conn: conn, err: err}:
		case <-done:
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	var res dialResult
	select {
	case res = <-ch:
	case <-ctx.Done():
		return Envelope{}, ctx.Err()
	}
	if res.err != nil {
		return Envelope{}, res.err
	}
	conn := res.conn
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeFrame(conn, env); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Envelope{}, ctxErr
		}
		return Envelope{}, err
	}
	reply, err := readFrame(conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Envelope{}, ctxErr
		}
		return Envelope{}, err
	}
	return reply, nil
}

func (c *Client) expectOK(reply Envelope) error {
	if reply.Type == MsgError {
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return err
		}
		return fmt.Errorf("%s", p.Message)
	}
	if reply.Type != MsgOK {
		return fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	return nil
}

// Ping verifies the worker responds to HealthPing.
func (c *Client) Ping(sandboxID string) error {
	reply, err := c.roundTrip(Envelope{Type: MsgHealthPing, SandboxID: sandboxID})
	if err != nil {
		return err
	}
	if reply.Type != MsgPong {
		return fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	return nil
}

// InstanceLoaded reports whether the worker currently has an engine/module loaded.
func (c *Client) InstanceLoaded(ctx context.Context, sandboxID string) (bool, error) {
	reply, err := c.roundTripContext(ctx, Envelope{Type: MsgInstanceStatus, SandboxID: sandboxID})
	if err != nil {
		return false, err
	}
	if reply.Type == MsgError {
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return false, err
		}
		return false, fmt.Errorf("%s", p.Message)
	}
	if reply.Type != MsgOK {
		return false, fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	var p instanceStatusPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return false, err
	}
	return p.Loaded, nil
}

// LoadModule compiles the module at path inside the worker process and returns
// the sub-stage timing breakdown (best-effort; zero-valued if the worker did
// not report it) so the host create path can emit wasm_load Server-Timing subs.
func (c *Client) LoadModule(sandboxID, path string, memoryMB int) (wasmengine.LoadTimings, error) {
	body, err := encodePayload(loadModulePayload{Path: path, MemoryMB: memoryMB})
	if err != nil {
		return wasmengine.LoadTimings{}, err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgLoadModule, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return wasmengine.LoadTimings{}, err
	}
	if err := c.expectOK(reply); err != nil {
		return wasmengine.LoadTimings{}, err
	}
	var p loadModuleResultPayload
	if len(reply.Payload) > 0 {
		// Timings are diagnostic only; a decode failure must not fail the load.
		_ = decodePayload(reply.Payload, &p)
	}
	return p.Timings, nil
}

// Instantiate creates a WASI instance with the given capabilities.
func (c *Client) Instantiate(sandboxID string, caps wasmengine.Capabilities) error {
	body, err := encodePayload(instantiatePayload{Caps: caps})
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgInstantiate, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// Exec re-instantiates with caps, invokes export, and returns captured IO.
func (c *Client) Exec(sandboxID string, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	body, err := encodePayload(execPayload{Caps: caps, Export: export})
	if err != nil {
		return wasmengine.RunResult{}, err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgExec, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return wasmengine.RunResult{}, err
	}
	if reply.Type == MsgError {
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return wasmengine.RunResult{}, err
		}
		return wasmengine.RunResult{}, fmt.Errorf("%s", p.Message)
	}
	if reply.Type != MsgInvokeResult {
		return wasmengine.RunResult{}, fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	var p execResultPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return wasmengine.RunResult{}, err
	}
	return wasmengine.RunResult{
		ExitCode: p.ExitCode,
		Stdout:   p.Stdout,
		Stderr:   p.Stderr,
		Usage:    p.Usage,
	}, nil
}

// Invoke calls an exported function (defaults to _start).
func (c *Client) Invoke(sandboxID, export string) error {
	body, err := encodePayload(invokePayload{Export: export})
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgInvoke, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// Checkpoint writes a mem.snap artifact to outDir.
func (c *Client) Checkpoint(ctx context.Context, sandboxID, outDir string, meta wasmengine.SnapshotConfig) error {
	body, err := encodePayload(checkpointPayload{OutDir: outDir, Meta: meta})
	if err != nil {
		return err
	}
	reply, err := c.roundTripContext(ctx, Envelope{Type: MsgCheckpoint, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// Restore loads a mem.snap artifact from dir into the active worker engine.
func (c *Client) Restore(sandboxID, dir string, caps wasmengine.Capabilities) error {
	body, err := encodePayload(restorePayload{Dir: dir, Caps: caps})
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgRestore, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// SetCapability hot-updates memory/wall-timeout caps on a running instance.
func (c *Client) SetCapability(sandboxID string, caps wasmengine.Capabilities) error {
	body, err := encodePayload(setCapabilityPayload{Caps: caps})
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgSetCapability, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// StopInstance tears down the active instance inside the worker.
func (c *Client) StopInstance(sandboxID string) error {
	reply, err := c.roundTrip(Envelope{Type: MsgStopInstance, SandboxID: sandboxID})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// NetstatsTick drains worker-side byte counters since the last poll (UC-43).
func (c *Client) NetstatsTick(sandboxID string) (bytesIn, bytesOut int64, err error) {
	reply, err := c.roundTrip(Envelope{Type: MsgNetstatsTick, SandboxID: sandboxID})
	if err != nil {
		return 0, 0, err
	}
	if reply.Type == MsgError {
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return 0, 0, err
		}
		return 0, 0, fmt.Errorf("%s", p.Message)
	}
	if reply.Type != MsgOK {
		return 0, 0, fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	var p netstatsResultPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return 0, 0, err
	}
	return p.BytesIn, p.BytesOut, nil
}

// SetNetworkBlocks applies quota blocks at the worker-side socket mediator (UC-43).
func (c *Client) SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) error {
	body, err := encodePayload(setNetworkBlocksPayload{
		BlockIngress: blockIngress,
		BlockEgress:  blockEgress,
	})
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgSetNetworkBlocks, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// TriggerPanic sends the test-only panic message. The worker process is expected to exit.
func (c *Client) TriggerPanic(sandboxID string) error {
	_, err := c.roundTrip(Envelope{Type: MsgTriggerPanic, SandboxID: sandboxID})
	return err
}
