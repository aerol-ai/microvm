package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
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

// dialWorker opens sandboxd's connection to the worker at path: refused
// for a quarantined worker, and read so that no descriptor the worker
// sends is released on the caller's goroutine (reaper.go).
func dialWorker(dial func(string) (net.Conn, error), path string) (net.Conn, error) {
	if err := workerQuarantined(path); err != nil {
		return nil, err
	}
	conn, err := dial(path)
	if err != nil {
		return nil, err
	}
	return wrapWorkerConn(conn, path)
}

func (c *Client) roundTrip(env Envelope, grants ...string) (Envelope, error) {
	conn, err := dialWorker(c.dial, c.socketPath)
	if err != nil {
		return Envelope{}, err
	}
	defer conn.Close()
	if err := writeGranted(conn, env, grants); err != nil {
		return Envelope{}, err
	}
	reply, err := readFrame(conn)
	if err != nil {
		return Envelope{}, err
	}
	return reply, nil
}

// roundTripStrict is roundTrip where the paths in strict must be files
// root owns.
func (c *Client) roundTripStrict(env Envelope, grants, strict []string) (Envelope, error) {
	conn, err := dialWorker(c.dial, c.socketPath)
	if err != nil {
		return Envelope{}, err
	}
	defer conn.Close()
	if err := writeGrantedFiles(conn, env, grants, strict); err != nil {
		return Envelope{}, err
	}
	return readFrame(conn)
}

func (c *Client) roundTripContext(ctx context.Context, env Envelope, grants ...string) (Envelope, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := c.dialContext(ctx)
	if err != nil {
		return Envelope{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeGranted(conn, env, grants); err != nil {
		if ctxErr := contextErr(ctx); ctxErr != nil {
			return Envelope{}, ctxErr
		}
		return Envelope{}, err
	}
	reply, err := readFrame(conn)
	if err != nil {
		if ctxErr := contextErr(ctx); ctxErr != nil {
			return Envelope{}, ctxErr
		}
		return Envelope{}, err
	}
	return reply, nil
}

// contextErr is ctx.Err(), but also reports a deadline that has passed
// before ctx's own timer fired. The connection carries the same deadline, so
// its read can fail with an i/o timeout a moment before ctx notices; callers
// must still see context.DeadlineExceeded, not the socket error.
func contextErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// dialContext dials the worker, giving up when ctx ends. A nil ctx means
// context.Background().
func (c *Client) dialContext(ctx context.Context) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Avoid launching a dial goroutine for an already-cancelled request. Apart
	// from unnecessary work, a custom/test dialer could otherwise outlive the
	// call and retain resources after the caller has moved on.
	if err := ctx.Err(); err != nil {
		return nil, err
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
		conn, err := dialWorker(dial, socketPath)
		select {
		case ch <- dialResult{conn: conn, err: err}:
		case <-done:
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case res := <-ch:
		return res.conn, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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

// InstanceStatus is a worker's answer about one sandbox's instance.
type InstanceStatus struct {
	// Loaded: the worker has its module loaded and, when Checked, holds the
	// asked sandbox's instance (a resident host: has an instance for it).
	Loaded bool
	// SandboxID is the sandbox whose instance the worker says it holds.
	SandboxID string
	// Checked is false from a worker that predates identity answers: it
	// cannot say whose instance it holds.
	Checked bool
}

// Foreign reports whether the worker said it holds another sandbox's
// instance than sandboxID's.
func (s InstanceStatus) Foreign(sandboxID string) bool {
	return s.Checked && sandboxID != "" && s.SandboxID != "" && s.SandboxID != sandboxID
}

// InstanceStatus asks the worker about sandboxID's instance ("" asks only
// whether the module is loaded).
func (c *Client) InstanceStatus(ctx context.Context, sandboxID string) (InstanceStatus, error) {
	reply, err := c.roundTripContext(ctx, Envelope{Type: MsgInstanceStatus, SandboxID: sandboxID})
	if err != nil {
		return InstanceStatus{}, err
	}
	if reply.Type == MsgError {
		var p errorPayload
		if err := decodePayload(reply.Payload, &p); err != nil {
			return InstanceStatus{}, err
		}
		return InstanceStatus{}, fmt.Errorf("%s", p.Message)
	}
	if reply.Type != MsgOK {
		return InstanceStatus{}, fmt.Errorf("unexpected reply type %q", reply.Type)
	}
	var p instanceStatusPayload
	if err := decodePayload(reply.Payload, &p); err != nil {
		return InstanceStatus{}, err
	}
	return InstanceStatus{Loaded: p.Loaded, SandboxID: p.SandboxID, Checked: p.Checked}, nil
}

// InstanceLoaded reports whether the worker has its module loaded and, for a
// sandboxID, still holds that sandbox's instance. A worker holding another
// sandbox's instance answers false, here as well as in the worker.
func (c *Client) InstanceLoaded(ctx context.Context, sandboxID string) (bool, error) {
	st, err := c.InstanceStatus(ctx, sandboxID)
	if err != nil {
		return false, err
	}
	return st.Loaded && !st.Foreign(sandboxID), nil
}

// LoadModule compiles the module at path inside the worker process and returns
// the sub-stage timing breakdown (best-effort; zero-valued if the worker did
// not report it) so the host create path can emit wasm_load Server-Timing subs.
func (c *Client) LoadModule(sandboxID, path string, memoryMB int) (wasmengine.LoadTimings, error) {
	body, err := encodePayload(loadModulePayload{Path: path, MemoryMB: memoryMB})
	if err != nil {
		return wasmengine.LoadTimings{}, err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgLoadModule, SandboxID: sandboxID, Payload: body}, path)
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
	reply, err := c.roundTrip(Envelope{Type: MsgInstantiate, SandboxID: sandboxID, Payload: body}, preopenPaths(caps)...)
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
	reply, err := c.roundTrip(Envelope{Type: MsgExec, SandboxID: sandboxID, Payload: body}, preopenPaths(caps)...)
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

// Checkpoint writes a mem.snap artifact to outDir. The worker is granted
// outDir's parent, where it writes the artifact and its temporary copy.
func (c *Client) Checkpoint(ctx context.Context, sandboxID, outDir string, meta wasmengine.SnapshotConfig) error {
	body, err := encodePayload(checkpointPayload{OutDir: outDir, Meta: meta})
	if err != nil {
		return err
	}
	reply, err := c.roundTripContext(ctx, Envelope{Type: MsgCheckpoint, SandboxID: sandboxID, Payload: body}, filepath.Dir(outDir))
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// Restore loads a mem.snap artifact from dir into the active worker engine.
// The worker is granted the artifact's files, never their directory.
func (c *Client) Restore(sandboxID, dir string, caps wasmengine.Capabilities) error {
	body, err := encodePayload(restorePayload{Dir: dir, Caps: caps})
	if err != nil {
		return err
	}
	files := wasmengine.SnapshotFiles(dir)
	reply, err := c.roundTripStrict(Envelope{Type: MsgRestore, SandboxID: sandboxID, Payload: body}, append(preopenPaths(caps), files...), files)
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
	reply, err := c.roundTrip(Envelope{Type: MsgSetCapability, SandboxID: sandboxID, Payload: body}, preopenPaths(caps)...)
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

// SetEgressPolicy replaces the sandbox's egress policy at the worker-side
// mediator (live update). Empty lists remove the policy.
func (c *Client) SetEgressPolicy(sandboxID string, allowOut, denyOut []string, learn bool) error {
	body, err := encodePayload(setEgressPolicyPayload{AllowOut: allowOut, DenyOut: denyOut, Learn: learn})
	if err != nil {
		return err
	}
	reply, err := c.roundTrip(Envelope{Type: MsgSetEgressPolicy, SandboxID: sandboxID, Payload: body})
	if err != nil {
		return err
	}
	return c.expectOK(reply)
}

// EgressLearned reads a sandbox's learn-mode recording from its worker.
func (c *Client) EgressLearned(sandboxID string) (egresspolicy.Learned, error) {
	reply, err := c.roundTrip(Envelope{Type: MsgEgressLearned, SandboxID: sandboxID})
	if err != nil {
		return egresspolicy.Learned{}, err
	}
	if reply.Type != MsgOK {
		return egresspolicy.Learned{}, c.expectOK(reply)
	}
	var l egresspolicy.Learned
	if err := decodePayload(reply.Payload, &l); err != nil {
		return egresspolicy.Learned{}, err
	}
	return l, nil
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

// preopenPaths are the host directories caps maps into the guest: what a
// message that (re)instantiates the guest grants the worker.
func preopenPaths(caps wasmengine.Capabilities) []string {
	paths := make([]string, 0, len(caps.Preopens))
	for _, p := range caps.Preopens {
		paths = append(paths, p.HostPath)
	}
	return paths
}

// writeGranted writes env with an open descriptor for each of paths
// attached (writeFrameFiles). sandboxd opens them as root; a path it cannot
// open, or that is neither a directory nor a regular file, is left out and
// the worker opens it itself, failing where it would have failed anyway.
// The descriptors are closed once sent: the worker has its own copies.
func writeGranted(conn net.Conn, env Envelope, paths []string) error {
	return writeGrantedFiles(conn, env, paths, nil)
}

// writeGrantedFiles is writeGranted where the paths in strict must be files
// root owns (snapshot files: openGrantPath).
func writeGrantedFiles(conn net.Conn, env Envelope, paths, strict []string) error {
	files, names := openGrantsStrict(paths, strict)
	defer closeFiles(files)
	env.FDPaths = names
	return writeFrameFiles(conn, env, files)
}

func openGrants(paths []string) ([]*os.File, []string) {
	return openGrantsStrict(paths, nil)
}

func openGrantsStrict(paths, strict []string) ([]*os.File, []string) {
	var files []*os.File
	var names []string
	seen := map[string]struct{}{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" || len(files) == maxFrameFiles {
			continue
		}
		path = filepath.Clean(path)
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		f, err := openGrant(path, grantOpenTimeout, slices.Contains(strict, path))
		if err != nil {
			continue
		}
		files = append(files, f)
		names = append(names, path)
	}
	return files, names
}

// grantOpenTimeout bounds one open in openGrants. A mount folder on a
// stalled network mount can hang an open; the message then goes without
// that grant (the worker fails to reach the mount, which is stalled
// anyway) rather than hold up the sandboxd request that sends it.
var grantOpenTimeout = 2 * time.Second

var errGrantTimeout = errors.New("open timed out")

// grantOpener is the open openGrant bounds (tests stand in a hung one).
var grantOpener = openGrantPath

// An open that outlives its timeout keeps running, and holds one of
// sandboxd's threads until the mount answers. A sandbox's messages name
// its mounts again and again (every exec, instantiate, set-capability and
// restore), so a path whose open is stuck is not opened again until that
// open returns: the message goes without the grant at once. And no more
// than maxGrantOpens opens run at once, stuck ones included, so stalled
// mounts can hold that many threads at most, far below the Go runtime's
// limit, at which the process dies. Past it, messages go without grants.
var (
	grantOpensMu  sync.Mutex
	grantRunning  int
	grantStuck    = map[string]struct{}{}
	maxGrantOpens = 512
)

var (
	errGrantStuck = errors.New("an earlier open of this path has not returned")
	errGrantBusy  = errors.New("too many opens in flight")
)

// openGrant opens path for a grant (openGrantPath), giving up after
// timeout. O_NONBLOCK keeps a FIFO from hanging the open; the type check
// then refuses it.
func openGrant(path string, timeout time.Duration, strict bool) (*os.File, error) {
	grantOpensMu.Lock()
	if _, stuck := grantStuck[path]; stuck {
		grantOpensMu.Unlock()
		return nil, errGrantStuck
	}
	if grantRunning >= maxGrantOpens {
		grantOpensMu.Unlock()
		return nil, errGrantBusy
	}
	grantRunning++
	grantOpensMu.Unlock()
	type result struct {
		f   *os.File
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := grantOpener(path, strict)
		done <- result{f, err}
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-done:
		grantOpenDone(path, false)
		return r.f, r.err
	case <-t.C:
		grantOpensMu.Lock()
		grantStuck[path] = struct{}{}
		grantOpensMu.Unlock()
		// Close it if the open ever returns; the path may be opened again
		// from then on.
		go func() {
			if r := <-done; r.f != nil {
				_ = r.f.Close()
			}
			grantOpenDone(path, true)
		}()
		return nil, errGrantTimeout
	}
}

// grantOpenDone ends an open openGrant started.
func grantOpenDone(path string, stuck bool) {
	grantOpensMu.Lock()
	grantRunning--
	if stuck {
		delete(grantStuck, path)
	}
	grantOpensMu.Unlock()
}
