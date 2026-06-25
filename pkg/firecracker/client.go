// Package firecracker is a thin Go wrapper around the Firecracker VMM's
// HTTP-over-Unix-socket REST API. It is intentionally small: a *Client
// owns a single VMM's API socket and exposes one Go method per Firecracker
// resource (machine-config, boot-source, drives, net-ifaces, vsock,
// actions, vm state, snapshot/{create,load}).
//
// The package has no daemon-side state of its own. Lifecycle ownership —
// spawning the `firecracker` (or `jailer`-wrapped) process, knowing where
// its socket lives, supervising its exit — lives in
// internal/runtime/firecracker/, which uses this client to talk to the
// VMM it manages. Mirrors pkg/caddy/client.go in spirit: thin per-resource
// methods, idempotent where the upstream API is idempotent, errors
// returned verbatim with HTTP status context attached.
//
// Firecracker's HTTP API is documented at
// https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml.
// Stay close to that wire shape — every type in types.go corresponds to
// exactly one schema there.
package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// DefaultRequestTimeout caps a single REST call against the VMM. Firecracker
// itself responds in single-digit milliseconds for normal operations; we keep
// a generous ceiling so snapshot-load on a large memory file (mmap is fast
// but the API call still blocks on the kernel side) doesn't trip on a tight
// deadline. Callers that need their own ctx deadline should pass it to the
// methods — this is only the fallback.
const DefaultRequestTimeout = 30 * time.Second

// Client is a single-VMM Firecracker API client. One Client per Firecracker
// process; callers must not share a Client across processes because each
// VMM has its own socket. Methods are safe for concurrent use — the
// Firecracker API serializes mutations server-side and our http.Client is
// goroutine-safe.
type Client struct {
	socketPath string
	httpClient *http.Client
}

// New returns a Client that talks to the Firecracker API socket at
// socketPath. The socket need not exist at construction time; method calls
// will fail with a connect error until the VMM is spawned and binds it.
//
// The returned client uses HTTP/1.1 over a Unix-domain stream — Firecracker's
// only transport. The fake "http://localhost" host in request URLs is a
// convention of net/http when the transport ignores it; the real address
// is socketPath.
func New(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		httpClient: &http.Client{
			Timeout: DefaultRequestTimeout,
			Transport: &http.Transport{
				// One UDS dial per request keeps the implementation
				// trivial. Firecracker's API is low-frequency (a few calls
				// at create time, then maybe a snapshot/action later), so
				// connection pooling buys nothing.
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
				DisableKeepAlives: true,
			},
		},
	}
}

// SocketPath returns the API socket path this client targets. Useful for
// log lines that want to identify which VMM a call landed against without
// reaching into the runtime driver's bookkeeping.
func (c *Client) SocketPath() string { return c.socketPath }

// Ping checks the VMM is reachable by issuing GET / (returns InstanceInfo).
// A nil error means the socket accepted a request and the VMM replied — it
// does NOT imply the guest has booted; for that, callers handshake with the
// in-VM agent over vsock.
func (c *Client) Ping(ctx context.Context) error {
	var info InstanceInfo
	return c.do(ctx, http.MethodGet, "/", nil, &info)
}

// InstanceInfo returns the VMM's self-reported state. Useful for confirming
// the guest is "Running" after InstanceStart or "Paused" after a snapshot
// load with resume_vm=false.
func (c *Client) InstanceInfo(ctx context.Context) (*InstanceInfo, error) {
	var info InstanceInfo
	if err := c.do(ctx, http.MethodGet, "/", nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// PutMachineConfig sets the VMM-wide CPU/memory shape. Must precede
// InstanceStart on a fresh VMM; ignored on a VMM that loads a snapshot
// (the snapshot already encodes the shape).
func (c *Client) PutMachineConfig(ctx context.Context, cfg MachineConfig) error {
	return c.do(ctx, http.MethodPut, "/machine-config", cfg, nil)
}

// PutBootSource declares the kernel image and command line for a cold-boot
// VMM. Not used on snapshot-load — the kernel is in the memory file there.
func (c *Client) PutBootSource(ctx context.Context, src BootSource) error {
	return c.do(ctx, http.MethodPut, "/boot-source", src, nil)
}

// PutDrive attaches (or replaces) a block device by drive_id. The first
// drive with IsRootDevice=true is the rootfs; additional drives are
// per-sandbox overlays / data disks.
//
// On a snapshot-loaded VMM, this method is used between snapshot/load and
// Resume to swap the per-sandbox overlay onto the clone — the host_dev_path
// is the only piece that differs between clones of the same template.
func (c *Client) PutDrive(ctx context.Context, driveID string, drv Drive) error {
	return c.do(ctx, http.MethodPut, "/drives/"+driveID, drv, nil)
}

// PatchDrive updates a subset of drive fields on a running or paused VMM.
// Today the only mutable field is path_on_host — used by the clone path to
// rebind a per-sandbox overlay before Resume.
func (c *Client) PatchDrive(ctx context.Context, driveID string, patch DrivePatch) error {
	return c.do(ctx, http.MethodPatch, "/drives/"+driveID, patch, nil)
}

// PutNetworkInterface attaches a TAP device by iface_id. Like PutDrive,
// this is also used post-snapshot-load to swap the per-sandbox TAP onto a
// resumed clone.
func (c *Client) PutNetworkInterface(ctx context.Context, ifaceID string, iface NetworkInterface) error {
	return c.do(ctx, http.MethodPut, "/network-interfaces/"+ifaceID, iface, nil)
}

// PatchNetworkInterface updates a subset of network-interface fields on a
// VMM after snapshot/load. The mutable field today is host_dev_name — the
// TAP swap on each clone.
func (c *Client) PatchNetworkInterface(ctx context.Context, ifaceID string, patch NetworkInterfacePatch) error {
	return c.do(ctx, http.MethodPatch, "/network-interfaces/"+ifaceID, patch, nil)
}

// PutVsock attaches a virtio-vsock device. The UDS path on the host is
// where in-guest connections to (CID 2, port N) appear; the toolbox agent
// listens on (CID 3, port N) inside the guest. Vsock is the snapshot-safe
// host↔guest channel; TCP over the TAP would tear on resume.
func (c *Client) PutVsock(ctx context.Context, v Vsock) error {
	return c.do(ctx, http.MethodPut, "/vsock", v, nil)
}

// PutLogger attaches a file-backed logger to the VMM. Optional but useful
// for capturing Firecracker's own diagnostic output during early bring-up.
func (c *Client) PutLogger(ctx context.Context, lg Logger) error {
	return c.do(ctx, http.MethodPut, "/logger", lg, nil)
}

// Action issues a single action against the VMM. Firecracker v1.15 keeps
// InstanceStart on /actions; Paused/Resumed transitions use PatchVM instead.
func (c *Client) Action(ctx context.Context, a Action) error {
	return c.do(ctx, http.MethodPut, "/actions", a, nil)
}

// PatchVM updates the microVM running state. Firecracker accepts Paused and
// Resumed here; sending those values to /actions is rejected by v1.15.
func (c *Client) PatchVM(ctx context.Context, vm VM) error {
	return c.do(ctx, http.MethodPatch, "/vm", vm, nil)
}

// CreateSnapshot writes a memory file + state file to the paths in req.
// Callers should put the VM in the Paused state first. SnapshotType=Full is
// the only option supported at template-build time; Diff is taken
// automatically by enable_diff_snapshots on load and does not flow through
// this call.
func (c *Client) CreateSnapshot(ctx context.Context, req SnapshotCreate) error {
	return c.do(ctx, http.MethodPut, "/snapshot/create", req, nil)
}

// LoadSnapshot resumes a VMM from a memory file + state file pair. With
// EnableDiffSnapshots=true, the loaded memory file is mmap'd as the CoW
// base for the clone; per-clone writes land in a dirty bitmap and do not
// disturb the base — the property the whole plan rests on. With
// ResumeVM=true, the action implicitly resumes execution; otherwise the
// caller must PATCH /vm state=Resumed after attaching per-clone drives/TAP.
func (c *Client) LoadSnapshot(ctx context.Context, req SnapshotLoad) error {
	return c.do(ctx, http.MethodPut, "/snapshot/load", req, nil)
}

// do executes a single REST call. The body, when non-nil, is JSON-encoded.
// The result, when non-nil, decodes a JSON response body. Firecracker
// returns 204 No Content on most mutations and a small JSON object on GET;
// we treat any 2xx as success and any non-2xx as APIError with the raw body
// surfaced so operators can read Firecracker's own error shape.
func (c *Client) do(ctx context.Context, method, path string, body, result any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("firecracker: marshal %s %s: %w", method, path, err)
		}
		reqBody = bytes.NewReader(buf)
	}
	// The host portion is ignored by the UDS transport but net/http requires
	// a well-formed URL. "http://localhost" is the conventional placeholder.
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, reqBody)
	if err != nil {
		return fmt.Errorf("firecracker: build request %s %s: %w", method, path, err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("firecracker: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		// Firecracker returns {"fault_message":"..."} on errors. We don't
		// parse it here so unknown shapes are still surfaced verbatim; the
		// runtime driver can grep on the substring if it needs to branch.
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &APIError{
			Method: method,
			Path:   path,
			Status: resp.StatusCode,
			Body:   string(bytes.TrimSpace(raw)),
		}
	}
	if result == nil {
		return nil
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(result); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("firecracker: decode %s %s: %w", method, path, err)
	}
	return nil
}

// APIError carries a non-2xx response from the Firecracker API. Body is the
// raw response payload (typically a {"fault_message": "..."} JSON object);
// callers can switch on Status for retry decisions.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("firecracker: %s %s -> %d", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("firecracker: %s %s -> %d: %s", e.Method, e.Path, e.Status, e.Body)
}
