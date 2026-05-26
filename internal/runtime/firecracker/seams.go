package firecracker

// seams.go declares the small set of "talks to the host" interfaces the
// driver depends on, so:
//
//   - cmd/sandboxd/main.go can inject one production implementation per
//     seam at boot (the adapters there are a few lines each — most are
//     passthroughs to pkg/oci.Builder, internal/network/tap.Host, and an
//     AF_VSOCK dialer).
//
//   - the test binary can swap in fakes that don't need root, don't need
//     subprocess access, and don't need a Linux kernel. Driver.Create's
//     orchestration is exercised on darwin against the same code path
//     the daemon runs in production.
//
//   - this package stays import-cycle-free: internal/network/tap depends
//     on internal/store, and pkg/oci shells out to skopeo/umoci/mkfs.ext4 —
//     dragging either into the driver's test binary makes test runs
//     fragile and slow.
//
// Adding a seam: only when Driver.Create / Destroy / ... actually
// needs one. Pre-populating with "everything tap.Host can do" is the
// fastest way to make this file rot.

import (
	"context"
	"io"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
)

// RootfsBuilder is the seam for turning an OCI image reference into a
// rootfs.ext4 file the VMM can boot. Production impl is a thin adapter
// around *pkg/oci.Builder; tests use a fake that touches a file at
// OutPath.
type RootfsBuilder interface {
	// Build produces an ext4 image at req.OutPath. Returns a *RootfsResult
	// describing where the staging directory is so the caller can clean
	// it up after the rootfs has been promoted to the per-template
	// directory.
	Build(ctx context.Context, req RootfsBuildRequest) (*RootfsResult, error)
}

// RootfsBuildRequest mirrors pkg/oci.BuildRequest. Re-declared here so
// the runtime package's seam can be satisfied without importing
// pkg/oci. main.go's adapter is the single conversion point. Field
// semantics match pkg/oci.BuildRequest exactly — see that doc comment
// for the wire-shape contract.
type RootfsBuildRequest struct {
	ImageRef   string
	OutPath    string
	MinSizeMiB int
	Tag        string
}

// RootfsResult is the seam-side mirror of pkg/oci.Result. The driver
// cares about three things: where the rootfs landed, where to clean
// up, and how to perform the cleanup (so the seam owns the temp tree).
type RootfsResult struct {
	RootfsPath string
	StagingDir string
	SizeBytes  int64
	cleanup    func() error
}

// Cleanup removes the staging tree. Idempotent (a second call is a
// no-op) and best-effort (a stale tree costs disk, not correctness).
func (r *RootfsResult) Cleanup() error {
	if r == nil || r.cleanup == nil {
		return nil
	}
	fn := r.cleanup
	r.cleanup = nil
	return fn()
}

// NewRootfsResult is the constructor adapters use to attach their own
// cleanup hook. The unexported field stays out of the public API so
// fake builders can't accidentally bypass the seam's idempotency
// guarantee.
func NewRootfsResult(rootfsPath, stagingDir string, sizeBytes int64, cleanup func() error) *RootfsResult {
	return &RootfsResult{
		RootfsPath: rootfsPath,
		StagingDir: stagingDir,
		SizeBytes:  sizeBytes,
		cleanup:    cleanup,
	}
}

// TapHost is the seam for putting a TAP slot onto the host's network
// surface. Production impl is *internal/network/tap.Host; tests use a
// fake that records calls. Uses TapSlot (declared in driver.go) so the
// seam stays inside the runtime package's type domain.
type TapHost interface {
	Ensure(ctx context.Context, slot TapSlot) error
	Remove(ctx context.Context, tapName string) error
}

// VsockDialer is the seam for opening AF_VSOCK from the host into the
// guest. The driver's post-InstanceStart readiness check dials
// (CID=guest-cid, port=defaultVsockPort) and Pings the toolbox. The
// dial deadline is enforced by ctx.
//
// Production impl is Linux-only (vsock_dial_linux.go); the darwin stub
// returns "AF_VSOCK is Linux-only" so the driver compiles on a dev box.
type VsockDialer interface {
	Dial(ctx context.Context, cid, port uint32) (io.ReadWriteCloser, error)
}

// VMMHandle is the subset of *vmm the driver uses. Interface form lets
// Create's orchestration be exercised in tests without spawning the
// real firecracker binary — vmm_fake.go in the test binary satisfies
// it and the tests inspect Start/WaitSocket/Shutdown calls directly.
type VMMHandle interface {
	APISocket() string
	RunDir() string
	Start(ctx context.Context) error
	WaitSocket(ctx context.Context, timeout time.Duration) error
	Shutdown(ctx context.Context, grace time.Duration) error
	Kill() error
	Cleanup() error
	StderrTail() string
}

// vmmSpawner is the seam Driver.Create uses to construct a VMMHandle.
// Function-shaped rather than interface-shaped because the only
// contract the driver depends on is "give me a handle for this
// sandbox ID under this config" — anything more (Stop, Status) would
// over-specify. Default impl wraps newVMM; tests inject a fake.
type vmmSpawner func(cfg Config, sandboxID string) (VMMHandle, error)

// vmmClientFactory is the seam for constructing a Firecracker REST
// client targeting a given API socket path. Default impl wraps
// firecracker.New; tests inject a fake that returns a mock client
// recording all REST calls without needing a UDS at all.
type vmmClientFactory func(socketPath string) VMMClient

// VMMClient is the subset of *pkg/firecracker.Client Driver.Create and
// Driver.SnapshotTemplate use. Adding a method here is the discipline
// gate for "yes, this orchestration step is part of the driver" — keep
// it tight. CreateSnapshot / LoadSnapshot are the Phase 3 additions for
// the template snapshot capture and the per-sandbox snapshot-load fast
// boot paths respectively.
type VMMClient interface {
	PutMachineConfig(ctx context.Context, cfg firecracker.MachineConfig) error
	PutBootSource(ctx context.Context, src firecracker.BootSource) error
	PutDrive(ctx context.Context, driveID string, drv firecracker.Drive) error
	PutNetworkInterface(ctx context.Context, ifaceID string, iface firecracker.NetworkInterface) error
	PutVsock(ctx context.Context, v firecracker.Vsock) error
	Action(ctx context.Context, a firecracker.Action) error
	InstanceInfo(ctx context.Context) (*firecracker.InstanceInfo, error)
	CreateSnapshot(ctx context.Context, req firecracker.SnapshotCreate) error
	LoadSnapshot(ctx context.Context, req firecracker.SnapshotLoad) error
	// PatchDrive is the snapshot-load + overlay seam (Phase 3 PR-B).
	// Firecracker accepts a PATCH of `path_on_host` between LoadSnapshot
	// and Action(Resume); the driver uses it to swap the template's
	// placeholder overlay (1 MiB scratch file from snapshot capture
	// time) for the clone's own per-sandbox overlay.ext4 before the VM
	// resumes. Drive geometry (read-only flag, cache type) is
	// inherited from the snapshot state — only the backing path is
	// mutable.
	PatchDrive(ctx context.Context, driveID string, patch firecracker.DrivePatch) error
}

// defaultVsockPort is the in-guest port the toolbox listens on. Must
// match cmd/toolboxd/vsock.go's defaultVsockPort exactly. Hardcoded
// here rather than imported because cmd/toolboxd is a main package and
// we don't want the runtime to pull it in just to share a constant.
const defaultVsockPort uint32 = 1024

// hostVsockUDSName is the filename used for the host-side vsock UDS
// firecracker binds inside the runDir. firecracker writes per-port
// sockets at <name>_<port>, but our dialer uses AF_VSOCK directly and
// never opens these files — they're for socat-style debugging.
const hostVsockUDSName = "vsock.sock"

// rootfsFileName is the filename of the rootfs.ext4 inside the per-
// sandbox runDir. Mirroring the firecracker docs' convention keeps the
// debug runbook ("look in /srv/firecracker/<id>/rootfs.ext4") accurate.
const rootfsFileName = "rootfs.ext4"

// rootDriveID is the drive_id firecracker uses for the rootfs drive.
// Mirrored from the firecracker example configs; the guest kernel boots
// from this drive id.
const rootDriveID = "rootfs"

// primaryIfaceID is the iface_id used for the per-sandbox TAP. One TAP
// per sandbox today; Phase 4+ may add a second for sandboxed-to-
// internet egress via a different bridge.
const primaryIfaceID = "eth0"

// overlayDriveID is the drive_id of the per-sandbox writable overlay
// drive (Phase 3 PR-B). On cold-boot the driver attaches it via
// PutDrive when CreateSandboxRequest.OverlaySizeGB > 0; on snapshot-
// load it is PATCHed in-place between LoadSnapshot and Resume so the
// clone gets its own backing file. The guest sees this device as
// /dev/vdb (rootfs is /dev/vda).
const overlayDriveID = "overlay"

// overlayFileName is the filename of the per-sandbox overlay.ext4
// sparse file inside the runDir. Mirrors rootfsFileName for the same
// debug-runbook reason.
const overlayFileName = "overlay.ext4"

// overlayPlaceholderBytes is the size of the placeholder overlay file
// allocated at snapshot capture time. The capture only persists the
// virtio-blk device shape into the snapshot state; the placeholder
// path is discarded with the staging runDir when the snapshot phase
// concludes. Kept at 1 MiB so the capture is fast and the placeholder
// occupies no real disk (sparse) — clones PATCH to their own
// per-sandbox file whose size is governed by OverlaySizeGB.
const overlayPlaceholderBytes int64 = 1 << 20
