package firecracker

// snapshot.go is the Phase 3 template-snapshot capture path. The service
// layer's two-stage template builder calls Driver.SnapshotTemplate after
// the rootfs.ext4 has landed on disk; this file owns the transient VMM
// lifecycle (spawn → boot → handshake → quiesce → pause → write snapshot
// → tear down) that turns "rootfs.ext4" into "rootfs.ext4 + snapshot.memory
// + snapshot.state".
//
// The cleanup contract mirrors Driver.Create's: every allocation gets a
// flag-and-defer release so a mid-pipeline error frees everything the
// goroutine acquired. The transient VMM, its TAP slot, and any partial
// snapshot files are all owned by this function — none of them leak into
// the Driver's per-sandbox registry maps.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TemplateSnapshotRequest is the driver-facing snapshot input. Mirrors
// service.TemplateSnapshotRequest exactly so the adapter in
// cmd/sandboxd/main.go is a one-field cast — keeping the shapes
// identical keeps the seam cheap and the mental model uniform.
type TemplateSnapshotRequest struct {
	TemplateID    string
	RootfsPath    string
	OutMemoryPath string
	OutStatePath  string
	GuestCID      uint32
	MemoryMB      int
	VCPU          int
}

// TemplateSnapshotResult is the driver-facing snapshot result. Mirrors
// service.TemplateSnapshotResult. Checksum is the joined
// "sha256:<hex>|sha256:<hex>" (memory|state) computed before return so
// the service layer can persist it as a single column.
type TemplateSnapshotResult struct {
	MemorySizeBytes int64
	StateSizeBytes  int64
	Checksum        string
}

// snapshotVMMIDPrefix scopes the synthetic sandbox ID used for the
// transient template VMM. The prefix keeps these IDs visibly distinct
// from real sandbox IDs in `ps` output and on-disk paths — operators
// triaging a stuck `tpl-snap-...` runDir know immediately it was a
// template build, not a user sandbox.
const snapshotVMMIDPrefix = "tpl-snap-"

// SnapshotTemplate captures a Firecracker full snapshot of the template
// VMM. Two artifact files (req.OutStatePath, req.OutMemoryPath) are
// written and SHA256'd before return; on success the rootfs.ext4 the
// snapshot booted from is untouched, so callers can promote both files
// to the per-template directory in one step.
//
// Cleanup discipline: every allocation (TAP slot, host TAP device, VMM
// process, partial output files) is wrapped in a flag-and-defer release
// so a mid-pipeline error tears everything down. Output files are
// removed on failure — a half-written snapshot.memory is worse than no
// snapshot at all because the integrity check at load time would
// rightly reject it but the row would be marked has_snapshot=true.
func (d *Driver) SnapshotTemplate(ctx context.Context, req TemplateSnapshotRequest) (*TemplateSnapshotResult, error) {
	// Same seam preconditions as Create. SnapshotTemplate shares the
	// pool, tapHost, and vsockDial dependencies — the rootfs builder
	// is the only seam Create needs that snapshot does not (the rootfs
	// is already on disk before we get here).
	if d.pool == nil {
		return nil, fmt.Errorf("firecracker snapshot: TAP pool not registered (main.go must call SetPool): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.tapHost == nil {
		return nil, fmt.Errorf("firecracker snapshot: TAP host manager not registered (main.go must call SetTapHost): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.vsockDial == nil {
		return nil, fmt.Errorf("firecracker snapshot: vsock dialer not registered (main.go must call SetVsockDialer): %w",
			models.ErrRuntimeNotImplemented)
	}
	if d.cfg.KernelImage == "" {
		return nil, fmt.Errorf("firecracker snapshot: KernelImage not configured (SB_FIRECRACKER_KERNEL): %w",
			models.ErrRuntimeNotImplemented)
	}
	if req.TemplateID == "" {
		return nil, errors.New("firecracker snapshot: template id is empty")
	}
	if req.RootfsPath == "" || req.OutMemoryPath == "" || req.OutStatePath == "" {
		return nil, errors.New("firecracker snapshot: rootfs/out paths are required")
	}
	if req.GuestCID < 3 {
		// CIDs 0-2 are reserved (host, hypervisor, loopback). Firecracker
		// would reject the PutVsock — catch it here with a clearer
		// message so the operator knows the allocator handed us garbage.
		return nil, fmt.Errorf("firecracker snapshot: GuestCID=%d is reserved (must be >= 3)", req.GuestCID)
	}

	vmmID := snapshotVMMIDPrefix + req.TemplateID
	if err := validateSandboxID(vmmID); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: %w", err)
	}

	// Step 1: allocate a transient TAP slot for the snapshot VMM. The
	// slot's VsockCID is ignored — we use req.GuestCID instead so the
	// captured snapshot has the template's reserved CID baked in.
	// We do still consume a TAP from the pool because the iface must
	// exist on the host for firecracker's PutNetworkInterface to
	// succeed; a synthetic per-template key keeps the pool's per-id
	// uniqueness gate honest if a previous build crashed mid-snapshot
	// and left the slot held.
	slot, err := d.pool.Allocate(ctx, vmmID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("firecracker snapshot: tap allocate: %w", err)
	}
	released := false
	defer func() {
		if !released {
			if relErr := d.pool.Release(context.Background(), vmmID); relErr != nil {
				d.logger.Warn("firecracker snapshot: pool release after error failed",
					"template_id", req.TemplateID, "tap", slot.TapName, "error", relErr)
			}
		}
	}()

	// Step 2: spawn the VMM (creates the runDir; does not start the
	// process yet).
	handle, err := d.spawn(d.cfg, vmmID)
	if err != nil {
		return nil, fmt.Errorf("firecracker snapshot: spawn handle: %w", err)
	}
	vmmStarted := false
	cleanupVMM := func() {
		if vmmStarted {
			_ = handle.Shutdown(context.Background(), 3*time.Second)
		}
		if cErr := handle.Cleanup(); cErr != nil {
			d.logger.Warn("firecracker snapshot: vmm cleanup after error failed",
				"template_id", req.TemplateID, "error", cErr)
		}
	}
	defer func() {
		if !released {
			cleanupVMM()
		}
	}()

	// Step 3: stage the template's rootfs into the VMM's runDir. The
	// jailer chroot covers the runDir, so the rootfs MUST live inside
	// it; hard-link first, copy on EXDEV.
	rootfsPath := filepath.Join(handle.RunDir(), rootfsFileName)
	if err := linkOrCopyRootfs(req.RootfsPath, rootfsPath); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: rootfs stage: %w", err)
	}

	// Step 4: bring up the host-side TAP. Same flag-and-defer release
	// pattern as Create's tap step.
	if err := d.tapHost.Ensure(ctx, *slot); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: tap ensure %s: %w", slot.TapName, err)
	}
	tapRemoved := false
	defer func() {
		if !tapRemoved {
			if rmErr := d.tapHost.Remove(context.Background(), slot.TapName); rmErr != nil {
				d.logger.Warn("firecracker snapshot: tap remove failed",
					"template_id", req.TemplateID, "tap", slot.TapName, "error", rmErr)
			}
		}
	}()

	// Step 5: start the VMM and wait for its API socket.
	if err := handle.Start(ctx); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: vmm start: %w", err)
	}
	vmmStarted = true
	if err := handle.WaitSocket(ctx, 5*time.Second); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: wait api socket: %w (stderr: %s)",
			err, handle.StderrTail())
	}

	// Step 6: REST orchestration. Order mirrors Create's configureVMM,
	// with three differences:
	//   - VcpuCount + MemSizeMib come from req (operator-tunable
	//     SB_FIRECRACKER_TEMPLATE_VCPU / SB_FIRECRACKER_TEMPLATE_MEMORY_MB)
	//     rather than the per-sandbox request — the snapshotted
	//     resources are what every clone resumes with.
	//   - GuestCID is req.GuestCID (the template's reserved CID) rather
	//     than slot.VsockCID; the snapshot state bakes this in.
	//   - rootfs is mounted read-only because the snapshot represents
	//     the template's immutable post-init state; if init wrote to
	//     disk, those writes are already on the ext4 we just staged.
	client := d.newClient(handle.APISocket())
	if err := client.PutMachineConfig(ctx, firecracker.MachineConfig{
		VcpuCount:       req.VCPU,
		MemSizeMib:      req.MemoryMB,
		TrackDirtyPages: true,
	}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: PutMachineConfig: %w", err)
	}
	if err := client.PutBootSource(ctx, firecracker.BootSource{
		KernelImagePath: d.cfg.KernelImage,
		BootArgs:        defaultBootArgs(),
	}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: PutBootSource: %w", err)
	}
	// Step 6: rootfs as read-only. PR-A captured rootfs as writable
	// because clones shared it directly; with PR-B the rootfs is the
	// immutable base under the per-sandbox overlay (Step 6b below), so
	// flipping IsReadOnly=true forces any clone that tries to mutate it
	// to fault loudly instead of corrupting the shared image. The
	// transient template VMM itself only boots far enough to handshake
	// with toolboxd, so it doesn't need to write to rootfs either.
	if err := client.PutDrive(ctx, rootDriveID, firecracker.Drive{
		DriveID:      rootDriveID,
		PathOnHost:   rootfsPath,
		IsRootDevice: true,
		IsReadOnly:   true,
		CacheType:    "Writeback",
	}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: PutDrive root: %w", err)
	}
	// Step 6b: overlay placeholder. The drive must exist at snapshot
	// time so /dev/vdb appears in the snapshot's virtio-blk state;
	// clones PATCH the backing path before Resume (Firecracker cannot
	// add a drive post-load, only PATCH an existing one's path). Size
	// is intentionally tiny — only the device shape is captured into
	// the snapshot state; the placeholder file is discarded with the
	// staging runDir at Step 12.
	placeholderPath := filepath.Join(handle.RunDir(), overlayFileName)
	if err := allocateSparse(placeholderPath, overlayPlaceholderBytes); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: overlay placeholder: %w", err)
	}
	if err := client.PutDrive(ctx, overlayDriveID, firecracker.Drive{
		DriveID:    overlayDriveID,
		PathOnHost: placeholderPath,
		IsReadOnly: false,
		CacheType:  "Writeback",
	}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: PutDrive overlay: %w", err)
	}
	if err := client.PutNetworkInterface(ctx, primaryIfaceID, firecracker.NetworkInterface{
		IfaceID:     primaryIfaceID,
		HostDevName: slot.TapName,
		GuestMAC:    macFromSlot(slot),
	}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: PutNetworkInterface: %w", err)
	}
	if err := client.PutVsock(ctx, firecracker.Vsock{
		GuestCID: int(req.GuestCID),
		UDSPath:  hostVsockUDSName,
	}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: PutVsock: %w", err)
	}

	// Step 7: boot.
	if err := client.Action(ctx, firecracker.Action{ActionType: firecracker.ActionInstanceStart}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: action InstanceStart: %w", err)
	}

	// Step 8: wait for the in-guest toolbox. Same handshake Create does
	// — the snapshot is only worth capturing once the agent is up.
	if err := d.vsockHandshake(ctx, req.GuestCID); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: vsock handshake: %w", err)
	}

	// Step 9: pre-snapshot quiesce signal. Best-effort: the PR-A toolbox
	// just logs and acks; PR-B will drain sessions and reseed entropy
	// here. We log a failed send rather than aborting because a missing
	// ack would leave us with no snapshot for an otherwise-healthy
	// template build.
	if err := d.sendVsockOp(ctx, req.GuestCID, "pre_snapshot", nil); err != nil {
		d.logger.Warn("firecracker snapshot: pre_snapshot send failed (continuing)",
			"template_id", req.TemplateID, "error", err)
	}

	// Step 10: pause. Firecracker requires Pause before CreateSnapshot;
	// resuming after a snapshot is the caller's choice (we don't —
	// we shut the VMM down).
	if err := client.Action(ctx, firecracker.Action{ActionType: firecracker.ActionPause}); err != nil {
		return nil, fmt.Errorf("firecracker snapshot: action Pause: %w", err)
	}

	// Step 11: write the snapshot. SnapshotType=Full because there is
	// no base snapshot to diff against. Diff snapshots are a Phase 4+
	// optimization (per-clone deltas above the shared template state).
	if err := client.CreateSnapshot(ctx, firecracker.SnapshotCreate{
		SnapshotType: "Full",
		SnapshotPath: req.OutStatePath,
		MemFilePath:  req.OutMemoryPath,
	}); err != nil {
		// On failure, drop any partial artifact files — better to have
		// no snapshot.memory than a half-written one that integrity
		// verification would reject hours later.
		_ = os.Remove(req.OutMemoryPath)
		_ = os.Remove(req.OutStatePath)
		return nil, fmt.Errorf("firecracker snapshot: CreateSnapshot: %w", err)
	}

	// Step 12: tear the transient VMM down. We Shutdown rather than
	// Action(Resume) because the snapshot is captured — anything the
	// VMM does after this is wasted CPU. handle.Shutdown signals the
	// firecracker process, which exits and releases its TAP grip;
	// then tapHost.Remove can succeed.
	if err := handle.Shutdown(ctx, 3*time.Second); err != nil {
		d.logger.Warn("firecracker snapshot: vmm shutdown after snapshot failed",
			"template_id", req.TemplateID, "error", err)
		// Not fatal — the snapshot files are good. We still want to
		// run tapHost.Remove + pool.Release below; the deferred
		// cleanup closures handle that when released stays false. But
		// we have a usable snapshot, so we'd rather promote it than
		// throw it away. Flip the flags as if cleanup succeeded.
	}
	vmmStarted = false

	if rmErr := d.tapHost.Remove(ctx, slot.TapName); rmErr != nil {
		d.logger.Warn("firecracker snapshot: tap remove after snapshot failed",
			"template_id", req.TemplateID, "tap", slot.TapName, "error", rmErr)
	}
	tapRemoved = true

	if cleanupErr := handle.Cleanup(); cleanupErr != nil {
		d.logger.Warn("firecracker snapshot: vmm cleanup after snapshot failed",
			"template_id", req.TemplateID, "error", cleanupErr)
	}

	if relErr := d.pool.Release(ctx, vmmID); relErr != nil {
		d.logger.Warn("firecracker snapshot: pool release after snapshot failed",
			"template_id", req.TemplateID, "error", relErr)
	}
	released = true

	// Step 13: integrity. Hash both artifacts so a later load can
	// detect bit-rot or tampering. We use streaming sha256 (constant
	// memory regardless of file size — the memory snapshot can be GiB).
	memDigest, memSize, err := hashFile(req.OutMemoryPath)
	if err != nil {
		return nil, fmt.Errorf("firecracker snapshot: hash memory: %w", err)
	}
	stateDigest, stateSize, err := hashFile(req.OutStatePath)
	if err != nil {
		return nil, fmt.Errorf("firecracker snapshot: hash state: %w", err)
	}

	return &TemplateSnapshotResult{
		MemorySizeBytes: memSize,
		StateSizeBytes:  stateSize,
		Checksum:        formatSnapshotChecksum(memDigest, stateDigest),
	}, nil
}

// sendVsockOp opens a fresh AF_VSOCK connection to the in-guest toolbox
// and writes one line of JSON ({"op":"<op>","data":<data>}). Used for
// the best-effort pre_snapshot / post_resume signals —
// vsockHandshake already proved the listener is up, so a failure here
// is "the agent didn't ack in time", not "agent unreachable". We do
// read the response so the connection stays well-formed (the toolbox
// writes ack-then-EOF), but we surface only the error path; the ack
// body itself is ignored. Passing data=nil omits the data field via
// json's "omitempty" on a *json.RawMessage built from the marshal.
func (d *Driver) sendVsockOp(ctx context.Context, guestCID uint32, op string, data any) error {
	payload := struct {
		Op   string          `json:"op"`
		Data json.RawMessage `json:"data,omitempty"`
	}{Op: op}
	if data != nil {
		raw, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("marshal data: %w", err)
		}
		payload.Data = raw
	}
	line, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal op: %w", err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := d.vsockDial.Dial(dialCtx, guestCID, defaultVsockPort)
	if err != nil {
		return fmt.Errorf("dial cid=%d: %w", guestCID, err)
	}
	defer conn.Close()
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	// Discard the ack. A short read budget keeps a hung guest from
	// pinning the snapshot pipeline.
	_, _ = io.CopyN(io.Discard, conn, 256)
	return nil
}

// allocateSparse creates (or truncates) path to be sizeBytes long
// without writing any zeros. The kernel records the size; physical
// blocks are allocated lazily on write — so a 4 GiB overlay file
// occupies a few KiB on disk until the guest actually mutates it.
// Used for both the snapshot-capture placeholder (1 MiB) and the
// per-sandbox clone overlay (cfg-sized). No Linux dependency: the
// portable os.File.Truncate works the same on darwin (where CI runs
// the unit tests).
func allocateSparse(path string, sizeBytes int64) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := f.Truncate(sizeBytes); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("truncate %s to %d: %w", path, sizeBytes, err)
	}
	return nil
}

// hashFile streams a file through SHA256 and returns the hex digest and
// the byte count. Constant memory — the memory snapshot can be several
// GiB on a large template; a one-shot Read would OOM.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// formatSnapshotChecksum joins the memory and state digests into the
// single-string shape persisted on the template row. The pipe
// separator and the explicit "sha256:" prefix make it self-describing
// — a future migration to a different hash can introduce a new prefix
// without breaking existing rows (verifySnapshotChecksum dispatches on
// the prefix).
func formatSnapshotChecksum(memHex, stateHex string) string {
	return "sha256:" + memHex + "|sha256:" + stateHex
}

// parseSnapshotChecksum splits the persisted "sha256:<hex>|sha256:<hex>"
// shape back into the two halves so verifySnapshotChecksum can re-hash
// each file independently. Empty or malformed input returns an error so
// the caller can fall back to "checksum not verifiable" rather than
// silently treating bad input as a match.
func parseSnapshotChecksum(s string) (memHex, stateHex string, err error) {
	// Two halves separated by "|"; each starts with "sha256:".
	const prefix = "sha256:"
	pipe := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			pipe = i
			break
		}
	}
	if pipe <= 0 || pipe >= len(s)-1 {
		return "", "", fmt.Errorf("snapshot checksum: missing %q separator", "|")
	}
	mem := s[:pipe]
	state := s[pipe+1:]
	if len(mem) <= len(prefix) || mem[:len(prefix)] != prefix {
		return "", "", fmt.Errorf("snapshot checksum: memory missing %q prefix", prefix)
	}
	if len(state) <= len(prefix) || state[:len(prefix)] != prefix {
		return "", "", fmt.Errorf("snapshot checksum: state missing %q prefix", prefix)
	}
	return mem[len(prefix):], state[len(prefix):], nil
}

// verifySnapshotChecksum re-hashes the memory and state files and
// returns an error if either differs from the persisted checksum.
// O(read) — the integrity gate at load time pays the same scan that
// the snapshot phase paid at write time. Operators benchmarking raw
// load latency can disable verification via
// SB_FIRECRACKER_SNAPSHOT_VERIFY_ON_LOAD=false.
func verifySnapshotChecksum(memPath, statePath, expected string) error {
	wantMem, wantState, err := parseSnapshotChecksum(expected)
	if err != nil {
		return err
	}
	gotMem, _, err := hashFile(memPath)
	if err != nil {
		return fmt.Errorf("hash memory: %w", err)
	}
	if gotMem != wantMem {
		return fmt.Errorf("snapshot checksum mismatch: memory file %s digest=%s expected=%s",
			memPath, gotMem, wantMem)
	}
	gotState, _, err := hashFile(statePath)
	if err != nil {
		return fmt.Errorf("hash state: %w", err)
	}
	if gotState != wantState {
		return fmt.Errorf("snapshot checksum mismatch: state file %s digest=%s expected=%s",
			statePath, gotState, wantState)
	}
	return nil
}
