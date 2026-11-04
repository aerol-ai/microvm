package firecracker

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/rootfstar"
	"github.com/aerol-ai/microvm/pkg/firecracker"
)

// A snapshot's files are read inside a helper VM, never by the host kernel.
// The disk is the tenant's: root in the guest can write any bytes to it, so
// mounting it on the host (as a loop device) would hand the host kernel's
// filesystem code input an attacker made, outside the Firecracker and jailer
// boundary. Instead the host boots a small VM whose root is a read-only
// image holding only toolboxd, attaches the disk copy as its second drive,
// and the agent there mounts it and streams its files back over vsock as a
// tar (cmd/toolboxd/export_helper.go). The host reads that stream as
// untrusted too (rootfstar.Filter) before the image store sees it.
//
// With no mount on the host, cleanup is only files: nothing can be left
// mounted under a directory a RemoveAll then walks into.

const (
	// exportHelperIDPrefix names helper VMs, their run dirs and chroots, so
	// the boot sweep can find what a crash left.
	exportHelperIDPrefix = "export-"
	// exportHelperDirName holds the helper's root image, one per toolboxd
	// build, next to the saved sandboxes.
	exportHelperDirName = "_export_helper"
	// exportHelperCID is the helper's vsock CID. Firecracker's vsock is a
	// unix socket per VM, so the CID need not be unique on the host.
	exportHelperCID = 3
	// exportHelperMemMiB and the one vCPU are enough to walk a filesystem
	// and stream it.
	exportHelperMemMiB = 256
	// exportDiskFileName is the disk copy, the helper's second drive.
	exportDiskFileName = "export.ext4"
	exportDriveID      = "export"
	// exportHelperImageMiB fits toolboxd with room to spare.
	exportHelperImageMiB = 128
)

var (
	// exportStreamTimeout bounds one export's stream. A var for tests.
	exportStreamTimeout = 30 * time.Minute
	// exportStreamSlack is what a stream may carry beyond four times the
	// disk's size. A var for tests.
	exportStreamSlack int64 = 64 << 20
	// runHelperMkfs runs mkfs.ext4; tests stand in for it.
	runHelperMkfs = func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, bin, args...).CombinedOutput()
	}
)

// exportHelperImages caches the helper image per toolboxd build, so a
// snapshot does not hash the agent each time. Keyed by path, size and
// modification time.
type exportHelperImages struct {
	mu   sync.Mutex
	key  string
	path string
}

// exportHelperRootfs returns the helper VM's root image for the configured
// toolboxd, building it the first time: an ext4 holding /toolboxd as init
// and the directories it mounts on. It is attached read-only, so every
// export shares it.
func (d *Driver) exportHelperRootfs(ctx context.Context) (string, error) {
	if d.cfg.ToolboxBinaryPath == "" || d.cfg.Mkfs4Bin == "" {
		return "", errors.New("a snapshot needs the toolbox binary and mkfs.ext4 configured, to build its export VM")
	}
	info, err := os.Stat(d.cfg.ToolboxBinaryPath)
	if err != nil {
		return "", fmt.Errorf("toolbox binary: %w", err)
	}
	key := fmt.Sprintf("%s|%d|%d", d.cfg.ToolboxBinaryPath, info.Size(), info.ModTime().UnixNano())
	d.helperImages.mu.Lock()
	defer d.helperImages.mu.Unlock()
	if d.helperImages.key == key {
		if _, err := os.Stat(d.helperImages.path); err == nil {
			return d.helperImages.path, nil
		}
	}
	base, err := d.sandboxSnapshotBase()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(base), exportHelperDirName)
	sum, err := fileSHA256(d.cfg.ToolboxBinaryPath)
	if err != nil {
		return "", fmt.Errorf("toolbox binary: %w", err)
	}
	image := filepath.Join(dir, sum[:16]+".ext4")
	if _, err := os.Stat(image); err != nil {
		if err := d.buildExportHelperImage(ctx, dir, image); err != nil {
			return "", fmt.Errorf("build the export VM's image: %w", err)
		}
	}
	d.helperImages.key, d.helperImages.path = key, image
	return image, nil
}

func (d *Driver) buildExportHelperImage(ctx context.Context, dir, image string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for _, sub := range []string{"dev", "proc", "sys", "mnt"} {
		if err := os.Mkdir(filepath.Join(stage, sub), 0o755); err != nil {
			return err
		}
	}
	if err := copyFile(d.cfg.ToolboxBinaryPath, filepath.Join(stage, "toolboxd")); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(stage, "toolboxd"), 0o755); err != nil {
		return err
	}
	tmp := image + ".tmp"
	_ = os.Remove(tmp)
	if out, err := runHelperMkfs(ctx, d.cfg.Mkfs4Bin, "-q", "-F", "-t", "ext4", "-L", "aerolvm-export",
		"-E", "root_owner=0:0", "-d", stage, tmp, fmt.Sprintf("%dM", exportHelperImageMiB)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("mkfs.ext4: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err := os.Rename(tmp, image); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// The images of earlier toolboxd builds are not used again.
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if p := filepath.Join(dir, entry.Name()); p != image {
				_ = os.RemoveAll(p)
			}
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// exportHelperID names one helper VM.
func exportHelperID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return exportHelperIDPrefix + hex.EncodeToString(b[:])
}

// exportViaHelper copies the sandbox's disk (fill), boots a helper VM on the
// copy, and imports the files it streams back as imageRef. The helper and
// the copy are always gone when it returns: the stream's producer is joined
// first, then the VM is stopped, then its files removed.
func (d *Driver) exportViaHelper(ctx context.Context, sandboxID, imageRef, workDir string, fill func(diskCopy string) error) (string, error) {
	helperImage, err := d.exportHelperRootfs(ctx)
	if err != nil {
		return "", err
	}
	helperID := exportHelperID()
	handle, err := d.spawn(d.cfg, helperID)
	if err != nil {
		return "", fmt.Errorf("export VM: %w", err)
	}
	runDir := handle.RunDir()
	started := false
	defer func() {
		if started {
			if err := handle.Shutdown(context.Background(), 2*time.Second); err != nil {
				_ = handle.Kill()
			}
		}
		if err := handle.Cleanup(); err != nil {
			d.logger.Warn("firecracker snapshot: export VM dir not removed; the next boot removes it",
				"run_dir", runDir, "error", err)
		}
	}()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", fmt.Errorf("export VM dir: %w", err)
	}
	// Jailed, the drive must be inside the chroot, which is on disk. Not
	// jailed, the run dir is tmpfs, and a disk copy there would be held in
	// memory: it goes in the export's work dir.
	diskDir := workDir
	if d.cfg.UseJailer {
		diskDir = runDir
	}
	diskCopy := filepath.Join(diskDir, exportDiskFileName)
	if err := fill(diskCopy); err != nil {
		return "", err
	}
	diskInfo, err := os.Stat(diskCopy)
	if err != nil {
		return "", err
	}
	started = true
	if err := handle.Start(ctx); err != nil {
		return "", fmt.Errorf("export VM: start: %w", err)
	}
	if err := handle.WaitSocket(ctx, 5*time.Second); err != nil {
		return "", fmt.Errorf("export VM: wait api socket: %w (stderr: %s)", err, handle.StderrTail())
	}
	client := d.newClient(handle.APISocket())
	if err := d.configureExportHelper(ctx, client, runDir, helperImage, diskCopy); err != nil {
		return "", err
	}
	if err := client.Action(ctx, firecracker.Action{ActionType: "InstanceStart"}); err != nil {
		return "", fmt.Errorf("export VM: start instance: %w", err)
	}
	vsockPath := filepath.Join(runDir, hostVsockUDSName)
	if err := d.vsockHandshake(ctx, vsockPath, exportHelperCID); err != nil {
		return "", fmt.Errorf("export VM: agent not up: %w (stderr: %s)", err, handle.StderrTail())
	}
	// A tar of a filesystem can outgrow it only by its sparse files' holes
	// and its headers; four times the disk only stops a runaway stream.
	limit := 4*diskInfo.Size() + exportStreamSlack
	return d.importHelperStream(ctx, vsockPath, imageRef, limit)
}

// configureExportHelper describes the helper VM: one vCPU, the read-only
// helper image as root with toolboxd as init in export mode, the disk copy
// as /dev/vdb, and vsock. No network.
func (d *Driver) configureExportHelper(ctx context.Context, client VMMClient, runDir, helperImage, diskCopy string) error {
	if err := client.PutMachineConfig(ctx, firecracker.MachineConfig{VcpuCount: 1, MemSizeMib: exportHelperMemMiB}); err != nil {
		return fmt.Errorf("export VM: machine config: %w", err)
	}
	kernel, err := d.chrootFilePath(runDir, d.cfg.KernelImage, kernelFileName)
	if err != nil {
		return fmt.Errorf("export VM: stage kernel: %w", err)
	}
	if err := client.PutBootSource(ctx, firecracker.BootSource{
		KernelImagePath: kernel,
		BootArgs:        baseBootArgsFor(runtime.GOARCH) + " init=/toolboxd aerolvm_export=1",
	}); err != nil {
		return fmt.Errorf("export VM: boot source: %w", err)
	}
	root, err := d.chrootFilePath(runDir, helperImage, rootfsFileName)
	if err != nil {
		return fmt.Errorf("export VM: stage its image: %w", err)
	}
	if err := client.PutDrive(ctx, rootDriveID, firecracker.Drive{
		DriveID: rootDriveID, PathOnHost: root, IsRootDevice: true, IsReadOnly: true,
	}); err != nil {
		return fmt.Errorf("export VM: root drive: %w", err)
	}
	disk, err := d.chrootFilePath(runDir, diskCopy, exportDiskFileName)
	if err != nil {
		return fmt.Errorf("export VM: stage the disk copy: %w", err)
	}
	if err := client.PutDrive(ctx, exportDriveID, firecracker.Drive{
		DriveID: exportDriveID, PathOnHost: disk,
	}); err != nil {
		return fmt.Errorf("export VM: disk drive: %w", err)
	}
	if err := client.PutVsock(ctx, firecracker.Vsock{GuestCID: exportHelperCID, UDSPath: hostVsockUDSName}); err != nil {
		return fmt.Errorf("export VM: vsock: %w", err)
	}
	return nil
}

// importHelperStream asks the helper for the tar and imports it, through
// rootfstar.Filter, as imageRef. The filter goroutine is joined before it
// returns, so nothing still reads the helper when the caller stops it.
func (d *Driver) importHelperStream(ctx context.Context, vsockPath, imageRef string, limit int64) (string, error) {
	conn, err := d.vsockDial.Dial(ctx, vsockPath, exportHelperCID, defaultVsockPort)
	if err != nil {
		return "", fmt.Errorf("export VM: dial: %w", err)
	}
	defer conn.Close()
	if dc, ok := conn.(deadlineConn); ok {
		if err := dc.SetDeadline(time.Now().Add(exportStreamTimeout)); err != nil {
			return "", fmt.Errorf("export VM: set deadline: %w", err)
		}
	}
	if _, err := conn.Write([]byte(`{"op":"export_rootfs"}` + "\n")); err != nil {
		return "", fmt.Errorf("export VM: request: %w", err)
	}
	stream := bufio.NewReader(conn)
	line, err := stream.ReadBytes('\n')
	if err != nil {
		return "", fmt.Errorf("export VM: read ack: %w", err)
	}
	var ack struct {
		Ok    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(line, &ack); err != nil {
		return "", fmt.Errorf("export VM: decode ack: %w", err)
	}
	if !ack.Ok {
		return "", fmt.Errorf("export VM: %s", ack.Error)
	}
	reader, writer := io.Pipe()
	filtered := make(chan error, 1)
	go func() {
		err := rootfstar.Filter(writer, stream, isExportExcluded, limit)
		writer.CloseWithError(err)
		filtered <- err
	}()
	id, importErr := d.images.ImportRootfs(ctx, imageRef, reader)
	// Ends the filter if the import stopped reading early, and its read
	// of the helper if the helper stalls.
	_ = reader.CloseWithError(errors.New("import finished"))
	_ = conn.Close()
	filterErr := <-filtered
	if importErr != nil {
		return "", fmt.Errorf("import image %s: %w", imageRef, importErr)
	}
	if filterErr != nil {
		return "", fmt.Errorf("import image %s: %w", imageRef, filterErr)
	}
	return id, nil
}

// isExportExcluded reports the guest paths a snapshot leaves out.
func isExportExcluded(guestPath string) bool { return snapshotExportExcluded[guestPath] }
