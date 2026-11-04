//go:build linux

package main

import (
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootfstar"
)

// Seams for tests: the helper's mounts and its vsock listener.
var (
	exportMount       = unix.Mount
	listenExportVsock = listenVsockFD
)

// runExportHelper is the export helper VM's init: mount what the guest
// needs and the disk copy, then serve the host until the VM is stopped. It
// returns only if it cannot listen; init exiting panics the kernel, and
// panic=1 ends the VM.
func runExportHelper(logger *slog.Logger) int {
	diskErr := mountExportDisk()
	if diskErr != nil {
		logger.Error("export helper: disk copy not mounted", "error", diskErr)
	}
	fd, err := listenExportVsock(defaultVsockPort)
	if err != nil {
		logger.Error("export helper: no vsock listener", "error", err)
		return 1
	}
	for {
		nfd, _, err := unix.Accept(fd)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			logger.Error("export helper: accept", "error", err)
			return 1
		}
		go func() {
			conn := newVsockConn(nfd)
			defer conn.Close()
			if err := serveExportConn(conn, diskErr, func(w io.Writer) error {
				return rootfstar.Write(w, exportDiskMount)
			}); err != nil {
				logger.Error("export helper: export failed", "error", err)
			}
		}()
	}
}

// mountExportDisk mounts the pseudo-filesystems, then the disk copy
// read-write: ext4 may replay its journal, and the copy is the helper's to
// change. No device, setuid or exec from it: the helper only reads it.
func mountExportDisk() error {
	for _, m := range []struct{ source, target, fstype string }{
		{"proc", "/proc", "proc"},
		{"sys", "/sys", "sysfs"},
		{"dev", "/dev", "devtmpfs"},
	} {
		if err := exportMount(m.source, m.target, m.fstype, 0, ""); err != nil && err != unix.EBUSY {
			return fmt.Errorf("mount %s: %w", m.target, err)
		}
	}
	flags := uintptr(unix.MS_NOATIME | unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	if err := exportMount(exportDiskDevice, exportDiskMount, "ext4", flags, ""); err != nil {
		return fmt.Errorf("mount the disk copy: %w", err)
	}
	return nil
}

// listenVsockFD listens on the vsock port the host dials.
func listenVsockFD(port uint32) (int, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("vsock bind port %d: %w", port, err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("vsock listen: %w", err)
	}
	return fd, nil
}
