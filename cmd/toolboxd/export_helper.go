package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// toolboxd is also the init of the helper VM a Firecracker snapshot is
// exported in. The host boots a small VM whose root is a read-only image
// holding only this binary, with a copy of the sandbox's disk as a second
// drive. The guest kernel mounts that copy and this agent streams its files
// back over vsock as a tar. A disk the tenant could have crafted is then
// parsed by a guest kernel, inside the VM boundary, never by the host's.

const (
	// exportHelperEnv is the kernel command-line parameter that boots
	// toolboxd as the export helper; the kernel hands it to init as an
	// environment variable.
	exportHelperEnv = "aerolvm_export"
	// exportDiskDevice is the disk copy, the helper VM's second drive.
	exportDiskDevice = "/dev/vdb"
	// OpExportRootfs asks the helper for the tar of the disk copy. Its ack
	// is followed by the tar stream, then the connection closes.
	OpExportRootfs VsockOp = "export_rootfs"
)

// exportDiskMount is where the disk copy is mounted. The helper image ships
// the directory: its root is read-only. A var for tests.
var exportDiskMount = "/mnt"

// exportHelperRequested reports a toolboxd booted as the export helper's
// init.
func exportHelperRequested(pid int, getenv func(string) string) bool {
	return pid == 1 && getenv(exportHelperEnv) == "1"
}

// serveExportConn answers one connection from the host: ping (the boot
// handshake), then export_rootfs, which is acked and followed by the tar.
// diskErr is why the disk copy could not be mounted, sent back as the
// export's error. write streams the tar.
func serveExportConn(conn io.ReadWriter, diskErr error, write func(io.Writer) error) error {
	reader := bufio.NewReader(conn)
	encoder := json.NewEncoder(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var msg VsockMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			_ = encoder.Encode(VsockResponse{Error: fmt.Sprintf("decode: %v", err)})
			return err
		}
		switch msg.Op {
		case OpPing:
			if err := encoder.Encode(VsockResponse{Ok: true}); err != nil {
				return err
			}
		case OpExportRootfs:
			if diskErr != nil {
				_ = encoder.Encode(VsockResponse{Error: diskErr.Error()})
				return diskErr
			}
			if err := encoder.Encode(VsockResponse{Ok: true}); err != nil {
				return err
			}
			return write(conn)
		default:
			if err := encoder.Encode(VsockResponse{Error: fmt.Sprintf("unknown op %q", msg.Op)}); err != nil {
				return err
			}
		}
	}
}
