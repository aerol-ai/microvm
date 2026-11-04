//go:build linux

package main

import (
	"archive/tar"
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type mountCall struct {
	source, target, fstype string
	flags                  uintptr
}

func stubExportMount(t *testing.T, fail map[string]error) *[]mountCall {
	t.Helper()
	var calls []mountCall
	saved := exportMount
	exportMount = func(source, target, fstype string, flags uintptr, _ string) error {
		calls = append(calls, mountCall{source, target, fstype, flags})
		return fail[target]
	}
	t.Cleanup(func() { exportMount = saved })
	return &calls
}

func TestMountExportDisk(t *testing.T) {
	calls := stubExportMount(t, map[string]error{"/proc": unix.EBUSY})
	if err := mountExportDisk(); err != nil {
		t.Fatal(err)
	}
	disk := (*calls)[len(*calls)-1]
	want := uintptr(unix.MS_NOATIME | unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC)
	if len(*calls) != 4 || disk.source != "/dev/vdb" || disk.target != exportDiskMount || disk.fstype != "ext4" || disk.flags != want {
		t.Fatalf("mounts %+v", *calls)
	}
	for target, wantErr := range map[string]string{"/sys": "mount /sys", exportDiskMount: "mount the disk copy"} {
		stubExportMount(t, map[string]error{target: errors.New("EINVAL")})
		if err := mountExportDisk(); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("%s failing: %v", target, err)
		}
	}
}

// listenUnix stands in for the vsock listener: an AF_UNIX listening fd the
// test can connect to.
func listenUnix(t *testing.T) (string, int) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "h.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 4); err != nil {
		t.Fatal(err)
	}
	return sock, fd
}

// The helper serves the export: it acks, streams the disk's files as a tar,
// and closes.
func TestRunExportHelperServesTheExport(t *testing.T) {
	stubExportMount(t, nil)
	disk := t.TempDir()
	if err := os.WriteFile(filepath.Join(disk, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedMount, savedListen := exportDiskMount, listenExportVsock
	t.Cleanup(func() { exportDiskMount, listenExportVsock = savedMount, savedListen })
	exportDiskMount = disk
	sock, fd := listenUnix(t)
	listenExportVsock = func(uint32) (int, error) { return fd, nil }
	done := make(chan int, 1)
	go func() { done <- runExportHelper(slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(`{"op":"export_rootfs"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	if ack, _ := r.ReadString('\n'); ack != `{"ok":true}`+"\n" {
		t.Fatalf("ack %q", ack)
	}
	tr := tar.NewReader(r)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "hello.txt" {
		t.Fatalf("first entry %+v, %v", hdr, err)
	}
	if _, err := tr.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the file: %v", err)
	}
	// Shutting the listener down ends the accept loop (a close would not
	// wake a blocked accept).
	_ = unix.Shutdown(fd, unix.SHUT_RDWR)
	if code := <-done; code != 1 {
		t.Fatalf("exit %d", code)
	}
}

// A helper whose disk did not mount still serves, so the host hears why.
func TestRunExportHelperReportsAnUnmountedDisk(t *testing.T) {
	stubExportMount(t, map[string]error{exportDiskMount: errors.New("EINVAL")})
	savedListen := listenExportVsock
	t.Cleanup(func() { listenExportVsock = savedListen })
	sock, fd := listenUnix(t)
	listenExportVsock = func(uint32) (int, error) { return fd, nil }
	go runExportHelper(slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(`{"op":"export_rootfs"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if ack, _ := bufio.NewReader(conn).ReadString('\n'); !strings.Contains(ack, "mount the disk copy") {
		t.Fatalf("ack %q", ack)
	}
	_ = unix.Shutdown(fd, unix.SHUT_RDWR)
}

func TestRunExportHelperWithoutAListener(t *testing.T) {
	stubExportMount(t, nil)
	savedListen := listenExportVsock
	t.Cleanup(func() { listenExportVsock = savedListen })
	listenExportVsock = func(uint32) (int, error) { return -1, errors.New("no vsock") }
	if code := runExportHelper(slog.New(slog.NewTextHandler(io.Discard, nil))); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

// Off a Firecracker guest there is usually no vsock device: the listener
// either binds or says why not.
func TestListenVsockFD(t *testing.T) {
	fd, err := listenVsockFD(52_000)
	if err == nil {
		_ = unix.Close(fd)
		return
	}
	if !strings.Contains(err.Error(), "vsock") {
		t.Fatalf("err = %v", err)
	}
}
