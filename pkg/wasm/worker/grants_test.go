package worker

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// unixPair is two ends of a connected Unix stream socket.
func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(shortTempDir(t), "p.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		c, _ := ln.AcceptUnix()
		accepted <- c
	}()
	client, err := net.DialUnix("unix", nil, ln.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

func TestFrameFilesRoundTrip(t *testing.T) {
	client, server := unixPair(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "module.wasm")
	if err := os.WriteFile(file, []byte("module bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, names := openGrants([]string{file, dir})
	if len(files) != 2 {
		t.Fatalf("opened %v", names)
	}
	env := Envelope{Type: MsgLoadModule, SandboxID: "sb", FDPaths: names}
	if err := writeFrameFiles(client, env, files); err != nil {
		t.Fatal(err)
	}
	closeFiles(files)
	got, recv, err := readFrameFiles(server)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(recv)
	if got.Type != MsgLoadModule || !slices.Equal(got.FDPaths, names) || len(recv) != 2 {
		t.Fatalf("frame %+v with %d files", got, len(recv))
	}
	b := make([]byte, 64)
	n, _ := recv[0].ReadAt(b, 0)
	if string(b[:n]) != "module bytes" {
		t.Fatalf("passed file reads %q", b[:n])
	}
	if st, err := recv[1].Stat(); err != nil || !st.IsDir() {
		t.Fatalf("passed dir = %v, %v", st, err)
	}

	// A frame without files on a Unix socket, and a big one read in parts.
	big := Envelope{Type: MsgOK, Payload: bytes.Repeat([]byte("x"), 1<<20)}
	go func() { _ = writeFrame(client, big) }()
	got, recv, err = readFrameFiles(server)
	if err != nil || len(recv) != 0 || len(got.Payload) != 1<<20 {
		t.Fatalf("plain frame = %d bytes, %d files, %v", len(got.Payload), len(recv), err)
	}

	// Names that do not match the descriptors: none are kept.
	files, _ = openGrants([]string{file})
	if err := writeFrameFiles(client, Envelope{Type: MsgOK, FDPaths: []string{"a", "b"}}, files); err == nil {
		t.Fatal("mismatched names written")
	}
	raw, _ := encodeFrame(Envelope{Type: MsgOK, FDPaths: []string{"a", "b"}})
	if _, _, err := client.WriteMsgUnix(raw, syscall.UnixRights(int(files[0].Fd())), nil); err != nil {
		t.Fatal(err)
	}
	closeFiles(files)
	got, recv, err = readFrameFiles(server)
	if err != nil || len(recv) != 0 || len(got.FDPaths) != 2 {
		t.Fatalf("mismatched frame kept %d files (%v)", len(recv), err)
	}

	// A plain writer cannot carry descriptors: the frame goes without them.
	var buf bytes.Buffer
	files, names = openGrants([]string{file})
	if err := writeFrameFiles(&buf, Envelope{Type: MsgOK, FDPaths: names}, files); err != nil {
		t.Fatal(err)
	}
	closeFiles(files)
	plain, err := readFrame(&buf)
	if err != nil || len(plain.FDPaths) != 0 {
		t.Fatalf("plain writer frame = %+v, %v", plain, err)
	}

	// readFrame closes what it receives; a clean close is EOF.
	_ = client.Close()
	if _, err := readFrame(server); err != io.EOF {
		t.Fatalf("closed socket = %v, want EOF", err)
	}
}

func TestReadFrameErrors(t *testing.T) {
	for name, raw := range map[string][]byte{
		"short header": {0, 0},
		"zero size":    {0, 0, 0, 0},
		"short body":   {0, 0, 0, 9, '{'},
		"not json":     {0, 0, 0, 1, 'x'},
	} {
		if _, err := readFrame(bytes.NewReader(raw)); err == nil {
			t.Fatalf("%s: read", name)
		}
	}
	if _, err := parseRights(bytes.Repeat([]byte{0xff}, 64)); err == nil {
		t.Fatal("garbage control message parsed")
	}
	if _, err := encodeFrame(Envelope{Payload: make([]byte, maxFrameSize)}); err == nil {
		t.Fatal("oversized frame encoded")
	}
}

func TestOpenGrants(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	many := []string{"", " ", file, file + "/", filepath.Join(dir, "missing"), fifo, dir}
	for range maxFrameFiles + 3 {
		sub, err := os.MkdirTemp(dir, "d")
		if err != nil {
			t.Fatal(err)
		}
		many = append(many, sub)
	}
	files, names := openGrants(many)
	defer closeFiles(files)
	if len(files) != maxFrameFiles || len(names) != maxFrameFiles {
		t.Fatalf("opened %d, want the cap %d", len(files), maxFrameFiles)
	}
	if names[0] != file || names[1] != dir {
		t.Fatalf("names = %v (blank, duplicate, missing and FIFO must be skipped)", names[:2])
	}
	if slices.Contains(names, fifo) {
		t.Fatal("a FIFO was granted")
	}
}

// What a worker receives is granted under the sandbox, or under the worker
// itself for a module, and reached through the descriptor from then on.
func TestReadGrantedFrame(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("grants are reached through /proc/self/fd")
	}
	client, server := unixPair(t)
	dir := t.TempDir()
	module := filepath.Join(dir, "m.wasm")
	if err := os.WriteFile(module, []byte("wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wasmengine.ReleaseHostGrants(""); wasmengine.ReleaseHostGrants("sb-g") })
	go func() {
		_ = writeGranted(client, Envelope{Type: MsgLoadModule, SandboxID: "sb-g"}, []string{module})
	}()
	env, _, err := readGrantedFrame(server)
	if err != nil || env.Type != MsgLoadModule {
		t.Fatalf("frame = %+v, %v", env, err)
	}
	if err := os.Remove(module); err != nil {
		t.Fatal(err)
	}
	// Module grants belong to the worker, not the sandbox that sent them.
	wasmengine.ReleaseHostGrants("sb-g")
	got, err := wasmengine.ReadHostFile(module)
	if err != nil || string(got) != "wasm" {
		t.Fatalf("granted module after unlink = %q, %v", got, err)
	}
	wasmengine.ReleaseHostGrants("")
	if _, err := wasmengine.ReadHostFile(module); err == nil {
		t.Fatal("released grant still read")
	}
	_ = client.Close()
	if _, _, err := readGrantedFrame(server); err == nil {
		t.Fatal("closed socket read")
	}
}

func TestClientGrantsPerMessage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("grants are reached through /proc/self/fd")
	}
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	snap := filepath.Join(dir, "mem.snap")
	for _, d := range []string{work, snap} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range wasmengine.SnapshotFiles(snap) {
		if err := os.WriteFile(f, []byte(filepath.Base(f)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	caps := wasmengine.Capabilities{Preopens: []wasmengine.Preopen{{GuestPath: "/work", HostPath: work}}}
	sock := filepath.Join(shortTempDir(t), "g.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan Envelope, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			env, files, err := readFrameFiles(conn)
			closeFiles(files)
			if err == nil {
				if len(files) != len(env.FDPaths) {
					env.FDPaths = nil
				}
				seen <- env
				_ = writeFrame(conn, Envelope{Type: MsgOK})
			}
			_ = conn.Close()
		}
	}()
	c := NewClient(sock)
	_ = c.Restore("sb", snap, caps)
	if env := <-seen; !slices.Contains(env.FDPaths, work) || !slices.Contains(env.FDPaths, wasmengine.SnapshotFiles(snap)[1]) || slices.Contains(env.FDPaths, snap) {
		t.Fatalf("restore granted %v", env.FDPaths)
	}
	_ = c.Checkpoint(context.Background(), "sb", filepath.Join(work, "mem.snap"), wasmengine.SnapshotConfig{})
	if env := <-seen; !slices.Equal(env.FDPaths, []string{work}) {
		t.Fatalf("checkpoint granted %v", env.FDPaths)
	}
	for name, call := range map[string]func(){
		"instantiate":    func() { _ = c.Instantiate("sb", caps) },
		"exec":           func() { _, _ = c.Exec("sb", caps, "_start") },
		"set capability": func() { _ = c.SetCapability("sb", caps) },
	} {
		call()
		if env := <-seen; !slices.Equal(env.FDPaths, []string{work}) {
			t.Fatalf("%s granted %v", name, env.FDPaths)
		}
	}
}

func TestWorkerFloorFailsClosed(t *testing.T) {
	t.Cleanup(func() {
		egresspolicy.SetFileFloorUnknown(false)
		egresspolicy.SetFileFloor(nil)
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "floor")
	if err := os.WriteFile(path, []byte("10.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := openFloorReader(path)
	syncWorkerFloor(r)
	if egresspolicy.FileFloorUnknown() || !slices.Contains(egresspolicy.FileFloor(), netip.MustParsePrefix("10.9.9.9/32")) {
		t.Fatalf("floor = %v unknown=%v", egresspolicy.FileFloor(), egresspolicy.FileFloorUnknown())
	}
	// An edit that does not parse keeps the addresses.
	if err := os.WriteFile(path, []byte("not-an-address\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	syncWorkerFloor(r)
	if egresspolicy.FileFloorUnknown() || len(egresspolicy.FileFloor()) != 1 {
		t.Fatal("a bad edit changed the floor")
	}
	// The path no longer names the file read at start, which still has a
	// name: read through the descriptor (what a dropped worker does for a
	// file only root may open, edited in place).
	if err := os.WriteFile(path, []byte("10.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".kept"); err != nil {
		t.Fatal(err)
	}
	syncWorkerFloor(r)
	if egresspolicy.FileFloorUnknown() || !slices.Contains(egresspolicy.FileFloor(), netip.MustParsePrefix("10.8.8.8/32")) {
		t.Fatalf("held read: floor = %v unknown=%v", egresspolicy.FileFloor(), egresspolicy.FileFloorUnknown())
	}
	// Gone for good: the floor is unknown, so every address is refused.
	if err := os.Remove(path + ".kept"); err != nil {
		t.Fatal(err)
	}
	syncWorkerFloor(r)
	if !egresspolicy.FileFloorUnknown() {
		t.Fatal("an unreadable floor was not failed closed")
	}
	if err := openCheck(egresspolicy.DialGuard{}, "", netip.MustParseAddrPort("1.1.1.1:443")); err == nil {
		t.Fatal("a public address was dialed with the floor unknown")
	}
	// Readable again: back to normal.
	if err := os.WriteFile(path, []byte("10.7.7.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	syncWorkerFloor(r)
	if egresspolicy.FileFloorUnknown() {
		t.Fatal("still unknown after the file came back")
	}
	// A reader with nothing held reports the path's error.
	if _, err := openFloorReader(filepath.Join(dir, "never")).read(); err == nil {
		t.Fatal("missing floor file read")
	}
	// The watch runs until its context ends.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchWorkerFloor(ctx, r, time.Millisecond); close(done) }()
	time.Sleep(5 * time.Millisecond)
	cancel()
	<-done
	stopWorkerFloorWatch()
	stopWorkerFloorWatch()
}

// An open that hangs (a stalled network mount) is given up on, and the
// file it opens later is closed.
func TestOpenGrantTimesOut(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// A FIFO opened without O_NONBLOCK would block; openGrant's does not,
	// so stand in a hang with a zero timeout instead.
	// With no time at all the open may or may not win; either way nothing
	// leaks.
	if f, err := openGrant(dir, 0, false); err != nil && err != errGrantTimeout {
		t.Fatalf("zero timeout = %v", err)
	} else if f != nil {
		_ = f.Close()
	}
	if _, err := openGrant(fifo, time.Second, false); err == nil {
		t.Fatal("a FIFO was opened for a grant")
	}
	f, err := openGrant(dir, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	prev := grantOpenTimeout
	grantOpenTimeout = 0
	t.Cleanup(func() { grantOpenTimeout = prev })
	files, _ := openGrants([]string{dir})
	closeFiles(files)
}
