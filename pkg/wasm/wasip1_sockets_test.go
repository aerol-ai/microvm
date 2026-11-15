//go:build linux || darwin

package wasm

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Guest memory layout for these tests.
const (
	tmResult  = 0    // u32 result slot
	tmResult2 = 8    // second result slot
	tmIOVecs  = 64   // iovec array
	tmData    = 1024 // data buffers
	tmSubs    = 4096 // subscriptions
	tmEvents  = 8192 // events
)

type countingMeter struct{ in, out atomic.Int64 }

func (m *countingMeter) AddIn(n int64)  { m.in.Add(n) }
func (m *countingMeter) AddOut(n int64) { m.out.Add(n) }

// newTestSockets binds the given listeners on loopback and closes them with
// the test.
func newTestSockets(t *testing.T, meter ByteMeter, listeners ...WASIListener) *wasip1Sockets {
	t.Helper()
	s, err := newWasip1Sockets(listeners, "", meter)
	if err != nil {
		t.Fatalf("newWasip1Sockets: %v", err)
	}
	t.Cleanup(s.close)
	return s
}

func hostPort(t *testing.T, s *wasip1Sockets, i int) int {
	t.Helper()
	live := s.listen.live()
	if i >= len(live) {
		t.Fatalf("listener %d of %d", i, len(live))
	}
	return live[i].hostPort
}

func dialTest(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// acceptTest accepts one connection on the listener at fd, waiting for it.
func acceptTest(t *testing.T, s *wasip1Sockets, mem []byte, fd int32, flags uint32) int32 {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		errno, err := s.sockAccept(mem, fd, flags, tmResult)
		if err != nil {
			t.Fatalf("sockAccept: %v", err)
		}
		if errno == 0 {
			return int32(binary.LittleEndian.Uint32(mem[tmResult:]))
		}
		if errno != wasiErrnoAgain || time.Now().After(deadline) {
			t.Fatalf("sockAccept errno %d", errno)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// connectedPair is a guest socket fd and the test's end of it.
func connectedPair(t *testing.T, s *wasip1Sockets, mem []byte, flags uint32) (int32, net.Conn) {
	t.Helper()
	client := dialTest(t, hostPort(t, s, 0))
	return acceptTest(t, s, mem, wasip1SocketFDBase, flags), client
}

func TestWasip1SocketsListeners(t *testing.T) {
	s := newTestSockets(t, nil, WASIListener{GuestPort: 8080}, WASIListener{GuestPort: 9090})
	fds := s.listenerFDs()
	if len(fds) != 2 || fds[0] != int(wasip1SocketFDBase) || fds[1] != int(wasip1SocketFDBase)+1 {
		t.Fatalf("listener fds = %v", fds)
	}
	live := s.listen.live()
	if len(live) != 2 || live[0].guestPort != 8080 || live[1].guestPort != 9090 || live[0].hostPort == live[1].hostPort {
		t.Fatalf("live = %+v", live)
	}
	if !s.owns(wasip1SocketFDBase) || s.owns(3) || s.owns(wasip1SocketFDBase+2) {
		t.Fatal("owns")
	}

	// With none, the layer still has its stop pipe and no listener.
	none := newTestSockets(t, nil)
	if none.listenerFDs() != nil || none.listen != nil {
		t.Fatal("no listeners expected")
	}
}

func TestWasip1SocketsListenErrors(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := taken.Addr().(*net.TCPAddr).Port
	for _, tc := range []struct {
		name string
		host string
		port int
	}{
		{"port in use", "127.0.0.1", port},
		{"bad host", "no such host.invalid", 0},
		{"bad port", "127.0.0.1", 70000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The first listener binds; the second fails and takes the
			// first down with it.
			s, err := newWasip1Sockets([]WASIListener{{GuestPort: 1}, {GuestPort: 2, HostPort: tc.port}}, tc.host, nil)
			if err == nil {
				s.close()
				t.Fatal("expected an error")
			}
		})
	}
}

func TestWasip1ListenIPv6(t *testing.T) {
	fd, port, err := wasip1Listen("::1", 0)
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer unix.Close(fd)
	if port <= 0 {
		t.Fatalf("port = %d", port)
	}
}

func TestWasip1SockAccept(t *testing.T) {
	meter := &countingMeter{}
	s := newTestSockets(t, meter, WASIListener{GuestPort: 8080})
	mem := make([]byte, 1<<16)
	lfd := wasip1SocketFDBase

	if s.listen.acceptedOn(8080) {
		t.Fatal("accepted before any accept")
	}
	// The listener's own flags decide whether accept waits (as Go's
	// SetNonblock sets them); sock_accept's flags are the new socket's.
	if errno := s.fdFdstatSetFlags(lfd, uint32(wasiFdflagNonblock)); errno != 0 {
		t.Fatalf("set flags: %d", errno)
	}
	if errno, _ := s.sockAccept(mem, lfd, 0, tmResult); errno != wasiErrnoAgain {
		t.Fatalf("nothing pending: errno %d", errno)
	}
	if !s.listen.acceptedOn(8080) {
		t.Fatal("an attempt marks the listener served")
	}
	conn, _ := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))
	if conn != lfd+1 || !s.owns(conn) {
		t.Fatalf("accepted fd %d", conn)
	}
	if meter.in.Load() != 1 {
		t.Fatalf("accept pulse = %d", meter.in.Load())
	}

	for _, tc := range []struct {
		name   string
		fd     int32
		flags  uint32
		result uint32
		want   uint16
	}{
		{"unknown fd", lfd + 50, 0, tmResult, wasiErrnoBadf},
		{"not a listener", conn, 0, tmResult, wasiErrnoInval},
		{"bad flags", lfd, uint32(wasiFdflagAppend), tmResult, wasiErrnoInval},
		{"result out of bounds", lfd, 0, 1 << 16, wasiErrnoFault},
	} {
		if errno, err := s.sockAccept(mem, tc.fd, tc.flags, tc.result); errno != tc.want || err != nil {
			t.Fatalf("%s: errno %d err %v, want %d", tc.name, errno, err, tc.want)
		}
	}
}

func TestWasip1SockAcceptBlocks(t *testing.T) {
	s := newTestSockets(t, nil, WASIListener{GuestPort: 8080})
	mem := make([]byte, 1<<16)

	// A blocking listener waits for a connection...
	got := make(chan uint16, 1)
	go func() {
		errno, _ := s.sockAccept(mem, wasip1SocketFDBase, 0, tmResult)
		got <- errno
	}()
	select {
	case errno := <-got:
		t.Fatalf("returned %d before any connection", errno)
	case <-time.After(50 * time.Millisecond):
	}
	dialTest(t, hostPort(t, s, 0))
	select {
	case errno := <-got:
		if errno != 0 {
			t.Fatalf("errno %d", errno)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking accept did not return on a connection")
	}

	// ...and a stop ends the wait.
	stopped := make(chan error, 1)
	go func() {
		_, err := s.sockAccept(mem, wasip1SocketFDBase, 0, tmResult2)
		stopped <- err
	}()
	time.Sleep(20 * time.Millisecond)
	s.stop()
	select {
	case err := <-stopped:
		if !errors.Is(err, errWasip1Stopped) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not end a blocked accept")
	}
}

func TestWasip1ReadWrite(t *testing.T) {
	meter := &countingMeter{}
	s := newTestSockets(t, meter, WASIListener{})
	mem := make([]byte, 1<<16)
	fd, client := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))

	// Nothing to read yet.
	putIOVec(mem, tmIOVecs, 0, tmData, 16)
	if errno, _ := s.fdRead(mem, fd, tmIOVecs, 1, tmResult); errno != wasiErrnoAgain {
		t.Fatalf("empty read: errno %d", errno)
	}

	// Client to guest, scattered over two iovecs.
	if _, err := client.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	putIOVec(mem, tmIOVecs, 0, tmData, 5)
	putIOVec(mem, tmIOVecs, 1, tmData+100, 64)
	waitReadable(t, s, fd)
	if errno, _ := s.fdRead(mem, fd, tmIOVecs, 2, tmResult); errno != 0 {
		t.Fatalf("read errno %d", errno)
	}
	if n := binary.LittleEndian.Uint32(mem[tmResult:]); n != 11 || string(mem[tmData:tmData+5]) != "hello" || string(mem[tmData+100:tmData+106]) != " world" {
		t.Fatalf("read %d bytes: %q %q", n, mem[tmData:tmData+5], mem[tmData+100:tmData+106])
	}

	// Guest to client, gathered from two iovecs.
	copy(mem[tmData:], "ping ")
	copy(mem[tmData+100:], "pong")
	putIOVec(mem, tmIOVecs, 0, tmData, 5)
	putIOVec(mem, tmIOVecs, 1, tmData+100, 4)
	if errno, _ := s.fdWrite(mem, fd, tmIOVecs, 2, tmResult); errno != 0 || binary.LittleEndian.Uint32(mem[tmResult:]) != 9 {
		t.Fatalf("write errno %d n %d", errno, binary.LittleEndian.Uint32(mem[tmResult:]))
	}
	buf := make([]byte, 9)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "ping pong" {
		t.Fatalf("client read %q: %v", buf, err)
	}

	// fd_read / fd_write are not metered: the worker's proxy counts them.
	if meter.in.Load() != 1 || meter.out.Load() != 0 {
		t.Fatalf("meter in=%d out=%d", meter.in.Load(), meter.out.Load())
	}

	// Zero-length vectors move nothing and do not block.
	if errno, _ := s.fdRead(mem, fd, tmIOVecs, 0, tmResult); errno != 0 || binary.LittleEndian.Uint32(mem[tmResult:]) != 0 {
		t.Fatal("empty read vector")
	}
	if errno, _ := s.fdWrite(mem, fd, tmIOVecs, 0, tmResult); errno != 0 || binary.LittleEndian.Uint32(mem[tmResult:]) != 0 {
		t.Fatal("empty write vector")
	}

	// The client closes: the guest reads EOF.
	_ = client.Close()
	waitReadable(t, s, fd)
	putIOVec(mem, tmIOVecs, 0, tmData, 16)
	if errno, _ := s.fdRead(mem, fd, tmIOVecs, 1, tmResult); errno != 0 || binary.LittleEndian.Uint32(mem[tmResult:]) != 0 {
		t.Fatalf("EOF read: errno %d n %d", errno, binary.LittleEndian.Uint32(mem[tmResult:]))
	}
}

// waitReadable polls fd for reading through the layer.
func waitReadable(t *testing.T, s *wasip1Sockets, fd int32) {
	t.Helper()
	mem := make([]byte, 1<<16)
	putFDSub(mem, tmSubs, 0, 1, wasiEventtypeFdRead, fd)
	putClockSub(mem, tmSubs, 1, 2, wasiClockMonotonic, uint64(2*time.Second), 0)
	errno, handled, err := s.pollOneoff(mem, tmSubs, tmEvents, 2, tmResult, nil)
	if errno != 0 || !handled || err != nil {
		t.Fatalf("poll: errno %d handled %v err %v", errno, handled, err)
	}
	if binary.LittleEndian.Uint64(mem[tmEvents:]) != 1 {
		t.Fatal("fd never became readable")
	}
}

func TestWasip1ReadWriteErrors(t *testing.T) {
	s := newTestSockets(t, nil, WASIListener{})
	mem := make([]byte, 1<<16)
	fd, _ := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))
	putIOVec(mem, tmIOVecs, 0, tmData, 16)
	putIOVec(mem, tmIOVecs+64, 0, 1<<16-4, 16) // runs past the end

	for _, tc := range []struct {
		name string
		call func() (uint16, error)
		want uint16
	}{
		{"read unknown fd", func() (uint16, error) { return s.fdRead(mem, fd+10, tmIOVecs, 1, tmResult) }, wasiErrnoBadf},
		{"read listener", func() (uint16, error) { return s.fdRead(mem, wasip1SocketFDBase, tmIOVecs, 1, tmResult) }, wasiErrnoNotconn},
		{"read result out of bounds", func() (uint16, error) { return s.fdRead(mem, fd, tmIOVecs, 1, 1<<16) }, wasiErrnoFault},
		{"read buffer out of bounds", func() (uint16, error) { return s.fdRead(mem, fd, tmIOVecs+64, 1, tmResult) }, wasiErrnoFault},
		{"write listener", func() (uint16, error) { return s.fdWrite(mem, wasip1SocketFDBase, tmIOVecs, 1, tmResult) }, wasiErrnoNotconn},
		{"write result out of bounds", func() (uint16, error) { return s.fdWrite(mem, fd, tmIOVecs, 1, 1<<16) }, wasiErrnoFault},
		{"write buffer out of bounds", func() (uint16, error) { return s.fdWrite(mem, fd, tmIOVecs+64, 1, tmResult) }, wasiErrnoFault},
		{"recv bad flags", func() (uint16, error) { return s.sockRecv(mem, fd, tmIOVecs, 1, 4, tmResult, tmResult2) }, wasiErrnoNotsup},
		{"recv len out of bounds", func() (uint16, error) { return s.sockRecv(mem, fd, tmIOVecs, 1, 0, 1<<16, tmResult2) }, wasiErrnoFault},
		{"recv flags out of bounds", func() (uint16, error) { return s.sockRecv(mem, fd, tmIOVecs, 1, 0, tmResult, 1<<16-1) }, wasiErrnoFault},
		{"recv unknown fd", func() (uint16, error) { return s.sockRecv(mem, fd+10, tmIOVecs, 1, 0, tmResult, tmResult2) }, wasiErrnoBadf},
		{"send flags", func() (uint16, error) { return s.sockSend(mem, fd, tmIOVecs, 1, 1, tmResult) }, wasiErrnoNotsup},
		{"send len out of bounds", func() (uint16, error) { return s.sockSend(mem, fd, tmIOVecs, 1, 0, 1<<16) }, wasiErrnoFault},
		{"send unknown fd", func() (uint16, error) { return s.sockSend(mem, fd+10, tmIOVecs, 1, 0, tmResult) }, wasiErrnoBadf},
	} {
		if errno, err := tc.call(); errno != tc.want || err != nil {
			t.Fatalf("%s: errno %d err %v, want %d", tc.name, errno, err, tc.want)
		}
	}
}

func TestWasip1SockRecvSend(t *testing.T) {
	meter := &countingMeter{}
	s := newTestSockets(t, meter, WASIListener{})
	mem := make([]byte, 1<<16)
	fd, client := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))

	if _, err := client.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	waitReadable(t, s, fd)
	putIOVec(mem, tmIOVecs, 0, tmData, 3)
	mem[tmResult2] = 0xff
	// PEEK leaves the bytes queued.
	if errno, _ := s.sockRecv(mem, fd, tmIOVecs, 1, uint32(wasiRiRecvPeek), tmResult, tmResult2); errno != 0 {
		t.Fatalf("peek errno %d", errno)
	}
	if binary.LittleEndian.Uint32(mem[tmResult:]) != 3 || string(mem[tmData:tmData+3]) != "abc" || mem[tmResult2] != 0 {
		t.Fatalf("peek got %q", mem[tmData:tmData+3])
	}
	putIOVec(mem, tmIOVecs, 0, tmData, 16)
	if errno, _ := s.sockRecv(mem, fd, tmIOVecs, 1, uint32(wasiRiRecvWaitall), tmResult, tmResult2); errno != 0 {
		t.Fatalf("recv errno %d", errno)
	}
	if n := binary.LittleEndian.Uint32(mem[tmResult:]); n != 6 || string(mem[tmData:tmData+6]) != "abcdef" {
		t.Fatalf("recv %d bytes: %q", n, mem[tmData:tmData+6])
	}

	copy(mem[tmData:], "xyz")
	putIOVec(mem, tmIOVecs, 0, tmData, 3)
	if errno, _ := s.sockSend(mem, fd, tmIOVecs, 1, 0, tmResult); errno != 0 || binary.LittleEndian.Uint32(mem[tmResult:]) != 3 {
		t.Fatalf("send errno %d", errno)
	}
	buf := make([]byte, 3)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "xyz" {
		t.Fatalf("client got %q: %v", buf, err)
	}
	// sock_recv / sock_send are metered, as on wazero, plus the accept pulse.
	if meter.in.Load() != 1+3+6 || meter.out.Load() != 3 {
		t.Fatalf("meter in=%d out=%d", meter.in.Load(), meter.out.Load())
	}
	// A failed recv counts nothing.
	if errno, _ := s.sockRecv(mem, fd, tmIOVecs, 1, 0, tmResult, tmResult2); errno != wasiErrnoAgain || meter.in.Load() != 10 {
		t.Fatalf("empty recv: errno %d meter %d", errno, meter.in.Load())
	}
}

func TestWasip1BlockingReadAndStop(t *testing.T) {
	s := newTestSockets(t, nil, WASIListener{})
	mem := make([]byte, 1<<16)
	fd, client := connectedPair(t, s, mem, 0) // blocking

	putIOVec(mem, tmIOVecs, 0, tmData, 16)
	got := make(chan uint16, 1)
	go func() {
		errno, _ := s.fdRead(mem, fd, tmIOVecs, 1, tmResult)
		got <- errno
	}()
	time.Sleep(30 * time.Millisecond)
	if _, err := client.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	select {
	case errno := <-got:
		if errno != 0 || string(mem[tmData:tmData+4]) != "late" {
			t.Fatalf("errno %d data %q", errno, mem[tmData:tmData+4])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking read did not return on data")
	}

	// A blocking write to a peer that reads nothing fills the buffers and
	// waits; a stop ends it, as it ends a blocking read.
	big := make([]byte, 1<<15)
	copy(mem[tmData:], big[:1<<14])
	putIOVec(mem, tmIOVecs, 0, tmData, 1<<14)
	writes := make(chan error, 1)
	go func() {
		for {
			if _, err := s.fdWrite(mem, fd, tmIOVecs, 1, tmResult); err != nil {
				writes <- err
				return
			}
		}
	}()
	reads := make(chan error, 1)
	readMem := make([]byte, 1<<16)
	putIOVec(readMem, tmIOVecs, 0, tmData, 16)
	fd2, _ := connectedPair(t, s, readMem, 0)
	go func() {
		_, err := s.fdRead(readMem, fd2, tmIOVecs, 1, tmResult)
		reads <- err
	}()
	time.Sleep(50 * time.Millisecond)
	s.stop()
	for name, ch := range map[string]chan error{"write": writes, "read": reads} {
		select {
		case err := <-ch:
			if !errors.Is(err, errWasip1Stopped) {
				t.Fatalf("%s: err = %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("stop did not end a blocked %s", name)
		}
	}
}

func TestWasip1ShutdownCloseRenumber(t *testing.T) {
	s := newTestSockets(t, nil, WASIListener{GuestPort: 8080}, WASIListener{GuestPort: 9090})
	mem := make([]byte, 1<<16)
	fd, client := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))

	for _, tc := range []struct {
		fd   int32
		how  uint32
		want uint16
	}{
		{fd, 0, wasiErrnoInval},
		{fd, 4, wasiErrnoInval},
		{fd, 0x101, wasiErrnoInval},
		{wasip1SocketFDBase, uint32(wasiSdflagWr), wasiErrnoNotconn},
		{fd + 10, uint32(wasiSdflagWr), wasiErrnoBadf},
	} {
		if errno := s.sockShutdown(tc.fd, tc.how); errno != tc.want {
			t.Fatalf("shutdown(%d, %d) = %d, want %d", tc.fd, tc.how, errno, tc.want)
		}
	}
	if errno := s.sockShutdown(fd, uint32(wasiSdflagWr)); errno != 0 {
		t.Fatalf("shutdown WR: %d", errno)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("client after SHUT_WR: %d, %v", n, err)
	}
	for _, how := range []uint32{uint32(wasiSdflagRd), uint32(wasiSdflagRd | wasiSdflagWr)} {
		if errno := s.sockShutdown(fd, how); errno != 0 && errno != wasiErrnoNotconn {
			t.Fatalf("shutdown %d: %d", how, errno)
		}
	}

	// Renumbering: socket onto socket moves it; a mixed pair is refused.
	fd2, _ := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))
	if errno := s.fdRenumber(fd, fd); errno != 0 {
		t.Fatalf("renumber onto itself: %d", errno)
	}
	if errno := s.fdRenumber(fd, 3); errno != wasiErrnoNotsup {
		t.Fatalf("renumber onto a file: %d", errno)
	}
	if errno := s.fdRenumber(fd2, fd); errno != 0 || s.owns(fd2) || !s.owns(fd) {
		t.Fatalf("renumber: %d", errno)
	}
	// Moving a listener retires it for routing, as on wazero.
	if errno := s.fdRenumber(wasip1SocketFDBase+1, fd); errno != 0 {
		t.Fatalf("renumber listener: %d", errno)
	}
	if live := s.listen.live(); len(live) != 1 || live[0].guestPort != 8080 {
		t.Fatalf("live after renumber = %+v", live)
	}

	// Closing the last listener leaves none live; closing twice is EBADF.
	if errno := s.fdClose(wasip1SocketFDBase); errno != 0 {
		t.Fatalf("close listener: %d", errno)
	}
	if live := s.listen.live(); len(live) != 0 {
		t.Fatalf("live after close = %+v", live)
	}
	if errno := s.fdClose(wasip1SocketFDBase); errno != wasiErrnoBadf {
		t.Fatalf("second close: %d", errno)
	}
	if errno := s.fdClose(fd); errno != 0 {
		t.Fatalf("close conn: %d", errno)
	}
}

func TestWasip1Fdstat(t *testing.T) {
	s := newTestSockets(t, nil, WASIListener{})
	mem := make([]byte, 1<<16)
	lfd := wasip1SocketFDBase

	if errno := s.fdFdstatGet(mem, lfd, tmData); errno != 0 || mem[tmData] != wasiFiletypeSocketStream || binary.LittleEndian.Uint16(mem[tmData+2:]) != 0 {
		t.Fatalf("fdstat: errno %d %x", errno, mem[tmData:tmData+4])
	}
	if errno := s.fdFdstatSetFlags(lfd, uint32(wasiFdflagNonblock|wasiFdflagAppend)); errno != 0 {
		t.Fatalf("set flags: %d", errno)
	}
	if s.fdFdstatGet(mem, lfd, tmData); binary.LittleEndian.Uint16(mem[tmData+2:]) != wasiFdflagNonblock|wasiFdflagAppend {
		t.Fatalf("flags = %#x", binary.LittleEndian.Uint16(mem[tmData+2:]))
	}
	if errno := s.fdFilestatGet(mem, lfd, tmData); errno != 0 || mem[tmData+16] != wasiFiletypeSocketStream {
		t.Fatalf("filestat: %d", errno)
	}
	for _, tc := range []struct {
		name string
		got  uint16
		want uint16
	}{
		{"fdstat unknown", s.fdFdstatGet(mem, lfd+9, tmData), wasiErrnoBadf},
		{"fdstat fault", s.fdFdstatGet(mem, lfd, 1<<16-8), wasiErrnoFault},
		{"set flags sync", s.fdFdstatSetFlags(lfd, 16), wasiErrnoInval},
		{"set flags unknown", s.fdFdstatSetFlags(lfd+9, 0), wasiErrnoBadf},
		{"filestat unknown", s.fdFilestatGet(mem, lfd+9, tmData), wasiErrnoBadf},
		{"filestat fault", s.fdFilestatGet(mem, lfd, 1<<16-8), wasiErrnoFault},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s: %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// pollEventsOf reads the n events poll wrote.
func pollEventsOf(mem []byte) []wasiEvent {
	n := binary.LittleEndian.Uint32(mem[tmResult:])
	out := make([]wasiEvent, n)
	for i := range out {
		b := mem[tmEvents+uint32(i)*wasiEventSize:]
		out[i] = wasiEvent{
			userdata: binary.LittleEndian.Uint64(b),
			errno:    binary.LittleEndian.Uint16(b[8:]),
			tag:      b[10],
			nbytes:   binary.LittleEndian.Uint64(b[16:]),
			flags:    binary.LittleEndian.Uint16(b[24:]),
		}
	}
	return out
}

func TestWasip1PollOneoff(t *testing.T) {
	s := newTestSockets(t, nil, WASIListener{GuestPort: 8080})
	mem := make([]byte, 1<<16)
	lfd := wasip1SocketFDBase
	poll := func(n uint32, clock wasip1Clock) (uint16, bool, error) {
		return s.pollOneoff(mem, tmSubs, tmEvents, n, tmResult, clock)
	}

	t.Run("relative clock sleeps", func(t *testing.T) {
		putClockSub(mem, tmSubs, 0, 11, wasiClockMonotonic, uint64(30*time.Millisecond), 0)
		start := time.Now()
		errno, handled, err := poll(1, nil)
		if errno != 0 || !handled || err != nil || time.Since(start) < 30*time.Millisecond {
			t.Fatalf("errno %d handled %v err %v after %v", errno, handled, err, time.Since(start))
		}
		if ev := pollEventsOf(mem); len(ev) != 1 || ev[0].userdata != 11 || ev[0].tag != wasiEventtypeClock {
			t.Fatalf("events = %+v", ev)
		}
	})

	t.Run("absolute clock reads the guest clock", func(t *testing.T) {
		putClockSub(mem, tmSubs, 0, 12, wasiClockMonotonic, 5_000, wasiSubclockAbstime)
		putClockSub(mem, tmSubs, 1, 13, wasiClockRealtime, 1_000+uint64(20*time.Millisecond), wasiSubclockAbstime)
		var asked []uint32
		clock := func(id uint32) (uint64, uint16) {
			asked = append(asked, id)
			return 1_000, 0
		}
		start := time.Now()
		if errno, handled, _ := poll(2, clock); errno != 0 || !handled {
			t.Fatalf("errno %d", errno)
		}
		// The monotonic deadline (4µs away) fires first; the realtime one
		// (20ms away) has not.
		if ev := pollEventsOf(mem); len(ev) != 1 || ev[0].userdata != 12 || time.Since(start) > 15*time.Millisecond {
			t.Fatalf("events = %+v after %v", ev, time.Since(start))
		}
		if len(asked) != 2 || asked[0] != wasiClockMonotonic || asked[1] != wasiClockRealtime {
			t.Fatalf("clocks asked = %v", asked)
		}
		putClockSub(mem, tmSubs, 0, 14, wasiClockMonotonic, 500, wasiSubclockAbstime)
		if errno, _, _ := poll(1, clock); errno != 0 || pollEventsOf(mem)[0].userdata != 14 {
			t.Fatal("a deadline already past fires at once")
		}
		if errno, handled, _ := poll(1, nil); errno != wasiErrnoNotsup || !handled {
			t.Fatalf("no clock: errno %d", errno)
		}
		failing := func(uint32) (uint64, uint16) { return 0, wasiErrnoInval }
		if errno, _, _ := poll(1, failing); errno != wasiErrnoInval {
			t.Fatalf("clock error: errno %d", errno)
		}
	})

	t.Run("a socket with a connection is readable", func(t *testing.T) {
		putFDSub(mem, tmSubs, 0, 21, wasiEventtypeFdRead, lfd)
		putClockSub(mem, tmSubs, 1, 22, wasiClockMonotonic, uint64(10*time.Millisecond), 0)
		if errno, _, _ := poll(2, nil); errno != 0 {
			t.Fatalf("errno %d", errno)
		}
		if ev := pollEventsOf(mem); len(ev) != 1 || ev[0].userdata != 22 {
			t.Fatalf("nothing pending: events = %+v", ev)
		}
		dialTest(t, hostPort(t, s, 0))
		putClockSub(mem, tmSubs, 1, 22, wasiClockMonotonic, uint64(2*time.Second), 0)
		if errno, _, _ := poll(2, nil); errno != 0 {
			t.Fatalf("errno %d", errno)
		}
		if ev := pollEventsOf(mem); len(ev) != 1 || ev[0].userdata != 21 || ev[0].tag != wasiEventtypeFdRead || ev[0].errno != 0 {
			t.Fatalf("pending: events = %+v", ev)
		}
	})

	t.Run("a connection is writable and hangs up", func(t *testing.T) {
		fd := acceptTest(t, s, mem, lfd, uint32(wasiFdflagNonblock))
		putFDSub(mem, tmSubs, 0, 31, wasiEventtypeFdWrite, fd)
		if errno, _, _ := poll(1, nil); errno != 0 {
			t.Fatalf("errno %d", errno)
		}
		if ev := pollEventsOf(mem); len(ev) != 1 || ev[0].tag != wasiEventtypeFdWrite || ev[0].errno != 0 {
			t.Fatalf("events = %+v", ev)
		}
	})

	t.Run("other fds are ready at once", func(t *testing.T) {
		putFDSub(mem, tmSubs, 0, 41, wasiEventtypeFdRead, 0)
		if _, handled, _ := poll(1, nil); handled {
			t.Fatal("a poll on stdio alone goes to wasmtime")
		}
		putFDSub(mem, tmSubs, 1, 42, wasiEventtypeFdRead, lfd+40) // closed socket
		if errno, handled, _ := poll(2, nil); errno != 0 || !handled {
			t.Fatalf("errno %d handled %v", errno, handled)
		}
		ev := pollEventsOf(mem)
		if len(ev) != 2 || ev[0].userdata != 41 || ev[0].errno != 0 || ev[1].userdata != 42 || ev[1].errno != wasiErrnoBadf {
			t.Fatalf("events = %+v", ev)
		}
	})

	t.Run("bad calls", func(t *testing.T) {
		if _, handled, _ := poll(0, nil); handled {
			t.Fatal("no subscriptions goes to wasmtime, which says EINVAL")
		}
		putClockSub(mem, tmSubs, 0, 1, wasiClockMonotonic, 0, 0)
		if errno, _, _ := s.pollOneoff(mem, tmSubs, 1<<16-16, 1, tmResult, nil); errno != wasiErrnoFault {
			t.Fatalf("events out of bounds: %d", errno)
		}
		if errno, _, _ := s.pollOneoff(mem, tmSubs, tmEvents, 1, 1<<16-2, nil); errno != wasiErrnoFault {
			t.Fatalf("count out of bounds: %d", errno)
		}
	})

	t.Run("stop ends a wait with no timeout", func(t *testing.T) {
		quiet := newTestSockets(t, nil, WASIListener{})
		qmem := make([]byte, 1<<16)
		putFDSub(qmem, tmSubs, 0, 1, wasiEventtypeFdRead, wasip1SocketFDBase)
		done := make(chan error, 1)
		go func() {
			_, _, err := quiet.pollOneoff(qmem, tmSubs, tmEvents, 1, tmResult, nil)
			done <- err
		}()
		time.Sleep(20 * time.Millisecond)
		quiet.stop()
		quiet.stop() // twice is fine
		select {
		case err := <-done:
			if !errors.Is(err, errWasip1Stopped) {
				t.Fatalf("err = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("stop did not end the poll")
		}
		quiet.close()
		quiet.close()
		quiet.stop() // after close: nothing to wake, no write to a closed fd
	})
}

func TestWasip1SocketError(t *testing.T) {
	// A non-blocking connect to a closed port fails asynchronously: poll
	// flags it and SO_ERROR holds ECONNREFUSED.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	fd, err := wasip1SysSocket(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if got := socketError(fd); got != wasiErrnoIO {
		t.Fatalf("no pending error: %d", got)
	}
	err = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
	if err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("connect: %v", err)
	}
	if errors.Is(err, unix.ECONNREFUSED) {
		t.Skip("connect failed synchronously")
	}
	pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	if _, err := wasip1SysPoll(pfds, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := socketError(fd); got != wasiErrnoConnrefused {
		t.Fatalf("refused connect: errno %d", got)
	}
	if got := socketError(-1); got != wasiErrnoBadf {
		t.Fatalf("bad fd: errno %d", got)
	}
}

func TestWasip1EdgeCases(t *testing.T) {
	t.Run("fd numbers run out", func(t *testing.T) {
		s := newTestSockets(t, nil, WASIListener{})
		mem := make([]byte, 1<<16)
		dialTest(t, hostPort(t, s, 0))
		s.next = math.MaxInt32
		if errno, err := s.sockAccept(mem, wasip1SocketFDBase, 0, tmResult); errno != wasiErrnoNfile || err != nil {
			t.Fatalf("errno %d err %v", errno, err)
		}
		s.close()
		if _, ok := s.add(0, 0); ok {
			t.Fatal("a closed layer takes no socket")
		}
	})

	t.Run("a full send buffer is EAGAIN when non-blocking", func(t *testing.T) {
		s := newTestSockets(t, nil, WASIListener{})
		mem := make([]byte, 1<<16)
		fd, _ := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))
		putIOVec(mem, tmIOVecs, 0, tmData, 1<<14)
		for i := 0; ; i++ {
			errno, _ := s.fdWrite(mem, fd, tmIOVecs, 1, tmResult)
			if errno == wasiErrnoAgain {
				break
			}
			if errno != 0 || i > 1<<16 {
				t.Fatalf("write %d: errno %d", i, errno)
			}
		}
	})

	t.Run("a write to a reset peer fails", func(t *testing.T) {
		s := newTestSockets(t, nil, WASIListener{})
		mem := make([]byte, 1<<16)
		fd, client := connectedPair(t, s, mem, uint32(wasiFdflagNonblock))
		_ = client.(*net.TCPConn).SetLinger(0)
		_ = client.Close()
		waitReadable(t, s, fd)
		putIOVec(mem, tmIOVecs, 0, tmData, 16)
		var errno uint16
		for i := 0; i < 50 && errno == 0; i++ {
			errno, _ = s.fdWrite(mem, fd, tmIOVecs, 1, tmResult)
			time.Sleep(time.Millisecond)
		}
		if errno != wasiErrnoConnreset && errno != wasiErrnoPipe {
			t.Fatalf("errno %d, want ECONNRESET or EPIPE", errno)
		}
		if errno, _ := s.fdRead(mem, fd, tmIOVecs, 1, tmResult); errno != wasiErrnoConnreset && errno != 0 {
			t.Fatalf("read after reset: errno %d", errno)
		}
	})

	t.Run("stoppedErr keeps only the stop", func(t *testing.T) {
		if stoppedErr(unix.EIO) != nil || !errors.Is(stoppedErr(errWasip1Stopped), errWasip1Stopped) {
			t.Fatal("stoppedErr")
		}
	})

	t.Run("poll flags errors and hangups", func(t *testing.T) {
		s := newTestSockets(t, nil)
		subs := []wasiSubscription{
			{userdata: 1, tag: wasiEventtypeFdRead, fd: wasip1SocketFDBase},
			{userdata: 2, tag: wasiEventtypeFdWrite, fd: wasip1SocketFDBase + 1},
			{userdata: 3, tag: wasiEventtypeFdRead, fd: wasip1SocketFDBase + 2},
			{userdata: 4, tag: wasiEventtypeFdWrite, fd: wasip1SocketFDBase + 3},
		}
		pfds := []unix.PollFd{
			{},
			{Fd: -1, Revents: unix.POLLNVAL},
			{Fd: -1, Revents: unix.POLLERR | unix.POLLHUP},
			{Fd: -1, Revents: unix.POLLOUT}, // a read sub ignores POLLOUT
			{Fd: -1, Revents: unix.POLLOUT},
		}
		events := s.pollEvents(subs, pfds, []int{1, 2, 3, 4}, make([]time.Time, 4), time.Now())
		if len(events) != 3 {
			t.Fatalf("events = %+v", events)
		}
		if events[0].userdata != 1 || events[0].errno != wasiErrnoBadf {
			t.Fatalf("POLLNVAL: %+v", events[0])
		}
		if events[1].userdata != 2 || events[1].errno != wasiErrnoBadf || events[1].flags != wasiEventFdReadwriteHangup {
			t.Fatalf("POLLERR|POLLHUP on fd -1: %+v", events[1])
		}
		if events[2].userdata != 4 || events[2].errno != 0 {
			t.Fatalf("POLLOUT: %+v", events[2])
		}
	})
}

func TestClockWaitCaps(t *testing.T) {
	d, errno := clockWait(wasiSubscription{tag: wasiEventtypeClock, timeout: ^uint64(0)}, nil)
	if errno != 0 || d <= 0 {
		t.Fatalf("huge timeout = %v, %d", d, errno)
	}
}
