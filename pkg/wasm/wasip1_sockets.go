//go:build linux || darwin

package wasm

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// wasip1SocketFDBase is the first guest fd the socket layer hands out.
// wasmtime's own WASI layer numbers a new descriptor one past the largest
// it holds, starting after stdio and the directory preopens, so its fds
// stay far below this one and the two never meet. A guest learns its
// listener fds from ListenFDEnv / ListenFDsEnv, never by counting.
const wasip1SocketFDBase int32 = 1 << 24

// wasip1SocketsSupported reports whether this host can serve guest sockets
// on the wasmtime engine (wasip1_sockets_other.go says no).
const wasip1SocketsSupported = true

// errWasip1Stopped ends a guest call blocked in the socket layer when the
// engine stops its instance. The call traps rather than returns, so the
// guest unwinds at once and the engine can release the store.
var errWasip1Stopped = errors.New("wasm instance stopped")

// wasip1Socket is one guest socket: a host TCP socket the guest sees as a
// WASI fd.
type wasip1Socket struct {
	hostFD   int
	listener bool
	// flags is the guest's fdflags. The host socket is always
	// non-blocking; a guest that leaves NONBLOCK off gets calls that wait,
	// and the layer waits with poll so a stop can end the wait.
	flags uint16
}

// wasip1Clock reads the guest's clock id in nanoseconds, the value
// clock_time_get would give it. poll_oneoff needs it only for a
// subscription with an absolute deadline.
type wasip1Clock func(id uint32) (uint64, uint16)

// wasip1Sockets serves the WASI preview-1 socket calls for one wasmtime
// instance. wasmtime's C API cannot pre-open a socket and its preview-1
// sock_accept is a stub, so the engine routes every call that names one of
// these fds here (wasmtime_sockets.go) and every other call to wasmtime.
//
// Only the guest's own thread makes the calls. stop is the one method
// another goroutine may call while a call runs: it wakes any wait so the
// call traps. close releases the host sockets and runs only once no call
// can be running, so a host fd is never closed under a poll that holds it.
type wasip1Sockets struct {
	mu     sync.Mutex
	socks  map[int32]*wasip1Socket
	next   int32
	closed bool
	// listen tracks the listeners for the worker (wazero_listeners.go): the
	// host ports, and which ones the guest has accepted on or closed.
	listen *instanceListen
	meter  ByteMeter
	// stopR is in every poll; stop writes stopW once and nothing drains
	// it, so every later wait ends at once too.
	stopR, stopW int
	stopped      bool
}

// newWasip1Sockets binds one host listener per entry of listeners on host
// (127.0.0.1 when empty), at the fds from wasip1SocketFDBase in order.
// With no listeners it holds only the stop pipe, which poll_oneoff needs to
// be stoppable. The caller closes it.
func newWasip1Sockets(listeners []WASIListener, host string, meter ByteMeter) (*wasip1Sockets, error) {
	r, w, err := wasip1SysPipe()
	if err != nil {
		return nil, fmt.Errorf("wasip1 sockets: stop pipe: %w", err)
	}
	s := &wasip1Sockets{
		socks: make(map[int32]*wasip1Socket),
		next:  wasip1SocketFDBase,
		meter: meter,
		stopR: r,
		stopW: w,
	}
	if host == "" {
		host = "127.0.0.1"
	}
	var bound []boundListener
	for _, l := range listeners {
		hostFD, port, err := wasip1Listen(host, l.HostPort)
		if err != nil {
			s.close()
			return nil, fmt.Errorf("wasip1 listener for port %d: %w", l.GuestPort, err)
		}
		fd := s.next
		s.next++
		s.socks[fd] = &wasip1Socket{hostFD: hostFD, listener: true}
		bound = append(bound, boundListener{fd: fd, guestPort: l.GuestPort, hostPort: port})
	}
	if len(bound) > 0 {
		s.listen = &instanceListen{bound: bound}
	}
	return s, nil
}

// wasip1Listen binds a non-blocking TCP listener on host:port and returns
// it with the port it got. SO_REUSEADDR, as net.Listen sets: the worker
// rebinds a re-instantiated guest's listener on the port the last one had
// (syncResolvedListeners), while that one's connections may sit in
// TIME_WAIT.
func wasip1Listen(host string, port int) (int, int, error) {
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return -1, 0, err
	}
	var sa unix.Sockaddr
	family := unix.AF_INET
	if ip4 := addr.IP.To4(); ip4 != nil || addr.IP == nil {
		sa4 := &unix.SockaddrInet4{Port: addr.Port}
		copy(sa4.Addr[:], ip4)
		sa = sa4
	} else {
		family = unix.AF_INET6
		sa6 := &unix.SockaddrInet6{Port: addr.Port}
		copy(sa6.Addr[:], addr.IP.To16())
		sa = sa6
	}
	fd, err := wasip1SysSocket(family)
	if err != nil {
		return -1, 0, err
	}
	fail := func(err error) (int, int, error) {
		_ = unix.Close(fd)
		return -1, 0, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fail(err)
	}
	if err := unix.Bind(fd, sa); err != nil {
		return fail(err)
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		return fail(err)
	}
	got, err := unix.Getsockname(fd)
	if err != nil {
		return fail(err)
	}
	switch a := got.(type) {
	case *unix.SockaddrInet4:
		return fd, a.Port, nil
	case *unix.SockaddrInet6:
		return fd, a.Port, nil
	}
	return fail(fmt.Errorf("listener bound to %T", got))
}

// listenerFDs are the guest fds of the listeners, in Listeners order.
func (s *wasip1Sockets) listenerFDs() []int {
	if s.listen == nil {
		return nil
	}
	fds := make([]int, len(s.listen.bound))
	for i, b := range s.listen.bound {
		fds[i] = int(b.fd)
	}
	return fds
}

// lookup is the open socket at fd, nil when fd names none.
func (s *wasip1Sockets) lookup(fd int32) *wasip1Socket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.socks[fd]
}

// owns reports whether fd is one of the guest's sockets; every other fd is
// wasmtime's.
func (s *wasip1Sockets) owns(fd int32) bool {
	return s.lookup(fd) != nil
}

// inRange reports whether fd is a number the socket layer hands out,
// open or not. A poll subscription on one that is closed gets EBADF here
// rather than going to wasmtime, which has never heard of it.
func inRange(fd int32) bool {
	return fd >= wasip1SocketFDBase
}

// stop wakes every wait the guest is in, and every later one, so its call
// traps with errWasip1Stopped. Safe from any goroutine, any number of
// times, before or after close.
func (s *wasip1Sockets) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped || s.closed {
		return
	}
	s.stopped = true
	_, _ = unix.Write(s.stopW, []byte{1})
}

// close releases every host socket and the stop pipe. The engine calls it
// once no guest call can be running. Idempotent.
func (s *wasip1Sockets) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for fd, sock := range s.socks {
		_ = unix.Close(sock.hostFD)
		delete(s.socks, fd)
	}
	_ = unix.Close(s.stopR)
	_ = unix.Close(s.stopW)
}

// add registers an accepted host socket under the next guest fd.
func (s *wasip1Sockets) add(hostFD int, flags uint16) (int32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.next == math.MaxInt32 {
		return 0, false
	}
	fd := s.next
	s.next++
	s.socks[fd] = &wasip1Socket{hostFD: hostFD, flags: flags}
	return fd, true
}

// wait blocks until hostFD has events or the instance stops.
func (s *wasip1Sockets) wait(hostFD int, events int16) error {
	fds := []unix.PollFd{{Fd: int32(s.stopR), Events: unix.POLLIN}, {Fd: int32(hostFD), Events: events}}
	for {
		_, err := wasip1SysPoll(fds, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if fds[0].Revents != 0 {
			return errWasip1Stopped
		}
		return err
	}
}

// sockAccept is sock_accept(fd, flags, result_fd).
func (s *wasip1Sockets) sockAccept(mem []byte, fd int32, flags uint32, resultFD uint32) (uint16, error) {
	sock := s.lookup(fd)
	if sock == nil {
		return wasiErrnoBadf, nil
	}
	if !sock.listener {
		return wasiErrnoInval, nil
	}
	// Recorded before the attempt, as on wazero: a guest that accepts on a
	// listener serves it, whether a connection is waiting yet or not.
	s.listen.fdAccepted(fd)
	if flags&^uint32(wasiFdflagNonblock) != 0 {
		return wasiErrnoInval, nil
	}
	if _, ok := guestSpan(mem, resultFD, 4); !ok {
		return wasiErrnoFault, nil
	}
	for {
		hostFD, err := wasip1SysAccept(sock.hostFD)
		switch {
		case err == nil:
			newFD, ok := s.add(hostFD, uint16(flags))
			if !ok {
				_ = unix.Close(hostFD)
				return wasiErrnoNfile, nil
			}
			guestPutU32(mem, resultFD, uint32(newFD))
			// A one-byte pulse, as wazero's meter counts an accept, so the
			// sandbox's network stats move before the first byte does.
			if s.meter != nil {
				s.meter.AddIn(1)
			}
			return wasiErrnoSuccess, nil
		case errors.Is(err, unix.EINTR), errors.Is(err, unix.ECONNABORTED):
			continue
		case errors.Is(err, unix.EAGAIN):
			if sock.flags&wasiFdflagNonblock != 0 {
				return wasiErrnoAgain, nil
			}
			if err := s.wait(sock.hostFD, unix.POLLIN); err != nil {
				return wasiErrno(err), stoppedErr(err)
			}
		default:
			return wasiErrno(err), nil
		}
	}
}

// stoppedErr passes errWasip1Stopped through and drops every other error,
// which the caller has already turned into an errno.
func stoppedErr(err error) error {
	if errors.Is(err, errWasip1Stopped) {
		return err
	}
	return nil
}

// conn is the connected socket at fd, or the errno for why there is none.
func (s *wasip1Sockets) conn(fd int32) (*wasip1Socket, uint16) {
	sock := s.lookup(fd)
	if sock == nil {
		return nil, wasiErrnoBadf
	}
	if sock.listener {
		return nil, wasiErrnoNotconn
	}
	return sock, wasiErrnoSuccess
}

// recv reads into the iovecs at iovs; peek leaves the data queued.
func (s *wasip1Sockets) recv(mem []byte, fd int32, iovs, n uint32, peek bool) (int, uint16, error) {
	sock, errno := s.conn(fd)
	if errno != 0 {
		return 0, errno, nil
	}
	bufs, errno := guestIOVecs(mem, iovs, n)
	if errno != 0 {
		return 0, errno, nil
	}
	if len(bufs) == 0 {
		return 0, wasiErrnoSuccess, nil
	}
	for {
		var got int
		var err error
		if peek {
			got, _, err = unix.Recvfrom(sock.hostFD, bufs[0], unix.MSG_PEEK)
		} else {
			got, err = unix.Readv(sock.hostFD, bufs)
		}
		switch {
		case err == nil:
			return got, wasiErrnoSuccess, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			if sock.flags&wasiFdflagNonblock != 0 {
				return 0, wasiErrnoAgain, nil
			}
			if err := s.wait(sock.hostFD, unix.POLLIN); err != nil {
				return 0, wasiErrno(err), stoppedErr(err)
			}
		default:
			return 0, wasiErrno(err), nil
		}
	}
}

// send writes the iovecs at iovs.
func (s *wasip1Sockets) send(mem []byte, fd int32, iovs, n uint32) (int, uint16, error) {
	sock, errno := s.conn(fd)
	if errno != 0 {
		return 0, errno, nil
	}
	bufs, errno := guestIOVecs(mem, iovs, n)
	if errno != 0 {
		return 0, errno, nil
	}
	if len(bufs) == 0 {
		return 0, wasiErrnoSuccess, nil
	}
	for {
		// A peer that has gone raises SIGPIPE here; the Go runtime ignores
		// it for any fd but 1 and 2, and the write fails with EPIPE.
		got, err := unix.Writev(sock.hostFD, bufs)
		switch {
		case err == nil:
			return got, wasiErrnoSuccess, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			if sock.flags&wasiFdflagNonblock != 0 {
				return 0, wasiErrnoAgain, nil
			}
			if err := s.wait(sock.hostFD, unix.POLLOUT); err != nil {
				return 0, wasiErrno(err), stoppedErr(err)
			}
		default:
			return 0, wasiErrno(err), nil
		}
	}
}

// fdRead is fd_read(fd, iovs, iovs_len, result_nread) on a socket. Not
// metered: Go's wasip1 net reads sockets with fd_read, and the worker
// already counts those bytes at its HTTP proxy, as it does on wazero,
// whose meter counts only sock_recv / sock_send.
func (s *wasip1Sockets) fdRead(mem []byte, fd int32, iovs, n, resultN uint32) (uint16, error) {
	if _, ok := guestSpan(mem, resultN, 4); !ok {
		return wasiErrnoFault, nil
	}
	got, errno, err := s.recv(mem, fd, iovs, n, false)
	if errno == 0 && err == nil {
		guestPutU32(mem, resultN, uint32(got))
	}
	return errno, err
}

// fdWrite is fd_write(fd, iovs, iovs_len, result_nwritten) on a socket.
func (s *wasip1Sockets) fdWrite(mem []byte, fd int32, iovs, n, resultN uint32) (uint16, error) {
	if _, ok := guestSpan(mem, resultN, 4); !ok {
		return wasiErrnoFault, nil
	}
	got, errno, err := s.send(mem, fd, iovs, n)
	if errno == 0 && err == nil {
		guestPutU32(mem, resultN, uint32(got))
	}
	return errno, err
}

// sockRecv is sock_recv(fd, ri_data, ri_data_len, ri_flags,
// result_ro_datalen, result_ro_flags).
func (s *wasip1Sockets) sockRecv(mem []byte, fd int32, iovs, n, riFlags, resultLen, resultFlags uint32) (uint16, error) {
	// WAITALL is taken and read once, as wazero does: the caller loops on
	// a short read either way.
	if riFlags&^uint32(wasiRiRecvPeek|wasiRiRecvWaitall) != 0 {
		return wasiErrnoNotsup, nil
	}
	if _, ok := guestSpan(mem, resultLen, 4); !ok {
		return wasiErrnoFault, nil
	}
	if _, ok := guestSpan(mem, resultFlags, 2); !ok {
		return wasiErrnoFault, nil
	}
	got, errno, err := s.recv(mem, fd, iovs, n, riFlags&uint32(wasiRiRecvPeek) != 0)
	if errno != 0 || err != nil {
		return errno, err
	}
	guestPutU32(mem, resultLen, uint32(got))
	guestPutU16(mem, resultFlags, 0)
	if s.meter != nil && got > 0 {
		s.meter.AddIn(int64(got))
	}
	return wasiErrnoSuccess, nil
}

// sockSend is sock_send(fd, si_data, si_data_len, si_flags,
// result_so_datalen). WASI defines no send flags.
func (s *wasip1Sockets) sockSend(mem []byte, fd int32, iovs, n, siFlags, resultLen uint32) (uint16, error) {
	if siFlags != 0 {
		return wasiErrnoNotsup, nil
	}
	if _, ok := guestSpan(mem, resultLen, 4); !ok {
		return wasiErrnoFault, nil
	}
	got, errno, err := s.send(mem, fd, iovs, n)
	if errno != 0 || err != nil {
		return errno, err
	}
	guestPutU32(mem, resultLen, uint32(got))
	if s.meter != nil && got > 0 {
		s.meter.AddOut(int64(got))
	}
	return wasiErrnoSuccess, nil
}

// sockShutdown is sock_shutdown(fd, how).
func (s *wasip1Sockets) sockShutdown(fd int32, how uint32) uint16 {
	sock, errno := s.conn(fd)
	if errno != 0 {
		return errno
	}
	var sysHow int
	switch how {
	case uint32(wasiSdflagRd | wasiSdflagWr):
		sysHow = unix.SHUT_RDWR
	case uint32(wasiSdflagRd):
		sysHow = unix.SHUT_RD
	case uint32(wasiSdflagWr):
		sysHow = unix.SHUT_WR
	default:
		return wasiErrnoInval
	}
	return wasiErrno(unix.Shutdown(sock.hostFD, sysHow))
}

// fdClose is fd_close(fd) on a socket.
func (s *wasip1Sockets) fdClose(fd int32) uint16 {
	s.mu.Lock()
	sock := s.socks[fd]
	delete(s.socks, fd)
	s.mu.Unlock()
	if sock == nil {
		return wasiErrnoBadf
	}
	if sock.listener {
		s.listen.fdGone(fd)
	}
	return wasiErrno(unix.Close(sock.hostFD))
}

// fdRenumber is fd_renumber(from, to) when either fd is a socket. Both must
// be: a socket cannot move into wasmtime's table, nor a file into this one.
func (s *wasip1Sockets) fdRenumber(from, to int32) uint16 {
	s.mu.Lock()
	src, dst := s.socks[from], s.socks[to]
	if src == nil || dst == nil {
		s.mu.Unlock()
		return wasiErrnoNotsup
	}
	if from != to {
		s.socks[to] = src
		delete(s.socks, from)
	}
	s.mu.Unlock()
	if from == to {
		return wasiErrnoSuccess
	}
	// The engine tracks a listener by the fd it opened it on, so one moved
	// elsewhere, or overwritten, is no longer routed to (as on wazero).
	s.listen.fdGone(from)
	s.listen.fdGone(to)
	_ = unix.Close(dst.hostFD)
	return wasiErrnoSuccess
}

// fdFdstatGet is fd_fdstat_get(fd, result_stat) on a socket.
func (s *wasip1Sockets) fdFdstatGet(mem []byte, fd int32, ptr uint32) uint16 {
	sock := s.lookup(fd)
	if sock == nil {
		return wasiErrnoBadf
	}
	dst, ok := guestSpan(mem, ptr, wasiFdstatSize)
	if !ok {
		return wasiErrnoFault
	}
	encodeSocketFdstat(dst, sock.flags)
	return wasiErrnoSuccess
}

// fdFdstatSetFlags is fd_fdstat_set_flags(fd, flags) on a socket. Only
// NONBLOCK changes anything; APPEND is kept and reported back, and the
// sync flags mean nothing for a socket.
func (s *wasip1Sockets) fdFdstatSetFlags(fd int32, flags uint32) uint16 {
	if flags&^uint32(wasiFdflagAppend|wasiFdflagNonblock) != 0 {
		return wasiErrnoInval
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sock := s.socks[fd]
	if sock == nil {
		return wasiErrnoBadf
	}
	sock.flags = uint16(flags)
	return wasiErrnoSuccess
}

// fdFilestatGet is fd_filestat_get(fd, result_stat) on a socket.
func (s *wasip1Sockets) fdFilestatGet(mem []byte, fd int32, ptr uint32) uint16 {
	if !s.owns(fd) {
		return wasiErrnoBadf
	}
	dst, ok := guestSpan(mem, ptr, wasiFilestatSize)
	if !ok {
		return wasiErrnoFault
	}
	encodeSocketFilestat(dst)
	return wasiErrnoSuccess
}

// pollOneoff is poll_oneoff(in, out, nsubscriptions, result_nevents) when
// the socket layer can serve it: handled is false when wasmtime should,
// which is when no subscription names a socket and some name another fd
// (a file or stdio, which wasmtime polls properly). Everything else is
// served here, a clock-only sleep too: wasmtime's own sleep cannot be cut
// short, and a guest idling in one would hold up a stop for as long as it
// sleeps.
//
// Sockets wait in poll(2) with the stop pipe; any other fd in the same
// call is reported ready at once, as wazero reports files. A clock
// subscription fires once its timeout has passed.
func (s *wasip1Sockets) pollOneoff(mem []byte, in, out, n, resultN uint32, clock wasip1Clock) (errno uint16, handled bool, err error) {
	subs, errno := decodeSubscriptions(mem, in, n)
	if errno != 0 {
		// wasmtime reports a bad call as well as this layer would.
		return 0, false, nil
	}
	ours, others := false, false
	for _, sub := range subs {
		if sub.tag == wasiEventtypeClock {
			continue
		}
		if inRange(sub.fd) {
			ours = true
		} else {
			others = true
		}
	}
	if others && !ours {
		return 0, false, nil
	}
	outBuf, ok := guestSpan(mem, out, uint64(n)*wasiEventSize)
	if !ok {
		return wasiErrnoFault, true, nil
	}
	if _, ok := guestSpan(mem, resultN, 4); !ok {
		return wasiErrnoFault, true, nil
	}

	start := time.Now()
	clockAt := make([]time.Time, len(subs))
	var deadline time.Time
	hasDeadline := false
	for i, sub := range subs {
		if sub.tag != wasiEventtypeClock {
			continue
		}
		wait, errno := clockWait(sub, clock)
		if errno != 0 {
			return errno, true, nil
		}
		clockAt[i] = start.Add(wait)
		if !hasDeadline || clockAt[i].Before(deadline) {
			deadline, hasDeadline = clockAt[i], true
		}
	}

	// pfds[0] is the stop pipe; polled[i] is subs[i]'s entry, or -1.
	pfds := []unix.PollFd{{Fd: int32(s.stopR), Events: unix.POLLIN}}
	polled := make([]int, len(subs))
	readyNow := false
	for i, sub := range subs {
		polled[i] = -1
		if sub.tag == wasiEventtypeClock {
			continue
		}
		sock := s.lookup(sub.fd)
		if sock == nil {
			// A file, stdio, or a closed socket: an event at once.
			readyNow = true
			continue
		}
		events := int16(unix.POLLIN)
		if sub.tag == wasiEventtypeFdWrite {
			events = unix.POLLOUT
		}
		pfds = append(pfds, unix.PollFd{Fd: int32(sock.hostFD), Events: events})
		polled[i] = len(pfds) - 1
	}

	for {
		timeout := time.Duration(-1)
		switch {
		case readyNow:
			timeout = 0
		case hasDeadline:
			timeout = max(time.Until(deadline), 0)
		}
		_, err := wasip1SysPoll(pfds, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return wasiErrno(err), true, nil
		}
		if pfds[0].Revents != 0 {
			return 0, true, errWasip1Stopped
		}
		events := s.pollEvents(subs, pfds, polled, clockAt, time.Now())
		if len(events) == 0 {
			// Woken early with nothing to report (poll rounds a timeout
			// down on some hosts): wait out the rest.
			continue
		}
		for k, ev := range events {
			encodeEvent(outBuf[k*wasiEventSize:], ev)
		}
		guestPutU32(mem, resultN, uint32(len(events)))
		return wasiErrnoSuccess, true, nil
	}
}

// clockWait is how long a clock subscription waits from now.
func clockWait(sub wasiSubscription, clock wasip1Clock) (time.Duration, uint16) {
	timeout := sub.timeout
	if sub.flags&wasiSubclockAbstime != 0 {
		if clock == nil {
			return 0, wasiErrnoNotsup
		}
		now, errno := clock(sub.clockID)
		if errno != 0 {
			return 0, errno
		}
		if timeout <= now {
			return 0, wasiErrnoSuccess
		}
		timeout -= now
	}
	// A timeout past what a Duration holds is as good as forever; cap it
	// well inside the range time.Time.Add stays exact for.
	const maxWait = uint64(math.MaxInt64 / 2)
	return time.Duration(min(timeout, maxWait)), wasiErrnoSuccess
}

// pollEvents is the events a poll has to report at now.
func (s *wasip1Sockets) pollEvents(subs []wasiSubscription, pfds []unix.PollFd, polled []int, clockAt []time.Time, now time.Time) []wasiEvent {
	var events []wasiEvent
	for i, sub := range subs {
		ev := wasiEvent{userdata: sub.userdata, tag: sub.tag}
		switch {
		case sub.tag == wasiEventtypeClock:
			if now.Before(clockAt[i]) {
				continue
			}
		case polled[i] < 0:
			if inRange(sub.fd) {
				ev.errno = wasiErrnoBadf
			}
		default:
			re := pfds[polled[i]].Revents
			want := int16(unix.POLLIN)
			if sub.tag == wasiEventtypeFdWrite {
				want = unix.POLLOUT
			}
			if re&(want|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) == 0 {
				continue
			}
			if re&unix.POLLHUP != 0 {
				ev.flags = wasiEventFdReadwriteHangup
			}
			switch {
			case re&unix.POLLNVAL != 0:
				ev.errno = wasiErrnoBadf
			case re&unix.POLLERR != 0:
				ev.errno = socketError(int(pfds[polled[i]].Fd))
			}
		}
		events = append(events, ev)
	}
	return events
}

// socketError is the pending error on a host socket poll flagged with
// POLLERR, as a WASI errno.
func socketError(hostFD int) uint16 {
	code, err := unix.GetsockoptInt(hostFD, unix.SOL_SOCKET, unix.SO_ERROR)
	if err != nil {
		return wasiErrno(err)
	}
	if code == 0 {
		return wasiErrnoIO
	}
	return wasiErrno(unix.Errno(code))
}
