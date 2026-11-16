package wasm

import (
	"encoding/binary"
	"errors"
	"syscall"
)

// The WASI preview-1 ABI the wasmtime engine's socket layer reads and writes
// in guest memory (wasip1_sockets.go). The values are those of the
// snapshot-01 witx, which Go's syscall/tables_wasip1.go mirrors; they are
// spelled out here because wazero keeps its copy in an internal package.

// WASI errno values.
const (
	wasiErrnoSuccess     uint16 = 0
	wasiErrnoAcces       uint16 = 2
	wasiErrnoAddrinuse   uint16 = 3
	wasiErrnoAddrnotavai uint16 = 4
	wasiErrnoAgain       uint16 = 6
	wasiErrnoBadf        uint16 = 8
	wasiErrnoCanceled    uint16 = 11
	wasiErrnoConnaborted uint16 = 13
	wasiErrnoConnrefused uint16 = 14
	wasiErrnoConnreset   uint16 = 15
	wasiErrnoFault       uint16 = 21
	wasiErrnoHostunreach uint16 = 23
	wasiErrnoIntr        uint16 = 27
	wasiErrnoInval       uint16 = 28
	wasiErrnoIO          uint16 = 29
	wasiErrnoMfile       uint16 = 33
	wasiErrnoMsgsize     uint16 = 35
	wasiErrnoNetdown     uint16 = 38
	wasiErrnoNetreset    uint16 = 39
	wasiErrnoNetunreach  uint16 = 40
	wasiErrnoNfile       uint16 = 41
	wasiErrnoNobufs      uint16 = 42
	wasiErrnoNomem       uint16 = 48
	wasiErrnoNosys       uint16 = 52
	wasiErrnoNotconn     uint16 = 53
	wasiErrnoNotsock     uint16 = 57
	wasiErrnoNotsup      uint16 = 58
	wasiErrnoPerm        uint16 = 63
	wasiErrnoPipe        uint16 = 64
	wasiErrnoTimedout    uint16 = 73
)

// File types (filetype), fd flags (fdflags) and the socket-related flags.
const (
	wasiFiletypeSocketStream uint8 = 6

	wasiFdflagAppend   uint16 = 1 << 0
	wasiFdflagNonblock uint16 = 1 << 2

	wasiRiRecvPeek    uint16 = 1 << 0
	wasiRiRecvWaitall uint16 = 1 << 1

	wasiSdflagRd uint8 = 1 << 0
	wasiSdflagWr uint8 = 1 << 1

	// wasiSocketRights is what fd_fdstat_get reports for a socket: read,
	// write, set its flags, poll it, and shut it down or accept on it.
	wasiSocketRights uint64 = 1<<1 | // fd_read
		1<<3 | // fd_fdstat_set_flags
		1<<6 | // fd_write
		1<<21 | // fd_filestat_get
		1<<27 | // poll_fd_readwrite
		1<<28 | // sock_shutdown
		1<<29 // sock_accept
)

// poll_oneoff subscription and event layouts.
const (
	wasiEventtypeClock   uint8 = 0
	wasiEventtypeFdRead  uint8 = 1
	wasiEventtypeFdWrite uint8 = 2

	wasiClockRealtime  uint32 = 0
	wasiClockMonotonic uint32 = 1

	wasiSubclockAbstime uint16 = 1 << 0

	wasiEventFdReadwriteHangup uint16 = 1 << 0

	wasiSubscriptionSize = 48
	wasiEventSize        = 32
	wasiFdstatSize       = 24
	wasiFilestatSize     = 64
	wasiIOVecSize        = 8

	// wasiMaxSubscriptions bounds one poll_oneoff: the decoded copy is the
	// worker's memory, not the guest's. Go's wasip1 poller holds at most
	// 65535 subscriptions, so no real guest asks for more.
	wasiMaxSubscriptions = 1 << 16
	// wasiMaxIOVecs is IOV_MAX on Linux and macOS: a longer vector fails
	// readv/writev with EINVAL there too.
	wasiMaxIOVecs = 1024
)

// wasiErrnoTable maps host errnos to WASI ones. A slice, not a switch or a
// map literal: EAGAIN/EWOULDBLOCK and ENOTSUP/EOPNOTSUPP are the same value
// on some hosts and different ones on others, which a constant switch or
// map key list rejects as a duplicate.
var wasiErrnoTable = []struct {
	host syscall.Errno
	wasi uint16
}{
	{syscall.EAGAIN, wasiErrnoAgain},
	{syscall.EWOULDBLOCK, wasiErrnoAgain},
	{syscall.EACCES, wasiErrnoAcces},
	{syscall.EADDRINUSE, wasiErrnoAddrinuse},
	{syscall.EADDRNOTAVAIL, wasiErrnoAddrnotavai},
	{syscall.EBADF, wasiErrnoBadf},
	{syscall.ECONNABORTED, wasiErrnoConnaborted},
	{syscall.ECONNREFUSED, wasiErrnoConnrefused},
	{syscall.ECONNRESET, wasiErrnoConnreset},
	{syscall.EFAULT, wasiErrnoFault},
	{syscall.EHOSTUNREACH, wasiErrnoHostunreach},
	{syscall.EINTR, wasiErrnoIntr},
	{syscall.EINVAL, wasiErrnoInval},
	{syscall.EIO, wasiErrnoIO},
	{syscall.EMFILE, wasiErrnoMfile},
	{syscall.EMSGSIZE, wasiErrnoMsgsize},
	{syscall.ENETDOWN, wasiErrnoNetdown},
	{syscall.ENETRESET, wasiErrnoNetreset},
	{syscall.ENETUNREACH, wasiErrnoNetunreach},
	{syscall.ENFILE, wasiErrnoNfile},
	{syscall.ENOBUFS, wasiErrnoNobufs},
	{syscall.ENOMEM, wasiErrnoNomem},
	{syscall.ENOTCONN, wasiErrnoNotconn},
	{syscall.ENOTSOCK, wasiErrnoNotsock},
	{syscall.ENOTSUP, wasiErrnoNotsup},
	{syscall.EOPNOTSUPP, wasiErrnoNotsup},
	{syscall.EPERM, wasiErrnoPerm},
	{syscall.EPIPE, wasiErrnoPipe},
	{syscall.ESHUTDOWN, wasiErrnoPipe},
	{syscall.ETIMEDOUT, wasiErrnoTimedout},
}

// wasiErrno is the WASI errno for a host call's error: 0 for nil, EIO for
// an error that carries no errno or one WASI has no name for.
func wasiErrno(err error) uint16 {
	if err == nil {
		return wasiErrnoSuccess
	}
	var en syscall.Errno
	if !errors.As(err, &en) {
		return wasiErrnoIO
	}
	for _, e := range wasiErrnoTable {
		if e.host == en {
			return e.wasi
		}
	}
	return wasiErrnoIO
}

// guestSpan returns mem[ptr:ptr+n], or false when any of it lies outside
// guest memory. The pointers and counts come from the guest, so every one
// is checked; n is 64-bit so a count times a record size cannot wrap.
func guestSpan(mem []byte, ptr uint32, n uint64) ([]byte, bool) {
	end := uint64(ptr) + n
	if end > uint64(len(mem)) {
		return nil, false
	}
	return mem[ptr:end], true
}

func guestPutU16(mem []byte, ptr uint32, v uint16) bool {
	b, ok := guestSpan(mem, ptr, 2)
	if ok {
		binary.LittleEndian.PutUint16(b, v)
	}
	return ok
}

func guestPutU32(mem []byte, ptr uint32, v uint32) bool {
	b, ok := guestSpan(mem, ptr, 4)
	if ok {
		binary.LittleEndian.PutUint32(b, v)
	}
	return ok
}

func guestU64(mem []byte, ptr uint32) (uint64, bool) {
	b, ok := guestSpan(mem, ptr, 8)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// guestIOVecs resolves an iovec array (n entries of {buf u32, len u32} at
// ptr) to the guest memory it names. Every buffer is bounds checked before
// any is used, so a bad entry fails the call without a partial transfer.
func guestIOVecs(mem []byte, ptr, n uint32) ([][]byte, uint16) {
	if n > wasiMaxIOVecs {
		return nil, wasiErrnoInval
	}
	entries, ok := guestSpan(mem, ptr, uint64(n)*wasiIOVecSize)
	if !ok {
		return nil, wasiErrnoFault
	}
	out := make([][]byte, 0, n)
	for i := uint32(0); i < n; i++ {
		e := entries[i*wasiIOVecSize:]
		buf, ok := guestSpan(mem, binary.LittleEndian.Uint32(e), uint64(binary.LittleEndian.Uint32(e[4:])))
		if !ok {
			return nil, wasiErrnoFault
		}
		if len(buf) > 0 {
			out = append(out, buf)
		}
	}
	return out, wasiErrnoSuccess
}

// wasiSubscription is one decoded poll_oneoff subscription.
type wasiSubscription struct {
	userdata uint64
	tag      uint8
	// fd is set for fd_read / fd_write subscriptions.
	fd int32
	// clockID, timeout and flags are set for clock subscriptions.
	clockID uint32
	timeout uint64
	flags   uint16
}

// decodeSubscriptions reads n subscriptions at in. Layout (48 bytes):
// userdata u64 @0, tag u8 @8, then the union @16 — clock: id u32 @16,
// timeout u64 @24, precision u64 @32, flags u16 @40; fd_readwrite: fd u32
// @16.
func decodeSubscriptions(mem []byte, in, n uint32) ([]wasiSubscription, uint16) {
	if n == 0 || n > wasiMaxSubscriptions {
		return nil, wasiErrnoInval
	}
	buf, ok := guestSpan(mem, in, uint64(n)*wasiSubscriptionSize)
	if !ok {
		return nil, wasiErrnoFault
	}
	subs := make([]wasiSubscription, n)
	for i := range subs {
		b := buf[i*wasiSubscriptionSize : (i+1)*wasiSubscriptionSize]
		s := wasiSubscription{userdata: binary.LittleEndian.Uint64(b), tag: b[8]}
		switch s.tag {
		case wasiEventtypeClock:
			s.clockID = binary.LittleEndian.Uint32(b[16:])
			s.timeout = binary.LittleEndian.Uint64(b[24:])
			s.flags = binary.LittleEndian.Uint16(b[40:])
		case wasiEventtypeFdRead, wasiEventtypeFdWrite:
			s.fd = int32(binary.LittleEndian.Uint32(b[16:]))
		default:
			return nil, wasiErrnoInval
		}
		subs[i] = s
	}
	return subs, wasiErrnoSuccess
}

// wasiEvent is one poll_oneoff result.
type wasiEvent struct {
	userdata uint64
	errno    uint16
	tag      uint8
	nbytes   uint64
	flags    uint16
}

// encodeEvent writes ev into a 32-byte slot. Layout: userdata u64 @0,
// error u16 @8, type u8 @10, fd_readwrite nbytes u64 @16, flags u16 @24.
// The slot is cleared first: the guest reads the padding as zero.
func encodeEvent(dst []byte, ev wasiEvent) {
	clear(dst[:wasiEventSize])
	binary.LittleEndian.PutUint64(dst, ev.userdata)
	binary.LittleEndian.PutUint16(dst[8:], ev.errno)
	dst[10] = ev.tag
	binary.LittleEndian.PutUint64(dst[16:], ev.nbytes)
	binary.LittleEndian.PutUint16(dst[24:], ev.flags)
}

// encodeSocketFdstat writes a socket's fdstat (24 bytes): filetype u8 @0,
// fs_flags u16 @2, rights_base u64 @8, rights_inheriting u64 @16.
func encodeSocketFdstat(dst []byte, flags uint16) {
	clear(dst[:wasiFdstatSize])
	dst[0] = wasiFiletypeSocketStream
	binary.LittleEndian.PutUint16(dst[2:], flags)
	binary.LittleEndian.PutUint64(dst[8:], wasiSocketRights)
	binary.LittleEndian.PutUint64(dst[16:], wasiSocketRights)
}

// encodeSocketFilestat writes a socket's filestat (64 bytes): dev u64 @0,
// ino u64 @8, filetype u8 @16, nlink u64 @24, size u64 @32, then three
// timestamps. A socket has no inode or times worth reporting.
func encodeSocketFilestat(dst []byte) {
	clear(dst[:wasiFilestatSize])
	dst[16] = wasiFiletypeSocketStream
	binary.LittleEndian.PutUint64(dst[24:], 1)
}
