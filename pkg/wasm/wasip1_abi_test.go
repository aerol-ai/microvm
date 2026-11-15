package wasm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestWasiErrno(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want uint16
	}{
		{"nil", nil, wasiErrnoSuccess},
		{"again", syscall.EAGAIN, wasiErrnoAgain},
		{"wouldblock", syscall.EWOULDBLOCK, wasiErrnoAgain},
		{"badf", syscall.EBADF, wasiErrnoBadf},
		{"reset", syscall.ECONNRESET, wasiErrnoConnreset},
		{"aborted", syscall.ECONNABORTED, wasiErrnoConnaborted},
		{"notconn", syscall.ENOTCONN, wasiErrnoNotconn},
		{"pipe", syscall.EPIPE, wasiErrnoPipe},
		{"intr", syscall.EINTR, wasiErrnoIntr},
		{"inval", syscall.EINVAL, wasiErrnoInval},
		{"notsup", syscall.ENOTSUP, wasiErrnoNotsup},
		{"opnotsupp", syscall.EOPNOTSUPP, wasiErrnoNotsup},
		{"addrinuse", syscall.EADDRINUSE, wasiErrnoAddrinuse},
		{"timedout", syscall.ETIMEDOUT, wasiErrnoTimedout},
		{"wrapped", fmt.Errorf("accept: %w", syscall.EMFILE), wasiErrnoMfile},
		{"errno WASI has no name for", syscall.ENOEXEC, wasiErrnoIO},
		{"not an errno", errors.New("boom"), wasiErrnoIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wasiErrno(tc.err); got != tc.want {
				t.Fatalf("wasiErrno(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestGuestSpanAndPuts(t *testing.T) {
	mem := make([]byte, 16)
	if _, ok := guestSpan(mem, 12, 4); !ok {
		t.Fatal("a span ending at the end of memory is in bounds")
	}
	for _, tc := range []struct {
		ptr uint32
		n   uint64
	}{{13, 4}, {16, 1}, {^uint32(0), 2}, {0, 1 << 40}} {
		if _, ok := guestSpan(mem, tc.ptr, tc.n); ok {
			t.Fatalf("guestSpan(%d, %d) is out of bounds", tc.ptr, tc.n)
		}
	}
	if !guestPutU16(mem, 0, 0xbeef) || binary.LittleEndian.Uint16(mem) != 0xbeef {
		t.Fatal("guestPutU16")
	}
	if !guestPutU32(mem, 4, 0xdeadbeef) || binary.LittleEndian.Uint32(mem[4:]) != 0xdeadbeef {
		t.Fatal("guestPutU32")
	}
	binary.LittleEndian.PutUint64(mem[8:], 42)
	if v, ok := guestU64(mem, 8); !ok || v != 42 {
		t.Fatalf("guestU64 = %d, %v", v, ok)
	}
	if guestPutU16(mem, 15, 1) || guestPutU32(mem, 13, 1) {
		t.Fatal("a put past the end must fail")
	}
	if _, ok := guestU64(mem, 9); ok {
		t.Fatal("a read past the end must fail")
	}
}

// putIOVec writes iovec i of the array at ptr.
func putIOVec(mem []byte, ptr uint32, i int, buf, n uint32) {
	binary.LittleEndian.PutUint32(mem[ptr+uint32(i)*8:], buf)
	binary.LittleEndian.PutUint32(mem[ptr+uint32(i)*8+4:], n)
}

func TestGuestIOVecs(t *testing.T) {
	mem := make([]byte, 256)
	putIOVec(mem, 0, 0, 100, 10)
	putIOVec(mem, 0, 1, 120, 0) // empty: dropped
	putIOVec(mem, 0, 2, 130, 6)
	bufs, errno := guestIOVecs(mem, 0, 3)
	if errno != 0 || len(bufs) != 2 || len(bufs[0]) != 10 || len(bufs[1]) != 6 {
		t.Fatalf("bufs = %d entries, errno %d", len(bufs), errno)
	}
	bufs[0][0] = 'x'
	if mem[100] != 'x' {
		t.Fatal("an iovec must alias guest memory")
	}
	if bufs, errno := guestIOVecs(mem, 0, 0); errno != 0 || len(bufs) != 0 {
		t.Fatalf("no iovecs: %d, %d", len(bufs), errno)
	}

	putIOVec(mem, 0, 1, 250, 10) // runs past the end
	if _, errno := guestIOVecs(mem, 0, 3); errno != wasiErrnoFault {
		t.Fatalf("buffer out of bounds: errno %d", errno)
	}
	if _, errno := guestIOVecs(mem, 250, 2); errno != wasiErrnoFault {
		t.Fatalf("array out of bounds: errno %d", errno)
	}
	if _, errno := guestIOVecs(mem, 0, wasiMaxIOVecs+1); errno != wasiErrnoInval {
		t.Fatalf("too many iovecs: errno %d", errno)
	}
}

// putClockSub writes a clock subscription at slot i of the array at in.
func putClockSub(mem []byte, in uint32, i int, userdata uint64, id uint32, timeout uint64, flags uint16) {
	b := mem[in+uint32(i)*wasiSubscriptionSize:]
	clear(b[:wasiSubscriptionSize])
	binary.LittleEndian.PutUint64(b, userdata)
	b[8] = wasiEventtypeClock
	binary.LittleEndian.PutUint32(b[16:], id)
	binary.LittleEndian.PutUint64(b[24:], timeout)
	binary.LittleEndian.PutUint64(b[32:], 1000)
	binary.LittleEndian.PutUint16(b[40:], flags)
}

// putFDSub writes an fd_read / fd_write subscription at slot i.
func putFDSub(mem []byte, in uint32, i int, userdata uint64, tag uint8, fd int32) {
	b := mem[in+uint32(i)*wasiSubscriptionSize:]
	clear(b[:wasiSubscriptionSize])
	binary.LittleEndian.PutUint64(b, userdata)
	b[8] = tag
	binary.LittleEndian.PutUint32(b[16:], uint32(fd))
}

func TestDecodeSubscriptions(t *testing.T) {
	mem := make([]byte, 1024)
	putClockSub(mem, 0, 0, 7, wasiClockMonotonic, 1500, wasiSubclockAbstime)
	putFDSub(mem, 0, 1, 8, wasiEventtypeFdRead, 1<<24)
	putFDSub(mem, 0, 2, 9, wasiEventtypeFdWrite, 1)
	subs, errno := decodeSubscriptions(mem, 0, 3)
	if errno != 0 {
		t.Fatalf("errno %d", errno)
	}
	want := []wasiSubscription{
		{userdata: 7, tag: wasiEventtypeClock, clockID: wasiClockMonotonic, timeout: 1500, flags: wasiSubclockAbstime},
		{userdata: 8, tag: wasiEventtypeFdRead, fd: 1 << 24},
		{userdata: 9, tag: wasiEventtypeFdWrite, fd: 1},
	}
	for i := range want {
		if subs[i] != want[i] {
			t.Fatalf("sub %d = %+v, want %+v", i, subs[i], want[i])
		}
	}

	for _, tc := range []struct {
		name string
		in   uint32
		n    uint32
		want uint16
	}{
		{"none", 0, 0, wasiErrnoInval},
		{"too many", 0, wasiMaxSubscriptions + 1, wasiErrnoInval},
		{"out of bounds", 1000, 1, wasiErrnoFault},
	} {
		if _, errno := decodeSubscriptions(mem, tc.in, tc.n); errno != tc.want {
			t.Fatalf("%s: errno %d, want %d", tc.name, errno, tc.want)
		}
	}
	mem[8] = 9 // no such event type
	if _, errno := decodeSubscriptions(mem, 0, 1); errno != wasiErrnoInval {
		t.Fatalf("bad tag: errno %d", errno)
	}
}

func TestEncodeEventAndStats(t *testing.T) {
	dst := make([]byte, wasiEventSize)
	for i := range dst {
		dst[i] = 0xff
	}
	encodeEvent(dst, wasiEvent{userdata: 0x0102030405060708, errno: wasiErrnoBadf, tag: wasiEventtypeFdRead, nbytes: 5, flags: wasiEventFdReadwriteHangup})
	if binary.LittleEndian.Uint64(dst) != 0x0102030405060708 ||
		binary.LittleEndian.Uint16(dst[8:]) != wasiErrnoBadf ||
		dst[10] != wasiEventtypeFdRead ||
		binary.LittleEndian.Uint64(dst[16:]) != 5 ||
		binary.LittleEndian.Uint16(dst[24:]) != wasiEventFdReadwriteHangup {
		t.Fatalf("event = %x", dst)
	}
	for _, i := range []int{11, 12, 13, 14, 15, 26, 31} {
		if dst[i] != 0 {
			t.Fatalf("padding byte %d = %#x, want 0", i, dst[i])
		}
	}

	st := make([]byte, wasiFdstatSize)
	encodeSocketFdstat(st, wasiFdflagNonblock)
	if st[0] != wasiFiletypeSocketStream || binary.LittleEndian.Uint16(st[2:]) != wasiFdflagNonblock ||
		binary.LittleEndian.Uint64(st[8:]) != wasiSocketRights || binary.LittleEndian.Uint64(st[16:]) != wasiSocketRights {
		t.Fatalf("fdstat = %x", st)
	}
	fs := make([]byte, wasiFilestatSize)
	encodeSocketFilestat(fs)
	if fs[16] != wasiFiletypeSocketStream || binary.LittleEndian.Uint64(fs[24:]) != 1 {
		t.Fatalf("filestat = %x", fs)
	}
}
