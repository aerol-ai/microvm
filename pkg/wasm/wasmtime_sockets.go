//go:build wasmtime

package wasm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bytecodealliance/wasmtime-go/v37"
)

// The wasmtime engine's WASI preview-1 layer. wasmtime's C API cannot
// pre-open a socket (wasi_config_preopen_socket existed in v14-v19 only)
// and its preview-1 sock_accept is a stub, so the engine serves the
// guest's sockets itself (wasip1_sockets.go): the guest's linker defines
// wasmtime's WASI first, then shadows the functions that can name a socket
// with Go ones. Each override serves a socket fd itself and hands every
// other fd to wasmtime's original function, through a trampoline.
//
// The trampoline is a small module instantiated in the guest's store after
// the guest, from a second linker that holds only wasmtime's WASI. It
// imports the guest's exported memory and re-exports it as "memory", and
// exports one pass-through function per override. wasmtime's WASI
// functions read and write the memory their caller exports as "memory", so
// called from Go they have none; called from the trampoline they see the
// guest's. Both linkers' WASI functions use the WASI context of the store,
// so the guest and the trampoline share one fd table.

const wasip1ModuleName = "wasi_snapshot_preview1"

// wasip1Passthrough is one WASI function the layer can hand to wasmtime.
type wasip1Passthrough struct {
	name   string
	params string // wasm param types, in order
}

// wasip1Passthroughs are the trampoline's exports, indexed by the wpX
// constants below.
var wasip1Passthroughs = []wasip1Passthrough{
	{"fd_read", "i32 i32 i32 i32"},
	{"fd_write", "i32 i32 i32 i32"},
	{"fd_close", "i32"},
	{"fd_fdstat_get", "i32 i32"},
	{"fd_fdstat_set_flags", "i32 i32"},
	{"fd_filestat_get", "i32 i32"},
	{"fd_renumber", "i32 i32"},
	{"poll_oneoff", "i32 i32 i32 i32"},
	{"sock_accept", "i32 i32 i32"},
	{"sock_recv", "i32 i32 i32 i32 i32 i32"},
	{"sock_send", "i32 i32 i32 i32 i32"},
	{"sock_shutdown", "i32 i32"},
	{"clock_time_get", "i32 i64 i32"},
}

const (
	wpFdRead = iota
	wpFdWrite
	wpFdClose
	wpFdFdstatGet
	wpFdFdstatSetFlags
	wpFdFilestatGet
	wpFdRenumber
	wpPollOneoff
	wpSockAccept
	wpSockRecv
	wpSockSend
	wpSockShutdown
	wpClockTimeGet
)

// wasip1TrampolineWAT is the trampoline's source. Its memory import has no
// minimum or maximum, so any 32-bit unshared guest memory fits it.
func wasip1TrampolineWAT() string {
	var b strings.Builder
	b.WriteString("(module\n  (import \"env\" \"memory\" (memory 0))\n")
	for i, p := range wasip1Passthroughs {
		fmt.Fprintf(&b, "  (import %q %q (func $f%d (param %s) (result i32)))\n", wasip1ModuleName, p.name, i, p.params)
	}
	b.WriteString("  (export \"memory\" (memory 0))\n")
	for i, p := range wasip1Passthroughs {
		fmt.Fprintf(&b, "  (func (export %q) (param %s) (result i32)", p.name, p.params)
		for j := range strings.Fields(p.params) {
			fmt.Fprintf(&b, " local.get %d", j)
		}
		fmt.Fprintf(&b, " call $f%d)\n", i)
	}
	b.WriteString(")\n")
	return b.String()
}

// compileWasip1Trampoline compiles the trampoline for engine. The engine
// compiles it once and instantiates it per store.
func compileWasip1Trampoline(engine *wasmtime.Engine) (*wasmtime.Module, error) {
	bin, err := wasmtime.Wat2Wasm(wasip1TrampolineWAT())
	if err != nil {
		return nil, fmt.Errorf("wasip1 trampoline: %w", err)
	}
	mod, err := wasmtime.NewModule(engine, bin)
	if err != nil {
		return nil, fmt.Errorf("wasip1 trampoline: %w", err)
	}
	return mod, nil
}

// wasip1MemoryExported reports whether mod exports the memory the layer
// needs: a 32-bit, unshared memory named "memory", which is what every
// WASI preview-1 guest has. Without it wasmtime's own WASI cannot serve
// the guest either.
func wasip1MemoryExported(mod *wasmtime.Module) bool {
	for _, exp := range mod.Exports() {
		if exp.Name() != "memory" {
			continue
		}
		mt := exp.Type().MemoryType()
		return mt != nil && !mt.Is64() && !mt.IsShared()
	}
	return false
}

// wasmtimeWasip1 is the layer for one instance.
type wasmtimeWasip1 struct {
	socks *wasip1Sockets
	// sockets is set when the instance has listeners: the fd functions are
	// overridden then. Without, only poll_oneoff is, so a stop can end a
	// guest's sleep.
	sockets bool
	// pass is the trampoline's exports by wpX index; nil until attach.
	pass []*wasmtime.Func
}

// define shadows wasmtime's WASI functions in linker, which must already
// hold them (DefineWasi).
func (h *wasmtimeWasip1) define(linker *wasmtime.Linker) error {
	linker.AllowShadowing(true)
	wrap := func(name string, f any) error {
		if err := linker.FuncWrap(wasip1ModuleName, name, f); err != nil {
			return fmt.Errorf("wasip1 %s: %w", name, err)
		}
		return nil
	}
	if err := wrap("poll_oneoff", h.pollOneoff); err != nil {
		return err
	}
	if !h.sockets {
		return nil
	}
	for _, d := range []struct {
		name string
		f    any
	}{
		{"fd_read", h.fdRead},
		{"fd_write", h.fdWrite},
		{"fd_close", h.fdClose},
		{"fd_fdstat_get", h.fdFdstatGet},
		{"fd_fdstat_set_flags", h.fdFdstatSetFlags},
		{"fd_filestat_get", h.fdFilestatGet},
		{"fd_renumber", h.fdRenumber},
		{"sock_accept", h.sockAccept},
		{"sock_recv", h.sockRecv},
		{"sock_send", h.sockSend},
		{"sock_shutdown", h.sockShutdown},
	} {
		if err := wrap(d.name, d.f); err != nil {
			return err
		}
	}
	return nil
}

// attach instantiates the trampoline in store against guest's memory.
// It runs after the guest is instantiated and before any guest code does:
// wasmtime runs no _start on instantiation.
func (h *wasmtimeWasip1) attach(engine *wasmtime.Engine, store *wasmtime.Store, guest *wasmtime.Instance, tramp *wasmtime.Module) error {
	ext := guest.GetExport(store, "memory")
	if ext == nil || ext.Memory() == nil {
		return errors.New("wasip1 trampoline: guest exports no memory")
	}
	orig := wasmtime.NewLinker(engine)
	defer orig.Close()
	if err := orig.DefineWasi(); err != nil {
		return fmt.Errorf("wasip1 trampoline: %w", err)
	}
	if err := orig.Define(store, "env", "memory", ext.Memory()); err != nil {
		return fmt.Errorf("wasip1 trampoline: %w", err)
	}
	inst, err := orig.Instantiate(store, tramp)
	if err != nil {
		return fmt.Errorf("wasip1 trampoline: %w", err)
	}
	pass := make([]*wasmtime.Func, len(wasip1Passthroughs))
	for i, p := range wasip1Passthroughs {
		if pass[i] = inst.GetFunc(store, p.name); pass[i] == nil {
			return fmt.Errorf("wasip1 trampoline: no export %s", p.name)
		}
	}
	h.pass = pass
	return nil
}

// passThrough calls wasmtime's own WASI function idx with args.
func (h *wasmtimeWasip1) passThrough(c *wasmtime.Caller, idx int, args ...any) (int32, *wasmtime.Trap) {
	if h.pass == nil {
		// Only a guest start function runs before attach.
		return int32(wasiErrnoNosys), nil
	}
	r, err := h.pass[idx].Call(c, args...)
	if err != nil {
		return 0, wasmtimeTrapOf(err)
	}
	v, _ := r.(int32)
	return v, nil
}

// wasmtimeTrapOf carries err out of a host function: a trap as itself, an
// error (a trap's cause chain) as a new trap with its message.
func wasmtimeTrapOf(err error) *wasmtime.Trap {
	var trap *wasmtime.Trap
	if errors.As(err, &trap) {
		return trap
	}
	return wasmtime.NewTrap(err.Error())
}

// wasip1Result turns a socket-layer outcome into the host function's: an
// errno, or a trap when the instance was stopped.
func wasip1Result(errno uint16, err error) (int32, *wasmtime.Trap) {
	if err != nil {
		return 0, wasmtime.NewTrap(err.Error())
	}
	return int32(errno), nil
}

// callerMemory is the calling guest's memory, nil if it exports none (every
// pointer then fails its bounds check with EFAULT).
func callerMemory(c *wasmtime.Caller) []byte {
	ext := c.GetExport("memory")
	if ext == nil {
		return nil
	}
	mem := ext.Memory()
	if mem == nil {
		return nil
	}
	return mem.UnsafeData(c)
}

func (h *wasmtimeWasip1) pollOneoff(c *wasmtime.Caller, in, out, n, resultN int32) (int32, *wasmtime.Trap) {
	// An absolute clock deadline needs the guest's own clock. wasmtime's
	// clock_time_get writes its answer to guest memory, so it borrows the
	// first 8 bytes of out: the events buffer is the guest's scratch for
	// this call and is written after.
	var clockTrap *wasmtime.Trap
	clock := func(id uint32) (uint64, uint16) {
		r, trap := h.passThrough(c, wpClockTimeGet, int32(id), int64(1), out)
		if trap != nil {
			clockTrap = trap
			return 0, wasiErrnoIO
		}
		if r != 0 {
			return 0, uint16(r)
		}
		v, ok := guestU64(callerMemory(c), uint32(out))
		if !ok {
			return 0, wasiErrnoFault
		}
		return v, wasiErrnoSuccess
	}
	errno, handled, err := h.socks.pollOneoff(callerMemory(c), uint32(in), uint32(out), uint32(n), uint32(resultN), clock)
	if clockTrap != nil {
		return 0, clockTrap
	}
	if !handled {
		return h.passThrough(c, wpPollOneoff, in, out, n, resultN)
	}
	return wasip1Result(errno, err)
}

func (h *wasmtimeWasip1) fdRead(c *wasmtime.Caller, fd, iovs, n, resultN int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpFdRead, fd, iovs, n, resultN)
	}
	return wasip1Result(h.socks.fdRead(callerMemory(c), fd, uint32(iovs), uint32(n), uint32(resultN)))
}

func (h *wasmtimeWasip1) fdWrite(c *wasmtime.Caller, fd, iovs, n, resultN int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpFdWrite, fd, iovs, n, resultN)
	}
	return wasip1Result(h.socks.fdWrite(callerMemory(c), fd, uint32(iovs), uint32(n), uint32(resultN)))
}

func (h *wasmtimeWasip1) fdClose(c *wasmtime.Caller, fd int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpFdClose, fd)
	}
	return int32(h.socks.fdClose(fd)), nil
}

func (h *wasmtimeWasip1) fdFdstatGet(c *wasmtime.Caller, fd, ptr int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpFdFdstatGet, fd, ptr)
	}
	return int32(h.socks.fdFdstatGet(callerMemory(c), fd, uint32(ptr))), nil
}

func (h *wasmtimeWasip1) fdFdstatSetFlags(c *wasmtime.Caller, fd, flags int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpFdFdstatSetFlags, fd, flags)
	}
	return int32(h.socks.fdFdstatSetFlags(fd, uint32(flags))), nil
}

func (h *wasmtimeWasip1) fdFilestatGet(c *wasmtime.Caller, fd, ptr int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpFdFilestatGet, fd, ptr)
	}
	return int32(h.socks.fdFilestatGet(callerMemory(c), fd, uint32(ptr))), nil
}

func (h *wasmtimeWasip1) fdRenumber(c *wasmtime.Caller, from, to int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(from) && !h.socks.owns(to) {
		return h.passThrough(c, wpFdRenumber, from, to)
	}
	return int32(h.socks.fdRenumber(from, to)), nil
}

func (h *wasmtimeWasip1) sockAccept(c *wasmtime.Caller, fd, flags, resultFD int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpSockAccept, fd, flags, resultFD)
	}
	return wasip1Result(h.socks.sockAccept(callerMemory(c), fd, uint32(flags), uint32(resultFD)))
}

func (h *wasmtimeWasip1) sockRecv(c *wasmtime.Caller, fd, iovs, n, flags, resultLen, resultFlags int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpSockRecv, fd, iovs, n, flags, resultLen, resultFlags)
	}
	return wasip1Result(h.socks.sockRecv(callerMemory(c), fd, uint32(iovs), uint32(n), uint32(flags), uint32(resultLen), uint32(resultFlags)))
}

func (h *wasmtimeWasip1) sockSend(c *wasmtime.Caller, fd, iovs, n, flags, resultLen int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpSockSend, fd, iovs, n, flags, resultLen)
	}
	return wasip1Result(h.socks.sockSend(callerMemory(c), fd, uint32(iovs), uint32(n), uint32(flags), uint32(resultLen)))
}

func (h *wasmtimeWasip1) sockShutdown(c *wasmtime.Caller, fd, how int32) (int32, *wasmtime.Trap) {
	if !h.socks.owns(fd) {
		return h.passThrough(c, wpSockShutdown, fd, how)
	}
	return int32(h.socks.sockShutdown(fd, uint32(how))), nil
}
