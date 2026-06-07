//go:build wasmtime

package wasm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/bytecodealliance/wasmtime-go/v37"
)

type wasmtimeNetHost struct {
	mu     sync.Mutex
	hook   *NetworkHook
	nextID atomic.Uint64
	conns  map[uint64]net.Conn
	closed bool
}

func (e *wasmtimeEngine) SetNetworkHook(hook *NetworkHook) {
	e.netHook = hook
}

func (e *wasmtimeEngine) ClearNetworkHook() {
	e.netHook = nil
}

func (e *wasmtimeEngine) ensureNetworkHost(linker *wasmtime.Linker) error {
	if e.netHook == nil || e.netHook.Dial == nil {
		return nil
	}
	if e.netHost != nil {
		e.netHost.mu.Lock()
		e.netHost.hook = e.netHook
		e.netHost.mu.Unlock()
		return nil
	}
	host := &wasmtimeNetHost{
		hook:  e.netHook,
		conns: make(map[uint64]net.Conn),
	}
	if err := linker.FuncWrap("aerol/vm/net", "tcp_dial", host.tcpDial); err != nil {
		return fmt.Errorf("aerol/vm/net tcp_dial: %w", err)
	}
	if err := linker.FuncWrap("aerol/vm/net", "tcp_close", host.tcpClose); err != nil {
		return fmt.Errorf("aerol/vm/net tcp_close: %w", err)
	}
	if err := linker.FuncWrap("aerol/vm/net", "tcp_read", host.tcpRead); err != nil {
		return fmt.Errorf("aerol/vm/net tcp_read: %w", err)
	}
	if err := linker.FuncWrap("aerol/vm/net", "tcp_write", host.tcpWrite); err != nil {
		return fmt.Errorf("aerol/vm/net tcp_write: %w", err)
	}
	if err := linker.FuncWrap("wasi:sockets", "tcp_connect", host.tcpDial); err != nil {
		return fmt.Errorf("wasi:sockets tcp_connect: %w", err)
	}
	if err := linker.FuncWrap("wasi:sockets", "stream_read", host.tcpRead); err != nil {
		return fmt.Errorf("wasi:sockets stream_read: %w", err)
	}
	if err := linker.FuncWrap("wasi:sockets", "stream_write", host.tcpWrite); err != nil {
		return fmt.Errorf("wasi:sockets stream_write: %w", err)
	}
	if err := linker.FuncWrap("wasi:sockets", "stream_close", host.tcpClose); err != nil {
		return fmt.Errorf("wasi:sockets stream_close: %w", err)
	}
	e.netHost = host
	return nil
}

func (h *wasmtimeNetHost) tcpDial(caller *wasmtime.Caller, addrPtr, addrLen int32) int32 {
	const (
		errInvalid = int32(1)
		errDial    = int32(2)
		errBlocked = int32(3)
	)
	h.mu.Lock()
	hook := h.hook
	closed := h.closed
	h.mu.Unlock()
	if closed || hook == nil || hook.Dial == nil {
		return errBlocked
	}
	memExport := caller.GetExport("memory")
	if memExport == nil {
		return errInvalid
	}
	mem := memExport.Memory()
	if mem == nil {
		return errInvalid
	}
	data := mem.UnsafeData(caller)
	start := int(addrPtr)
	end := start + int(addrLen)
	if start < 0 || end > len(data) {
		return errInvalid
	}
	conn, err := hook.Dial.DialContext(context.Background(), "tcp", string(data[start:end]))
	if err != nil {
		if errors.Is(err, ErrNetworkEgressBlocked) {
			return errBlocked
		}
		return errDial
	}
	id := h.nextID.Add(1)
	h.mu.Lock()
	h.conns[id] = conn
	h.mu.Unlock()
	return int32(id)
}

func (h *wasmtimeNetHost) tcpClose(_ *wasmtime.Caller, connID int32) int32 {
	id := uint64(connID)
	h.mu.Lock()
	conn := h.conns[id]
	delete(h.conns, id)
	h.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	return 0
}

func (h *wasmtimeNetHost) meter() ByteMeter {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hook == nil {
		return nil
	}
	return h.hook.Meter
}

func (h *wasmtimeNetHost) tcpRead(caller *wasmtime.Caller, connID, bufPtr, bufLen int32) int32 {
	const (
		errInvalid = int32(1)
		errClosed  = int32(2)
	)
	id := uint64(connID)
	h.mu.Lock()
	conn := h.conns[id]
	h.mu.Unlock()
	if conn == nil {
		return errClosed
	}
	memExport := caller.GetExport("memory")
	if memExport == nil {
		return errInvalid
	}
	mem := memExport.Memory()
	if mem == nil {
		return errInvalid
	}
	data := mem.UnsafeData(caller)
	start := int(bufPtr)
	end := start + int(bufLen)
	if start < 0 || end > len(data) {
		return errInvalid
	}
	n, err := conn.Read(data[start:end])
	if n > 0 {
		if m := h.meter(); m != nil {
			m.AddIn(int64(n))
		}
	}
	if err != nil {
		return int32(n)
	}
	return int32(n)
}

func (h *wasmtimeNetHost) tcpWrite(caller *wasmtime.Caller, connID, bufPtr, bufLen int32) int32 {
	const (
		errInvalid = int32(1)
		errClosed  = int32(2)
	)
	id := uint64(connID)
	h.mu.Lock()
	conn := h.conns[id]
	h.mu.Unlock()
	if conn == nil {
		return errClosed
	}
	memExport := caller.GetExport("memory")
	if memExport == nil {
		return errInvalid
	}
	mem := memExport.Memory()
	if mem == nil {
		return errInvalid
	}
	data := mem.UnsafeData(caller)
	start := int(bufPtr)
	end := start + int(bufLen)
	if start < 0 || end > len(data) {
		return errInvalid
	}
	n, err := conn.Write(data[start:end])
	if n > 0 {
		if m := h.meter(); m != nil {
			m.AddOut(int64(n))
		}
	}
	if err != nil {
		return int32(n)
	}
	return int32(n)
}
