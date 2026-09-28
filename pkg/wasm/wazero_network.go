package wasm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero/api"
	experimentalsock "github.com/tetratelabs/wazero/experimental/sock"
)

type wazeroNetHost struct {
	mu     sync.Mutex
	hook   *NetworkHook
	nextID atomic.Uint64
	conns  map[uint64]net.Conn
	closed bool
}

// closeConns interrupts all active mediated I/O without permanently closing
// the host. It is used before an instance is stopped or replaced so a guest
// blocked in tcpRead/tcpWrite can unwind before runtime state is released.
func (h *wazeroNetHost) closeConns() {
	if h == nil {
		return
	}
	h.mu.Lock()
	conns := h.conns
	h.conns = make(map[uint64]net.Conn)
	h.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (e *wazeroEngine) SetNetworkHook(hook *NetworkHook) {
	e.netHook = hook
}

func (e *wazeroEngine) ClearNetworkHook() {
	e.netHook = nil
}

func (e *wazeroEngine) withNetworkContext(ctx context.Context, caps Capabilities) context.Context {
	ctx = withWasip1Meter(ctx, e.netHook)
	if caps.ListenEnabled() {
		host := caps.WASIListenHost
		if host == "" {
			host = "127.0.0.1"
		}
		sockCfg := experimentalsock.NewConfig().WithTCPListener(host, caps.WASIListenPort)
		ctx = experimentalsock.WithConfig(ctx, sockCfg)
	}
	return ctx
}

func (e *wazeroEngine) ensureNetworkHost(ctx context.Context) error {
	if e.netHook == nil || e.netHook.Dial == nil || e.runtime == nil {
		return nil
	}
	if e.netHost != nil {
		e.netHost.mu.Lock()
		e.netHost.hook = e.netHook
		e.netHost.mu.Unlock()
		return nil
	}
	host := &wazeroNetHost{
		hook:  e.netHook,
		conns: make(map[uint64]net.Conn),
	}
	builder := e.runtime.NewHostModuleBuilder("aerol/vm/net")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.tcpDial), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("addr_ptr", "addr_len").
		Export("tcp_dial")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.tcpClose), []api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("conn_id").
		Export("tcp_close")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.tcpRead), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("conn_id", "buf_ptr", "buf_len").
		Export("tcp_read")
	builder.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(host.tcpWrite), []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}).
		WithParameterNames("conn_id", "buf_ptr", "buf_len").
		Export("tcp_write")
	if _, err := builder.Instantiate(ctx); err != nil {
		return fmt.Errorf("aerol/vm/net host module: %w", err)
	}
	e.netHost = host
	return nil
}

func (h *wazeroNetHost) tcpDial(ctx context.Context, mod api.Module, stack []uint64) {
	const (
		errInvalid = int32(1)
		errDial    = int32(2)
		errBlocked = int32(3)
	)

	addrPtr := uint32(stack[0])
	addrLen := uint32(stack[1])
	stack[0] = uint64(errInvalid)

	h.mu.Lock()
	hook := h.hook
	closed := h.closed
	h.mu.Unlock()
	if closed || hook == nil || hook.Dial == nil {
		stack[0] = uint64(errBlocked)
		return
	}

	addr, ok := mod.Memory().Read(addrPtr, addrLen)
	if !ok {
		return
	}
	// Honor the invocation deadline (D6-A): previously dialed with
	// context.Background(), which ignored caps wall timeout under co-tenancy
	// and the single-instance path alike.
	conn, err := hook.Dial.DialContext(ctx, "tcp", string(addr))
	if err != nil {
		if errors.Is(err, ErrNetworkEgressBlocked) {
			stack[0] = uint64(errBlocked)
			return
		}
		stack[0] = uint64(errDial)
		return
	}
	id := h.nextID.Add(1)
	h.mu.Lock()
	h.conns[id] = conn
	h.mu.Unlock()
	stack[0] = uint64(int32(id))
}

func (h *wazeroNetHost) tcpClose(_ context.Context, _ api.Module, stack []uint64) {
	id := uint64(stack[0])
	h.mu.Lock()
	conn := h.conns[id]
	delete(h.conns, id)
	h.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	stack[0] = 0
}

func (h *wazeroNetHost) hookMeter() ByteMeter {
	if h.hook == nil {
		return nil
	}
	return h.hook.Meter
}

func (h *wazeroNetHost) tcpRead(_ context.Context, mod api.Module, stack []uint64) {
	const (
		errInvalid = int32(1)
		errClosed  = int32(2)
	)
	connID := uint64(stack[0])
	bufPtr := uint32(stack[1])
	bufLen := uint32(stack[2])
	stack[0] = uint64(errInvalid)

	h.mu.Lock()
	conn := h.conns[connID]
	meter := h.hookMeter()
	h.mu.Unlock()
	if conn == nil {
		stack[0] = uint64(errClosed)
		return
	}
	buf, ok := mod.Memory().Read(bufPtr, bufLen)
	if !ok {
		return
	}
	stack[0] = uint64(netConnRead(conn, meter, buf))
}

func (h *wazeroNetHost) tcpWrite(_ context.Context, mod api.Module, stack []uint64) {
	const (
		errInvalid = int32(1)
		errClosed  = int32(2)
	)
	connID := uint64(stack[0])
	bufPtr := uint32(stack[1])
	bufLen := uint32(stack[2])
	stack[0] = uint64(errInvalid)

	h.mu.Lock()
	conn := h.conns[connID]
	meter := h.hookMeter()
	h.mu.Unlock()
	if conn == nil {
		stack[0] = uint64(errClosed)
		return
	}
	buf, ok := mod.Memory().Read(bufPtr, bufLen)
	if !ok {
		return
	}
	stack[0] = uint64(netConnWrite(conn, meter, buf))
}
