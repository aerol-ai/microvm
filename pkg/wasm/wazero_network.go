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

func (e *wazeroEngine) SetNetworkHook(hook *NetworkHook) {
	e.netHook = hook
}

func (e *wazeroEngine) ClearNetworkHook() {
	e.netHook = nil
}

func (e *wazeroEngine) withNetworkContext(ctx context.Context, caps Capabilities) context.Context {
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
	if _, err := builder.Instantiate(ctx); err != nil {
		return fmt.Errorf("aerol/vm/net host module: %w", err)
	}
	e.netHost = host
	return nil
}

func (h *wazeroNetHost) tcpDial(_ context.Context, mod api.Module, stack []uint64) {
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
	conn, err := hook.Dial.DialContext(context.Background(), "tcp", string(addr))
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
