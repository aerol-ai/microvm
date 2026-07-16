package wasm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero/api"
)

// multiNetHost is the co-tenant aerol/vm/net host module for MultiInstanceEngine.
// Hooks and connections are keyed by mod.Name() (= sandboxID, set via WithName at
// Instantiate), so guest B cannot resolve guest A's conn_id — ownership is
// structural (nested map), not a check that can be forgotten.
// See plans/wasm-resident-module-host.md Phase 2b / PR-A.
type multiNetHost struct {
	mu     sync.Mutex
	hooks  map[string]*NetworkHook
	conns  map[string]map[uint64]net.Conn
	nextID atomic.Uint64
	closed bool
}

func newMultiNetHost() *multiNetHost {
	return &multiNetHost{
		hooks: make(map[string]*NetworkHook),
		conns: make(map[string]map[uint64]net.Conn),
	}
}

func (h *multiNetHost) setHook(sandboxID string, hook *NetworkHook) {
	if sandboxID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if hook == nil {
		delete(h.hooks, sandboxID)
		return
	}
	h.hooks[sandboxID] = hook
}

// closeConns closes and deletes every conn owned by sandboxID, leaving the hook
// in place (used by Run's re-instantiate so the next Exec still has a dialer).
// Closing unblocks a pinned tcp_read/tcp_write (the conn's Read/Write returns).
func (h *multiNetHost) closeConns(sandboxID string) {
	if h == nil || sandboxID == "" {
		return
	}
	h.mu.Lock()
	owned := h.conns[sandboxID]
	delete(h.conns, sandboxID)
	h.mu.Unlock()
	for _, c := range owned {
		if c != nil {
			_ = c.Close()
		}
	}
}

// clearSandbox drops the hook and closes every conn owned by sandboxID.
func (h *multiNetHost) clearSandbox(sandboxID string) {
	if h == nil || sandboxID == "" {
		return
	}
	h.mu.Lock()
	delete(h.hooks, sandboxID)
	owned := h.conns[sandboxID]
	delete(h.conns, sandboxID)
	h.mu.Unlock()
	for _, c := range owned {
		if c != nil {
			_ = c.Close()
		}
	}
}

func (h *multiNetHost) closeAll() {
	h.mu.Lock()
	h.closed = true
	h.hooks = make(map[string]*NetworkHook)
	all := h.conns
	h.conns = make(map[string]map[uint64]net.Conn)
	h.mu.Unlock()
	for _, owned := range all {
		for _, c := range owned {
			if c != nil {
				_ = c.Close()
			}
		}
	}
}

func (h *multiNetHost) resolveHook(sandboxID string) *NetworkHook {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	return h.hooks[sandboxID]
}

func (h *multiNetHost) takeConn(sandboxID string, id uint64) (net.Conn, ByteMeter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	owned := h.conns[sandboxID]
	if owned == nil {
		return nil, nil
	}
	conn := owned[id]
	var meter ByteMeter
	if hook := h.hooks[sandboxID]; hook != nil {
		meter = hook.Meter
	}
	return conn, meter
}

func (h *multiNetHost) popConn(sandboxID string, id uint64) net.Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	owned := h.conns[sandboxID]
	if owned == nil {
		return nil
	}
	conn := owned[id]
	delete(owned, id)
	if len(owned) == 0 {
		delete(h.conns, sandboxID)
	}
	return conn
}

func (h *multiNetHost) putConn(sandboxID string, id uint64, conn net.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conns[sandboxID] == nil {
		h.conns[sandboxID] = make(map[uint64]net.Conn)
	}
	h.conns[sandboxID][id] = conn
}

func (h *multiNetHost) tcpDial(ctx context.Context, mod api.Module, stack []uint64) {
	const (
		errInvalid = int32(1)
		errDial    = int32(2)
		errBlocked = int32(3)
	)
	addrPtr := uint32(stack[0])
	addrLen := uint32(stack[1])
	stack[0] = uint64(errInvalid)

	sid := mod.Name()
	hook := h.resolveHook(sid)
	if hook == nil || hook.Dial == nil {
		// Fail closed: never fall through to another tenant's dialer.
		stack[0] = uint64(errBlocked)
		return
	}
	addr, ok := mod.Memory().Read(addrPtr, addrLen)
	if !ok {
		return
	}
	// Honor the invocation deadline (D6-A): dial is bounded by min(ctx, dialer timeout).
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
	h.putConn(sid, id, conn)
	stack[0] = uint64(int32(id))
}

func (h *multiNetHost) tcpClose(_ context.Context, mod api.Module, stack []uint64) {
	id := uint64(stack[0])
	conn := h.popConn(mod.Name(), id)
	if conn != nil {
		_ = conn.Close()
	}
	stack[0] = 0
}

func (h *multiNetHost) tcpRead(_ context.Context, mod api.Module, stack []uint64) {
	const (
		errInvalid = int32(1)
		errClosed  = int32(2)
	)
	connID := uint64(stack[0])
	bufPtr := uint32(stack[1])
	bufLen := uint32(stack[2])
	stack[0] = uint64(errInvalid)

	conn, meter := h.takeConn(mod.Name(), connID)
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

func (h *multiNetHost) tcpWrite(_ context.Context, mod api.Module, stack []uint64) {
	const (
		errInvalid = int32(1)
		errClosed  = int32(2)
	)
	connID := uint64(stack[0])
	bufPtr := uint32(stack[1])
	bufLen := uint32(stack[2])
	stack[0] = uint64(errInvalid)

	conn, meter := h.takeConn(mod.Name(), connID)
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

// ensureNetworkHostLocked registers aerol/vm/net once on the shared runtime.
// Caller must hold m.mu.
func (m *MultiInstanceEngine) ensureNetworkHostLocked(ctx context.Context) error {
	if m.netHost != nil && m.netHostRegistered {
		return nil
	}
	if m.runtime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	if m.netHost == nil {
		m.netHost = newMultiNetHost()
	}
	if m.netHostRegistered {
		return nil
	}
	host := m.netHost
	builder := m.runtime.NewHostModuleBuilder("aerol/vm/net")
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
	m.netHostRegistered = true
	return nil
}
