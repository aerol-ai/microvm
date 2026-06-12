package wasm

import (
	"context"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	wasip1SockRecv   = "sock_recv"
	wasip1SockSend   = "sock_send"
	wasip1SockAccept = "sock_accept"
)

type wasip1MeterFactory struct {
	meter ByteMeter
}

func newWasip1MeterFactory(meter ByteMeter) experimental.FunctionListenerFactory {
	if meter == nil {
		return nil
	}
	return &wasip1MeterFactory{meter: meter}
}

func (f *wasip1MeterFactory) NewFunctionListener(def api.FunctionDefinition) experimental.FunctionListener {
	if def.ModuleName() != wasi_snapshot_preview1.ModuleName {
		return nil
	}
	switch def.Name() {
	case wasip1SockRecv:
		return &wasip1SockRecvMeter{meter: f.meter}
	case wasip1SockSend:
		return &wasip1SockSendMeter{meter: f.meter}
	case wasip1SockAccept:
		return &wasip1SockAcceptMeter{meter: f.meter}
	default:
		return nil
	}
}

type wasip1SockRecvMeter struct {
	meter         ByteMeter
	mem           api.Memory
	roDatalenAddr uint32
}

func (l *wasip1SockRecvMeter) Before(_ context.Context, mod api.Module, _ api.FunctionDefinition, params []uint64, _ experimental.StackIterator) {
	l.mem = mod.Memory()
	if len(params) > 4 {
		l.roDatalenAddr = uint32(params[4])
	}
}

func (l *wasip1SockRecvMeter) After(_ context.Context, _ api.Module, _ api.FunctionDefinition, _ []uint64) {
	if l.meter == nil || l.mem == nil || l.roDatalenAddr == 0 {
		return
	}
	n, ok := l.mem.ReadUint32Le(l.roDatalenAddr)
	if ok && n > 0 {
		l.meter.AddIn(int64(n))
	}
}

func (l *wasip1SockRecvMeter) Abort(context.Context, api.Module, api.FunctionDefinition, error) {
	_ = l
}

type wasip1SockSendMeter struct {
	meter         ByteMeter
	mem           api.Memory
	soDatalenAddr uint32
}

func (l *wasip1SockSendMeter) Before(_ context.Context, mod api.Module, _ api.FunctionDefinition, params []uint64, _ experimental.StackIterator) {
	l.mem = mod.Memory()
	if len(params) > 4 {
		l.soDatalenAddr = uint32(params[4])
	}
}

func (l *wasip1SockSendMeter) After(_ context.Context, _ api.Module, _ api.FunctionDefinition, _ []uint64) {
	if l.meter == nil || l.mem == nil || l.soDatalenAddr == 0 {
		return
	}
	n, ok := l.mem.ReadUint32Le(l.soDatalenAddr)
	if ok && n > 0 {
		l.meter.AddOut(int64(n))
	}
}

func (l *wasip1SockSendMeter) Abort(context.Context, api.Module, api.FunctionDefinition, error) {
	_ = l
}

// wasip1SockAcceptMeter counts inbound accepts as a 1-byte ingress pulse so
// netstats reflects listener activity even before recv/send.
type wasip1SockAcceptMeter struct {
	meter       ByteMeter
	mem         api.Memory
	resultFDPtr uint32
}

func (l *wasip1SockAcceptMeter) Before(_ context.Context, mod api.Module, _ api.FunctionDefinition, params []uint64, _ experimental.StackIterator) {
	l.mem = mod.Memory()
	if len(params) > 2 {
		l.resultFDPtr = uint32(params[2])
	}
}

func (l *wasip1SockAcceptMeter) After(_ context.Context, _ api.Module, _ api.FunctionDefinition, _ []uint64) {
	if l.meter == nil || l.mem == nil || l.resultFDPtr == 0 {
		return
	}
	if fd, ok := l.mem.ReadUint32Le(l.resultFDPtr); ok && fd != 0 {
		l.meter.AddIn(1)
	}
}

func (l *wasip1SockAcceptMeter) Abort(context.Context, api.Module, api.FunctionDefinition, error) {
	_ = l
}

func withWasip1Meter(ctx context.Context, hook *NetworkHook) context.Context {
	if hook == nil || hook.Meter == nil {
		return ctx
	}
	factory := newWasip1MeterFactory(hook.Meter)
	if factory == nil {
		return ctx
	}
	return experimental.WithFunctionListenerFactory(ctx, factory)
}
