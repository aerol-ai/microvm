package wasm

import (
	"context"
	"sync"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// boundListener is one pre-opened listener of a running instance: the fd
// the guest sees it on and the loopback port it is bound to.
type boundListener struct {
	fd       int32
	hostPort int
}

// instanceListen is what the engine knows about the listeners of the
// instance it runs. The ports are read once, when the instance is made and
// before any guest code runs: wazero's fd table is not safe to read while
// the guest runs, and the worker asks on every proxied request. From then
// on the guest's own WASI calls say which listeners it has closed
// (fdWatchFactory), so a request never goes to the port of a listener that
// is gone: once closed, its port is free for any other bind on the host.
type instanceListen struct {
	mu    sync.Mutex
	bound []boundListener
	gone  map[int32]struct{}
}

// resolveInstanceListen reads the ports of the listeners caps pre-opens on
// a module that has not run yet. nil when caps open none or none resolved.
func resolveInstanceListen(mod api.Module, caps Capabilities) *instanceListen {
	if !caps.ListenEnabled() {
		return nil
	}
	fd := int32(ListenerFD(caps))
	file, ok := moduleLookupFile(mod, fd)
	if !ok {
		return nil
	}
	port, ok := tcpListenPort(file)
	if !ok {
		return nil
	}
	return &instanceListen{bound: []boundListener{{fd: fd, hostPort: port}}}
}

// live returns the listeners the guest has not closed, in fd order.
func (l *instanceListen) live() []boundListener {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]boundListener, 0, len(l.bound))
	for _, b := range l.bound {
		if _, gone := l.gone[b.fd]; !gone {
			out = append(out, b)
		}
	}
	return out
}

// fdGone records that the guest closed fd (or moved another file onto it).
func (l *instanceListen) fdGone(fd int32) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range l.bound {
		if b.fd == fd {
			if l.gone == nil {
				l.gone = make(map[int32]struct{})
			}
			l.gone[fd] = struct{}{}
			return
		}
	}
}

// fdWatcher hears the guest's WASI calls that end a file descriptor.
type fdWatcher interface {
	fdGone(mod api.Module, fd int32)
}

// fdWatchFactory puts function listeners on the wasip1 calls that close a
// descriptor. It is set where the wasi_snapshot_preview1 host module is
// instantiated: wazero builds host-function listeners when it compiles that
// module, so a factory in a later context does nothing. Every other
// function gets none and runs as before; the guest's own compiled code is
// unchanged, so the compilation cache still hits.
type fdWatchFactory struct {
	w fdWatcher
}

func (f fdWatchFactory) NewFunctionListener(def api.FunctionDefinition) experimental.FunctionListener {
	if def.ModuleName() != wasi_snapshot_preview1.ModuleName {
		return nil
	}
	switch def.Name() {
	case "fd_close":
		// fd_close(fd)
		return fdWatchListener{w: f.w, params: []int{0}}
	case "fd_renumber":
		// fd_renumber(from, to): to is closed and from moves onto it. A
		// listener moved to another number is treated as gone too: the
		// engine tracks listeners by the fd it opened them on.
		return fdWatchListener{w: f.w, params: []int{0, 1}}
	}
	return nil
}

// fdWatchListener reports the descriptors named by params before the call
// runs, whether or not it then succeeds: a listener the guest tried to give
// up is not routed to again.
type fdWatchListener struct {
	w      fdWatcher
	params []int
}

func (l fdWatchListener) Before(_ context.Context, mod api.Module, _ api.FunctionDefinition, params []uint64, _ experimental.StackIterator) {
	for _, i := range l.params {
		if i < len(params) {
			l.w.fdGone(mod, int32(params[i]))
		}
	}
}

func (fdWatchListener) After(context.Context, api.Module, api.FunctionDefinition, []uint64) {}

func (fdWatchListener) Abort(context.Context, api.Module, api.FunctionDefinition, error) {}

// fdGone is the wazeroEngine's fdWatcher: it applies to the instance it
// runs now, never to one it has replaced.
func (e *wazeroEngine) fdGone(mod api.Module, fd int32) {
	e.callMu.Lock()
	listen := e.listen
	current := e.module != nil && e.module == mod
	e.callMu.Unlock()
	if current {
		listen.fdGone(fd)
	}
}
