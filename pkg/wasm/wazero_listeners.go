package wasm

import (
	"context"
	"sync"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// boundListener is one pre-opened listener of a running instance: the fd
// the guest sees it on, the exposed port it serves (0 for the single
// WASIListenPort listener) and the loopback port it is bound to.
type boundListener struct {
	fd        int32
	guestPort int
	hostPort  int
}

// instanceListen is what the engine knows about the listeners of the
// instance it runs. The ports are read once, when the instance is made and
// before any guest code runs: wazero's fd table is not safe to read while
// the guest runs, and the worker asks on every proxied request. From then
// on the guest's own WASI calls say which listeners it has closed and which
// it accepts on (fdWatchFactory). A request never goes to the port of a
// listener that is gone: once closed, its port is free for any other bind
// on the host.
type instanceListen struct {
	mu       sync.Mutex
	bound    []boundListener
	gone     map[int32]struct{}
	accepted map[int32]struct{}
}

// resolveInstanceListen reads the ports of the listeners caps pre-opens on
// a module that has not run yet, each at its exact fd (ListenerFDs). nil
// when caps open none or none resolved.
func resolveInstanceListen(mod api.Module, caps Capabilities) *instanceListen {
	listeners := caps.Listeners()
	if len(listeners) == 0 {
		return nil
	}
	fds := ListenerFDs(caps)
	ports := resolveListenPortsAt(mod, fds)
	var bound []boundListener
	for i, l := range listeners {
		if ports[i] > 0 {
			bound = append(bound, boundListener{fd: int32(fds[i]), guestPort: l.GuestPort, hostPort: ports[i]})
		}
	}
	if len(bound) == 0 {
		return nil
	}
	return &instanceListen{bound: bound}
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

// mark records fd in set when it is one of the listeners' fds.
func (l *instanceListen) mark(set *map[int32]struct{}, fd int32) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range l.bound {
		if b.fd == fd {
			if *set == nil {
				*set = make(map[int32]struct{})
			}
			(*set)[fd] = struct{}{}
			return
		}
	}
}

// fdGone records that the guest closed fd (or moved another file onto it).
func (l *instanceListen) fdGone(fd int32) {
	if l != nil {
		l.mark(&l.gone, fd)
	}
}

// fdAccepted records that the guest called sock_accept on fd.
func (l *instanceListen) fdAccepted(fd int32) {
	if l != nil {
		l.mark(&l.accepted, fd)
	}
}

// acceptedOn reports whether the guest has accepted on guestPort's
// listener and still has it.
func (l *instanceListen) acceptedOn(guestPort int) bool {
	if l == nil || guestPort <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range l.bound {
		if b.guestPort != guestPort {
			continue
		}
		_, accepted := l.accepted[b.fd]
		_, gone := l.gone[b.fd]
		return accepted && !gone
	}
	return false
}

// fdWatcher hears the guest's WASI calls on its descriptors.
type fdWatcher interface {
	fdGone(mod api.Module, fd int32)
	fdAccepted(mod api.Module, fd int32)
}

// fdWatchFactory puts function listeners on the wasip1 calls that close a
// descriptor or accept on one. It is set where the wasi_snapshot_preview1
// host module is instantiated: wazero builds host-function listeners when
// it compiles that module, so a factory in a later context does nothing.
// Every other function gets none and runs as before; the guest's own
// compiled code is unchanged, so the compilation cache still hits.
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
	case wasip1SockAccept:
		// sock_accept(fd, flags, result_fd_ptr): the guest serves fd. Go's
		// wasip1 net calls it as soon as Accept is called, before waiting.
		return fdWatchListener{w: f.w, params: []int{0}, accept: true}
	}
	return nil
}

// fdWatchListener reports the descriptors named by params before the call
// runs, whether or not it then succeeds: a listener the guest tried to give
// up is not routed to again, and one it tried to accept on is one it
// serves.
type fdWatchListener struct {
	w      fdWatcher
	params []int
	accept bool
}

func (l fdWatchListener) Before(_ context.Context, mod api.Module, _ api.FunctionDefinition, params []uint64, _ experimental.StackIterator) {
	for _, i := range l.params {
		if i >= len(params) {
			continue
		}
		if l.accept {
			l.w.fdAccepted(mod, int32(params[i]))
		} else {
			l.w.fdGone(mod, int32(params[i]))
		}
	}
}

func (fdWatchListener) After(context.Context, api.Module, api.FunctionDefinition, []uint64) {}

func (fdWatchListener) Abort(context.Context, api.Module, api.FunctionDefinition, error) {}

// currentListen is the running instance's listen state when mod is that
// instance, nil otherwise: a report never applies to an instance the
// engine has replaced.
func (e *wazeroEngine) currentListen(mod api.Module) *instanceListen {
	e.callMu.Lock()
	defer e.callMu.Unlock()
	if e.module == nil || e.module != mod {
		return nil
	}
	return e.listen
}

// fdGone and fdAccepted make wazeroEngine the fdWatcher of its runtime.
func (e *wazeroEngine) fdGone(mod api.Module, fd int32) {
	e.currentListen(mod).fdGone(fd)
}

func (e *wazeroEngine) fdAccepted(mod api.Module, fd int32) {
	e.currentListen(mod).fdAccepted(fd)
}
