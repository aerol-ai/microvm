package wasm

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tetratelabs/wazero/api"
)

// wasiCallerWasm builds a module whose _start makes one wasip1 call,
// name(args...), and drops the result. It has one page of memory (exported
// as "memory") for calls that write results.
func wasiCallerWasm(t *testing.T, name string, args ...int32) string {
	t.Helper()
	for _, a := range args {
		if a < 0 || a > 63 {
			t.Fatalf("arg %d does not fit the one-byte encoding used here", a)
		}
	}
	section := func(id byte, body []byte) []byte {
		if len(body) > 127 {
			t.Fatalf("section %d too long for the one-byte encoding used here", id)
		}
		return append([]byte{id, byte(len(body))}, body...)
	}
	str := func(s string) []byte { return append([]byte{byte(len(s))}, s...) }

	// type 0: (i32 x n) -> i32, the wasi call; type 1: () -> (), _start.
	callType := []byte{0x60, byte(len(args))}
	for range args {
		callType = append(callType, 0x7f)
	}
	callType = append(callType, 0x01, 0x7f)
	types := append([]byte{0x02}, callType...)
	types = append(types, 0x60, 0x00, 0x00)

	imports := []byte{0x01}
	imports = append(imports, str("wasi_snapshot_preview1")...)
	imports = append(imports, str(name)...)
	imports = append(imports, 0x00, 0x00)

	exports := []byte{0x02}
	exports = append(exports, str("_start")...)
	exports = append(exports, 0x00, 0x01)
	exports = append(exports, str("memory")...)
	exports = append(exports, 0x02, 0x00)

	body := []byte{0x00}
	for _, a := range args {
		body = append(body, 0x41, byte(a))
	}
	body = append(body, 0x10, 0x00, 0x1a, 0x0b)
	code := append([]byte{0x01, byte(len(body))}, body...)

	mod := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	mod = append(mod, section(1, types)...)
	mod = append(mod, section(2, imports)...)
	mod = append(mod, section(3, []byte{0x01, 0x01})...)
	mod = append(mod, section(5, []byte{0x01, 0x00, 0x01})...)
	mod = append(mod, section(7, exports)...)
	mod = append(mod, section(10, code)...)
	path := filepath.Join(t.TempDir(), name+".wasm")
	if err := os.WriteFile(path, mod, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newListeningEngine(t *testing.T, modPath string, caps Capabilities) *wazeroEngine {
	t.Helper()
	ctx := context.Background()
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatalf("newWazeroEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, modPath, LoadOptions{}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	if err := eng.Instantiate(ctx, caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	return eng
}

// A guest that closes its listener, or moves another file onto its fd, has
// given the port up: the host can hand it to any other bind, so the engine
// stops naming it. Closing an unrelated fd changes nothing.
func TestWazeroEngineForgetsAListenerTheGuestCloses(t *testing.T) {
	caps := Capabilities{WASIListenPort: 0, WASIListenHost: "127.0.0.1"}
	listenerFD := int32(ListenerFD(caps))
	cases := []struct {
		name     string
		call     string
		args     []int32
		wantLive bool
	}{
		{"fd_close of the listener", "fd_close", []int32{listenerFD}, false},
		{"fd_close of another fd", "fd_close", []int32{listenerFD + 5}, true},
		{"fd_renumber onto the listener", "fd_renumber", []int32{listenerFD + 5, listenerFD}, false},
		{"fd_renumber of the listener", "fd_renumber", []int32{listenerFD, listenerFD + 5}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newListeningEngine(t, wasiCallerWasm(t, tc.call, tc.args...), caps)
			if port, ok := eng.ResolvedListenPort(); !ok || port <= 0 {
				t.Fatalf("before the call: ResolvedListenPort = (%d,%v)", port, ok)
			}
			if err := eng.InvokeExport(context.Background(), "_start"); err != nil {
				t.Fatalf("_start: %v", err)
			}
			if _, ok := eng.ResolvedListenPort(); ok != tc.wantLive {
				t.Fatalf("after %s(%v): live = %v, want %v", tc.call, tc.args, ok, tc.wantLive)
			}
		})
	}
}

// The watch applies to the instance the engine runs: a re-instantiation
// starts with every listener live again.
func TestWazeroEngineListenWatchIsPerInstance(t *testing.T) {
	caps := Capabilities{WASIListenPort: 0, WASIListenHost: "127.0.0.1"}
	eng := newListeningEngine(t, wasiCallerWasm(t, "fd_close", int32(ListenerFD(caps))), caps)
	if err := eng.InvokeExport(context.Background(), "_start"); err != nil {
		t.Fatalf("_start: %v", err)
	}
	if _, ok := eng.ResolvedListenPort(); ok {
		t.Fatal("listener still named after the guest closed it")
	}
	if err := eng.Instantiate(context.Background(), caps); err != nil {
		t.Fatalf("re-Instantiate: %v", err)
	}
	if port, ok := eng.ResolvedListenPort(); !ok || port <= 0 {
		t.Fatalf("after re-Instantiate: ResolvedListenPort = (%d,%v)", port, ok)
	}
	// A report about a module the engine no longer runs is ignored.
	eng.fdGone(nil, int32(ListenerFD(caps)))
	if _, ok := eng.ResolvedListenPort(); !ok {
		t.Fatal("a report for another module dropped the listener")
	}
}

func TestInstanceListenEdges(t *testing.T) {
	var nilListen *instanceListen
	if got := nilListen.live(); got != nil {
		t.Fatalf("nil live = %v", got)
	}
	nilListen.fdGone(3)

	l := &instanceListen{bound: []boundListener{{fd: 3, hostPort: 1000}, {fd: 4, hostPort: 1001}}}
	l.fdGone(9)
	if got := l.live(); len(got) != 2 {
		t.Fatalf("live after unrelated fd = %v", got)
	}
	l.fdGone(3)
	if got := l.live(); len(got) != 1 || got[0].hostPort != 1001 {
		t.Fatalf("live after closing fd 3 = %v", got)
	}

	if got := resolveInstanceListen(nil, Capabilities{WASIListenPort: WASIListenPortDisabled}); got != nil {
		t.Fatalf("resolve without listeners = %+v", got)
	}
	if got := resolveInstanceListen(&mockWazeroModValidFS{}, Capabilities{WASIListenPort: 0}); got != nil {
		t.Fatalf("resolve with no file at the fd = %+v", got)
	}
}

// A listener with no live port is reported as none.
func TestWazeroEngineResolvedListenPortWithoutListener(t *testing.T) {
	eng := newListeningEngine(t, writeDummyWasm(t, t.TempDir()), Capabilities{WASIListenPort: WASIListenPortDisabled})
	if port, ok := eng.ResolvedListenPort(); ok {
		t.Fatalf("ResolvedListenPort = (%d,%v) with no listener", port, ok)
	}
}

func TestFdWatchFactoryIgnoresOtherFunctions(t *testing.T) {
	f := fdWatchFactory{}
	defs := map[string]bool{}
	ctx := context.Background()
	r, err := newBaseRuntime(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)
	for _, m := range []string{"wasi_snapshot_preview1"} {
		mod := r.Module(m)
		if mod == nil {
			t.Fatalf("module %s missing", m)
		}
		for name, def := range mod.ExportedFunctionDefinitions() {
			defs[name] = f.NewFunctionListener(def) != nil
		}
	}
	for name, watched := range defs {
		want := name == "fd_close" || name == "fd_renumber" || name == "sock_accept"
		if watched != want {
			t.Errorf("%s watched = %v, want %v", name, watched, want)
		}
	}
	// A function of another module is never watched.
	if l := f.NewFunctionListener(&mockFuncDef{modName: "env", funcName: "fd_close"}); l != nil {
		t.Fatal("env.fd_close watched")
	}
	var l fdWatchListener
	l.After(ctx, nil, nil, nil)
	l.Abort(ctx, nil, nil, nil)
	// A call with fewer params than the listener names reports nothing.
	rec := &recordingFDWatcher{}
	fdWatchListener{w: rec, params: []int{1}}.Before(ctx, nil, nil, []uint64{3}, nil)
	if len(rec.gone)+len(rec.accepted) != 0 {
		t.Fatalf("short params reported %+v", rec)
	}
}

type recordingFDWatcher struct{ gone, accepted []int32 }

func (r *recordingFDWatcher) fdGone(_ api.Module, fd int32)     { r.gone = append(r.gone, fd) }
func (r *recordingFDWatcher) fdAccepted(_ api.Module, fd int32) { r.accepted = append(r.accepted, fd) }

func TestCapabilitiesListeners(t *testing.T) {
	cases := []struct {
		name string
		caps Capabilities
		want []WASIListener
		fds  []int
		env  string
	}{
		{"disabled", Capabilities{WASIListenPort: WASIListenPortDisabled}, nil, []int{}, ""},
		{"single ephemeral", Capabilities{WASIListenPort: 0}, []WASIListener{{}}, []int{3}, "0=3"},
		{"single fixed after a preopen", Capabilities{WASIListenPort: 7000, Preopens: []Preopen{{GuestPath: "/work"}}},
			[]WASIListener{{HostPort: 7000}}, []int{4}, "0=4"},
		{"per port, sorted, replacing the single one",
			Capabilities{WASIListenPort: 0, Preopens: []Preopen{{GuestPath: "/work"}},
				WASIListeners: []WASIListener{{GuestPort: 9090}, {GuestPort: 8080, HostPort: 41000}}},
			[]WASIListener{{GuestPort: 8080, HostPort: 41000}, {GuestPort: 9090}}, []int{4, 5}, "8080=4,9090=5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.caps.Listeners()
			if len(got) != len(tc.want) {
				t.Fatalf("Listeners = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Listeners = %+v, want %+v", got, tc.want)
				}
			}
			if tc.caps.ListenEnabled() != (len(tc.want) > 0) {
				t.Fatalf("ListenEnabled = %v", tc.caps.ListenEnabled())
			}
			fds := ListenerFDs(tc.caps)
			if len(fds) != len(tc.fds) {
				t.Fatalf("ListenerFDs = %v, want %v", fds, tc.fds)
			}
			for i := range fds {
				if fds[i] != tc.fds[i] {
					t.Fatalf("ListenerFDs = %v, want %v", fds, tc.fds)
				}
			}
			if got := listenFDsValue(tc.caps); got != tc.env {
				t.Fatalf("listenFDsValue = %q, want %q", got, tc.env)
			}
		})
	}
	// The caller's slice is not reordered.
	caps := Capabilities{WASIListeners: []WASIListener{{GuestPort: 9090}, {GuestPort: 8080}}}
	_ = caps.Listeners()
	if caps.WASIListeners[0].GuestPort != 9090 {
		t.Fatal("Listeners sorted the caps' own slice")
	}
}

// Every listener resolves at its exact fd, however many dir preopens come
// first: the old fd 3-10 scan missed a listener behind eight of them.
func TestWazeroEngineResolvesListenersBehindManyPreopens(t *testing.T) {
	var preopens []Preopen
	for i := 0; i < 9; i++ {
		dir := t.TempDir()
		preopens = append(preopens, Preopen{GuestPath: "/p" + string(rune('a'+i)), HostPath: dir})
	}
	caps := Capabilities{
		Preopens:       preopens,
		WASIListenPort: WASIListenPortDisabled,
		WASIListenHost: "127.0.0.1",
		WASIListeners:  []WASIListener{{GuestPort: 9090}, {GuestPort: 8080}},
	}
	eng := newListeningEngine(t, writeDummyWasm(t, t.TempDir()), caps)
	got := eng.ResolvedListeners()
	if len(got) != 2 || got[0].GuestPort != 8080 || got[1].GuestPort != 9090 || got[0].HostPort <= 0 || got[1].HostPort <= 0 || got[0].HostPort == got[1].HostPort {
		t.Fatalf("ResolvedListeners = %+v", got)
	}
	if port, ok := eng.ResolvedListenPort(); !ok || port != got[0].HostPort {
		t.Fatalf("ResolvedListenPort = (%d,%v), want the 8080 listener %d", port, ok, got[0].HostPort)
	}
	if _, ok := ResolvedListenPort(eng.module); ok {
		t.Fatal("the fd 3-10 scan now finds a listener at fd 12; this test no longer covers the exact lookup")
	}
	ports := ResolvedListenPorts(eng.module, ListenerFDs(caps))
	if len(ports) != 2 || ports[0] != got[0].HostPort || ports[1] != got[1].HostPort {
		t.Fatalf("ResolvedListenPorts = %v", ports)
	}
	if ports := ResolvedListenPorts(nil, []int{3}); ports[0] != 0 {
		t.Fatalf("ResolvedListenPorts(nil) = %v", ports)
	}
}

// The engine reports a listener as accepted once the guest calls
// sock_accept on its fd; the others stay unaccepted.
func TestWazeroEngineListenerAccepted(t *testing.T) {
	caps := Capabilities{
		WASIListenPort: WASIListenPortDisabled,
		WASIListenHost: "127.0.0.1",
		WASIListeners:  []WASIListener{{GuestPort: 8080}, {GuestPort: 9090}},
	}
	fds := ListenerFDs(caps)
	eng := newListeningEngine(t, wasiCallerWasm(t, "sock_accept", int32(fds[1]), 0, 16), caps)
	if eng.ListenerAccepted(8080) || eng.ListenerAccepted(9090) {
		t.Fatal("a listener counts as accepted before the guest ran")
	}
	// The listener blocks in accept: queue a connection so the guest's one
	// sock_accept returns.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(eng.ResolvedListeners()[1].HostPort)))
	if err != nil {
		t.Fatalf("dial the 9090 listener: %v", err)
	}
	defer conn.Close()
	if err := eng.InvokeExport(context.Background(), "_start"); err != nil {
		t.Fatalf("_start: %v", err)
	}
	if eng.ListenerAccepted(8080) || !eng.ListenerAccepted(9090) || eng.ListenerAccepted(0) || eng.ListenerAccepted(7070) {
		t.Fatalf("accepted 8080=%v 9090=%v", eng.ListenerAccepted(8080), eng.ListenerAccepted(9090))
	}
	// A listener the guest accepted on and then gave up is not accepted.
	eng.listen.fdGone(int32(fds[1]))
	if eng.ListenerAccepted(9090) {
		t.Fatal("a closed listener still counts as accepted")
	}
	var nilListen *instanceListen
	nilListen.fdAccepted(3)
	if nilListen.acceptedOn(8080) {
		t.Fatal("nil listen accepted")
	}
	if got := (&wazeroEngine{}).ResolvedListeners(); got != nil {
		t.Fatalf("ResolvedListeners with no instance = %+v", got)
	}
}
