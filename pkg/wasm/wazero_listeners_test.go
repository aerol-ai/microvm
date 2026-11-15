package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
		want := name == "fd_close" || name == "fd_renumber"
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
}
