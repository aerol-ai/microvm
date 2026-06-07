package wasm

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestFSConfigMountsPreopensWithListenEnabled(t *testing.T) {
	e := &wazeroEngine{}
	caps := Capabilities{
		WASIListenPort: 0,
		Preopens: []Preopen{{
			GuestPath: "/work",
			HostPath:  t.TempDir(),
		}},
	}
	// Preopens are mounted even while listening so an HTTP guest can also read
	// /work; the listener moves off fd 3 and the guest learns its fd from
	// ListenFDEnv (see ListenerFD). This inverts the earlier omit-on-listen rule.
	if got := e.fsConfigForCaps(caps); got == nil {
		t.Fatal("fsConfigForCaps with listen enabled should still mount preopens")
	}
	if got := ListenerFD(caps); got != 4 {
		t.Fatalf("ListenerFD with one preopen = %d, want 4", got)
	}
	caps.WASIListenPort = WASIListenPortDisabled
	if got := e.fsConfigForCaps(caps); got == nil {
		t.Fatal("fsConfigForCaps without listen should mount preopens")
	}
}

func TestWazeroEngineLoadAndInvokeStart(t *testing.T) {
	dir := t.TempDir()
	path := wasmmod.WriteMinimalWasm(t, dir, "empty.wasm")

	ctx := context.Background()
	eng, err := NewEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close(ctx)

	if err := eng.LoadModule(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err := eng.Instantiate(ctx, Capabilities{Args: []string{"test"}}); err != nil {
		t.Fatal(err)
	}
	if err := eng.InvokeExport(ctx, "_start"); err != nil {
		t.Fatal(err)
	}
	if err := eng.StopInstance(ctx); err != nil {
		t.Fatal(err)
	}
	// Re-instantiate after stop.
	if err := eng.Instantiate(ctx, Capabilities{Args: []string{filepath.Base(path)}}); err != nil {
		t.Fatal(err)
	}
}
