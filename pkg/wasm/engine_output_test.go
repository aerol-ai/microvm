package wasm

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
	"github.com/tetratelabs/wazero/sys"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// The serving instance writes to the writers it was given; a one-shot Run
// keeps its own output.
func TestSetInstanceOutput(t *testing.T) {
	path := wasmtestguest.Path(t, wasmtestguest.Stdio)
	ctx := context.Background()
	raw, err := NewEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close(ctx)
	eng, ok := raw.(InstanceOutputSetter)
	if !ok {
		t.Fatal("the wazero engine cannot send its output anywhere")
	}
	if err := raw.LoadModule(ctx, path, LoadOptions{MemoryMB: 64}); err != nil {
		t.Fatal(err)
	}
	// The stdio guest imports aerol/vm/net, which a network hook provides.
	raw.(NetworkAwareEngine).SetNetworkHook(&NetworkHook{SandboxID: "sb", Dial: &countingDialer{}})
	var out, errOut lockedBuffer
	eng.SetInstanceOutput(&out, &errOut)

	if err := raw.Instantiate(ctx, stdioCaps("args", "served")); err != nil {
		t.Fatal(err)
	}
	if code := ExitCode(raw.InvokeExport(ctx, "_start")); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if err := raw.Instantiate(ctx, stdioCaps("stderr", "warned")); err != nil {
		t.Fatal(err)
	}
	_ = raw.InvokeExport(ctx, "_start")
	if out.String() != "served\n" || errOut.String() != "warned" {
		t.Fatalf("instance output = %q / %q", out.String(), errOut.String())
	}

	res, err := raw.Run(ctx, stdioCaps("args", "ran"), "_start")
	if err != nil || res.Stdout != "ran\n" {
		t.Fatalf("Run = %+v %v", res, err)
	}
	if out.String() != "served\n" {
		t.Fatalf("Run's output reached the instance writer: %q", out.String())
	}
}

func TestExitCode(t *testing.T) {
	for err, want := range map[error]int{
		nil:                       0,
		sys.NewExitError(3):       3,
		errors.New("unreachable"): 1,
	} {
		if got := ExitCode(err); got != want {
			t.Errorf("ExitCode(%v) = %d, want %d", err, got, want)
		}
	}
}
