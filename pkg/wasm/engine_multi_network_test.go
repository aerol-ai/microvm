package wasm

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestMultiNetHost_CrossTenantConnDenied is the IRON-RULE isolation regression:
// guest B must not read/write/close guest A's conn_id. Conn ownership is the
// nested map; a foreign id is unresolvable → errClosed, and A's conn stays usable.
func TestMultiNetHost_CrossTenantConnDenied(t *testing.T) {
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
			_ = c.Close()
		}
	}()

	host := newMultiNetHost()
	meterA, meterB := &mockMeter{}, &mockMeter{}
	host.setHook("sbx-A", &NetworkHook{SandboxID: "sbx-A", Dial: &countingDialer{}, Meter: meterA})
	host.setHook("sbx-B", &NetworkHook{SandboxID: "sbx-B", Dial: &countingDialer{}, Meter: meterB})

	addr := []byte(ln.Addr().String())
	modA := &mockModule{name: "sbx-A", mem: &mockMemory{buf: append([]byte{}, addr...)}}
	stack := []uint64{0, uint64(len(addr))}
	host.tcpDial(ctx, modA, stack)
	connID := stack[0]
	if int32(connID) <= 0 {
		t.Fatalf("A dial failed: %v", int32(connID))
	}

	modB := &mockModule{name: "sbx-B", mem: &mockMemory{buf: make([]byte, 8)}}
	// B tries to use A's conn_id → errClosed (2).
	readStack := []uint64{connID, 0, 2}
	host.tcpRead(ctx, modB, readStack)
	if readStack[0] != 2 {
		t.Fatalf("B tcp_read with A's id: got %v, want errClosed(2)", readStack[0])
	}
	writeStack := []uint64{connID, 0, 2}
	host.tcpWrite(ctx, modB, writeStack)
	if writeStack[0] != 2 {
		t.Fatalf("B tcp_write with A's id: got %v, want errClosed(2)", writeStack[0])
	}
	closeStack := []uint64{connID}
	host.tcpClose(ctx, modB, closeStack) // B's close is a no-op on unknown id
	if closeStack[0] != 0 {
		t.Fatalf("B tcp_close: got %v", closeStack[0])
	}

	// A's conn still works.
	modA.mem.buf = make([]byte, 2)
	readStack = []uint64{connID, 0, 2}
	host.tcpRead(ctx, modA, readStack)
	if int32(readStack[0]) <= 0 {
		t.Fatalf("A read after B's attempt failed: %v", int32(readStack[0]))
	}
	if meterB.in.Load() != 0 || meterB.out.Load() != 0 {
		t.Fatalf("B meter moved on A's traffic: in=%d out=%d", meterB.in.Load(), meterB.out.Load())
	}
}

func TestMultiNetHost_PerTenantMeterAndBlocks(t *testing.T) {
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 8)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("xy"))
			_ = c.Close()
		}
	}()

	host := newMultiNetHost()
	meterA, meterB := &mockMeter{}, &mockMeter{}
	host.setHook("a", &NetworkHook{Dial: &countingDialer{}, Meter: meterA})
	host.setHook("b", &NetworkHook{Dial: &countingDialer{}, Meter: meterB})

	addr := []byte(ln.Addr().String())
	dial := func(sid string) uint64 {
		mod := &mockModule{name: sid, mem: &mockMemory{buf: append([]byte{}, addr...)}}
		stack := []uint64{0, uint64(len(addr))}
		host.tcpDial(ctx, mod, stack)
		if int32(stack[0]) <= 0 {
			t.Fatalf("%s dial failed", sid)
		}
		return stack[0]
	}
	idA := dial("a")
	idB := dial("b")

	modA := &mockModule{name: "a", mem: &mockMemory{buf: []byte("hi????")}}
	host.tcpWrite(ctx, modA, []uint64{idA, 0, 2})
	host.tcpRead(ctx, modA, []uint64{idA, 2, 2})
	if meterA.out.Load() != 2 {
		t.Fatalf("A out=%d, want 2", meterA.out.Load())
	}
	if meterB.in.Load() != 0 || meterB.out.Load() != 0 {
		t.Fatalf("B meter polluted: in=%d out=%d", meterB.in.Load(), meterB.out.Load())
	}
	_ = idB

	// Fail-closed: no hook → errBlocked.
	host.clearSandbox("a")
	modGone := &mockModule{name: "a", mem: &mockMemory{buf: append([]byte{}, addr...)}}
	stack := []uint64{0, uint64(len(addr))}
	host.tcpDial(ctx, modGone, stack)
	if stack[0] != 3 {
		t.Fatalf("cleared hook dial: got %v, want errBlocked(3)", stack[0])
	}

	// Blocked dialer → errBlocked; sibling still dials.
	host.setHook("a", &NetworkHook{Dial: &mockBlockedDialer{}})
	host.setHook("b", &NetworkHook{Dial: &countingDialer{}})
	stack = []uint64{0, uint64(len(addr))}
	host.tcpDial(ctx, &mockModule{name: "a", mem: &mockMemory{buf: append([]byte{}, addr...)}}, stack)
	if stack[0] != 3 {
		t.Fatalf("blocked A: got %v, want 3", stack[0])
	}
	stack = []uint64{0, uint64(len(addr))}
	host.tcpDial(ctx, &mockModule{name: "b", mem: &mockMemory{buf: append([]byte{}, addr...)}}, stack)
	if int32(stack[0]) <= 0 {
		t.Fatalf("B dial under A's block failed: %v", int32(stack[0]))
	}
}

func TestMultiNetHost_DialHonorsInvocationDeadline(t *testing.T) {
	host := newMultiNetHost()
	var sawCancel atomic.Bool
	host.setHook("a", &NetworkHook{Dial: &contextAwareDialer{sawCancel: &sawCancel}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	addr := []byte("127.0.0.1:9")
	mod := &mockModule{name: "a", mem: &mockMemory{buf: addr}}
	stack := []uint64{0, uint64(len(addr))}
	host.tcpDial(ctx, mod, stack)
	if stack[0] != 2 { // errDial
		t.Fatalf("canceled dial: got %v, want errDial(2)", stack[0])
	}
	if !sawCancel.Load() {
		t.Fatal("dialer did not observe canceled context")
	}
}

func TestMultiNetHost_StopClosesOwnedConns(t *testing.T) {
	ctx := context.Background()
	c1, c2 := net.Pipe()
	defer c2.Close()

	host := newMultiNetHost()
	host.setHook("a", &NetworkHook{Dial: &pipeDialer{c: c1}})
	mod := &mockModule{name: "a", mem: &mockMemory{buf: []byte("x")}}
	stack := []uint64{0, 1}
	host.tcpDial(ctx, mod, stack)
	if int32(stack[0]) <= 0 {
		t.Fatalf("dial: %v", int32(stack[0]))
	}

	blocked := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = c2.Read(buf) // blocks until peer closed
		close(blocked)
	}()
	time.Sleep(20 * time.Millisecond)
	host.clearSandbox("a")
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("clearSandbox did not unblock peer Read")
	}
}

type contextAwareDialer struct {
	sawCancel *atomic.Bool
}

func (d *contextAwareDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	d.sawCancel.Store(true)
	return nil, ctx.Err()
}

type pipeDialer struct{ c net.Conn }

func (d *pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.c, nil
}

// TestMultiInstanceEngine_ParallelCallAcrossModules stress-tests the core
// assumption that wazero permits parallel Call across different modules on one
// runtime, and that StopInstance waits for in-flight calls (D8).
func TestMultiInstanceEngine_ParallelCallAcrossModules(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	ctx := context.Background()
	eng, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatalf("NewMultiInstanceEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, modPath); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}

	const n = 8
	caps := Capabilities{Args: []string{"wasm"}, WallTimeoutNs: int64(time.Minute)}
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = fmt.Sprintf("sb-%d", i)
		if err := eng.Instantiate(ctx, ids[i], caps); err != nil {
			t.Fatalf("Instantiate %s: %v", ids[i], err)
		}
	}

	// Parallel Call across distinct modules — the design's core unproven assumption.
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for _, id := range ids {
		wg.Add(1)
		go func(sid string) {
			defer wg.Done()
			if err := eng.InvokeExport(ctx, sid, "_start"); err != nil {
				errCh <- err
			}
		}(id)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("parallel InvokeExport: %v", err)
	}

	// Re-instantiate via Run so each sandbox has a fresh module, then Stop under
	// concurrent Invoke (Stop must wait for the per-instance lock, not UAF).
	for _, id := range ids {
		if _, err := eng.Run(ctx, id, caps, "_start"); err != nil {
			t.Fatalf("Run %s: %v", id, err)
		}
	}
	errCh = make(chan error, n)
	var stopWG sync.WaitGroup
	for _, id := range ids {
		stopWG.Add(1)
		go func(sid string) {
			defer stopWG.Done()
			if err := eng.StopInstance(ctx, sid); err != nil {
				errCh <- err
			}
		}(id)
	}
	stopWG.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("Stop under load: %v", err)
	}
	if got := eng.InstanceCount(); got != 0 {
		t.Fatalf("InstanceCount=%d after stop-all, want 0", got)
	}
}
