package worker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCoverage95ClientTransportFailures(t *testing.T) {
	boom := errors.New("dial failed")
	c := NewClient("unused")
	c.dial = func(string) (net.Conn, error) { return nil, boom }
	if err := c.Ping("sb"); !errors.Is(err, boom) {
		t.Fatalf("Ping error = %v, want dial error", err)
	}
	if _, err := c.InstanceLoaded(context.Background(), "sb"); !errors.Is(err, boom) {
		t.Fatalf("InstanceLoaded error = %v, want dial error", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.InstanceLoaded(ctx, "sb"); !errors.Is(err, context.Canceled) {
		t.Fatalf("InstanceLoaded canceled error = %v", err)
	}
}

func TestCoverage95ResidentLifecycleProtocol(t *testing.T) {
	dir := t.TempDir()
	module := wasmmod.WriteMinimalWasm(t, dir, "lifecycle.wasm")
	client, _ := serveResident(t)
	if _, err := client.LoadModule("host", module, 16); err != nil {
		t.Fatal(err)
	}
	loaded, err := client.InstanceLoaded(context.Background(), "sb")
	if err != nil || loaded {
		t.Fatalf("pre-instantiate loaded = %v, %v", loaded, err)
	}
	caps := nonListenCaps("wasm")
	if err := client.Instantiate("sb", caps); err != nil {
		t.Fatal(err)
	}
	loaded, err = client.InstanceLoaded(context.Background(), "sb")
	if err != nil || !loaded {
		t.Fatalf("post-instantiate loaded = %v, %v", loaded, err)
	}
	if err := client.Invoke("sb", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.StopInstance("sb"); err != nil {
		t.Fatal(err)
	}
}

func TestCoverage95ResidentServerServeBranches(t *testing.T) {
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client, _ := serveResident(t)

	loaded, err := client.InstanceLoaded(context.Background(), "host")
	if err != nil || loaded {
		t.Fatalf("pre-load InstanceLoaded = %v, %v", loaded, err)
	}
	if _, err := client.LoadModule("host", mod, 16); err != nil {
		t.Fatal(err)
	}
	// InstanceStatus with a sandboxID checks HasInstance, not module load.
	loaded, err = client.InstanceLoaded(context.Background(), "host")
	if err != nil || loaded {
		t.Fatalf("post-load without instance = %v, %v", loaded, err)
	}
	if _, err := client.LoadModule("host", mod, 16); err != nil {
		t.Fatalf("reload same module: %v", err)
	}

	caps := nonListenCaps("wasm")
	if err := client.Instantiate("sb-dup", caps); err != nil {
		t.Fatal(err)
	}
	if err := client.Instantiate("sb-dup", caps); err == nil {
		t.Fatal("expected duplicate instantiate error")
	}
	loaded, err = client.InstanceLoaded(context.Background(), "sb-dup")
	if err != nil || !loaded {
		t.Fatalf("post-instantiate InstanceLoaded = %v, %v", loaded, err)
	}
	if err := client.Invoke("sb-missing", "_start"); err == nil {
		t.Fatal("expected invoke error on missing instance")
	}
	res, err := client.Exec("sb-exec", caps, "_start")
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("Exec new sandbox = %+v, %v", res, err)
	}
	if err := client.Restore("sb-dup", dir, caps); err == nil {
		t.Fatal("expected restore unsupported")
	}
	if err := client.SetCapability("sb-dup", caps); err == nil {
		t.Fatal("expected set-capability unsupported")
	}
	if err := client.StopInstance("sb-dup"); err != nil {
		t.Fatal(err)
	}
}

func TestCoverage95ClientDecodeAndReplyErrors(t *testing.T) {
	c := NewClient("dummy")
	sb := "sb"

	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: []byte(`{`)})
	if _, err := c.InstanceLoaded(context.Background(), sb); err == nil {
		t.Fatal("expected InstanceLoaded decode error")
	}

	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: []byte(`{`)})
	if _, err := c.Exec(sb, nonListenCaps("wasm"), "_start"); err == nil {
		t.Fatal("expected Exec error decode failure")
	}

	c.dial = mockDialer(t, Envelope{Type: MsgInvokeResult})
	if _, err := c.Exec(sb, nonListenCaps("wasm"), "_start"); err == nil {
		t.Fatal("expected Exec unexpected reply type")
	}

	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: []byte(`{`)})
	if _, _, err := c.NetstatsTick(sb); err == nil {
		t.Fatal("expected NetstatsTick error decode failure")
	}

	c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: []byte(`{`)})
	if _, _, err := c.NetstatsTick(sb); err == nil {
		t.Fatal("expected NetstatsTick result decode failure")
	}

	if err := c.expectOK(Envelope{Type: MsgError, Payload: []byte(`{`)}); err == nil {
		t.Fatal("expected expectOK decode error")
	}

	c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: []byte(`not-json`)})
	if _, err := c.InstanceLoaded(context.Background(), sb); err == nil {
		t.Fatal("expected InstanceLoaded status decode error")
	}
}

func TestCoverage95ServerStopInstanceError(t *testing.T) {
	eng := &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{}, stopErr: errors.New("stop failed")}
	s := &Server{eng: eng}
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MsgStopInstance, SandboxID: "sb"})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgError {
		t.Fatalf("stop error reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}

func TestCoverage95RoundTripContextSlowDialCleanup(t *testing.T) {
	c := NewClient("dummy")
	block := make(chan struct{})
	c.dial = func(string) (net.Conn, error) {
		<-block
		return nil, errors.New("too late")
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := c.roundTripContext(ctx, Envelope{Type: MsgHealthPing})
		errCh <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	close(block)
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("roundTripContext = %v, want canceled", err)
	}
}

func TestCoverage95ClientRoundTripWriteError(t *testing.T) {
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c1.Close()
		return c2, nil
	}
	if err := c.Ping("sb"); err == nil {
		t.Fatal("expected write error")
	}
}

func TestCoverage95RoundTripContextIOErrors(t *testing.T) {
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = readFrame(c1)
			_ = c1.Close()
		}()
		return c2, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.roundTripContext(ctx, Envelope{Type: MsgHealthPing}); err == nil {
		t.Fatal("expected read error")
	}
}

func TestCoverage95RoundTripContextDialAfterCancel(t *testing.T) {
	c := NewClient("dummy")
	block := make(chan struct{})
	c.dial = func(string) (net.Conn, error) {
		<-block
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := c.roundTripContext(ctx, Envelope{Type: MsgHealthPing})
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	close(block)
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestCoverage95ServerLoadModuleSuccessTimings(t *testing.T) {
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	s := &Server{}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()
	load, _ := encodePayload(loadModulePayload{Path: mod, MemoryMB: 16})
	_ = writeFrame(client, Envelope{Type: MsgLoadModule, SandboxID: "sb", Payload: load})
	reply, err := readFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgOK {
		t.Fatalf("load reply = %s", reply.Type)
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ClientInstanceLoadedErrorMessage(t *testing.T) {
	c := NewClient("dummy")
	payload, _ := encodePayload(errorPayload{Message: "not loaded"})
	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
	if _, err := c.InstanceLoaded(context.Background(), "sb"); err == nil || err.Error() != "not loaded" {
		t.Fatalf("InstanceLoaded err = %v", err)
	}
}

func TestCoverage95ClientNetstatsUnexpectedType(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgHealthPing})
	if _, _, err := c.NetstatsTick("sb"); err == nil {
		t.Fatal("expected unexpected reply type")
	}
}

func TestCoverage95ServerLoadModuleEngineError(t *testing.T) {
	old := os.Getenv("AEROL_WASM_ENGINE")
	t.Cleanup(func() { _ = os.Setenv("AEROL_WASM_ENGINE", old) })
	_ = os.Setenv("AEROL_WASM_ENGINE", "not-a-real-engine")
	s := &Server{}
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	load, _ := encodePayload(loadModulePayload{Path: "x.wasm", MemoryMB: 16})
	_ = writeFrame(c1, Envelope{Type: MsgLoadModule, SandboxID: "sb", Payload: load})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgError {
		t.Fatalf("load reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}

func TestCoverage95RoundTripContextWriteAfterDial(t *testing.T) {
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = readFrame(c1)
			_ = c1.Close()
		}()
		return c2, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.roundTripContext(ctx, Envelope{Type: MsgHealthPing}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestCoverage95ClientInstanceLoadedUnexpectedType(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgHealthPing})
	if _, err := c.InstanceLoaded(context.Background(), "sb"); err == nil {
		t.Fatal("expected unexpected reply type")
	}
}

func TestCoverage95ServerCheckpointWriteSnapshotError(t *testing.T) {
	eng := &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{}}
	s := &Server{eng: eng}
	chk, _ := encodePayload(checkpointPayload{OutDir: filepath.Join("/no", "such", "checkpoint", "dir"), Meta: wasmengine.SnapshotConfig{}})
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MsgCheckpoint, SandboxID: "sb", Payload: chk})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgError {
		t.Fatalf("checkpoint reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}
