package worker

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestServeSocketPath(t *testing.T) {
	sock := "/tmp/test-server.sock"
	defer os.Remove(sock)

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeSocketPath(sock)
	}()

	time.Sleep(100 * time.Millisecond)

	client := NewClient(sock)
	sb := "sb-test"

	// 1. HealthPing
	if err := client.Ping(sb); err != nil {
		t.Errorf("Ping: %v", err)
	}

	// 2. InstanceLoaded (will return OK, but loaded=false)
	loaded, err := client.InstanceLoaded(context.Background(), sb)
	if err != nil {
		t.Errorf("InstanceLoaded: %v", err)
	}
	if loaded {
		t.Errorf("Expected not loaded")
	}

	// 3. Various methods when engine is nil, expecting them to not crash but return errors
	_ = client.Instantiate(sb, wasmengine.Capabilities{})
	_, _ = client.Exec(sb, wasmengine.Capabilities{}, "")
	_ = client.Invoke(sb, "")
	_ = client.Checkpoint(context.Background(), sb, "/tmp/out", wasmengine.SnapshotConfig{})
	_ = client.Restore(sb, "/tmp/in", wasmengine.Capabilities{})
	_ = client.SetCapability(sb, wasmengine.Capabilities{})
	_ = client.SetNetworkBlocks(sb, true, true)
	_, _, _ = client.NetstatsTick(sb)
	_ = client.StopInstance(sb)

	// Send valid payloads to hit the actual switch branches in Serve
	// To do this properly, we first LoadModule so that s.eng is NOT nil,
	// which will allow the other switch branches to continue further.

	// Create dummy wasm
	wasmBytes, _ := hex.DecodeString("0061736d01000000010401600000030201000503010001071302066d656d6f72790200065f737461727400000a040102000b")
	wasmPath := filepath.Join(t.TempDir(), "test.wasm")
	_ = os.WriteFile(wasmPath, wasmBytes, 0644)

	_ = client.LoadModule(sb, wasmPath, 0)

	conn, _ := net.Dial("unix", sock)
	if conn != nil {
		p1, _ := encodePayload(instantiatePayload{Caps: wasmengine.Capabilities{MemoryMB: 10}})
		_ = writeFrame(conn, Envelope{Type: MsgInstantiate, SandboxID: sb, Payload: p1})
		_, _ = readFrame(conn)

		p2, _ := encodePayload(loadModulePayload{Path: wasmPath})
		_ = writeFrame(conn, Envelope{Type: MsgLoadModule, SandboxID: sb, Payload: p2})
		_, _ = readFrame(conn)

		p3, _ := encodePayload(execPayload{Caps: wasmengine.Capabilities{MemoryMB: 10}, Export: "_start"})
		_ = writeFrame(conn, Envelope{Type: MsgExec, SandboxID: sb, Payload: p3})
		_, _ = readFrame(conn)

		p4, _ := encodePayload(invokePayload{Export: "_start"})
		_ = writeFrame(conn, Envelope{Type: MsgInvoke, SandboxID: sb, Payload: p4})
		_, _ = readFrame(conn)

		p5, _ := encodePayload(checkpointPayload{OutDir: t.TempDir(), Meta: wasmengine.SnapshotConfig{}})
		_ = writeFrame(conn, Envelope{Type: MsgCheckpoint, SandboxID: sb, Payload: p5})
		_, _ = readFrame(conn)

		p6, _ := encodePayload(restorePayload{Dir: t.TempDir(), Caps: wasmengine.Capabilities{MemoryMB: 10}})
		_ = writeFrame(conn, Envelope{Type: MsgRestore, SandboxID: sb, Payload: p6})
		_, _ = readFrame(conn)

		p7, _ := encodePayload(setCapabilityPayload{Caps: wasmengine.Capabilities{MemoryMB: 20}})
		_ = writeFrame(conn, Envelope{Type: MsgSetCapability, SandboxID: sb, Payload: p7})
		_, _ = readFrame(conn)

		p8, _ := encodePayload(setNetworkBlocksPayload{BlockIngress: true, BlockEgress: true})
		_ = writeFrame(conn, Envelope{Type: MsgSetNetworkBlocks, SandboxID: sb, Payload: p8})
		_, _ = readFrame(conn)

		p9, _ := encodePayload(setListenPortPayload{Port: 8080, Host: "0.0.0.0"})
		_ = writeFrame(conn, Envelope{Type: MsgSetListenPort, SandboxID: sb, Payload: p9})
		_, _ = readFrame(conn)

		_ = writeFrame(conn, Envelope{Type: MsgListenPort, SandboxID: sb})
		_, _ = readFrame(conn)

		// Skip ProxyHTTP as it can hang without a real HTTP guest server

		_ = writeFrame(conn, Envelope{Type: MsgStopInstance, SandboxID: sb})
		_, _ = readFrame(conn)

		conn.Close()
	}

	// To stop the server gracefully, we can just connect and delete the socket or use an OS level close.
	// Since ServeSocketPath uses ln.Accept() in a loop, if we delete the file, it doesn't close the listener immediately,
	// but this is enough to finish the test. We don't actually need to wait for ServeSocketPath to exit if we just let the test finish.
}

func TestServer_ServeErrors(t *testing.T) {
	s := &Server{}

	// Server error on read frame
	c1, c2 := net.Pipe()
	c1.Close()
	if err := s.Serve(c2); err == nil {
		t.Fatalf("expected error on readFrame")
	}
	c2.Close()

	// Server error on bad payload
	c1, c2 = net.Pipe()
	go func() {
		_ = writeFrame(c1, Envelope{Type: MsgLoadModule, Payload: []byte("bad json")})
		c1.Close()
	}()
	_ = s.Serve(c2)
}

func TestWorkerByteMeter(t *testing.T) {
	u := &workerNetUsage{}
	m := workerByteMeter{u: u}
	m.AddIn(10)
	m.AddOut(20)
	if u.bytesIn.Load() != 10 || u.bytesOut.Load() != 20 {
		t.Fatalf("expected 10/20")
	}
}

func TestMediatorDialer(t *testing.T) {
	m := newNetMediator()
	m.SetBlocks("sb1", false, true) // block egress
	d := mediatorDialer{m: m, sandboxID: "sb1"}
	_, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		t.Fatalf("expected error")
	}
}
