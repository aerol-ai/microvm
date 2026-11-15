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

	_, _ = client.LoadModule(sb, wasmPath, 0)

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

// A per-sandbox worker answers for the one sandbox whose instance it holds,
// bound by its first Instantiate: asked about another sandbox it says "not
// loaded" and names the one it holds, and it refuses every message for
// another sandbox, so a socket path that leads to the wrong worker cannot
// drive it. Before it holds an instance (a warm slot), nothing is refused.
func TestServerAnswersOnlyForItsSandbox(t *testing.T) {
	s := &Server{eng: &successNetworkEngine{}}
	roundTrip := func(req Envelope) Envelope {
		t.Helper()
		c1, c2 := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.Serve(c2) }()
		if err := writeFrame(c1, req); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(c1)
		if err != nil {
			t.Fatal(err)
		}
		_ = c1.Close()
		<-done
		return reply
	}
	status := func(id string) instanceStatusPayload {
		t.Helper()
		reply := roundTrip(Envelope{Type: MsgInstanceStatus, SandboxID: id})
		var p instanceStatusPayload
		if reply.Type != MsgOK || decodePayload(reply.Payload, &p) != nil {
			t.Fatalf("status(%q) reply = %+v", id, reply)
		}
		return p
	}
	refused := func(reply Envelope) bool {
		var p errorPayload
		return reply.Type == MsgError && decodePayload(reply.Payload, &p) == nil && p.Message == errForeignSandbox.Error()
	}

	if st := status(""); !st.Loaded || !st.Checked || st.SandboxID != "" {
		t.Fatalf("unbound worker, module question = %+v", st)
	}
	if st := status("sb-a"); st.Loaded || !st.Checked || st.SandboxID != "" {
		t.Fatalf("unbound worker asked about sb-a = %+v, want not loaded", st)
	}
	// A warm slot is driven under its slot id before a sandbox takes it.
	if reply := roundTrip(Envelope{Type: MsgSetNetworkBlocks, SandboxID: "pool-0123456789abcdef", Payload: mustPayload(t, setNetworkBlocksPayload{})}); reply.Type != MsgOK {
		t.Fatalf("unbound worker refused a slot message: %+v", reply)
	}
	inst := mustPayload(t, instantiatePayload{Caps: wasmengine.Capabilities{WASIListenPort: wasmengine.WASIListenPortDisabled}})
	if reply := roundTrip(Envelope{Type: MsgInstantiate, SandboxID: "sb-a", Payload: inst}); reply.Type != MsgOK {
		t.Fatalf("instantiate sb-a = %+v", reply)
	}
	if st := status("sb-a"); !st.Loaded || !st.Checked || st.SandboxID != "sb-a" {
		t.Fatalf("status for its own sandbox = %+v", st)
	}
	if st := status("sb-b"); st.Loaded || !st.Checked || st.SandboxID != "sb-a" {
		t.Fatalf("status for another sandbox = %+v, want not loaded, naming sb-a", st)
	}
	// The client refuses the wrong sandbox too.
	c := NewClient("unused")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() { _ = s.Serve(c2) }()
		return c1, nil
	}
	if loaded, err := c.InstanceLoaded(context.Background(), "sb-b"); err != nil || loaded {
		t.Fatalf("InstanceLoaded(sb-b) = %v, %v", loaded, err)
	}
	if st, err := c.InstanceStatus(context.Background(), "sb-a"); err != nil || !st.Loaded || !st.Checked || st.SandboxID != "sb-a" || st.Foreign("sb-a") || !st.Foreign("sb-b") || st.Foreign("") {
		t.Fatalf("InstanceStatus(sb-a) = %+v, %v", st, err)
	}

	snapDir := t.TempDir()
	if reply := roundTrip(Envelope{Type: MsgCheckpoint, SandboxID: "sb-a", Payload: mustPayload(t, checkpointPayload{OutDir: snapDir})}); reply.Type != MsgOK {
		t.Fatalf("checkpoint sb-a = %+v", reply)
	}
	for _, msg := range []struct {
		typ     MessageType
		payload any
	}{
		{MsgLoadModule, loadModulePayload{Path: "/nowhere.wasm"}},
		{MsgInstantiate, instantiatePayload{}},
		{MsgRestore, restorePayload{Dir: snapDir}},
		{MsgExec, execPayload{}},
		{MsgInvoke, invokePayload{}},
		{MsgStopInstance, nil},
		{MsgCheckpoint, checkpointPayload{OutDir: t.TempDir()}},
		{MsgSetCapability, setCapabilityPayload{}},
		{MsgSetNetworkBlocks, setNetworkBlocksPayload{BlockEgress: true}},
		{MsgSetEgressPolicy, setEgressPolicyPayload{}},
		{MsgEgressLearned, nil},
		{MsgSetListenPort, setListenPortPayload{Port: 8080}},
		{MsgListenPort, nil},
		{MsgProxyHTTP, proxyHTTPPayload{}},
		{MsgNetstatsTick, nil},
	} {
		var body []byte
		if msg.payload != nil {
			body = mustPayload(t, msg.payload)
		}
		for _, id := range []string{"sb-b", " sb-b "} {
			if reply := roundTrip(Envelope{Type: msg.typ, SandboxID: id, Payload: body}); !refused(reply) {
				t.Errorf("%s for %q = %+v, want refused", msg.typ, id, reply)
			}
		}
	}
	// Still bound to sb-a, which is still served; ping is answered for anyone.
	if st := status("sb-a"); !st.Loaded || st.SandboxID != "sb-a" {
		t.Fatalf("after refusals, status = %+v", st)
	}
	if reply := roundTrip(Envelope{Type: MsgNetstatsTick, SandboxID: " sb-a "}); reply.Type != MsgOK {
		t.Fatalf("netstats for its own sandbox = %+v", reply)
	}
	if reply := roundTrip(Envelope{Type: MsgRestore, SandboxID: "sb-a", Payload: mustPayload(t, restorePayload{Dir: snapDir})}); reply.Type != MsgOK {
		t.Fatalf("restore of its own sandbox = %+v", reply)
	}
	if reply := roundTrip(Envelope{Type: MsgHealthPing, SandboxID: "sb-b"}); reply.Type != MsgPong {
		t.Fatalf("ping for another sandbox = %+v", reply)
	}
}

// A worker bound by Restore (a passivated sandbox's wake) holds that
// sandbox as Instantiate would.
func TestServerRestoreBindsItsSandbox(t *testing.T) {
	eng := &successNetworkEngine{}
	snapDir := t.TempDir()
	capture, _ := eng.CaptureSnapshot(context.Background())
	if err := wasmengine.WriteSnapshotDir(snapDir, capture); err != nil {
		t.Fatal(err)
	}
	s := &Server{eng: eng}
	c1, c2 := net.Pipe()
	go func() { _ = s.Serve(c2) }()
	defer c1.Close()
	if err := writeFrame(c1, Envelope{Type: MsgRestore, SandboxID: "sb-r", Payload: mustPayload(t, restorePayload{Dir: snapDir})}); err != nil {
		t.Fatal(err)
	}
	if reply, err := readFrame(c1); err != nil || reply.Type != MsgOK {
		t.Fatalf("restore = %+v, %v", reply, err)
	}
	if got := s.holderID(); got != "sb-r" {
		t.Fatalf("holder after restore = %q", got)
	}
	s.bindHolder("sb-other") // the first binding stays
	if got := s.holderID(); got != "sb-r" {
		t.Fatalf("holder rebound to %q", got)
	}
}

func mustPayload(t *testing.T, v any) []byte {
	t.Helper()
	b, err := encodePayload(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
