package worker

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCoverage95ServerNoEngineProtocolErrors(t *testing.T) {
	roundTrip := func(t *testing.T, req Envelope) Envelope {
		t.Helper()
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- (&Server{}).Serve(server) }()
		if err := writeFrame(client, req); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		<-done
		return reply
	}
	caps, err := encodePayload(instantiatePayload{Caps: nonListenCaps("wasm")})
	if err != nil {
		t.Fatal(err)
	}
	exec, err := encodePayload(execPayload{Caps: nonListenCaps("wasm")})
	if err != nil {
		t.Fatal(err)
	}
	setCap, err := encodePayload(setCapabilityPayload{Caps: nonListenCaps("wasm")})
	if err != nil {
		t.Fatal(err)
	}
	setPort, err := encodePayload(setListenPortPayload{Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []Envelope{
		{Type: MsgInstantiate, SandboxID: "sb", Payload: caps},
		{Type: MsgExec, SandboxID: "sb", Payload: exec},
		{Type: MsgInvoke, SandboxID: "sb", Payload: []byte(`{"export":"_start"}`)},
		{Type: MsgCheckpoint, SandboxID: "sb", Payload: []byte(`{"out_dir":"/tmp/nope"}`)},
		{Type: MsgSetCapability, SandboxID: "sb", Payload: setCap},
		{Type: MsgSetListenPort, SandboxID: "sb", Payload: setPort},
	} {
		if reply := roundTrip(t, req); reply.Type != MsgError {
			t.Fatalf("%s reply = %s, want error", req.Type, reply.Type)
		}
	}
}

func TestCoverage95SocketServersAcceptConnections(t *testing.T) {
	for name, serve := range map[string]func(string) error{
		"worker":   ServeSocketPath,
		"resident": ServeSocketPathResident,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(os.TempDir(), "aerol-worker-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".sock")
			t.Cleanup(func() { _ = os.Remove(path) })
			go func() { _ = serve(path) }()
			deadline := time.Now().Add(time.Second)
			for {
				if _, err := os.Stat(path); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("socket was not created")
				}
				time.Sleep(time.Millisecond)
			}
			conn, err := net.Dial("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeFrame(conn, Envelope{Type: MsgHealthPing, SandboxID: "sb"}); err != nil {
				t.Fatal(err)
			}
			reply, err := readFrame(conn)
			if err != nil {
				t.Fatal(err)
			}
			if reply.Type != MsgPong {
				t.Fatalf("reply = %s, want pong", reply.Type)
			}
			_ = conn.Close()
		})
	}
}

func TestCoverage95ProtocolDecodeAndLoadErrors(t *testing.T) {
	roundTrip := func(t *testing.T, srv interface{ Serve(net.Conn) error }, req Envelope) Envelope {
		t.Helper()
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- srv.Serve(server) }()
		if err := writeFrame(client, req); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		<-done
		return reply
	}

	for _, srv := range []interface{ Serve(net.Conn) error }{&ResidentServer{}, &Server{}} {
		if reply := roundTrip(t, srv, Envelope{Type: MsgLoadModule, SandboxID: "sb", Payload: []byte(`{`)}); reply.Type != MsgError {
			t.Fatalf("bad load payload reply = %s", reply.Type)
		}
		if reply := roundTrip(t, srv, Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: []byte(`{`)}); reply.Type != MsgError {
			t.Fatalf("bad instantiate payload reply = %s", reply.Type)
		}
		if reply := roundTrip(t, srv, Envelope{Type: MsgExec, SandboxID: "sb", Payload: []byte(`{`)}); reply.Type != MsgError {
			t.Fatalf("bad exec payload reply = %s", reply.Type)
		}
	}

	// Resident: load missing module path, then refuse a second distinct path.
	s := &ResidentServer{}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()
	send := func(req Envelope) Envelope {
		t.Helper()
		if err := writeFrame(client, req); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	missing, err := encodePayload(loadModulePayload{Path: filepath.Join(t.TempDir(), "missing.wasm"), MemoryMB: 16})
	if err != nil {
		t.Fatal(err)
	}
	if reply := send(Envelope{Type: MsgLoadModule, SandboxID: "sb", Payload: missing}); reply.Type != MsgError {
		t.Fatalf("missing module reply = %s", reply.Type)
	}
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "a.wasm")
	okPayload, err := encodePayload(loadModulePayload{Path: mod, MemoryMB: 16})
	if err != nil {
		t.Fatal(err)
	}
	if reply := send(Envelope{Type: MsgLoadModule, SandboxID: "sb", Payload: okPayload}); reply.Type != MsgOK {
		t.Fatalf("load ok reply = %s", reply.Type)
	}
	other, err := encodePayload(loadModulePayload{Path: filepath.Join(dir, "b.wasm"), MemoryMB: 16})
	if err != nil {
		t.Fatal(err)
	}
	if reply := send(Envelope{Type: MsgLoadModule, SandboxID: "sb", Payload: other}); reply.Type != MsgError {
		t.Fatalf("second-path reply = %s", reply.Type)
	}
	listenCaps, err := encodePayload(instantiatePayload{Caps: wasmengine.Capabilities{
		WASIListenHost: "127.0.0.1", WASIListenPort: 8080,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if reply := send(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: listenCaps}); reply.Type != MsgError {
		t.Fatalf("listener reject reply = %s", reply.Type)
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ServerExecStdoutMetering(t *testing.T) {
	s := &Server{eng: &mockEngine{}}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()
	exec, _ := encodePayload(execPayload{Caps: nonListenCaps("wasm"), Export: "_start"})
	_ = writeFrame(client, Envelope{Type: MsgExec, SandboxID: "sb", Payload: exec})
	reply, err := readFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgInvokeResult {
		t.Fatalf("exec reply = %s", reply.Type)
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ServerServeSuccessPaths(t *testing.T) {
	eng := &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{port: 9090}}
	s := &Server{eng: eng}
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

	listenCaps := wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: 0, MemoryMB: 16}
	inst, _ := encodePayload(instantiatePayload{Caps: listenCaps})
	if reply := roundTrip(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: inst}); reply.Type != MsgOK {
		t.Fatalf("instantiate reply = %s", reply.Type)
	}
	exec, _ := encodePayload(execPayload{Caps: listenCaps})
	if reply := roundTrip(Envelope{Type: MsgExec, SandboxID: "sb", Payload: exec}); reply.Type != MsgInvokeResult {
		t.Fatalf("exec reply = %s", reply.Type)
	}
	invoke, _ := encodePayload(invokePayload{})
	if reply := roundTrip(Envelope{Type: MsgInvoke, SandboxID: "sb", Payload: invoke}); reply.Type != MsgOK {
		t.Fatalf("invoke reply = %s", reply.Type)
	}
	setCap, _ := encodePayload(setCapabilityPayload{Caps: wasmengine.Capabilities{MemoryMB: 32, WallTimeoutNs: 1}})
	if reply := roundTrip(Envelope{Type: MsgSetCapability, SandboxID: "sb", Payload: setCap}); reply.Type != MsgOK {
		t.Fatalf("set-cap reply = %s", reply.Type)
	}
	setPort, _ := encodePayload(setListenPortPayload{Port: 8080, Host: "0.0.0.0"})
	if reply := roundTrip(Envelope{Type: MsgSetListenPort, SandboxID: "sb", Payload: setPort}); reply.Type != MsgOK {
		t.Fatalf("set-listen reply = %s", reply.Type)
	}
	if reply := roundTrip(Envelope{Type: MsgListenPort, SandboxID: "sb"}); reply.Type != MsgOK {
		t.Fatalf("listen-port reply = %s", reply.Type)
	}
	snapDir := t.TempDir()
	chk, _ := encodePayload(checkpointPayload{OutDir: snapDir, Meta: wasmengine.SnapshotConfig{}})
	if reply := roundTrip(Envelope{Type: MsgCheckpoint, SandboxID: "sb", Payload: chk}); reply.Type != MsgOK {
		t.Fatalf("checkpoint reply = %s", reply.Type)
	}
	rst, _ := encodePayload(restorePayload{Dir: snapDir, Caps: listenCaps})
	if reply := roundTrip(Envelope{Type: MsgRestore, SandboxID: "sb", Payload: rst}); reply.Type != MsgOK {
		t.Fatalf("restore reply = %s (snapshot dir may be empty)", reply.Type)
	}
	if reply := roundTrip(Envelope{Type: MsgNetstatsTick, SandboxID: " sb "}); reply.Type != MsgOK {
		t.Fatalf("netstats reply = %s", reply.Type)
	}
	if reply := roundTrip(Envelope{Type: MsgStopInstance, SandboxID: "sb"}); reply.Type != MsgOK {
		t.Fatalf("stop reply = %s", reply.Type)
	}
}

func TestCoverage95ServerUnknownMessage(t *testing.T) {
	s := &Server{eng: &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{}}}
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MessageType("unknown")})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgInvokeResult {
		t.Fatalf("unknown reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}

func TestCoverage95ResidentServerFullSession(t *testing.T) {
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	s := &ResidentServer{}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()
	send := func(req Envelope) Envelope {
		t.Helper()
		if err := writeFrame(client, req); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	load, _ := encodePayload(loadModulePayload{Path: mod, MemoryMB: 16})
	caps, _ := encodePayload(instantiatePayload{Caps: nonListenCaps("wasm")})
	exec, _ := encodePayload(execPayload{Caps: nonListenCaps("wasm"), Export: "_start"})
	invoke, _ := encodePayload(invokePayload{Export: "_start"})
	blocks, _ := encodePayload(setNetworkBlocksPayload{BlockEgress: true})
	for _, req := range []Envelope{
		{Type: MsgHealthPing, SandboxID: "host"},
		{Type: MsgInstanceStatus},
		{Type: MsgLoadModule, SandboxID: "host", Payload: load},
		{Type: MsgInstantiate, SandboxID: "sb-full", Payload: caps},
		{Type: MsgInstanceStatus, SandboxID: "sb-full"},
		{Type: MsgExec, SandboxID: "sb-full", Payload: exec},
		{Type: MsgInvoke, SandboxID: "sb-full", Payload: invoke},
		{Type: MsgSetNetworkBlocks, SandboxID: "sb-full", Payload: blocks},
		{Type: MsgNetstatsTick, SandboxID: "sb-full"},
		{Type: MsgStopInstance, SandboxID: "sb-full"},
		{Type: MsgCheckpoint, SandboxID: "sb-full"},
	} {
		reply := send(req)
		if req.Type == MsgHealthPing && reply.Type != MsgPong {
			t.Fatalf("%s reply = %s", req.Type, reply.Type)
		}
		if req.Type == MsgCheckpoint && reply.Type != MsgError {
			t.Fatalf("%s reply = %s", req.Type, reply.Type)
		}
		if req.Type != MsgHealthPing && req.Type != MsgCheckpoint && reply.Type != MsgOK && reply.Type != MsgInvokeResult {
			t.Fatalf("%s reply = %s", req.Type, reply.Type)
		}
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ServerExecRunError(t *testing.T) {
	eng := &successNetworkEngine{
		fakeNetworkAwareEngine: fakeNetworkAwareEngine{},
		runErr:                 errors.New("run failed"),
	}
	s := &Server{eng: eng}
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	exec, _ := encodePayload(execPayload{Caps: wasmengine.Capabilities{MemoryMB: 16}})
	_ = writeFrame(c1, Envelope{Type: MsgExec, SandboxID: "sb", Payload: exec})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgError {
		t.Fatalf("exec run error reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}

func TestCoverage95CodecInvalidFrames(t *testing.T) {
	var zeroLen [4]byte
	if _, err := readFrame(&byteReader{b: zeroLen[:]}); err == nil {
		t.Fatal("expected invalid frame size 0")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 5)
	if _, err := readFrame(&byteReader{b: append(hdr[:], []byte("{bad}")...)}); err == nil {
		t.Fatal("expected json unmarshal error")
	}
	if err := writeFrame(errWriter{}, Envelope{Type: MsgOK, Payload: make([]byte, 0)}); err == nil {
		t.Fatal("expected header write error")
	}
}

type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func TestCoverage95ServerRestoreBadSnapshotDir(t *testing.T) {
	s := &Server{eng: &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{}}}
	rst, _ := encodePayload(restorePayload{Dir: t.TempDir(), Caps: wasmengine.Capabilities{MemoryMB: 16}})
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MsgRestore, SandboxID: "sb", Payload: rst})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgError {
		t.Fatalf("restore reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
}
