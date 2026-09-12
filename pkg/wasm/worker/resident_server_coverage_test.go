package worker

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestAuditBindingResolvers(t *testing.T) {
	s := &Server{}
	if _, ok := s.auditBinding("sb"); ok {
		t.Fatal("empty server had a binding")
	}
	s.setAuditBinding("sb", wasmengine.Capabilities{AuditCapability: "cap", AuditIncarnation: "inc"})
	if b, ok := s.auditBinding("sb"); !ok || b.capability != "cap" || b.incarnationID != "inc" {
		t.Fatalf("server binding = %+v %v", b, ok)
	}
	s.clearAuditBinding("sb")
	if _, ok := s.auditBinding("sb"); ok {
		t.Fatal("cleared server binding still present")
	}

	r := &ResidentServer{}
	if _, ok := r.auditBinding("sb"); ok {
		t.Fatal("empty resident had a binding")
	}
	r.setAuditBinding("sb", wasmengine.Capabilities{AuditCapability: "cap2", AuditIncarnation: "inc2"})
	if b, ok := r.auditBinding("sb"); !ok || b.capability != "cap2" {
		t.Fatalf("resident binding = %+v %v", b, ok)
	}
	r.clearAuditBinding("sb")
}

func TestCoverage95ResidentServerMissingEngineReplies(t *testing.T) {
	s := &ResidentServer{}
	roundTrip := func(t *testing.T, req Envelope) Envelope {
		t.Helper()
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.Serve(server) }()
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
	for _, req := range []Envelope{
		{Type: MsgInstantiate, SandboxID: "sb", Payload: caps},
		{Type: MsgExec, SandboxID: "sb", Payload: []byte(`{"caps":{},"export":"_start"}`)},
		{Type: MsgInvoke, SandboxID: "sb", Payload: []byte(`{"export":"_start"}`)},
	} {
		if reply := roundTrip(t, req); reply.Type != MsgError {
			t.Fatalf("%s reply = %s, want error", req.Type, reply.Type)
		}
	}
}

func TestCoverage95ResidentServerControlMessages(t *testing.T) {
	s := &ResidentServer{}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()

	roundTrip := func(req Envelope) Envelope {
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
	if reply := roundTrip(Envelope{Type: MsgHealthPing, SandboxID: "sb"}); reply.Type != MsgPong {
		t.Fatalf("health reply = %s", reply.Type)
	}
	if reply := roundTrip(Envelope{Type: MsgInstanceStatus, SandboxID: "sb"}); reply.Type != MsgOK {
		t.Fatalf("status reply = %s", reply.Type)
	}
	blocks, err := encodePayload(setNetworkBlocksPayload{BlockIngress: true, BlockEgress: true})
	if err != nil {
		t.Fatal(err)
	}
	if reply := roundTrip(Envelope{Type: MsgSetNetworkBlocks, SandboxID: "sb", Payload: blocks}); reply.Type != MsgOK {
		t.Fatalf("blocks reply = %s", reply.Type)
	}
	if reply := roundTrip(Envelope{Type: MsgNetstatsTick, SandboxID: "sb"}); reply.Type != MsgOK {
		t.Fatalf("netstats reply = %s", reply.Type)
	}
	if reply := roundTrip(Envelope{Type: MsgCheckpoint, SandboxID: "sb"}); reply.Type != MsgError {
		t.Fatalf("unsupported reply = %s", reply.Type)
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ResidentServerInstanceStatusModuleLoaded(t *testing.T) {
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
	load, err := encodePayload(loadModulePayload{Path: mod, MemoryMB: 16})
	if err != nil {
		t.Fatal(err)
	}
	if reply := send(Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: load}); reply.Type != MsgOK {
		t.Fatalf("load reply = %s", reply.Type)
	}
	reply := send(Envelope{Type: MsgInstanceStatus})
	if reply.Type != MsgOK {
		t.Fatalf("status reply = %s", reply.Type)
	}
	var status instanceStatusPayload
	if err := decodePayload(reply.Payload, &status); err != nil {
		t.Fatal(err)
	}
	if !status.Loaded {
		t.Fatal("expected module loaded status")
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ResidentServerNetworkHookEdges(t *testing.T) {
	s := &ResidentServer{}
	s.bindNetworkHook(nil, "sb")
	s.bindNetworkHook(&wasmengine.MultiInstanceEngine{}, "")
	s.clearNetworkHook(nil, "sb")

	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client, _ := serveResident(t)
	if _, err := client.LoadModule("host", mod, 16); err != nil {
		t.Fatal(err)
	}
	caps := nonListenCaps("wasm")
	if err := client.Instantiate("sb-net", caps); err != nil {
		t.Fatal(err)
	}
	if err := client.StopInstance("sb-net"); err != nil {
		t.Fatal(err)
	}
}

func TestCoverage95ResidentServerServeWriteErrors(t *testing.T) {
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	s := &ResidentServer{}
	runServeWithWriteError := func(env Envelope) {
		c1, c2 := net.Pipe()
		go func() {
			_ = writeFrame(c1, env)
			c1.Close()
		}()
		_ = s.Serve(c2)
	}
	caps, _ := encodePayload(instantiatePayload{Caps: nonListenCaps("wasm")})
	exec, _ := encodePayload(execPayload{Caps: nonListenCaps("wasm")})
	invoke, _ := encodePayload(invokePayload{Export: "_start"})
	load, _ := encodePayload(loadModulePayload{Path: mod, MemoryMB: 16})
	runServeWithWriteError(Envelope{Type: MsgHealthPing})
	runServeWithWriteError(Envelope{Type: MsgInstanceStatus, SandboxID: "sb"})
	runServeWithWriteError(Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: load})
	runServeWithWriteError(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: caps})
	runServeWithWriteError(Envelope{Type: MsgExec, SandboxID: "sb", Payload: exec})
	runServeWithWriteError(Envelope{Type: MsgInvoke, SandboxID: "sb", Payload: invoke})
	runServeWithWriteError(Envelope{Type: MsgStopInstance, SandboxID: "sb"})
	runServeWithWriteError(Envelope{Type: MsgNetstatsTick, SandboxID: "sb"})
}

func TestCoverage95ResidentServerEncodeErrors(t *testing.T) {
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		return nil, errors.New("encode failed")
	}
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	load, _ := origEncode(loadModulePayload{Path: mod, MemoryMB: 16})
	caps, _ := origEncode(instantiatePayload{Caps: nonListenCaps("wasm")})
	run := func(req Envelope) {
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- (&ResidentServer{}).Serve(server) }()
		_ = writeFrame(client, req)
		_ = client.Close()
		<-done
	}
	run(Envelope{Type: MsgInstanceStatus, SandboxID: "sb"})
	run(Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: load})
	run(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: caps})
	run(Envelope{Type: MsgNetstatsTick, SandboxID: "sb"})
}

func TestCoverage95ResidentServerLoadAndUnsupportedOps(t *testing.T) {
	s := &ResidentServer{}
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
	badPath := filepath.Join(t.TempDir(), "bad.wasm")
	if err := os.WriteFile(badPath, []byte("not-wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	load, _ := encodePayload(loadModulePayload{Path: badPath, MemoryMB: 16})
	if reply := roundTrip(Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: load}); reply.Type != MsgError {
		t.Fatalf("bad load reply = %s", reply.Type)
	}
	for _, msg := range []Envelope{
		{Type: MsgRestore, SandboxID: "sb"},
		{Type: MsgSetCapability, SandboxID: "sb"},
		{Type: MsgSetListenPort, SandboxID: "sb"},
		{Type: MsgListenPort, SandboxID: "sb"},
		{Type: MsgProxyHTTP, SandboxID: "sb"},
	} {
		if reply := roundTrip(msg); reply.Type != MsgError {
			t.Fatalf("%s reply = %s, want error", msg.Type, reply.Type)
		}
	}
}

func TestCoverage95ResidentServerInstantiateClearsHook(t *testing.T) {
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
	if reply := send(Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: load}); reply.Type != MsgOK {
		t.Fatalf("load = %s", reply.Type)
	}
	if reply := send(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: caps}); reply.Type != MsgOK {
		t.Fatalf("instantiate = %s", reply.Type)
	}
	if reply := send(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: caps}); reply.Type != MsgError {
		t.Fatalf("duplicate instantiate = %s", reply.Type)
	}
	exec, _ := encodePayload(execPayload{Caps: nonListenCaps("wasm"), Export: ""})
	if reply := send(Envelope{Type: MsgExec, SandboxID: "sb", Payload: exec}); reply.Type != MsgInvokeResult {
		t.Fatalf("exec = %s", reply.Type)
	}
	if reply := send(Envelope{Type: MsgInvoke, SandboxID: "sb", Payload: []byte(`{"export":""}`)}); reply.Type != MsgOK {
		t.Fatalf("invoke default export = %s", reply.Type)
	}
	blocks, _ := encodePayload(setNetworkBlocksPayload{BlockIngress: true})
	if reply := send(Envelope{Type: MsgSetNetworkBlocks, SandboxID: "sb", Payload: blocks}); reply.Type != MsgOK {
		t.Fatalf("blocks = %s", reply.Type)
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ResidentServerExecEncodeError(t *testing.T) {
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		if _, ok := v.(execResultPayload); ok {
			return nil, errors.New("exec encode failed")
		}
		return origEncode(v)
	}
	s := &ResidentServer{}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()
	load, _ := origEncode(loadModulePayload{Path: mod, MemoryMB: 16})
	caps, _ := origEncode(instantiatePayload{Caps: nonListenCaps("wasm")})
	exec, _ := origEncode(execPayload{Caps: nonListenCaps("wasm")})
	_ = writeFrame(client, Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: load})
	_, _ = readFrame(client)
	_ = writeFrame(client, Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: caps})
	_, _ = readFrame(client)
	_ = writeFrame(client, Envelope{Type: MsgExec, SandboxID: "sb", Payload: exec})
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("expected serve error from exec encode failure")
	}
}

func TestCoverage95ResidentServerInvokeBadExport(t *testing.T) {
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client, _ := serveResident(t)
	if _, err := client.LoadModule("host", mod, 16); err != nil {
		t.Fatal(err)
	}
	caps := nonListenCaps("wasm")
	if err := client.Instantiate("sb-bad-export", caps); err != nil {
		t.Fatal(err)
	}
	if err := client.Invoke("sb-bad-export", "missing_export"); err == nil {
		t.Fatal("expected invoke error for missing export")
	}
}

func TestCoverage95ResidentServerReplyErrEncodeFailure(t *testing.T) {
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		if _, ok := v.(errorPayload); ok {
			return nil, errors.New("error payload encode failed")
		}
		return origEncode(v)
	}
	s := &ResidentServer{}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()
	_ = writeFrame(client, Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: []byte(`{`)})
	_ = client.Close()
	if err := <-done; err == nil {
		t.Fatal("expected serve error when replyErr encode fails")
	}
}

func TestCoverage95ResidentServerRunErrors(t *testing.T) {
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
	exec, _ := encodePayload(execPayload{Caps: nonListenCaps("wasm")})
	_ = send(Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: load})
	_ = send(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: caps})
	if reply := send(Envelope{Type: MsgExec, SandboxID: "", Payload: exec}); reply.Type != MsgError {
		t.Fatalf("empty sandbox exec = %s", reply.Type)
	}
	if reply := send(Envelope{Type: MsgInvoke, SandboxID: "sb-missing", Payload: []byte(`{"export":"_start"}`)}); reply.Type != MsgError {
		t.Fatalf("missing invoke = %s", reply.Type)
	}
	_ = client.Close()
	<-done
}

func TestCoverage95ResidentServerWriteErrorsOnReplyErr(t *testing.T) {
	s := &ResidentServer{}
	run := func(req Envelope) {
		c1, c2 := net.Pipe()
		go func() {
			_ = writeFrame(c1, req)
			c1.Close()
		}()
		_ = s.Serve(c2)
	}
	run(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: []byte(`{`)})
	run(Envelope{Type: MsgRestore, SandboxID: "sb"})
	run(Envelope{Type: MsgSetNetworkBlocks, SandboxID: "sb", Payload: []byte(`{`)})
	listenCaps, _ := encodePayload(instantiatePayload{Caps: wasmengine.Capabilities{WASIListenPort: 8080}})
	run(Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: listenCaps})
}

func TestCoverage95ResidentServerRefuseSecondModuleWriteError(t *testing.T) {
	dir := t.TempDir()
	a := wasmmod.WriteMinimalWasm(t, dir, "a.wasm")
	b := filepath.Join(dir, "b.wasm")
	if err := os.WriteFile(b, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ResidentServer{}
	loadA, _ := encodePayload(loadModulePayload{Path: a, MemoryMB: 16})
	loadB, _ := encodePayload(loadModulePayload{Path: b, MemoryMB: 16})
	c1, c2 := net.Pipe()
	go func() {
		_ = writeFrame(c1, Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: loadA})
		_, _ = readFrame(c1)
		_ = writeFrame(c1, Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: loadB})
		c1.Close()
	}()
	_ = s.Serve(c2)
}

func TestCoverage95ResidentServerLoadModuleWriteErrorOnReply(t *testing.T) {
	dir := t.TempDir()
	a := wasmmod.WriteMinimalWasm(t, dir, "a.wasm")
	b := filepath.Join(dir, "b.wasm")
	if err := os.WriteFile(b, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ResidentServer{}
	loadA, _ := encodePayload(loadModulePayload{Path: a, MemoryMB: 16})
	loadB, _ := encodePayload(loadModulePayload{Path: b, MemoryMB: 16})
	c1, c2 := net.Pipe()
	go func() {
		_ = writeFrame(c1, Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: loadA})
		_, _ = readFrame(c1)
		_ = writeFrame(c1, Envelope{Type: MsgLoadModule, SandboxID: "host", Payload: loadB})
		_, _ = readFrame(c1)
		c1.Close()
	}()
	_ = s.Serve(c2)
}
