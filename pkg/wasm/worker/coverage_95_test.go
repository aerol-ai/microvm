package worker

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestCoverage95ProxyRecorderEdges(t *testing.T) {
	r := newLimitedProxyResponseRecorder(2)
	if _, err := r.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if !r.Overflowed() || string(r.Body()) != "ab" {
		t.Fatalf("recorder = overflow:%v body:%q", r.Overflowed(), r.Body())
	}
	if _, err := r.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	if r.StatusCode() != http.StatusOK {
		t.Fatalf("implicit status = %d", r.StatusCode())
	}

	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenPort: wasmengine.WASIListenPortDisabled}}
	if _, err := s.guestHTTPTarget(0); err == nil {
		t.Fatal("disabled guest listener unexpectedly resolved")
	}
	s.lastCaps = wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: 1}
	if _, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{Method: "BAD METHOD", RequestURI: "/"}); err == nil {
		t.Fatal("invalid method unexpectedly succeeded")
	}
}

func TestCoverage95ProxyGuestHTTPFailureAndCounters(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("reply"))
	}))
	defer upstream.Close()
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	_, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: port}}
	req := httptest.NewRequest(http.MethodPost, "http://guest/x", strings.NewReader("request"))
	rec := httptest.NewRecorder()
	if err := s.proxyGuestHTTP(context.Background(), "sb", 0, rec, req); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "reply" {
		t.Fatalf("proxy response = %d %q", rec.Code, rec.Body.String())
	}
	usage := s.netUsageFor("sb")
	if usage.bytesIn.Load() == 0 || usage.bytesOut.Load() == 0 {
		t.Fatalf("proxy bytes were not metered: in=%d out=%d", usage.bytesIn.Load(), usage.bytesOut.Load())
	}
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

func TestCoverage95ServerNetworkHookEdges(t *testing.T) {
	s := &Server{}
	s.bindNetworkHook("sb")
	s.clearNetworkHook()
	s.eng = &mockEngine{}
	s.bindNetworkHook("sb")
	s.clearNetworkHook()
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

func TestCoverage95ReadyPollSleepCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	ReadyPollSleep(ctx, 3)
	if time.Since(start) > 5*time.Millisecond {
		t.Fatalf("canceled context should not sleep")
	}
	ReadyPollSleep(context.Background(), 5)
}

func TestCoverage95NetMediatorDialError(t *testing.T) {
	m := newNetMediator()
	_, err := m.DialContext(context.Background(), "sb", "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected dial error on closed port")
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

func TestCoverage95ProxyHTTPBranches(t *testing.T) {
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: 1}}
	rec := newLimitedProxyResponseRecorder(4)
	req, _ := http.NewRequest(http.MethodGet, "http://guest/big", nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("overflow-body"))
	}))
	defer upstream.Close()
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	_, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s.lastCaps.WASIListenPort = port
	if err := s.proxyGuestHTTP(context.Background(), "sb", 0, rec, req); err != nil {
		t.Fatal(err)
	}
	if !rec.Overflowed() {
		t.Fatal("expected proxy response overflow")
	}
	result, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: http.MethodGet, RequestURI: "/big", GuestPort: port,
	})
	if err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("proxyGuestHTTPFromPayload = %+v, %v", result, err)
	}
	_, err = s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: "\x00", RequestURI: "/",
	})
	if err == nil {
		t.Fatal("expected invalid method error")
	}

	body, err := buildProxyHTTPPayload(0, httptest.NewRequest(http.MethodGet, "http://x/", strings.NewReader("ok")))
	if err != nil || len(body.Body) != 2 {
		t.Fatalf("buildProxyHTTPPayload = %+v, %v", body, err)
	}

	c := NewClient("dummy")
	resultPayload, _ := encodePayload(proxyHTTPResultPayload{StatusCode: 201, Body: []byte("ok")})
	c.dial = mockDialer(t, Envelope{Type: MsgProxyHTTPResult, Payload: resultPayload})
	recorder := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if err := c.ProxyHTTP("sb", 80, recorder, req2); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 201 {
		t.Fatalf("proxy status = %d", recorder.Code)
	}
}

func TestCoverage95SupervisorStartLockedEdges(t *testing.T) {
	s := NewSupervisor(mockSpawner)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Ensure(ctx, "sb-cancel", "/tmp/cancel.sock"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ensure canceled ctx = %v", err)
	}

	s2 := NewSupervisor(mockSpawner)
	s2.mu.Lock()
	err := s2.startLocked(nil, "sb-nil", "/tmp/nil-ctx.sock")
	s2.mu.Unlock()
	if err != nil {
		t.Fatalf("startLocked(nil ctx): %v", err)
	}
	s2.Stop("sb-nil")
}

type successNetworkEngine struct {
	fakeNetworkAwareEngine
	runResult wasmengine.RunResult
	runErr    error
	stopErr   error
}

func (e *successNetworkEngine) Run(ctx context.Context, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	if e.runErr != nil || e.runResult.ExitCode != 0 || e.runResult.Stderr != "" {
		return e.runResult, e.runErr
	}
	return wasmengine.RunResult{Stdout: "stdout", Stderr: "stderr", ExitCode: 0}, nil
}

func (e *successNetworkEngine) StopInstance(ctx context.Context) error {
	return e.stopErr
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

func TestCoverage95BuildProxyHTTPPayloadReadError(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://x/", errReader{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildProxyHTTPPayload(0, req); err == nil {
		t.Fatal("expected body read error")
	}
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

func TestCoverage95ProxyGuestHTTPFromPayloadOverflow(t *testing.T) {
	big := make([]byte, maxProxyHTTPBody+1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer upstream.Close()
	hostPort := strings.TrimPrefix(upstream.URL, "http://")
	_, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: port}}
	_, err = s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: http.MethodGet, RequestURI: "/big", GuestPort: port,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("overflow err = %v", err)
	}
}

func TestCoverage95ClientProxyHTTPDecodeErrors(t *testing.T) {
	c := NewClient("dummy")
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)

	c.dial = mockDialer(t, Envelope{Type: MsgProxyHTTPResult, Payload: []byte(`{`)})
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected decode error")
	}

	c.dial = mockDialer(t, Envelope{Type: MsgHealthPing})
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected unexpected reply type")
	}

	payload, _ := encodePayload(errorPayload{Message: "boom"})
	c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected resolved listen error")
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

func TestCoverage95ServerProxyHTTPSuccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("guest-ok"))
	}))
	defer upstream.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	eng := &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{port: port}}
	s := &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: port}}
	payload, _ := encodePayload(proxyHTTPPayload{Method: http.MethodGet, RequestURI: "/", GuestPort: port})
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MsgProxyHTTP, SandboxID: "sb", Payload: payload})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgProxyHTTPResult {
		t.Fatalf("proxy reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
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

func TestCoverage95ResidentServerEncodeFailures(t *testing.T) {
	dir := t.TempDir()
	mod := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	origEncode := encodePayload
	t.Cleanup(func() { encodePayload = origEncode })

	runUntilEncodeFail := func(match func(any) bool, reqs []Envelope) {
		t.Helper()
		encodePayload = func(v any) ([]byte, error) {
			if match(v) {
				return nil, errors.New("encode failed")
			}
			return origEncode(v)
		}
		s := &ResidentServer{}
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.Serve(server) }()
		for i, req := range reqs {
			if err := writeFrame(client, req); err != nil {
				t.Fatal(err)
			}
			if i < len(reqs)-1 {
				if _, err := readFrame(client); err != nil {
					t.Fatal(err)
				}
			}
		}
		_ = client.Close()
		if err := <-done; err == nil {
			t.Fatal("expected serve error from encode failure")
		}
	}

	load, _ := origEncode(loadModulePayload{Path: mod, MemoryMB: 16})
	caps, _ := origEncode(instantiatePayload{Caps: nonListenCaps("wasm")})
	exec, _ := origEncode(execPayload{Caps: nonListenCaps("wasm")})

	runUntilEncodeFail(
		func(v any) bool { _, ok := v.(instanceStatusPayload); return ok },
		[]Envelope{{Type: MsgInstanceStatus}},
	)
	runUntilEncodeFail(
		func(v any) bool { _, ok := v.(loadModuleResultPayload); return ok },
		[]Envelope{{Type: MsgLoadModule, SandboxID: "host", Payload: load}},
	)
	runUntilEncodeFail(
		func(v any) bool { _, ok := v.(okPayload); return ok },
		[]Envelope{
			{Type: MsgLoadModule, SandboxID: "host", Payload: load},
			{Type: MsgInstantiate, SandboxID: "sb", Payload: caps},
		},
	)
	runUntilEncodeFail(
		func(v any) bool { _, ok := v.(netstatsResultPayload); return ok },
		[]Envelope{{Type: MsgNetstatsTick, SandboxID: "sb"}},
	)
	runUntilEncodeFail(
		func(v any) bool { _, ok := v.(execResultPayload); return ok },
		[]Envelope{
			{Type: MsgLoadModule, SandboxID: "host", Payload: load},
			{Type: MsgInstantiate, SandboxID: "sb", Payload: caps},
			{Type: MsgExec, SandboxID: "sb", Payload: exec},
		},
	)
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

func TestCoverage95ServerEncodeFailures(t *testing.T) {
	origEncode := encodePayload
	t.Cleanup(func() { encodePayload = origEncode })
	eng := &successNetworkEngine{fakeNetworkAwareEngine: fakeNetworkAwareEngine{port: 8080}}

	runUntilEncodeFail := func(match func(any) bool, req Envelope) {
		t.Helper()
		encodePayload = func(v any) ([]byte, error) {
			if match(v) {
				return nil, errors.New("encode failed")
			}
			return origEncode(v)
		}
		s := &Server{eng: eng, lastCaps: wasmengine.Capabilities{WASIListenHost: "127.0.0.1", WASIListenPort: 8080}}
		c1, c2 := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- s.Serve(c2) }()
		_ = writeFrame(c1, req)
		_ = c1.Close()
		if err := <-done; err == nil {
			t.Fatal("expected serve error from encode failure")
		}
	}

	inst, _ := origEncode(instantiatePayload{Caps: wasmengine.Capabilities{MemoryMB: 16}})
	exec, _ := origEncode(execPayload{Caps: wasmengine.Capabilities{MemoryMB: 16}})
	chk, _ := origEncode(checkpointPayload{OutDir: t.TempDir()})

	runUntilEncodeFail(func(v any) bool { _, ok := v.(instanceStatusPayload); return ok }, Envelope{Type: MsgInstanceStatus, SandboxID: "sb"})
	runUntilEncodeFail(func(v any) bool { _, ok := v.(okPayload); return ok }, Envelope{Type: MsgInstantiate, SandboxID: "sb", Payload: inst})
	runUntilEncodeFail(func(v any) bool { _, ok := v.(execResultPayload); return ok }, Envelope{Type: MsgExec, SandboxID: "sb", Payload: exec})
	runUntilEncodeFail(func(v any) bool { _, ok := v.(checkpointResultPayload); return ok }, Envelope{Type: MsgCheckpoint, SandboxID: "sb", Payload: chk})
	runUntilEncodeFail(func(v any) bool { _, ok := v.(listenPortResultPayload); return ok }, Envelope{Type: MsgListenPort, SandboxID: "sb"})
	runUntilEncodeFail(func(v any) bool { _, ok := v.(netstatsResultPayload); return ok }, Envelope{Type: MsgNetstatsTick, SandboxID: "sb"})
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

func TestCoverage95SupervisorStopKillError(t *testing.T) {
	s := NewSupervisor(func(ctx context.Context, socketPath string) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "sleep", "3600"), nil
	})
	if err := s.Ensure(context.Background(), "sb-kill", filepath.Join(t.TempDir(), "x.sock")); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop("sb-kill"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := s.Stop("missing"); err != nil {
		t.Fatalf("Stop missing: %v", err)
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

func TestCoverage95ProxyGuestHTTPFromPayloadTargetError(t *testing.T) {
	s := &Server{lastCaps: wasmengine.Capabilities{WASIListenPort: wasmengine.WASIListenPortDisabled}}
	_, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", proxyHTTPPayload{
		Method: http.MethodGet, RequestURI: "/",
	})
	if err == nil {
		t.Fatal("expected disabled guest listener error")
	}
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

func TestCoverage95ClientInstanceLoadedUnexpectedType(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgHealthPing})
	if _, err := c.InstanceLoaded(context.Background(), "sb"); err == nil {
		t.Fatal("expected unexpected reply type")
	}
}

func TestCoverage95ClientResolvedListenPortDecodeError(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: []byte(`{`)})
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestCoverage95ClientProxyHTTPUnexpectedReply(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgOK})
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected unexpected reply type")
	}
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

func TestCoverage95ServerSetListenPortUnsupportedEngine(t *testing.T) {
	s := &Server{eng: noListenEngine{}}
	setPort, _ := encodePayload(setListenPortPayload{Port: 8080})
	c1, c2 := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(c2) }()
	_ = writeFrame(c1, Envelope{Type: MsgSetListenPort, SandboxID: "sb", Payload: setPort})
	reply, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Type != MsgError {
		t.Fatalf("set listen reply = %s", reply.Type)
	}
	_ = c1.Close()
	<-done
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

func TestCoverage95ClientErrorReplyDecodeFailures(t *testing.T) {
	c := NewClient("dummy")
	bad := Envelope{Type: MsgError, Payload: []byte(`{`)}
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)

	c.dial = mockDialer(t, bad)
	if _, err := c.ResolvedListenPort("sb"); err == nil {
		t.Fatal("expected ResolvedListenPort error payload decode failure")
	}

	c.dial = mockDialer(t, bad)
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected ProxyHTTP error payload decode failure")
	}
}

func TestCoverage95ProxyHTTPEncodeFailure(t *testing.T) {
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		if _, ok := v.(proxyHTTPPayload); ok {
			return nil, errors.New("encode proxy payload failed")
		}
		return origEncode(v)
	}
	c := NewClient("dummy")
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if err := c.ProxyHTTP("sb", 80, httptest.NewRecorder(), req); err == nil {
		t.Fatal("expected ProxyHTTP encode failure")
	}
}
