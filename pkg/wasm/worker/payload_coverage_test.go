package worker

import (
	"errors"
	"net"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

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
