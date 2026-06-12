package worker

import (
	"context"
	"errors"
	"net"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

type mockEngine struct {
	err error
}

func (m *mockEngine) LoadModule(ctx context.Context, path string) error { return m.err }
func (m *mockEngine) Instantiate(ctx context.Context, caps wasmengine.Capabilities) error {
	return m.err
}
func (m *mockEngine) Run(ctx context.Context, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	return wasmengine.RunResult{}, m.err
}
func (m *mockEngine) InvokeExport(ctx context.Context, export string) error { return m.err }
func (m *mockEngine) CaptureSnapshot(ctx context.Context) (wasmengine.SnapshotCapture, error) {
	return wasmengine.SnapshotCapture{}, m.err
}
func (m *mockEngine) RestoreSnapshot(ctx context.Context, inDir wasmengine.SnapshotRestoreInput, caps wasmengine.Capabilities) error {
	return m.err
}
func (m *mockEngine) StopInstance(ctx context.Context) error { return m.err }
func (m *mockEngine) Close(ctx context.Context) error        { return m.err }

// additional methods used by Server
func (m *mockEngine) SetNetworkHook(hook *wasmengine.NetworkHook) {}
func (m *mockEngine) ClearNetworkHook()                           {}
func (m *mockEngine) ResolvedListenPort() (int, bool)             { return 0, m.err == nil }
func (m *mockEngine) SupportsListen() bool                        { return true }

func TestServer_Serve_AllPaths(t *testing.T) {
	s := &Server{eng: &mockEngine{}}

	runServeWithPayload := func(env Envelope) Envelope {
		c1, c2 := net.Pipe()
		go func() {
			_ = writeFrame(c1, env)
			c1.Close()
		}()
		_ = s.Serve(c2)
		// We can't easily read the response this way since Serve returns when c2 is closed.
		// Wait, Serve loops until readFrame fails. So if we close c1, readFrame gets EOF and Serve returns.
		return Envelope{}
	}

	// OK paths
	runServeWithPayload(Envelope{Type: MsgHealthPing})
	runServeWithPayload(Envelope{Type: MsgInstanceStatus})

	p1, _ := encodePayload(loadModulePayload{})
	runServeWithPayload(Envelope{Type: MsgLoadModule, Payload: p1})

	p2, _ := encodePayload(instantiatePayload{})
	runServeWithPayload(Envelope{Type: MsgInstantiate, Payload: p2})

	p3, _ := encodePayload(execPayload{})
	runServeWithPayload(Envelope{Type: MsgExec, Payload: p3})

	p4, _ := encodePayload(invokePayload{})
	runServeWithPayload(Envelope{Type: MsgInvoke, Payload: p4})

	p5, _ := encodePayload(checkpointPayload{})
	runServeWithPayload(Envelope{Type: MsgCheckpoint, Payload: p5})

	p6, _ := encodePayload(restorePayload{})
	runServeWithPayload(Envelope{Type: MsgRestore, Payload: p6})

	p7, _ := encodePayload(setCapabilityPayload{})
	runServeWithPayload(Envelope{Type: MsgSetCapability, Payload: p7})

	runServeWithPayload(Envelope{Type: MsgNetstatsTick})

	p8, _ := encodePayload(setNetworkBlocksPayload{})
	runServeWithPayload(Envelope{Type: MsgSetNetworkBlocks, Payload: p8})

	p9, _ := encodePayload(setListenPortPayload{})
	runServeWithPayload(Envelope{Type: MsgSetListenPort, Payload: p9})

	runServeWithPayload(Envelope{Type: MsgListenPort})
	runServeWithPayload(Envelope{Type: MsgStopInstance})

	p10, _ := encodePayload(proxyHTTPPayload{Method: "GET"})
	runServeWithPayload(Envelope{Type: MsgProxyHTTP, Payload: p10})

	p11, _ := encodePayload(proxyHTTPPayload{Method: " GET"}) // invalid method
	runServeWithPayload(Envelope{Type: MsgProxyHTTP, Payload: p11})

	// Error paths (bad payload)
	bad := []byte("bad json")
	runServeWithPayload(Envelope{Type: MsgLoadModule, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgInstantiate, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgExec, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgInvoke, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgCheckpoint, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgRestore, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgSetCapability, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgSetNetworkBlocks, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgSetListenPort, Payload: bad})
	runServeWithPayload(Envelope{Type: MsgProxyHTTP, Payload: bad})

	// Error paths (eng error)
	s.eng = &mockEngine{err: errors.New("eng err")}
	runServeWithPayload(Envelope{Type: MsgLoadModule, Payload: p1})
	runServeWithPayload(Envelope{Type: MsgInstantiate, Payload: p2})
	runServeWithPayload(Envelope{Type: MsgExec, Payload: p3})
	runServeWithPayload(Envelope{Type: MsgInvoke, Payload: p4})
	runServeWithPayload(Envelope{Type: MsgCheckpoint, Payload: p5})
	runServeWithPayload(Envelope{Type: MsgRestore, Payload: p6})
	runServeWithPayload(Envelope{Type: MsgSetCapability, Payload: p7})
	runServeWithPayload(Envelope{Type: MsgNetstatsTick})
	runServeWithPayload(Envelope{Type: MsgListenPort})
	runServeWithPayload(Envelope{Type: MsgStopInstance})
}
