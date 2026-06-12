package worker

import (
	"context"
	"errors"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"net"
	"net/http"
	"testing"
)

type mockEngineError struct{}

func (m *mockEngineError) LoadModule(ctx context.Context, path string) error {
	return errors.New("err")
}
func (m *mockEngineError) Instantiate(ctx context.Context, caps wasmengine.Capabilities) error {
	return errors.New("err")
}
func (m *mockEngineError) Exec(ctx context.Context, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	return wasmengine.RunResult{}, errors.New("err")
}
func (m *mockEngineError) Run(ctx context.Context, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	return wasmengine.RunResult{}, errors.New("err")
}
func (m *mockEngineError) Invoke(ctx context.Context, export string) error { return errors.New("err") }
func (m *mockEngineError) InvokeExport(ctx context.Context, export string) error {
	return errors.New("err")
}
func (m *mockEngineError) Checkpoint(ctx context.Context, outDir string, meta wasmengine.SnapshotConfig) error {
	return errors.New("err")
}
func (m *mockEngineError) CaptureSnapshot(ctx context.Context) (wasmengine.SnapshotCapture, error) {
	return wasmengine.SnapshotCapture{}, errors.New("err")
}
func (m *mockEngineError) RestoreSnapshot(ctx context.Context, input wasmengine.SnapshotRestoreInput, caps wasmengine.Capabilities) error {
	return errors.New("err")
}
func (m *mockEngineError) Restore(ctx context.Context, dir string, caps wasmengine.Capabilities) error {
	return errors.New("err")
}
func (m *mockEngineError) SetCapability(ctx context.Context, caps wasmengine.Capabilities) error {
	return errors.New("err")
}
func (m *mockEngineError) StopInstance(ctx context.Context) error { return errors.New("err") }
func (m *mockEngineError) Close(ctx context.Context) error        { return errors.New("err") }
func (m *mockEngineError) ProxyHTTP(guestPort int, w http.ResponseWriter, r *http.Request) error {
	return errors.New("err")
}
func (m *mockEngineError) SetListenPort(port int, targetHost string) error { return errors.New("err") }
func (m *mockEngineError) ResolvedListenPort() (int, bool)                 { return 0, false }
func (m *mockEngineError) SupportsListen() bool                            { return false }
func (m *mockEngineError) SetNetworkHook(hook *wasmengine.NetworkHook)     {}

func TestServer_Serve_EngineErrors(t *testing.T) {
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		return nil, errors.New("err")
	}

	runServe := func(env Envelope) {
		s := &Server{eng: &mockEngineError{}}
		c1, c2 := net.Pipe()
		go func() {
			_ = writeFrame(c1, env)
			c1.Close()
		}()
		_ = s.Serve(c2)
	}

	p1, _ := origEncode(loadModulePayload{})
	p2, _ := origEncode(instantiatePayload{})
	p3, _ := origEncode(execPayload{})
	p4, _ := origEncode(invokePayload{})
	p5, _ := origEncode(checkpointPayload{})
	p6, _ := origEncode(restorePayload{})
	p7, _ := origEncode(setCapabilityPayload{})
	p9, _ := origEncode(setListenPortPayload{})
	p10, _ := origEncode(proxyHTTPPayload{Method: "GET", RequestURI: "http://localhost"})

	runServe(Envelope{Type: MsgLoadModule, Payload: p1})
	runServe(Envelope{Type: MsgInstantiate, Payload: p2})
	runServe(Envelope{Type: MsgExec, Payload: p3})
	runServe(Envelope{Type: MsgInvoke, Payload: p4})
	runServe(Envelope{Type: MsgCheckpoint, Payload: p5})
	runServe(Envelope{Type: MsgRestore, Payload: p6})
	runServe(Envelope{Type: MsgSetCapability, Payload: p7})
	runServe(Envelope{Type: MsgSetListenPort, Payload: p9})
	runServe(Envelope{Type: MsgListenPort})
	runServe(Envelope{Type: MsgProxyHTTP, Payload: p10})
}
