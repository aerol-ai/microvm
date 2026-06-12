package worker

import (
	"net/http/httptest"

	"context"
	"errors"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"net"
	"testing"
)

func TestClient_EncodeDecodeErrors(t *testing.T) {
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = readFrame(c1)
			_ = writeFrame(c1, Envelope{Type: MsgOK, SandboxID: "sb", Payload: []byte("{}")})
			c1.Close()
		}()
		return c2, nil
	}

	ctx := context.Background()
	sb := "sb"

	// Mock encodePayload
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		return nil, errors.New("mock encode error")
	}

	_ = c.LoadModule(sb, "path")
	_ = c.Instantiate(sb, wasmengine.Capabilities{})
	_, _ = c.Exec(sb, wasmengine.Capabilities{}, "")
	_ = c.Invoke(sb, "")
	_ = c.Checkpoint(ctx, sb, "", wasmengine.SnapshotConfig{})
	_ = c.Restore(sb, "", wasmengine.Capabilities{})
	_ = c.SetCapability(sb, wasmengine.Capabilities{})
	_ = c.SetNetworkBlocks(sb, true, true)
	_ = c.TriggerPanic("sb")
	_, _, _ = c.NetstatsTick("sb")
	_ = c.SetListenPort("sb", 80, "localhost")
	_ = c.ProxyHTTP("sb", 80, httptest.NewRecorder(), httptest.NewRequest("GET", "http://x", nil))

	// Mock decodePayload
	encodePayload = origEncode
	origDecode := decodePayload
	defer func() { decodePayload = origDecode }()
	decodePayload = func(b []byte, v any) error {
		return errors.New("mock decode error")
	}

	_, _ = c.InstanceLoaded(ctx, sb)
	_, _ = c.Exec(sb, wasmengine.Capabilities{}, "")
	_, _, _ = c.NetstatsTick(sb)
	_, _ = c.ResolvedListenPort(sb)
}
