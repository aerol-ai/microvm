package worker

import (
	"net/http/httptest"

	"context"
	"net"
	"net/http"
	"testing"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestClient_ConnectionClosed_AllMethods(t *testing.T) {
	client := NewClient("/does/not/exist.sock")

	ctx := context.Background()
	sb := "sb"

	if _, err := client.LoadModule(sb, "path", 0); err == nil {
		t.Error("expected error")
	}
	if err := client.Instantiate(sb, wasmengine.Capabilities{}); err == nil {
		t.Error("expected error")
	}
	if _, err := client.Exec(sb, wasmengine.Capabilities{}, ""); err == nil {
		t.Error("expected error")
	}
	if err := client.Invoke(sb, ""); err == nil {
		t.Error("expected error")
	}
	if err := client.Checkpoint(ctx, sb, "", wasmengine.SnapshotConfig{}); err == nil {
		t.Error("expected error")
	}
	if err := client.Restore(sb, "", wasmengine.Capabilities{}); err == nil {
		t.Error("expected error")
	}
	if err := client.SetCapability(sb, wasmengine.Capabilities{}); err == nil {
		t.Error("expected error")
	}
	if _, _, err := client.NetstatsTick(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.SetNetworkBlocks(sb, true, true); err == nil {
		t.Error("expected error")
	}
	if _, err := client.InstanceLoaded(ctx, sb); err == nil {
		t.Error("expected error")
	}
	if err := client.Ping(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.StopInstance(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.TriggerPanic(sb); err == nil {
		t.Error("expected error")
	}
	if err := client.SetListenPort(sb, 80, ""); err == nil {
		t.Error("expected error")
	}
	if _, err := client.ResolvedListenPort(sb); err == nil {
		t.Error("expected error")
	}
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	if err := client.ProxyHTTP(sb, 80, nil, req); err == nil {
		t.Error("expected error")
	}
}

func TestClient_MockSuccess(t *testing.T) {
	sb := "sb"
	c := NewClient("dummy")

	// SetListenPort
	c.dial = mockDialer(t, Envelope{Type: MsgOK})
	if err := c.SetListenPort(sb, 80, ""); err != nil {
		t.Error(err)
	}

	// ResolvedListenPort
	payload, _ := encodePayload(listenPortResultPayload{Port: 8080})
	c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: payload})
	if _, err := c.ResolvedListenPort(sb); err != nil {
		t.Error(err)
	}

	// ProxyHTTP
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	resultPayload, _ := encodePayload(proxyHTTPResultPayload{StatusCode: 200})
	c.dial = mockDialer(t, Envelope{Type: MsgProxyHTTPResult, Payload: resultPayload})
	if err := c.ProxyHTTP(sb, 80, newLimitedProxyResponseRecorder(100), req); err != nil {
		t.Error(err)
	}
}

func TestClient_MockError(t *testing.T) {
	sb := "sb"
	c := NewClient("dummy")

	errPayload, _ := encodePayload(errorPayload{Message: "boom"})
	errEnv := Envelope{Type: MsgError, Payload: errPayload}

	c.dial = mockDialer(t, errEnv)
	if err := c.SetListenPort(sb, 80, ""); err == nil {
		t.Error("expected err")
	}

	c.dial = mockDialer(t, errEnv)
	if _, err := c.ResolvedListenPort(sb); err == nil {
		t.Error("expected err")
	}

	req, _ := http.NewRequest("GET", "http://localhost", nil)
	c.dial = mockDialer(t, errEnv)
	if err := c.ProxyHTTP(sb, 80, newLimitedProxyResponseRecorder(100), req); err == nil {
		t.Error("expected err")
	}

	// Unexpected type
	c.dial = mockDialer(t, Envelope{Type: MsgOK})
	if err := c.ProxyHTTP(sb, 80, newLimitedProxyResponseRecorder(100), req); err == nil {
		t.Error("expected err")
	}
	c.dial = mockDialer(t, Envelope{Type: MsgHealthPing})
	if _, err := c.ResolvedListenPort(sb); err == nil {
		t.Error("expected err")
	}

	// Test decodePayload empty error
	c.dial = mockDialer(t, Envelope{Type: MsgProxyHTTPResult, Payload: nil})
	if err := c.ProxyHTTP(sb, 80, newLimitedProxyResponseRecorder(100), req); err == nil {
		t.Error("expected err empty")
	}
}

func TestClient_ContextErrors(t *testing.T) {
	c := NewClient("dummy")

	// Test Dial error
	c.dial = func(string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}
	if _, err := c.InstanceLoaded(context.Background(), "sb"); err == nil {
		t.Error("expected dial error")
	}

	// Test canceled context before read
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() { _ = c1.Close() }()
		return c2, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	if _, err := c.InstanceLoaded(ctx, "sb"); err == nil {
		t.Error("expected error on canceled context")
	}
}
func TestClient_AllMethods_Success(t *testing.T) {
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			env, _ := readFrame(c1)
			var payload []byte
			switch env.Type {
			case MsgExec:
				payload, _ = encodePayload(execResultPayload{})
			case MsgNetstatsTick:
				payload, _ = encodePayload(netstatsResultPayload{})
			default:
				payload = []byte("{}")
			}
			_ = writeFrame(c1, Envelope{Type: MsgOK, SandboxID: "sb", Payload: payload})
			c1.Close()
		}()
		return c2, nil
	}

	ctx := context.Background()
	_, _ = c.LoadModule("sb", "path", 0)
	_ = c.Instantiate("sb", wasmengine.Capabilities{})
	_, _ = c.Exec("sb", wasmengine.Capabilities{}, "export")
	_ = c.Invoke("sb", "export")
	_ = c.Checkpoint(ctx, "sb", "out", wasmengine.SnapshotConfig{})
	_ = c.Restore("sb", "dir", wasmengine.Capabilities{})
	_ = c.SetCapability("sb", wasmengine.Capabilities{})
	_, _, _ = c.NetstatsTick("sb")
	_ = c.SetNetworkBlocks("sb", true, true)
}

func TestClient_AllMethods_Error(t *testing.T) {
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = readFrame(c1)
			p, _ := encodePayload(errorPayload{Message: "mock err"})
			_ = writeFrame(c1, Envelope{Type: MsgError, SandboxID: "sb", Payload: p})
			c1.Close()
		}()
		return c2, nil
	}

	ctx := context.Background()
	_, _ = c.LoadModule("sb", "path", 0)
	_ = c.Instantiate("sb", wasmengine.Capabilities{})
	_, _ = c.Exec("sb", wasmengine.Capabilities{}, "export")
	_ = c.Invoke("sb", "export")
	_ = c.Checkpoint(ctx, "sb", "out", wasmengine.SnapshotConfig{})
	_ = c.Restore("sb", "dir", wasmengine.Capabilities{})
	_ = c.SetCapability("sb", wasmengine.Capabilities{})
	_, _, _ = c.NetstatsTick("sb")
	_ = c.SetNetworkBlocks("sb", true, true)
}

func TestClient_RemainingMethods(t *testing.T) {
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

	_ = c.Ping("sb")
	_ = c.StopInstance("sb")
	_ = c.TriggerPanic("sb")
	_, _ = c.InstanceLoaded(context.Background(), "sb")
	_ = c.SetListenPort("sb", 80, "localhost")
	_ = c.ProxyHTTP("sb", 80, httptest.NewRecorder(), httptest.NewRequest("GET", "http://x", nil))
}

type unblockableConn struct {
	net.Conn
	ch chan struct{}
}

func (c *unblockableConn) Read(b []byte) (int, error) {
	<-c.ch
	return 0, net.ErrClosed
}

func (c *unblockableConn) Write(b []byte) (int, error) {
	<-c.ch
	return 0, net.ErrClosed
}

func (c *unblockableConn) Close() error {
	close(c.ch)
	return c.Conn.Close()
}

func TestClient_ContextErrors_Blocks(t *testing.T) {
	c := NewClient("dummy")

	// Test block write
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() { _ = c1.Close() }()
		return &unblockableConn{Conn: c2, ch: make(chan struct{})}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = c.InstanceLoaded(ctx, "sb")

	// Test block read
	c.dial = func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			_, _ = readFrame(c1)
		}()
		// Create a connection that allows one write but blocks on read
		return &unblockableConn{Conn: c2, ch: make(chan struct{})}, nil
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, _ = c.InstanceLoaded(ctx2, "sb")
}

func TestClient_RoundTripContext_Canceled(t *testing.T) {
	c1, c2 := net.Pipe()
	c1.Close()
	c2.Close()
	c := NewClient("socket")
	c.dial = func(_ string) (net.Conn, error) {
		return c1, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = c.InstanceLoaded(ctx, "sb")
}

func TestClient_RoundTripContext_Canceled_Read(t *testing.T) {
	c1, c2 := net.Pipe()
	c := NewClient("socket")
	c.dial = func(_ string) (net.Conn, error) {
		return c1, nil
	}
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		_, _ = readFrame(c2)
		cancel()
		c2.Close()
	}()

	_, _ = c.InstanceLoaded(ctx, "sb")
}
