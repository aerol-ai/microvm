package worker

import (
	"context"
	"net"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func mockDialer(t *testing.T, reply Envelope) func(string) (net.Conn, error) {
	return func(string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			_, err := readFrame(serverConn)
			if err != nil {
				return
			}
			_ = writeFrame(serverConn, reply)
		}()
		return clientConn, nil
	}
}

func TestClient_roundTripContext_Cancel(t *testing.T) {
	c := NewClient("dummy")
	c.dial = func(string) (net.Conn, error) {
		time.Sleep(1 * time.Second)
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := c.roundTripContext(ctx, Envelope{Type: MsgHealthPing})
	if err != context.Canceled {
		t.Fatalf("expected context canceled, got: %v", err)
	}
}

func TestClient_Methods(t *testing.T) {
	sb := "sb-123"

	tests := []struct {
		name    string
		run     func(c *Client) error
		reply   Envelope
		wantErr bool
	}{
		{
			name: "InstanceLoaded_OK",
			run: func(c *Client) error {
				payload, _ := encodePayload(instanceStatusPayload{Loaded: true})
				c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: payload})
				loaded, err := c.InstanceLoaded(context.Background(), sb)
				if err == nil && !loaded {
					t.Fatalf("expected loaded=true")
				}
				return err
			},
		},
		{
			name: "InstanceLoaded_Error",
			run: func(c *Client) error {
				payload, _ := encodePayload(errorPayload{Message: "boom"})
				c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
				_, err := c.InstanceLoaded(context.Background(), sb)
				return err
			},
			wantErr: true,
		},
		{
			name: "Checkpoint_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				return c.Checkpoint(context.Background(), sb, "/tmp/out", wasmengine.SnapshotConfig{})
			},
		},
		{
			name: "Restore_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				return c.Restore(sb, "/tmp/in", wasmengine.Capabilities{})
			},
		},
		{
			name: "SetCapability_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				return c.SetCapability(sb, wasmengine.Capabilities{})
			},
		},
		{
			name: "StopInstance_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				return c.StopInstance(sb)
			},
		},
		{
			name: "NetstatsTick_OK",
			run: func(c *Client) error {
				payload, _ := encodePayload(netstatsResultPayload{BytesIn: 10, BytesOut: 20})
				c.dial = mockDialer(t, Envelope{Type: MsgOK, Payload: payload})
				in, out, err := c.NetstatsTick(sb)
				if err == nil && (in != 10 || out != 20) {
					t.Fatalf("expected 10/20, got %d/%d", in, out)
				}
				return err
			},
		},
		{
			name: "NetstatsTick_Error",
			run: func(c *Client) error {
				payload, _ := encodePayload(errorPayload{Message: "netstats err"})
				c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
				_, _, err := c.NetstatsTick(sb)
				return err
			},
			wantErr: true,
		},
		{
			name: "SetNetworkBlocks_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				return c.SetNetworkBlocks(sb, true, true)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient("dummy")
			err := tt.run(c)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestClient_MoreMethods(t *testing.T) {
	sb := "sb-123"

	tests := []struct {
		name    string
		run     func(c *Client) error
		wantErr bool
	}{
		{
			name: "LoadModule_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				_, err := c.LoadModule(sb, "path/to/module", 0)
				return err
			},
		},
		{
			name: "LoadModule_Error",
			run: func(c *Client) error {
				payload, _ := encodePayload(errorPayload{Message: "boom"})
				c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
				_, err := c.LoadModule(sb, "path/to/module", 0)
				return err
			},
			wantErr: true,
		},
		{
			name: "Instantiate_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				return c.Instantiate(sb, wasmengine.Capabilities{})
			},
		},
		{
			name: "Instantiate_Error",
			run: func(c *Client) error {
				payload, _ := encodePayload(errorPayload{Message: "boom"})
				c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
				return c.Instantiate(sb, wasmengine.Capabilities{})
			},
			wantErr: true,
		},
		{
			name: "Exec_OK",
			run: func(c *Client) error {
				payload, _ := encodePayload(execResultPayload{ExitCode: 0})
				c.dial = mockDialer(t, Envelope{Type: MsgInvokeResult, Payload: payload})
				_, err := c.Exec(sb, wasmengine.Capabilities{}, "cmd")
				return err
			},
		},
		{
			name: "Exec_Error",
			run: func(c *Client) error {
				payload, _ := encodePayload(errorPayload{Message: "boom"})
				c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
				_, err := c.Exec(sb, wasmengine.Capabilities{}, "cmd")
				return err
			},
			wantErr: true,
		},
		{
			name: "Invoke_OK",
			run: func(c *Client) error {
				c.dial = mockDialer(t, Envelope{Type: MsgOK})
				return c.Invoke(sb, "funcName")
			},
		},
		{
			name: "Invoke_Error",
			run: func(c *Client) error {
				payload, _ := encodePayload(errorPayload{Message: "boom"})
				c.dial = mockDialer(t, Envelope{Type: MsgError, Payload: payload})
				return c.Invoke(sb, "funcName")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient("dummy")
			err := tt.run(c)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error: %v, got: %v", tt.wantErr, err)
			}
		})
	}
}
