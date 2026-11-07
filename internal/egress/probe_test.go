package egress

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortSocket returns a socket path short enough for macOS's 104-byte cap.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "egp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "gw.sock")
}

// fakeGateway answers the first frame with reply and closes.
func fakeGateway(t *testing.T, reply string) string {
	t.Helper()
	path := shortSocket(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var req request
			_ = newFrameReader(c).read(&req)
			if reply != "" {
				_, _ = c.Write([]byte(reply + "\n"))
			}
			_ = c.Close()
		}
	}()
	return path
}

func TestProbeGatewayProtocolAsksTheRunningGateway(t *testing.T) {
	g, _, _ := newTestGateway(t)
	path := shortSocket(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(g, ServerHooks{}, nil, nil, nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close(); srv.Close() })

	got, err := ProbeGatewayProtocol(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if got != ProtocolVersion {
		t.Fatalf("probe = %d, want the gateway's ProtocolVersion %d", got, ProtocolVersion)
	}
}

func TestProbeGatewayProtocolErrors(t *testing.T) {
	cases := []struct {
		name  string
		path  func(t *testing.T) string
		want  error
		match string
	}{
		{name: "no gateway", path: func(t *testing.T) string { return shortSocket(t) }, want: ErrUnavailable},
		{name: "closes without answering", path: func(t *testing.T) string { return fakeGateway(t, "") }, want: ErrUnavailable},
		{name: "version refused", path: func(t *testing.T) string {
			return fakeGateway(t, `{"id":1,"code":"version","error":"gateway speaks 9 and 8"}`)
		}, want: ErrVersionMismatch},
		{name: "refused without a code", path: func(t *testing.T) string {
			return fakeGateway(t, `{"id":1,"error":"nope"}`)
		}, match: "refused hello: nope"},
		{name: "no version in the answer", path: func(t *testing.T) string { return fakeGateway(t, `{"id":1}`) }, want: ErrVersionMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ProbeGatewayProtocol(context.Background(), tc.path(t))
			if err == nil {
				t.Fatal("probe succeeded")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.match != "" && !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.match)
			}
		})
	}
}
