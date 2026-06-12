package worker

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

type mockReadCloser struct{}

func (m *mockReadCloser) Read(p []byte) (int, error) { return 0, errors.New("read error") }
func (m *mockReadCloser) Close() error               { return nil }

func TestProxyHTTP_Write(t *testing.T) {
	var n atomic.Int64
	c := &countReadCloser{ReadCloser: &mockReadCloser{}, counter: &n}
	_, err := c.Read([]byte{})
	if err == nil {
		t.Error("expected error")
	}

	c1, c2 := net.Pipe()
	go func() { _ = c2.Close() }()
	c3 := &countConn{Conn: c1, out: &n}
	_, err = c3.Write([]byte("foo"))
	if err == nil {
		t.Error("expected error on closed pipe")
	}
}
