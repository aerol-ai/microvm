package worker

import (
	"bytes"
	"context"

	"io"
	"net"
	"testing"
)

func TestNetMediator_SetBlocks(t *testing.T) {
	m := newNetMediator()
	m.SetBlocks("", true, true)
	if m.egressBlocked("") {
		t.Fatal("expected empty string to be ignored")
	}

	m.SetBlocks("sb1", true, true)
	if !m.ingressBlocked("sb1") || !m.egressBlocked("sb1") {
		t.Fatal("expected blocked")
	}

	m.SetBlocks("sb1", false, false)
	if m.ingressBlocked("sb1") || m.egressBlocked("sb1") {
		t.Fatal("expected not blocked")
	}
}

func TestNetMediator_DialContext(t *testing.T) {
	m := newNetMediator()
	m.SetBlocks("sb1", false, true)
	_, err := m.DialContext(context.Background(), "sb1", "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("ok"))
			c.Close()
		}
	}()

	m.SetBlocks("sb1", false, false)
	conn, err := m.DialContext(context.Background(), "sb1", "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 2)
	conn.Read(buf)
	conn.Write([]byte("hi"))

	in, out := m.DrainUsage("sb1")
	if in != 2 || out != 2 {
		t.Fatalf("expected 2/2, got %d/%d", in, out)
	}
}

func TestNetMediator_Copy(t *testing.T) {
	m := newNetMediator()

	// outbound blocked
	m.SetBlocks("sb1", false, true)
	_, err := m.Copy("sb1", bytes.NewBuffer(nil), bytes.NewBuffer(nil), true)
	if err == nil {
		t.Fatal("expected error")
	}

	// ingress blocked
	m.SetBlocks("sb1", true, false)
	_, err = m.Copy("sb1", bytes.NewBuffer(nil), bytes.NewBuffer(nil), false)
	if err == nil {
		t.Fatal("expected error")
	}

	// ok copy outbound
	m.SetBlocks("sb1", false, false)
	dst := new(bytes.Buffer)
	src := bytes.NewBufferString("hello")
	n, err := m.Copy("sb1", dst, src, true)
	if err != nil || n != 5 {
		t.Fatalf("expected 5 bytes, got %d, err %v", n, err)
	}

	// read error
	_, err = m.Copy("sb1", dst, errReaderNet{}, true)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected errReader error, got %v", err)
	}

	// write error
	_, err = m.Copy("sb1", errWriterNet{}, bytes.NewBufferString("hi"), false)
	if err != io.ErrClosedPipe {
		t.Fatalf("expected errWriter error, got %v", err)
	}

	// short write error
	_, err = m.Copy("sb1", shortWriterNet{}, bytes.NewBufferString("hi"), false)
	if err != io.ErrShortWrite {
		t.Fatalf("expected errShortWrite error, got %v", err)
	}
}

type errWriterNet struct{}

func (e errWriterNet) Write(p []byte) (n int, err error) { return 0, io.ErrClosedPipe }

type shortWriterNet struct{}

func (e shortWriterNet) Write(p []byte) (n int, err error) { return 1, nil }

type errReaderNet struct{}

func (e errReaderNet) Read(p []byte) (n int, err error) { return 0, io.ErrUnexpectedEOF }
