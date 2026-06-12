package worker

import (
	"bytes"
	"io"
	"testing"
)

type errWriter struct{}

func (e errWriter) Write(p []byte) (n int, err error) {
	return 0, io.ErrClosedPipe
}

type errWriterAfter struct {
	writes int
}

func (e *errWriterAfter) Write(p []byte) (n int, err error) {
	if e.writes == 1 {
		return 0, io.ErrClosedPipe
	}
	e.writes++
	return len(p), nil
}

type errReader struct{}

func (e errReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func TestCodec(t *testing.T) {
	// Test writeFrame header error
	if err := writeFrame(errWriter{}, Envelope{Type: MsgOK}); err == nil {
		t.Fatal("expected error on writeFrame header")
	}

	// Test writeFrame body error
	if err := writeFrame(&errWriterAfter{}, Envelope{Type: MsgOK}); err == nil {
		t.Fatal("expected error on writeFrame body")
	}

	// Test readFrame header error
	if _, err := readFrame(errReader{}); err == nil {
		t.Fatal("expected error on readFrame header")
	}

	// Test readFrame body error
	var lenBuf [4]byte
	lenBuf[3] = 10 // size 10
	if _, err := readFrame(bytes.NewReader(lenBuf[:])); err == nil {
		t.Fatal("expected error on readFrame body (EOF)")
	}

	// Test writeFrame large payload
	buf := new(bytes.Buffer)
	largeEnv := Envelope{Type: MsgOK, Payload: make([]byte, 17*1024*1024)} // > 16MB
	if err := writeFrame(buf, largeEnv); err == nil {
		t.Fatal("expected error on large payload write")
	}

	// Test readFrame large payload
	buf.Reset()
	lenBuf[0] = 0x01
	lenBuf[1] = 0x00
	lenBuf[2] = 0x00
	lenBuf[3] = 0x01 // > 16MB
	buf.Write(lenBuf[:])
	if _, err := readFrame(buf); err == nil {
		t.Fatal("expected error on large payload read")
	}
}
