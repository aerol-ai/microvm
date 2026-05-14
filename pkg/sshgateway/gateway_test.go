package sshgateway

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// encodeString writes an SSH-format string (uint32 length + bytes).
func encodeString(s string) []byte {
	buf := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(s)))
	copy(buf[4:], s)
	return buf
}

func encodeUint32(n uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], n)
	return buf[:]
}

func TestParsePTYRequest(t *testing.T) {
	payload := bytes.Join([][]byte{
		encodeString("xterm-256color"),
		encodeUint32(120), // cols
		encodeUint32(40),  // rows
		encodeUint32(0),   // pixwidth
		encodeUint32(0),   // pixheight
		encodeString(""),  // modes
	}, nil)

	term, rows, cols, ok := parsePTYRequest(payload)
	if !ok {
		t.Fatal("parsePTYRequest returned !ok")
	}
	if term != "xterm-256color" {
		t.Errorf("term = %q, want xterm-256color", term)
	}
	if rows != 40 || cols != 120 {
		t.Errorf("rows/cols = %d/%d, want 40/120", rows, cols)
	}
}

func TestParseEnvRequest(t *testing.T) {
	payload := append(encodeString("LANG"), encodeString("en_US.UTF-8")...)
	name, value, ok := parseEnvRequest(payload)
	if !ok {
		t.Fatal("parseEnvRequest returned !ok")
	}
	if name != "LANG" || value != "en_US.UTF-8" {
		t.Errorf("got %q=%q, want LANG=en_US.UTF-8", name, value)
	}
}

func TestParseExecRequest(t *testing.T) {
	payload := encodeString("ls -la /workspace")
	cmd, ok := parseExecRequest(payload)
	if !ok {
		t.Fatal("parseExecRequest returned !ok")
	}
	if cmd != "ls -la /workspace" {
		t.Errorf("cmd = %q", cmd)
	}
}

func TestParseWindowChange(t *testing.T) {
	payload := bytes.Join([][]byte{
		encodeUint32(80),
		encodeUint32(24),
		encodeUint32(0),
		encodeUint32(0),
	}, nil)
	rows, cols, ok := parseWindowChange(payload)
	if !ok {
		t.Fatal("parseWindowChange returned !ok")
	}
	if rows != 24 || cols != 80 {
		t.Errorf("rows/cols = %d/%d, want 24/80", rows, cols)
	}
}

func TestParseShortPayloads(t *testing.T) {
	if _, _, _, ok := parsePTYRequest([]byte{0, 0, 0, 5, 'x'}); ok {
		t.Error("pty-req should reject truncated payload")
	}
	if _, _, ok := parseEnvRequest([]byte{0, 0, 0, 1}); ok {
		t.Error("env should reject truncated payload")
	}
	if _, ok := parseExecRequest(nil); ok {
		t.Error("exec should reject empty payload")
	}
	if _, _, ok := parseWindowChange([]byte{0, 0}); ok {
		t.Error("window-change should reject short payload")
	}
}

func TestAllowEnvVar(t *testing.T) {
	allowed := []string{"TERM", "LANG", "LC_ALL", "LC_TIME"}
	for _, name := range allowed {
		if !allowEnvVar(name) {
			t.Errorf("allowEnvVar(%q) = false, want true", name)
		}
	}
	if allowEnvVar("LD_PRELOAD") {
		t.Error("allowEnvVar should reject LD_PRELOAD")
	}
}

func TestDemuxDockerStream(t *testing.T) {
	// Two frames: stdout "hi", stderr "err".
	frame := func(stream byte, payload string) []byte {
		out := make([]byte, 8+len(payload))
		out[0] = stream
		binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
		copy(out[8:], payload)
		return out
	}
	input := bytes.NewReader(append(frame(1, "hi"), frame(2, "err")...))

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	demuxDockerStream(fakeChannel{stdout: stdout, stderr: stderr}, input)

	if stdout.String() != "hi" {
		t.Errorf("stdout = %q, want hi", stdout.String())
	}
	if stderr.String() != "err" {
		t.Errorf("stderr = %q, want err", stderr.String())
	}
}

// fakeChannel is the smallest ssh.Channel surface we need for demuxDockerStream.
type fakeChannel struct {
	stdout io.Writer
	stderr io.Writer
}

func (f fakeChannel) Read(p []byte) (int, error)  { return 0, io.EOF }
func (f fakeChannel) Write(p []byte) (int, error) { return f.stdout.Write(p) }
func (f fakeChannel) Close() error                { return nil }
func (f fakeChannel) CloseWrite() error           { return nil }
func (f fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (f fakeChannel) Stderr() io.ReadWriter { return stderrAdapter{w: f.stderr} }

type stderrAdapter struct{ w io.Writer }

func (s stderrAdapter) Read([]byte) (int, error)    { return 0, io.EOF }
func (s stderrAdapter) Write(p []byte) (int, error) { return s.w.Write(p) }
