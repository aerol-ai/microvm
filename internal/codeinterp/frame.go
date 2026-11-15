package codeinterp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxFramePayload caps one driver frame. A result frame carries a base64
// PNG, so the cap is generous; it exists so a broken driver cannot make the
// host allocate without bound.
const MaxFramePayload = 32 << 20

// maxKindLen bounds the header word so a stray line of user output cannot
// make the reader scan far for a space.
const maxKindLen = 16

// ErrBadFrame is returned for a malformed frame header.
var ErrBadFrame = errors.New("codeinterp: malformed driver frame")

// WriteFrame writes one frame. kind must be an upper-case word.
func WriteFrame(w io.Writer, kind string, payload []byte) error {
	if _, err := fmt.Fprintf(w, "%s %d\n", kind, len(payload)); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// FrameReader reads frames from a driver.
type FrameReader struct {
	r *bufio.Reader
}

// NewFrameReader wraps r.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: bufio.NewReaderSize(r, 64<<10)}
}

// Read returns the next frame. io.EOF means the driver closed the stream
// between frames; io.ErrUnexpectedEOF means it died in the middle of one.
func (f *FrameReader) Read() (string, []byte, error) {
	header, err := f.r.ReadString('\n')
	if err != nil {
		if err == io.EOF && header != "" {
			return "", nil, io.ErrUnexpectedEOF
		}
		return "", nil, err
	}
	header = strings.TrimSuffix(header, "\n")
	kind, size, ok := strings.Cut(header, " ")
	if !ok || kind == "" || len(kind) > maxKindLen || strings.ToUpper(kind) != kind {
		return "", nil, fmt.Errorf("%w: header %q", ErrBadFrame, truncate(header, 64))
	}
	n, err := strconv.Atoi(size)
	if err != nil || n < 0 || n > MaxFramePayload {
		return "", nil, fmt.Errorf("%w: length %q", ErrBadFrame, truncate(size, 32))
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(f.r, payload); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return "", nil, err
	}
	return kind, payload, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ParseErrorPayload splits an ERROR frame's payload (name US value US
// traceback). Missing parts are empty.
func ParseErrorPayload(p []byte) (name, value, traceback string) {
	parts := strings.SplitN(string(p), "\x1f", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return parts[0], parts[1], parts[2]
}
