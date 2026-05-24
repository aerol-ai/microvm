package ingressproxy

import (
	"bytes"
	"errors"
	"io"
)

// errBodyTooLarge is returned when the incoming request body exceeds the
// configured wake buffer cap. The handler translates this to 413.
var errBodyTooLarge = errors.New("request body exceeds wake buffer cap")

// bufferBody reads up to max+1 bytes from r so we can distinguish "fit
// exactly" from "overflowed". Returns errBodyTooLarge if the body would
// exceed max.
//
// We buffer because a cold-start wake may take up to wakeStartTimeout
// (15s) and we can't replay a body the client has already streamed.
// Streaming-while-waking is the alternative — chosen against here for
// D2 simplicity. WebSocket / SSE upgrades skip this path entirely
// (no body, header-only handshake).
func bufferBody(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errBodyTooLarge
	}
	limited := io.LimitReader(r, max+1)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, limited)
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, errBodyTooLarge
	}
	return buf.Bytes(), nil
}
