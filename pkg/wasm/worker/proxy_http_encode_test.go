package worker

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProxyHTTP_EncodeDecodeErrors(t *testing.T) {
	origEncode := encodePayload
	defer func() { encodePayload = origEncode }()
	encodePayload = func(v any) ([]byte, error) {
		return nil, errors.New("mock encode error")
	}

	// buildProxyHTTPPayload
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	_, _ = buildProxyHTTPPayload(80, req)

	// writeProxyHTTPResult
	w := httptest.NewRecorder()
	writeProxyHTTPResult(w, proxyHTTPResultPayload{})

	// Write
	var n atomic.Int64
	c3 := &countConn{Conn: &net.TCPConn{}, out: &n}
	_, _ = c3.Write([]byte("foo"))
}
