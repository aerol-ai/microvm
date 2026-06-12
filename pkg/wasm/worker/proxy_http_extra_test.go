package worker

import (
	"net/http"
	"testing"
)

func TestProxyHTTP_MissingPaths(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	_, err := buildProxyHTTPPayload(80, req)
	if err != nil {
		t.Fatal(err)
	}

	// newLimitedProxyResponseRecorder Write missing path
	w := newLimitedProxyResponseRecorder(1024 * 1024)

	// Write more than limit to trigger overflow
	buf := make([]byte, 2*1024*1024)
	w.Write(buf)
	if !w.Overflowed() {
		t.Fatal("expected overflow")
	}

	// Check headers and status code defaults
	w2 := newLimitedProxyResponseRecorder(1024 * 1024)
	if w2.StatusCode() != http.StatusOK {
		t.Fatal("expected 200")
	}
}
