package cluster

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyCacheDoubleCheckAndErrorHandler(t *testing.T) {
	pc := newProxyCache()
	p1, err := pc.getForPeer("node-1", "https://example.invalid", http.DefaultTransport)
	if err != nil || p1 == nil {
		t.Fatalf("get=%v err=%v", p1, err)
	}
	p2, err := pc.getForPeer("node-1", "https://example.invalid", http.DefaultTransport)
	if err != nil || p2 != p1 {
		t.Fatalf("cache hit p2=%v err=%v", p2, err)
	}
	if _, err := pc.getForPeer("node-1", "://bad", http.DefaultTransport); err == nil {
		t.Fatal("expected parse error")
	}
	// Fire ErrorHandler.
	w := httptest.NewRecorder()
	p1.ErrorHandler(w, httptest.NewRequest(http.MethodGet, "http://x", nil), errors.New("boom"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", w.Code)
	}
}
