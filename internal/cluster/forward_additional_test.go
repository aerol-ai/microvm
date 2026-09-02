package cluster

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyCacheGet(t *testing.T) {
	pc := newProxyCache()

	p1, err := pc.getForPeer("node-1", "https://localhost:8080", http.DefaultTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p2, err := pc.getForPeer("node-1", "https://localhost:8080", http.DefaultTransport)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 != p2 {
		t.Errorf("expected identical proxy instance")
	}

	// invalid url
	_, err = pc.getForPeer("node-1", "https://192.168.0.%31/", http.DefaultTransport)
	if err == nil {
		t.Errorf("expected error for invalid url")
	}
}

func TestServeProxy(t *testing.T) {
	pc := newProxyCache()
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	err := servePeerProxy(pc, "node-1", "localhost:8080", http.DefaultTransport, w, req)
	if err == nil {
		t.Errorf("expected error for missing scheme")
	}

	err = servePeerProxy(pc, "node-1", "https://192.168.0.%31/", http.DefaultTransport, w, req)
	if err == nil {
		t.Errorf("expected error for invalid URL")
	}
}
