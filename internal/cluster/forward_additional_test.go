package cluster

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyCacheGet(t *testing.T) {
	pc := newProxyCache(http.DefaultTransport)

	p1, err := pc.get("http://localhost:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p2, err := pc.get("http://localhost:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 != p2 {
		t.Errorf("expected identical proxy instance")
	}

	// invalid url
	_, err = pc.get("http://192.168.0.%31/")
	if err == nil {
		t.Errorf("expected error for invalid url")
	}
}

func TestServeProxy(t *testing.T) {
	pc := newProxyCache(http.DefaultTransport)
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	w := httptest.NewRecorder()

	err := serveProxy(pc, "localhost:8080", w, req)
	if err == nil {
		t.Errorf("expected error for missing scheme")
	}

	err = serveProxy(pc, "http://192.168.0.%31/", w, req)
	if err == nil {
		t.Errorf("expected error for invalid URL")
	}
}
