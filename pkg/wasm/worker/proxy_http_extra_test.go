package worker

import (
	"context"
	"net/http"
	"testing"
)

func TestGuestHTTPTarget_Errors(t *testing.T) {
	s := &Server{}

	s.lastCaps.WASIListenPort = -1
	_, err := s.guestHTTPTarget(0)
	if err == nil {
		t.Error("expected error on negative port")
	}

	// Test host == ""
	s.lastCaps.WASIListenHost = ""
	target, _ := s.guestHTTPTarget(80)
	if target != "127.0.0.1:80" {
		t.Errorf("expected 127.0.0.1:80, got %v", target)
	}

	// Test url.Parse error by using a bad host
	s.lastCaps.WASIListenPort = 80
	s.lastCaps.WASIListenHost = " \x00 "
	req, _ := http.NewRequest("GET", "http://localhost", nil)
	err = s.proxyGuestHTTP(context.Background(), "sb", 0, nil, req)
	if err == nil {
		t.Error("expected error on proxyGuestHTTP url parse")
	}
}

func TestServer_ServeSocketPath(t *testing.T) {
	// Use an invalid socket path to test listen error
	err := ServeSocketPath("/invalid/path/that/does/not/exist/foo/bar.sock")
	if err == nil {
		t.Error("expected error listening on invalid path")
	}
}
