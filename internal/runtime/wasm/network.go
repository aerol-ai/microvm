package wasm

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// PortGateway is the host-mediated HTTP ingress surface for WASM sandboxes.
// Caddy and the loopback ingress proxy dial the loopback address returned by
// EnsureHTTPListener rather than a guest container IP.
type PortGateway interface {
	EnsureHTTPListener(ctx context.Context, sandboxID string, guestPort int) (dialAddr string, err error)
	ReleaseHTTPListener(sandboxID string, guestPort int)
	SyncAllowedPorts(sandboxID string, ports []int)
}

// AsPortGateway returns the HTTP ingress surface when rt implements it.
func AsPortGateway(rt any) (PortGateway, bool) {
	pg, ok := rt.(PortGateway)
	return pg, ok
}

type httpListener struct {
	guestPort int
	listener  net.Listener
	server    *http.Server
}

type networkGateway struct {
	mu sync.Mutex
	// sandboxID -> guestPort -> listener
	listeners map[string]map[int]*httpListener
	// sandboxID -> allowed guest ports (from expose_port / syncAllowedPorts)
	allowed map[string]map[int]struct{}
}

func newNetworkGateway() *networkGateway {
	return &networkGateway{
		listeners: make(map[string]map[int]*httpListener),
		allowed:   make(map[string]map[int]struct{}),
	}
}

func (g *networkGateway) EnsureHTTPListener(_ context.Context, sandboxID string, guestPort int) (string, error) {
	if sandboxID == "" || guestPort <= 0 || guestPort > 65535 {
		return "", fmt.Errorf("invalid wasm http listener request")
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.listeners[sandboxID] != nil {
		if ln := g.listeners[sandboxID][guestPort]; ln != nil {
			return ln.listener.Addr().String(), nil
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen wasm http mediator: %w", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.serveHTTP(sandboxID, guestPort, w, r)
		}),
	}
	go func() {
		_ = srv.Serve(ln)
	}()

	if g.listeners[sandboxID] == nil {
		g.listeners[sandboxID] = make(map[int]*httpListener)
	}
	g.listeners[sandboxID][guestPort] = &httpListener{
		guestPort: guestPort,
		listener:  ln,
		server:    srv,
	}
	return ln.Addr().String(), nil
}

func (g *networkGateway) ReleaseHTTPListener(sandboxID string, guestPort int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closeListenerLocked(sandboxID, guestPort)
}

func (g *networkGateway) ReleaseSandbox(sandboxID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for port := range g.listeners[sandboxID] {
		g.closeListenerLocked(sandboxID, port)
	}
	delete(g.allowed, sandboxID)
}

func (g *networkGateway) SyncAllowedPorts(sandboxID string, ports []int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if sandboxID == "" {
		return
	}
	set := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			set[p] = struct{}{}
		}
	}
	g.allowed[sandboxID] = set
}

func (g *networkGateway) serveHTTP(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) {
	if !g.portAllowed(sandboxID, guestPort) {
		http.Error(w, "port not allowed", http.StatusForbidden)
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
	_ = r.Body.Close()
	// Guest wasi-http bridging is a later phase; the listener exists so Caddy
	// and ingress can route end-to-end while the worker HTTP surface lands.
	http.Error(w, "wasm guest http not connected", http.StatusServiceUnavailable)
}

func (g *networkGateway) portAllowed(sandboxID string, guestPort int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	ports := g.allowed[sandboxID]
	if len(ports) == 0 {
		return false
	}
	_, ok := ports[guestPort]
	return ok
}

func (g *networkGateway) closeListenerLocked(sandboxID string, guestPort int) {
	ports := g.listeners[sandboxID]
	if ports == nil {
		return
	}
	ln := ports[guestPort]
	if ln == nil {
		return
	}
	_ = ln.server.Close()
	delete(ports, guestPort)
	if len(ports) == 0 {
		delete(g.listeners, sandboxID)
	}
}
