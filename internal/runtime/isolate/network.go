package isolate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// PortGateway is the host-mediated HTTP ingress surface for isolate sandboxes
// (plans/isolate-runtime.md §4 / Phase 3). Same shape as the WASM PortGateway:
// Caddy dials the loopback address returned by EnsureHTTPListener rather than
// a guest container IP, so expose_port never walks the TCP host-port pool.
type PortGateway interface {
	EnsureHTTPListener(ctx context.Context, sandboxID string, guestPort int) (dialAddr string, err error)
	ReleaseHTTPListener(sandboxID string, guestPort int)
	SyncAllowedPorts(sandboxID string, ports []int)
}

// NetworkByteCounter drains ingress/egress byte deltas observed at the mediators.
type NetworkByteCounter interface {
	DrainNetworkByteCounters() map[string]struct{ BytesIn, BytesOut int64 }
}

// NetworkPolicySink applies ingress/egress quota blocks at the mediator.
type NetworkPolicySink interface {
	SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool)
}

// AsPortGateway returns the HTTP ingress surface when rt implements it.
func AsPortGateway(rt any) (PortGateway, bool) {
	pg, ok := rt.(PortGateway)
	return pg, ok
}

type sandboxNetUsage struct {
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
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
	allowed   map[string]map[int]struct{}
	usage     map[string]*sandboxNetUsage
	blocked   map[string]struct{ ingress, egress bool }
	httpProxy func(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error
}

func newNetworkGateway() *networkGateway {
	return &networkGateway{
		listeners: make(map[string]map[int]*httpListener),
		allowed:   make(map[string]map[int]struct{}),
		usage:     make(map[string]*sandboxNetUsage),
		blocked:   make(map[string]struct{ ingress, egress bool }),
	}
}

// SetHTTPProxy registers the driver→group-host bridge used for inbound fetch.
func (g *networkGateway) SetHTTPProxy(fn func(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) error) {
	g.mu.Lock()
	g.httpProxy = fn
	g.mu.Unlock()
}

func (g *networkGateway) EnsureHTTPListener(_ context.Context, sandboxID string, guestPort int) (string, error) {
	if sandboxID == "" || guestPort <= 0 || guestPort > 65535 {
		return "", fmt.Errorf("invalid isolate http listener request")
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
		return "", fmt.Errorf("listen isolate http mediator: %w", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.serveHTTP(sandboxID, guestPort, w, r)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
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
	delete(g.usage, sandboxID)
	delete(g.blocked, sandboxID)
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

func (g *networkGateway) SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if sandboxID == "" {
		return
	}
	g.blocked[sandboxID] = struct{ ingress, egress bool }{ingress: blockIngress, egress: blockEgress}
}

func (g *networkGateway) DrainNetworkByteCounters() map[string]struct{ BytesIn, BytesOut int64 } {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.usage) == 0 {
		return nil
	}
	out := make(map[string]struct{ BytesIn, BytesOut int64 }, len(g.usage))
	for id, u := range g.usage {
		out[id] = struct{ BytesIn, BytesOut int64 }{
			BytesIn:  u.bytesIn.Swap(0),
			BytesOut: u.bytesOut.Swap(0),
		}
	}
	return out
}

func (g *networkGateway) serveHTTP(sandboxID string, guestPort int, w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	block := g.blocked[sandboxID]
	if block.ingress {
		g.mu.Unlock()
		http.Error(w, "network ingress blocked", http.StatusForbidden)
		return
	}
	if !g.portAllowedLocked(sandboxID, guestPort) {
		g.mu.Unlock()
		http.Error(w, "port not allowed", http.StatusForbidden)
		return
	}
	usage := g.usageForLocked(sandboxID)
	proxy := g.httpProxy
	g.mu.Unlock()

	if r.Body != nil {
		r.Body = &byteCountReader{r: r.Body, counter: &usage.bytesIn}
	}
	if block.egress {
		http.Error(w, "network egress blocked", http.StatusForbidden)
		return
	}
	if proxy == nil {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
		}
		cw := &byteCountWriter{ResponseWriter: w, counter: &usage.bytesOut}
		http.Error(cw, "isolate guest http not connected", http.StatusServiceUnavailable)
		return
	}
	cw := &byteCountWriter{ResponseWriter: w, counter: &usage.bytesOut}
	if err := proxy(sandboxID, guestPort, cw, r); err != nil {
		http.Error(cw, err.Error(), http.StatusBadGateway)
	}
}

func (g *networkGateway) usageForLocked(sandboxID string) *sandboxNetUsage {
	if g.usage[sandboxID] == nil {
		g.usage[sandboxID] = &sandboxNetUsage{}
	}
	return g.usage[sandboxID]
}

func (g *networkGateway) portAllowedLocked(sandboxID string, guestPort int) bool {
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

// Driver PortGateway / NetworkPolicySink / NetworkByteCounter methods.

func (d *Driver) EnsureHTTPListener(ctx context.Context, sandboxID string, guestPort int) (string, error) {
	return d.net.EnsureHTTPListener(ctx, sandboxID, guestPort)
}

func (d *Driver) ReleaseHTTPListener(sandboxID string, guestPort int) {
	d.net.ReleaseHTTPListener(sandboxID, guestPort)
}

func (d *Driver) SyncAllowedPorts(sandboxID string, ports []int) {
	d.net.SyncAllowedPorts(sandboxID, ports)
}

func (d *Driver) SetNetworkBlocks(sandboxID string, blockIngress, blockEgress bool) {
	d.net.SetNetworkBlocks(sandboxID, blockIngress, blockEgress)
}

func (d *Driver) DrainNetworkByteCounters() map[string]struct{ BytesIn, BytesOut int64 } {
	return d.net.DrainNetworkByteCounters()
}

type byteCountReader struct {
	r       io.ReadCloser
	counter *atomic.Int64
}

func (b *byteCountReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		b.counter.Add(int64(n))
	}
	return n, err
}

func (b *byteCountReader) Close() error { return b.r.Close() }

type byteCountWriter struct {
	http.ResponseWriter
	counter *atomic.Int64
}

func (w *byteCountWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.counter.Add(int64(n))
	}
	return n, err
}
