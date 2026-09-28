package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/routedns"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// indexRouteWriter is the publicRouteWriter SB_INGRESS_PROXY_ROUTING installs
// on an owner node (plans/ingress-proxy-routing.md §3.2). Where the Caddy
// writer turned each route intent into an admin write (and a full reload),
// this one records the same intent in the route responder's OwnerTable. The
// 77 call sites behind the 4A choke point therefore maintain the table with
// exactly the semantics of the routes it replaces, and no store read ever
// lands on the DNS answer path.
//
//	intent (via publicRoutes())            OwnerTable
//	UpsertSandboxRoute(id, ip, tb, cust) → {id}.{domain} = ip:tb ; custom = ip:port | router
//	UpsertPortRoute*(id, ip, p, opts)    → {id}-{p}.{domain} = ip:p (router if masked)
//	UpsertWakeHTTPPortRoute(id, _, p)    → {id}-{p}.{domain} state=wake
//	UpsertInFlux*(id[, p])               → host state=in-flux
//	Delete*/DeleteRouteByID              → remove (routeID→host map mirrors Caddy GC)
//
// SNI passthrough and raw-TCP intents are not owner http routes. The ingress
// index is built from the placement view, and TCP moves to sandboxd listeners
// (T7), so those intents are no-ops here.
type indexRouteWriter struct {
	table  *routedns.OwnerTable
	domain string

	// tcp forwards raw-TCP host ports in the kernel (hostport.Forwarder),
	// and redirectPort is the sandboxd listener that wake/mediator ports are
	// REDIRECTed to. nil tcp: TCP intents are no-ops.
	tcp          tcpForwarder
	redirectPort int
	lookupIP     func(string) ([]net.IP, error)

	mu sync.Mutex
	// routeHosts maps a Caddy route ID to the host it would have matched, so
	// by-ID deletes (reconcile GC) keep the table exact.
	routeHosts map[string]string
	// sandboxHosts tracks every host a sandbox's root route carried (custom
	// hostnames ride it), so DeleteSandboxRoute drops them all, like Caddy.
	sandboxHosts map[string]map[string]struct{}
}

var _ publicRouteWriter = (*indexRouteWriter)(nil)

// tcpForwarder is the hostport.Forwarder surface the writer uses.
type tcpForwarder interface {
	Ensure(hostPort int, t hostport.Target) error
	Remove(hostPort int) error
}

var _ tcpForwarder = (*hostport.Forwarder)(nil)

func newIndexRouteWriter(table *routedns.OwnerTable, domain string) *indexRouteWriter {
	return &indexRouteWriter{table: table, domain: domain, routeHosts: map[string]string{}, sandboxHosts: map[string]map[string]struct{}{}}
}

func (w *indexRouteWriter) rootHost(id string) string { return id + "." + w.domain }
func (w *indexRouteWriter) portHost(id string, port int) string {
	return id + "-" + strconv.Itoa(port) + "." + w.domain
}

func masked(opts []caddy.HTTPRouteOptions) bool {
	for _, o := range opts {
		if o.MaskRequestHost != "" {
			return true
		}
	}
	return false
}

func dialIP(dial string) (net.IP, int) {
	host, port, err := net.SplitHostPort(dial)
	if err != nil {
		return nil, 0
	}
	p, _ := strconv.Atoi(port)
	return net.ParseIP(host), p
}

func (w *indexRouteWriter) set(routeID, sandboxID, host string, t routedns.OwnerTarget) {
	w.table.Set(host, t)
	w.mu.Lock()
	defer w.mu.Unlock()
	if routeID != "" {
		w.routeHosts[routeID] = host
	}
	if sandboxID != "" {
		if w.sandboxHosts[sandboxID] == nil {
			w.sandboxHosts[sandboxID] = map[string]struct{}{}
		}
		w.sandboxHosts[sandboxID][host] = struct{}{}
	}
}

func (w *indexRouteWriter) remove(routeID, host string) {
	w.table.Delete(host)
	w.mu.Lock()
	defer w.mu.Unlock()
	if routeID != "" {
		delete(w.routeHosts, routeID)
	}
}

func (w *indexRouteWriter) UpsertSandboxRoute(_ context.Context, id, containerIP string, toolboxPort int, customs []caddy.CustomHostnameRoute) error {
	ip := net.ParseIP(containerIP)
	w.set(caddy.SandboxRouteID(id), id, w.rootHost(id), routedns.OwnerTarget{IP: ip, Port: toolboxPort, SandboxID: id, GuestPort: toolboxPort})
	for _, c := range customs {
		t := routedns.OwnerTarget{IP: ip, Port: c.TargetPort, SandboxID: id, GuestPort: c.TargetPort}
		if c.TargetPort == 0 {
			t.Port, t.GuestPort = toolboxPort, toolboxPort
		}
		if c.MaskRequestHost != "" {
			t.State = routedns.TargetRouter
		}
		w.set("", id, c.Hostname, t)
	}
	return nil
}

// UpsertSandboxRouteToPeer is IP mode (path routing to a peer); the static
// design is domain mode only.
func (w *indexRouteWriter) UpsertSandboxRouteToPeer(context.Context, string, string, []string) error {
	return nil
}

func (w *indexRouteWriter) DeleteSandboxRoute(_ context.Context, id string) error {
	// The root route carried the root host and the sandbox's custom
	// hostnames; port routes have their own deletes and are not tracked here.
	w.mu.Lock()
	hosts := w.sandboxHosts[id]
	delete(w.sandboxHosts, id)
	delete(w.routeHosts, caddy.SandboxRouteID(id))
	w.mu.Unlock()
	w.table.Delete(w.rootHost(id))
	for h := range hosts {
		w.table.Delete(h)
	}
	return nil
}

func (w *indexRouteWriter) upsertPort(id, containerIP string, port int, opts []caddy.HTTPRouteOptions) {
	t := routedns.OwnerTarget{IP: net.ParseIP(containerIP), Port: port, SandboxID: id, GuestPort: port}
	if masked(opts) {
		t.State = routedns.TargetRouter
	}
	w.set(caddy.PortRouteID(id, port), "", w.portHost(id, port), t)
}

func (w *indexRouteWriter) UpsertPortRoute(_ context.Context, id, containerIP string, port int, opts ...caddy.HTTPRouteOptions) error {
	w.upsertPort(id, containerIP, port, opts)
	return nil
}

func (w *indexRouteWriter) UpsertPortRouteWithRetry(_ context.Context, id, containerIP string, port int, _ time.Duration, opts ...caddy.HTTPRouteOptions) error {
	w.upsertPort(id, containerIP, port, opts)
	return nil
}

// UpsertPortRouteWithDial carries a full dial (WASM/isolate loopback
// mediators). The responder never answers loopback, so these always take the
// router, which knows the mediator.
func (w *indexRouteWriter) UpsertPortRouteWithDial(_ context.Context, id string, guestPort int, dial string, opts ...caddy.HTTPRouteOptions) error {
	ip, port := dialIP(dial)
	t := routedns.OwnerTarget{IP: ip, Port: port, SandboxID: id, GuestPort: guestPort}
	if masked(opts) || ip == nil || port != guestPort {
		t.State = routedns.TargetRouter
	}
	w.set(caddy.PortRouteID(id, guestPort), "", w.portHost(id, guestPort), t)
	return nil
}

func (w *indexRouteWriter) UpsertPortRouteToPeer(context.Context, string, int, string) error {
	return nil
}

func (w *indexRouteWriter) DeletePortRoute(_ context.Context, id string, port int) error {
	w.remove(caddy.PortRouteID(id, port), w.portHost(id, port))
	return nil
}

func (w *indexRouteWriter) UpsertWakeHTTPPortRoute(_ context.Context, id, _ string, port int) error {
	host := w.portHost(id, port)
	w.table.Set(host, routedns.OwnerTarget{State: routedns.TargetWake, SandboxID: id, GuestPort: port})
	w.mu.Lock()
	w.routeHosts[caddy.WakePortRouteID(id, port)] = host
	w.mu.Unlock()
	return nil
}

// DeleteWakeHTTPPortRoute removes only a wake entry: in Caddy the wake route
// and the direct route are distinct, and the direct route (if any) is
// re-installed by its own upsert.
func (w *indexRouteWriter) DeleteWakeHTTPPortRoute(_ context.Context, id string, port int) error {
	host := w.portHost(id, port)
	if t, ok := w.table.Lookup(host); ok && t.State == routedns.TargetWake {
		w.table.Delete(host)
	}
	w.mu.Lock()
	delete(w.routeHosts, caddy.WakePortRouteID(id, port))
	w.mu.Unlock()
	return nil
}

func (w *indexRouteWriter) UpsertInFluxSandboxRoute(_ context.Context, id string) error {
	w.table.SetState(w.rootHost(id), routedns.TargetInFlux)
	return nil
}

func (w *indexRouteWriter) DeleteInFluxSandboxRoute(_ context.Context, id string) error {
	if t, ok := w.table.Lookup(w.rootHost(id)); ok && t.State == routedns.TargetInFlux {
		w.table.Delete(w.rootHost(id))
	}
	return nil
}

func (w *indexRouteWriter) UpsertInFluxPortRoute(_ context.Context, id string, port int) error {
	w.table.SetState(w.portHost(id, port), routedns.TargetInFlux)
	return nil
}

func (w *indexRouteWriter) DeleteInFluxPortRoute(_ context.Context, id string, port int) error {
	host := w.portHost(id, port)
	if t, ok := w.table.Lookup(host); ok && t.State == routedns.TargetInFlux {
		w.table.Delete(host)
	}
	return nil
}

func (w *indexRouteWriter) UpsertCustomDomainHTTPRouteWithDial(_ context.Context, sandboxID, hostname, dial string, opts ...caddy.HTTPRouteOptions) error {
	ip, port := dialIP(dial)
	t := routedns.OwnerTarget{IP: ip, Port: port, SandboxID: sandboxID, GuestPort: port}
	if masked(opts) || ip == nil {
		t.State = routedns.TargetRouter
	}
	w.set(caddy.IngressCustomDomainHTTPRouteID(sandboxID, hostname), sandboxID, hostname, t)
	return nil
}

func (w *indexRouteWriter) DeleteCustomDomainHTTPRoute(_ context.Context, sandboxID, hostname string) error {
	w.remove(caddy.IngressCustomDomainHTTPRouteID(sandboxID, hostname), hostname)
	w.mu.Lock()
	delete(w.sandboxHosts[sandboxID], hostname)
	w.mu.Unlock()
	return nil
}

// UpsertSNIPassthroughRoute is a no-op: the ingress index comes from the
// placement view (IngressIndex), not from these intents.
func (w *indexRouteWriter) UpsertSNIPassthroughRoute(context.Context, string, string, string, int) error {
	return nil
}

// Raw TCP (review T7, "kernel DNAT"): host ports are forwarded by the kernel
// through w.tcp, not Caddy. Sessions live in conntrack, so they survive
// sandboxd restarts, and bytes never pass through sandboxd. With no
// forwarder wired (w.tcp nil) these stay no-ops.

// UpsertTCPRoute (owner): DNAT the host port to the sandbox. A loopback or
// unparsable target (a WASM/isolate mediator) can't be reached by the kernel
// from outside, so it is REDIRECTed to the sandboxd listener, which splices
// it through the wake path.
func (w *indexRouteWriter) UpsertTCPRoute(_ context.Context, _ string, containerIP string, port, hostPort int) error {
	if w.tcp == nil {
		return nil
	}
	ip, err := netip.ParseAddr(containerIP)
	if err != nil || ip.IsLoopback() || !ip.Is4() {
		return w.tcp.Ensure(hostPort, hostport.Target{Kind: hostport.Redirect, RedirectPort: w.redirectPort})
	}
	return w.tcp.Ensure(hostPort, hostport.Target{Kind: hostport.DNAT, Addr: netip.AddrPortFrom(ip, uint16(port))})
}

// UpsertWakeTCPRoute (owner, stopped serverless): REDIRECT to the sandboxd
// listener, which wakes the sandbox and splices the connection that woke it.
func (w *indexRouteWriter) UpsertWakeTCPRoute(_ context.Context, _ string, _ int, hostPort int, _ string) error {
	if w.tcp == nil {
		return nil
	}
	return w.tcp.Ensure(hostPort, hostport.Target{Kind: hostport.Redirect, RedirectPort: w.redirectPort})
}

// UpsertTCPProxyRoute (ingress): DNAT to the owner's host port WITH
// masquerade, so the owner replies through this ingress. A DNS-name owner
// host is resolved once per call (kernel NAT needs an address).
func (w *indexRouteWriter) UpsertTCPProxyRoute(_ context.Context, _ string, _ int, hostPort int, peerHost string, peerPort int) error {
	if w.tcp == nil {
		return nil
	}
	ip, err := w.resolveIPv4(peerHost)
	if err != nil {
		return fmt.Errorf("tcp host port %d: owner %q: %w", hostPort, peerHost, err)
	}
	return w.tcp.Ensure(hostPort, hostport.Target{Kind: hostport.DNAT, Addr: netip.AddrPortFrom(ip, uint16(peerPort)), Masquerade: true})
}

func (w *indexRouteWriter) DeleteTCPRoute(_ context.Context, hostPort int) error {
	if w.tcp == nil {
		return nil
	}
	return w.tcp.Remove(hostPort)
}

// DeleteTCPServer removes the "tcp-port-<hp>" server Caddy used to hold:
// here, that host port's forwarding.
func (w *indexRouteWriter) DeleteTCPServer(_ context.Context, serverID string) error {
	if w.tcp == nil {
		return nil
	}
	n, ok := strings.CutPrefix(serverID, "tcp-port-")
	if !ok {
		return nil
	}
	hp, err := strconv.Atoi(n)
	if err != nil {
		return nil
	}
	return w.tcp.Remove(hp)
}

func (w *indexRouteWriter) resolveIPv4(host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() {
			return netip.Addr{}, fmt.Errorf("not an IPv4 address")
		}
		return ip, nil
	}
	lookup := w.lookupIP
	if lookup == nil {
		lookup = net.LookupIP
	}
	ips, err := lookup(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			a, _ := netip.AddrFromSlice(v4)
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address")
}

// DeleteRouteByID mirrors reconcile GC: whatever host that route ID would
// have matched is dropped.
func (w *indexRouteWriter) DeleteRouteByID(_ context.Context, routeID string) error {
	w.mu.Lock()
	host, ok := w.routeHosts[routeID]
	delete(w.routeHosts, routeID)
	w.mu.Unlock()
	if ok {
		w.table.Delete(host)
	}
	return nil
}
