package gatewayd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
)

// bound is one bridge's listener set: DNS over UDP and TCP, and the proxy.
type bound struct {
	ip       netip.Addr
	dnsUDP   *dns.Server
	dnsTCP   *dns.Server
	proxyLn  net.Listener
	addrs    []string
	shutdown func()
}

// bridgeListeners binds the DNS filter and proxy on each sandbox bridge's
// gateway IP. REDIRECT rewrites the destination to the incoming interface's
// primary address, so binding there (not a wildcard) keeps the listeners off
// every other interface; IP_FREEBIND lets the bind succeed before a bridge
// such as aerolvm0 has its first address. The Firecracker TAP pool is the
// exception (egress.TapPoolBridge): one host address per TAP, so with it
// present a single wildcard set serves every bridge, behind the input
// guard that drops the ports from any source not in gateway mode.
type bridgeListeners struct {
	mu        sync.Mutex
	dnsPort   uint16
	proxyPort uint16
	dns       dns.Handler
	serve     func(net.Listener)
	listen    func(network, addr string) (net.Listener, net.PacketConn, error)
	byIP      map[netip.Addr]*bound
	bridges   []egress.Bridge
	log       *slog.Logger
}

func newBridgeListeners(dnsPort, proxyPort uint16, h dns.Handler, serve func(net.Listener), listen func(network, addr string) (net.Listener, net.PacketConn, error), log *slog.Logger) *bridgeListeners {
	return &bridgeListeners{dnsPort: dnsPort, proxyPort: proxyPort, dns: h, serve: serve, listen: listen, byIP: map[netip.Addr]*bound{}, log: log}
}

// Set binds new bridges and closes removed ones. Addresses still wanted
// keep their listeners. Removals go first, so a move to or from the
// wildcard can take the ports.
func (b *bridgeListeners) Set(bridges []egress.Bridge) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	wildcard := false
	for _, br := range bridges {
		if !br.GatewayIP.Is4() {
			return fmt.Errorf("bridge %s: gateway IP %q is not IPv4 (gateway mode refuses IPv6 bridges, CEO D18)", br.Name, br.GatewayIP)
		}
		wildcard = wildcard || br.Wildcard()
	}
	want := map[netip.Addr]string{}
	for _, br := range bridges {
		if wildcard {
			want[netip.IPv4Unspecified()] = "*"
			break
		}
		want[br.GatewayIP] = br.Name
	}
	var errs []error
	for ip, cur := range b.byIP {
		if _, ok := want[ip]; !ok {
			cur.shutdown()
			delete(b.byIP, ip)
		}
	}
	for ip, name := range want {
		if _, ok := b.byIP[ip]; ok {
			continue
		}
		bd, err := b.bind(ip)
		if err != nil {
			errs = append(errs, fmt.Errorf("bridge %s: %w", name, err))
			continue
		}
		b.byIP[ip] = bd
	}
	b.bridges = append([]egress.Bridge(nil), bridges...)
	return errors.Join(errs...)
}

func (b *bridgeListeners) bind(ip netip.Addr) (*bound, error) {
	dnsAddr := net.JoinHostPort(ip.String(), strconv.Itoa(int(b.dnsPort)))
	proxyAddr := net.JoinHostPort(ip.String(), strconv.Itoa(int(b.proxyPort)))
	_, pc, err := b.listen("udp", dnsAddr)
	if err != nil {
		return nil, fmt.Errorf("dns udp %s: %w", dnsAddr, err)
	}
	tcpLn, _, err := b.listen("tcp", dnsAddr)
	if err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("dns tcp %s: %w", dnsAddr, err)
	}
	proxyLn, _, err := b.listen("tcp", proxyAddr)
	if err != nil {
		_ = pc.Close()
		_ = tcpLn.Close()
		return nil, fmt.Errorf("proxy %s: %w", proxyAddr, err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: b.dns}
	tcp := &dns.Server{Listener: tcpLn, Handler: b.dns}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	go b.serve(proxyLn)
	bd := &bound{ip: ip, dnsUDP: udp, dnsTCP: tcp, proxyLn: proxyLn,
		addrs: []string{"udp:" + pc.LocalAddr().String(), "tcp:" + tcpLn.Addr().String(), "proxy:" + proxyLn.Addr().String()}}
	bd.shutdown = func() {
		_ = udp.ShutdownContext(context.Background())
		_ = tcp.ShutdownContext(context.Background())
		// Shutdown is a no-op on a server whose serve goroutine hasn't
		// started yet; the sockets must still go, or a rebind of the port
		// (on the wildcard) fails.
		_ = pc.Close()
		_ = tcpLn.Close()
		_ = proxyLn.Close()
	}
	b.log.Info("egress: listeners bound", "ip", ip, "dns_port", b.dnsPort, "proxy_port", b.proxyPort)
	return bd, nil
}

// Addrs lists the bound addresses (Ready).
func (b *bridgeListeners) Addrs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, bd := range b.byIP {
		out = append(out, bd.addrs...)
	}
	sort.Strings(out)
	return out
}

// Bridges returns the last bridge list (snapshotted).
func (b *bridgeListeners) Bridges() []egress.Bridge {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]egress.Bridge(nil), b.bridges...)
}

// Close shuts every listener.
func (b *bridgeListeners) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ip, bd := range b.byIP {
		bd.shutdown()
		delete(b.byIP, ip)
	}
}

// listenFreebind is the production listen: IP_FREEBIND on every socket.
func listenFreebind(network, addr string) (net.Listener, net.PacketConn, error) {
	lc := net.ListenConfig{Control: freebindControl}
	if network == "udp" {
		pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
		return nil, pc, err
	}
	ln, err := lc.Listen(context.Background(), "tcp4", addr)
	return ln, nil, err
}
