//go:build linux

package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// bridgeNFCallIPTables must read 1 for bridged sandbox-to-sandbox traffic
// to hit the redirect (CEO D18); sandboxd sets it at gateway bootstrap.
var bridgeNFCallIPTables = "/proc/sys/net/bridge/bridge-nf-call-iptables"

// probeTargets are TEST-NET-1 addresses: never routable, so the probe can
// only be answered by the redirect.
var (
	probeDNSTarget = "192.0.2.53:53"
	probeTCPTarget = "192.0.2.1:443"
)

// NewProbeNet returns the netlink-backed probe network builder.
func NewProbeNet() ProbeNet { return linuxProbeNet{} }

type linuxProbeNet struct{}

func (linuxProbeNet) Setup(_ context.Context, b Bridge, src netip.Addr, index int) (ProbeEnv, error) {
	br, err := netlink.LinkByName(b.Name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil, ErrBridgeAbsent
		}
		return nil, err
	}
	if v6, _ := netlink.AddrList(br, netlink.FAMILY_V6); hasGlobalV6(v6) {
		return nil, fmt.Errorf("%w: bridge %s carries IPv6, which the gateway does not redirect (CEO D18)", ErrSelfTest, b.Name)
	}
	if v, err := os.ReadFile(bridgeNFCallIPTables); err != nil || strings.TrimSpace(string(v)) != "1" {
		return nil, fmt.Errorf("%w: %s is not 1, so bridged traffic bypasses the redirect (load br_netfilter)", ErrSelfTest, bridgeNFCallIPTables)
	}
	e := &linuxProbeEnv{
		nsName: fmt.Sprintf("aerolvm-egprobe%d", index),
		hostIf: fmt.Sprintf("egprobe%dh", index),
		nsIf:   fmt.Sprintf("egprobe%dn", index),
		src:    src,
		brIdx:  br.Attrs().Index,
	}
	e.cleanup() // a probe from a crashed run
	if err := e.build(b.GatewayIP); err != nil {
		_ = e.Close()
		return nil, err
	}
	return e, nil
}

func hasGlobalV6(addrs []netlink.Addr) bool {
	for _, a := range addrs {
		if a.IP != nil && a.IP.To4() == nil && a.IP.IsGlobalUnicast() {
			return true
		}
	}
	return false
}

type linuxProbeEnv struct {
	nsName, hostIf, nsIf string
	src                  netip.Addr
	brIdx                int
	ns                   netns.NsHandle
}

func (e *linuxProbeEnv) build(gw netip.Addr) error {
	ns, err := newNamedNetns(e.nsName)
	if err != nil {
		return fmt.Errorf("probe netns: %w", err)
	}
	e.ns = ns
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: e.hostIf, MasterIndex: e.brIdx}, PeerName: e.nsIf}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("probe veth: %w", err)
	}
	host, err := netlink.LinkByName(e.hostIf)
	if err != nil {
		return err
	}
	peer, err := netlink.LinkByName(e.nsIf)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetNsFd(peer, int(ns)); err != nil {
		return fmt.Errorf("move probe veth: %w", err)
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return err
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return err
	}
	defer h.Close()
	if lo, err := h.LinkByName("lo"); err == nil {
		_ = h.LinkSetUp(lo)
	}
	in, err := h.LinkByName(e.nsIf)
	if err != nil {
		return err
	}
	if err := h.LinkSetUp(in); err != nil {
		return err
	}
	if err := h.AddrAdd(in, &netlink.Addr{IPNet: hostNet(e.src)}); err != nil {
		return fmt.Errorf("probe address: %w", err)
	}
	// The /32 has no subnet, so reach the bridge's gateway by an on-link
	// route, then route everything through it.
	if err := h.RouteAdd(&netlink.Route{LinkIndex: in.Attrs().Index, Dst: hostNet(gw), Scope: netlink.SCOPE_LINK}); err != nil {
		return fmt.Errorf("probe gateway route: %w", err)
	}
	if err := h.RouteAdd(&netlink.Route{LinkIndex: in.Attrs().Index, Gw: gw.AsSlice()}); err != nil {
		return fmt.Errorf("probe default route: %w", err)
	}
	// And the host's way back to the probe address.
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: e.brIdx, Dst: hostNet(e.src), Scope: netlink.SCOPE_LINK}); err != nil {
		return fmt.Errorf("probe host route: %w", err)
	}
	return nil
}

func hostNet(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

// Send runs on a goroutine locked to a thread that enters the probe netns.
// Sockets keep the netns they were created in, so both are opened there.
// If the thread can't be put back it is never unlocked, and Go retires it
// with the goroutine instead of reusing a thread in the wrong netns.
func (e *linuxProbeEnv) Send(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			errc <- err
			return
		}
		defer orig.Close()
		if err := netns.Set(e.ns); err != nil {
			errc <- err
			return
		}
		sendErr := sendProbeFlows(ctx)
		if err := netns.Set(orig); err != nil {
			errc <- errors.Join(sendErr, err)
			return
		}
		runtime.UnlockOSThread()
		errc <- sendErr
	}()
	return <-errc
}

func sendProbeFlows(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var d net.Dialer
	var errs []error
	if c, err := d.DialContext(ctx, "udp4", probeDNSTarget); err != nil {
		errs = append(errs, fmt.Errorf("dns: %w", err))
	} else {
		_, err := c.Write(probeDNSQuery)
		_ = c.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("dns: %w", err))
		}
	}
	if c, err := d.DialContext(ctx, "tcp4", probeTCPTarget); err != nil {
		errs = append(errs, fmt.Errorf("tcp: %w", err))
	} else {
		_ = c.Close()
	}
	return errors.Join(errs...)
}

// probeDNSQuery is a standard query for "aerolvm-probe.invalid. A".
var probeDNSQuery = func() []byte {
	q := []byte{0xae, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"aerolvm-probe", "invalid"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}()

func (e *linuxProbeEnv) Close() error {
	if e.ns != 0 {
		_ = e.ns.Close()
		e.ns = 0
	}
	e.cleanup()
	return nil
}

// cleanup removes everything a probe may have created; each step tolerates
// it being gone already.
func (e *linuxProbeEnv) cleanup() {
	_ = netlink.RouteDel(&netlink.Route{LinkIndex: e.brIdx, Dst: hostNet(e.src), Scope: netlink.SCOPE_LINK})
	if l, err := netlink.LinkByName(e.hostIf); err == nil {
		_ = netlink.LinkDel(l) // takes the peer with it
	}
	_ = netns.DeleteNamed(e.nsName)
}

// newNamedNetns creates a named netns without leaving the calling thread in
// it: netns.NewNamed switches the current thread, so it runs on a locked
// thread that switches back (and is retired if it can't).
func newNamedNetns(name string) (netns.NsHandle, error) {
	type result struct {
		ns  netns.NsHandle
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer orig.Close()
		ns, err := netns.NewNamed(name)
		if serr := netns.Set(orig); serr != nil {
			if err == nil {
				_ = ns.Close()
			}
			ch <- result{err: errors.Join(err, serr)}
			return
		}
		runtime.UnlockOSThread()
		ch <- result{ns: ns, err: err}
	}()
	r := <-ch
	return r.ns, r.err
}
