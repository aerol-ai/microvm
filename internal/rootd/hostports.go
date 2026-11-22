package rootd

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// Raw-TCP host-port forwarding for ingress proxy routing (M1 PR 5b): the
// kernel rules sandboxd's hostport.Forwarder writes in privilege mode
// single, written here in split. A forward takes traffic to one of this
// node's ports and hands it on, so the helper bounds both ends from its
// own settings and the kernel's word, never from the agent's:
//
//   - the port taken is one of the node's host-port range (HostPortBounds,
//     the helper's SB_L4_PORT_RANGE_START/END): never a port the node's
//     own services listen on;
//   - a sandbox target is an address the helper's CNI leased to a slot
//     (not the bridge's own address, not another runtime's);
//   - a peer target (an ingress node's hop to a sandbox's owner) is
//     another node's host port: no sandbox's address, and none of this
//     node's own addresses by the kernel's list;
//   - a redirect goes to the helper's SB_HOSTPORT_REDIRECT_PORT alone,
//     sandboxd's own listener.
//
// The calls write the kernel's rules as they should be, whatever wrote
// them before (hostport.Forwarder.Set and Reconcile): a helper that
// restarts keeps no memory of the rules, and must still replace or remove
// an earlier helper's. None is on the create path: the agent's route index
// writer forwards a port when it is exposed, woken or moved, and makes the
// set exact once at boot.

// HostPortHost is the kernel work behind HostPort: the helper's own
// forwarder on Linux (hostports_linux.go), a fake in tests.
type HostPortHost interface {
	// Set makes hp's forward exactly t, or none with t nil.
	Set(hp int, t *hostport.Target) error
	// Reconcile makes the node's forwards exactly desired.
	Reconcile(desired map[int]hostport.Target) error
	// IsLocal reports whether a is one of this node's own addresses.
	IsLocal(a netip.Addr) (bool, error)
}

// hostPortCalls serves HostPort; nil without a network configuration
// (a sandbox target's lease and the sandboxes' range come from it).
type hostPortCalls struct {
	net    *network
	bounds rootpolicy.HostPortBounds
	locks  *keyedLocks
	open   func() (HostPortHost, error)

	mu   sync.Mutex
	host HostPortHost
}

var hostPortFeatures = []string{rootdpb.FeatureHostPort}

func newHostPortCalls(cfg Config, net *network, injected HostPortHost, locks *keyedLocks) *hostPortCalls {
	if net == nil {
		return nil
	}
	open := openHostPorts
	if injected != nil {
		open = func() (HostPortHost, error) { return injected, nil }
	}
	return &hostPortCalls{net: net, bounds: cfg.HostPorts, locks: locks, open: open}
}

// opened is the kernel forwarder, opened on the first call; a failed open
// is tried again on the next.
func (h *hostPortCalls) opened() (HostPortHost, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.host != nil {
		return h.host, nil
	}
	host, err := h.open()
	if err != nil {
		return nil, &fileError{code: codes.FailedPrecondition, msg: "root helper: host-port forwarding is not available on this node: " + err.Error()}
	}
	h.host = host
	return host, nil
}

// hostPortsKey serializes the node's host-port writes: a reconcile and a
// set must not interleave (the agent's adapter does the same).
const hostPortsKey = "hostports"

func (h *hostPortCalls) hostPort(ctx context.Context, req *rootdpb.HostPortRequest) (*rootdpb.HostPortResponse, error) {
	n, err := h.net.opened()
	if err != nil {
		return nil, err
	}
	if err := h.bounds.Check(); err != nil {
		return nil, &fileError{code: codes.FailedPrecondition, msg: "root helper: " + err.Error()}
	}
	op := req.GetOp()
	switch op {
	case rootdpb.HostPortOp_HOST_PORT_OP_SET, rootdpb.HostPortOp_HOST_PORT_OP_REMOVE, rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE:
	default:
		return nil, badRequest("root helper: host-port op %v is not one the helper does", op)
	}
	host, err := h.opened()
	if err != nil {
		return nil, err
	}
	unlock, err := h.locks.lock(ctx, hostPortsKey)
	if err != nil {
		return nil, err
	}
	defer unlock()
	resp := &rootdpb.HostPortResponse{}
	switch op {
	case rootdpb.HostPortOp_HOST_PORT_OP_SET:
		if len(req.GetForwards()) != 1 || req.GetHostPort() != 0 {
			return nil, badRequest("root helper: a host-port set names one forward and no host_port")
		}
		hp, t, leased, err := h.forward(n, host, req.GetForwards()[0])
		if err != nil {
			return nil, err
		}
		if !leased {
			return nil, &fileError{code: codes.PermissionDenied, reason: string(rootpolicy.RuleLease),
				msg: fmt.Sprintf("root helper: address %s is not leased to a sandbox; a host port is forwarded only to a sandbox's address", t.Addr.Addr())}
		}
		if err := host.Set(hp, &t); err != nil {
			return nil, fmt.Errorf("root helper: forward host port %d: %w", hp, err)
		}
	case rootdpb.HostPortOp_HOST_PORT_OP_REMOVE:
		if len(req.GetForwards()) != 0 {
			return nil, badRequest("root helper: a host-port remove names host_port alone")
		}
		hp, err := rootpolicy.CheckHostPort(h.bounds, req.GetHostPort())
		if err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
		if err := host.Set(hp, nil); err != nil {
			return nil, fmt.Errorf("root helper: stop forwarding host port %d: %w", hp, err)
		}
	case rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE:
		if req.GetHostPort() != 0 {
			return nil, badRequest("root helper: a host-port reconcile names its forwards alone")
		}
		fwds := req.GetForwards()
		if err := rootpolicy.CheckHostPortCount(h.bounds, len(fwds)); err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
		// Every forward is checked before any is written: a refused list
		// changes nothing.
		desired := make(map[int]hostport.Target, len(fwds))
		for _, f := range fwds {
			hp, t, leased, err := h.forward(n, host, f)
			if err != nil {
				return nil, err
			}
			if _, dup := desired[hp]; dup {
				return nil, refusedRule(codes.InvalidArgument, rootpolicy.HostPortListedTwice(hp))
			}
			if !leased {
				// The sandbox went while the agent made the list: its port
				// is not forwarded, and the agent hears which.
				resp.Skipped = append(resp.Skipped, uint32(hp))
				continue
			}
			desired[hp] = t
		}
		if err := host.Reconcile(desired); err != nil {
			return nil, fmt.Errorf("root helper: host-port reconcile: %w", err)
		}
	}
	return resp, nil
}

// forward checks one forward against its kind's rule. leased is false for
// a sandbox target whose address no slot holds; every other refusal is an
// error.
func (h *hostPortCalls) forward(n NetworkHost, host HostPortHost, f *rootdpb.HostPortForward) (int, hostport.Target, bool, error) {
	hp, err := rootpolicy.CheckHostPort(h.bounds, f.GetHostPort())
	if err != nil {
		return 0, hostport.Target{}, false, refusedRule(codes.InvalidArgument, err)
	}
	switch f.GetKind() {
	case rootdpb.HostPortKind_HOST_PORT_KIND_SANDBOX:
		ap, err := rootpolicy.CheckSandboxTarget(n.Subnet(), f.GetAddress(), f.GetPort())
		if err != nil {
			return 0, hostport.Target{}, false, refusedRule(codes.InvalidArgument, err)
		}
		_, leased, err := n.Leaseholder(ap.Addr())
		if err != nil {
			return 0, hostport.Target{}, false, fmt.Errorf("root helper: lease of %s: %w", ap.Addr(), err)
		}
		return hp, hostport.Target{Kind: hostport.DNAT, Addr: ap}, leased, nil
	case rootdpb.HostPortKind_HOST_PORT_KIND_PEER:
		ap, err := rootpolicy.CheckPeerTarget(h.bounds, n.Subnet(), f.GetAddress(), f.GetPort())
		if err != nil {
			return 0, hostport.Target{}, false, refusedRule(codes.InvalidArgument, err)
		}
		local, err := host.IsLocal(ap.Addr())
		if err != nil {
			return 0, hostport.Target{}, false, fmt.Errorf("root helper: this node's addresses: %w", err)
		}
		if local {
			return 0, hostport.Target{}, false, refusedRule(codes.PermissionDenied, rootpolicy.PeerIsLocal(ap.Addr()))
		}
		return hp, hostport.Target{Kind: hostport.DNAT, Addr: ap, Masquerade: true}, true, nil
	case rootdpb.HostPortKind_HOST_PORT_KIND_REDIRECT:
		port, err := rootpolicy.CheckRedirectTarget(h.bounds, f.GetAddress(), f.GetPort())
		if err != nil {
			return 0, hostport.Target{}, false, refusedRule(codes.InvalidArgument, err)
		}
		return hp, hostport.Target{Kind: hostport.Redirect, RedirectPort: port}, true, nil
	}
	return 0, hostport.Target{}, false, badRequest("root helper: host-port kind %v is not one the helper forwards to", f.GetKind())
}
