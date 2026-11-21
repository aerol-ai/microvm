package rootclient

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// HostPortForwarder is ingress proxy routing's kernel host-port forwarding
// (service.HostPortForwarder) through the root helper, in privilege mode
// split: what hostport.Forwarder does in process in single mode, with the
// same meaning for each method. The helper writes the kernel's rules as
// they should be whatever wrote them before, so a helper restart loses
// nothing; this side keeps what sandboxd asserted since it started, so
// PruneUnasserted makes the node's set exactly that, as the in-process
// forwarder's does.
type HostPortForwarder struct {
	c *Client
	// onSkipped hears the host ports a reconcile left out because their
	// sandbox went while the set was made.
	onSkipped func([]int)

	// mu orders the calls, as the in-process forwarder's lock does: a
	// prune takes the asserted set and writes it under one lock, so a
	// concurrent Ensure is never pruned.
	mu       sync.Mutex
	asserted map[int]hostport.Target
}

// NewHostPortForwarder is c's host-port forwarder; onSkipped may be nil.
func NewHostPortForwarder(c *Client, onSkipped func([]int)) *HostPortForwarder {
	return &HostPortForwarder{c: c, onSkipped: onSkipped, asserted: map[int]hostport.Target{}}
}

// reconcileTimeout bounds a whole-set write: a node's range holds up to a
// thousand ports by default, and the helper writes their rules one by one
// (iptables, as single mode does), longer than one call's usual bound.
const reconcileTimeout = 10 * time.Minute

// Ensure forwards hp to t, replacing what hp had.
func (f *HostPortForwarder) Ensure(hp int, t hostport.Target) error {
	fwd, err := forwardOf(hp, t)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.c.HostPort(context.Background(), &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_SET,
		Forwards: []*rootdpb.HostPortForward{fwd}}); err != nil {
		return fmt.Errorf("host port %d: %w", hp, err)
	}
	f.asserted[hp] = t
	return nil
}

// Remove stops forwarding hp and cuts its tracked connections.
func (f *HostPortForwarder) Remove(hp int) error {
	if hp <= 0 || hp > 65535 {
		return fmt.Errorf("hostport: invalid host port %d", hp)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.c.HostPort(context.Background(), &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_REMOVE,
		HostPort: uint32(hp)}); err != nil {
		return fmt.Errorf("host port %d: %w", hp, err)
	}
	delete(f.asserted, hp)
	return nil
}

// Reconcile makes the node's forwards exactly desired (none: no
// forwarding, the routing rollback).
func (f *HostPortForwarder) Reconcile(desired map[int]hostport.Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reconcileLocked(maps.Clone(desired))
}

// PruneUnasserted makes the node's forwards exactly what was asserted
// since this process started (after the boot re-assert): what is left in
// the kernel belongs to exposures that went while sandboxd was down.
func (f *HostPortForwarder) PruneUnasserted() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reconcileLocked(maps.Clone(f.asserted))
}

func (f *HostPortForwarder) reconcileLocked(desired map[int]hostport.Target) error {
	req := &rootdpb.HostPortRequest{Op: rootdpb.HostPortOp_HOST_PORT_OP_RECONCILE}
	for _, hp := range slices.Sorted(maps.Keys(desired)) {
		fwd, err := forwardOf(hp, desired[hp])
		if err != nil {
			return err
		}
		req.Forwards = append(req.Forwards, fwd)
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()
	skipped, err := f.c.HostPort(ctx, req)
	if err != nil {
		return fmt.Errorf("host-port reconcile: %w", err)
	}
	var left []int
	for _, hp := range skipped {
		delete(desired, int(hp))
		left = append(left, int(hp))
	}
	f.asserted = desired
	if len(left) > 0 && f.onSkipped != nil {
		f.onSkipped(left)
	}
	return nil
}

// forwardOf is a forward as the helper's typed call takes it: a redirect to
// sandboxd's listener, a sandbox on this node, or another node's host port
// (the masqueraded ingress hop).
func forwardOf(hp int, t hostport.Target) (*rootdpb.HostPortForward, error) {
	if hp <= 0 || hp > 65535 {
		return nil, fmt.Errorf("hostport: invalid host port %d", hp)
	}
	f := &rootdpb.HostPortForward{HostPort: uint32(hp)}
	switch {
	case t.Kind == hostport.Redirect:
		f.Kind, f.Port = rootdpb.HostPortKind_HOST_PORT_KIND_REDIRECT, uint32(t.RedirectPort)
	case t.Kind == hostport.DNAT && t.Addr.IsValid():
		f.Kind = rootdpb.HostPortKind_HOST_PORT_KIND_SANDBOX
		if t.Masquerade {
			f.Kind = rootdpb.HostPortKind_HOST_PORT_KIND_PEER
		}
		f.Address, f.Port = t.Addr.Addr().String(), uint32(t.Addr.Port())
	default:
		return nil, fmt.Errorf("hostport: host port %d: no target the helper forwards to", hp)
	}
	return f, nil
}
