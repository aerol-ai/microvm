// Package nsbuild builds and tears down a containerd sandbox's network
// namespace: the named namespace under the netns folder, loopback up, IPv6
// off, and the CNI attachment to the sandboxes' bridge.
//
// Two processes run it. sandboxd does, in its own process, when it runs as
// root (privilege mode single, internal/network/netns.Host); the root
// helper does, for a sandboxd that runs with no rights (privilege mode
// split, internal/rootd). It lives apart from the netns pool, which keeps
// its bookkeeping in sandboxd's store, so the helper runs exactly these
// steps without linking the store: one sequence, two callers, no drift.
package nsbuild

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

// Steps are the parts of a build and a teardown a caller supplies: the CNI
// runner and, for each namespace step, the function that does it (the
// primitives in this package, or a test's stand-ins).
type Steps struct {
	Runner cni.Runner
	// Root is the netns folder (/run/netns).
	Root string
	// Create makes the named namespace at <Root>/<name>; an existing one
	// is success. LoopbackUp sets lo up in it; Delete removes it, a
	// missing one being success.
	Create     func(ctx context.Context, name string) error
	LoopbackUp func(ctx context.Context, name string) error
	Delete     func(ctx context.Context, name string) error
	// DisableIPv6 turns IPv6 off inside the namespace at a path.
	DisableIPv6 func(path string) error
	// FlushConntrack drops the connection tracking of an address; nil is
	// hostnet.FlushConntrackForIP.
	FlushConntrack func(ctx context.Context, ip string) error
	// StopOnCancel ends a teardown between steps once ctx is done, so no
	// step (no child process) starts for a call its caller gave up on.
	StopOnCancel bool
}

// Realize builds name's namespace and attaches it to the bridge, and
// answers its path and the address CNI gave it. One name keys the
// namespace AND the CNI container id; Remove takes the same name back. On
// any failure everything it made is undone.
func (s Steps) Realize(ctx context.Context, name string) (string, string, error) {
	// Create a REAL network namespace, not just a directory: the CNI plugin and
	// the containerd shim both open this path as a netns. createNetns bind-
	// mounts a fresh netns at <root>/<name>; a plain mkdir'd directory makes
	// CNI ADD fail with a bare "exit status 1" (the plugin cannot enter a dir).
	if err := s.Create(ctx, name); err != nil {
		return "", "", fmt.Errorf("netns host: create netns %s: %w", name, err)
	}
	// A fresh netns has loopback DOWN, and the CNI runner invokes only the bridge
	// plugin (cni.resolve reduces the conflist to plugins[0]), so nothing brings
	// lo up. Without this, 127.0.0.1 / localhost TCP inside the sandbox times out
	// even though a service binds 0.0.0.0 — breaking any app that dials localhost
	// (postgres, redis, dev servers, multi-process apps). Do it before CNI ADD so
	// the namespace is fully usable the instant the container attaches; roll back
	// the netns on failure, mirroring the CNI ADD path below.
	if err := s.LoopbackUp(ctx, name); err != nil {
		_ = s.Delete(ctx, name)
		return "", "", fmt.Errorf("netns host: loopback up %s: %w", name, err)
	}
	path := filepath.Join(s.Root, name)
	// IPv6 off before the sandbox's interface exists: "default" is what the
	// veth CNI ADD creates in here starts with, so it never gets a
	// link-local address a neighbour on the bridge could reach (every host
	// rule between sandboxes is IPv4). Prewarmed slots come through here
	// too.
	if err := s.DisableIPv6(path); err != nil {
		_ = s.Delete(ctx, name)
		return "", "", fmt.Errorf("netns host: disable ipv6 in %s: %w", name, err)
	}
	res, err := s.Runner.Add(ctx, path, name)
	if err != nil {
		_ = s.Delete(ctx, name)
		return "", "", fmt.Errorf("netns host: cni add: %w", err)
	}
	// And again after: IPAM turns IPv6 back on for an interface it gives an
	// IPv6 address (an operator conflist with a v6 range). "all" switches
	// it off on every interface there. The ADD succeeded, so a failure
	// here undoes all of it, as Remove would.
	if err := s.DisableIPv6(path); err != nil {
		rmErr := s.Remove(ctx, name, path, res.IP4)
		return "", "", errors.Join(fmt.Errorf("netns host: disable ipv6 in %s after cni add: %w", name, err), rmErr)
	}
	return path, res.IP4, nil
}

// Remove deletes everything Realize made for name: the CNI attachment
// (veth, host-local lease, masquerade chain), conntrack entries for ip, and
// the named netns at path. Errors are joined, never swallowed: the pool
// keeps a slot out of circulation until Remove succeeds.
func (s Steps) Remove(ctx context.Context, name, path, ip string) error {
	delErr := s.Runner.Del(ctx, path, name)
	if s.StopOnCancel && ctx.Err() != nil {
		return errors.Join(delErr, ctx.Err())
	}
	// The bridge plugin's DEL removes the masquerade chain only for addresses
	// it still finds on the container interface. gVisor (runsc, network=sandbox)
	// moves the address into its own netstack and deletes it from that
	// interface at start, so for every gVisor sandbox DEL finds nothing and the
	// chain plus its POSTROUTING jump stay behind. Tear them down by identity.
	var masqErr error
	if t, ok := s.Runner.(cni.IPMasqTeardown); ok {
		masqErr = t.TeardownIPMasq(ctx, name, ip)
	}
	if s.FlushConntrack != nil {
		if s.StopOnCancel && ctx.Err() != nil {
			return errors.Join(delErr, masqErr, ctx.Err())
		}
		_ = s.FlushConntrack(ctx, ip)
	} else {
		_ = hostnet.FlushConntrackForIP(ip)
	}
	rmErr := s.Delete(ctx, name)
	return errors.Join(delErr, masqErr, rmErr)
}
