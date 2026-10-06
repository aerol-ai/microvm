package wasm

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// ErrNetworkEgressBlocked is returned when quota policy blocks outbound dials.
var ErrNetworkEgressBlocked = errors.New("network egress blocked by quota")

// EgressDeniedError is an egress-policy denial (not a quota block). It names
// the destination and why, so a denial fails fast with a reason instead of
// looking like a broken network (plans/egress-domain-filtering.md CEO D10).
// It matches ErrNetworkEgressBlocked, so engines hand the guest the same
// "blocked" error either way.
type EgressDeniedError struct {
	Host   string
	Port   uint16
	Reason string
}

func (e *EgressDeniedError) Error() string {
	return fmt.Sprintf("aerolvm egress policy: %s:%d not allowed (%s)", e.Host, e.Port, e.Reason)
}

// Is makes the denial match ErrNetworkEgressBlocked.
func (e *EgressDeniedError) Is(target error) bool { return target == ErrNetworkEgressBlocked }

// NetDialer dials outbound TCP for a sandbox. Implementations must enforce
// egress policy and byte accounting (UC-43 NetMediator in the worker).
type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NetworkHook binds a sandbox identity to mediated egress dials for the engine.
type NetworkHook struct {
	SandboxID string
	Dial      NetDialer
	// Meter receives wasip1 sock_accept/recv/send and host-module socket bytes.
	Meter ByteMeter
}

// NetworkAwareEngine exposes per-sandbox network mediation on the default engine.
type NetworkAwareEngine interface {
	Engine
	SetNetworkHook(hook *NetworkHook)
	ClearNetworkHook()
}
