package wasm

import (
	"context"
	"errors"
	"net"
)

// ErrNetworkEgressBlocked is returned when quota policy blocks outbound dials.
var ErrNetworkEgressBlocked = errors.New("network egress blocked by quota")

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
