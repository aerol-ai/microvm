//go:build !linux

package rootd

// havePeerCred: off Linux egress.UnixPeerCheck lets every peer in, so the
// helper refuses to start without a check of its own.
const havePeerCred = false
