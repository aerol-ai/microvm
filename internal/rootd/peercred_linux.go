//go:build linux

package rootd

// havePeerCred: egress.UnixPeerCheck reads SO_PEERCRED here.
const havePeerCred = true
