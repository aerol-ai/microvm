// Package toolboxhttp is the HTTP transport sandboxd uses to reach a
// sandbox's toolbox over the network.
package toolboxhttp

import (
	"net/http"
	"time"
)

// Transport never keeps a connection open between calls. A sandbox's
// address outlives it: the next sandbox on the same Firecracker TAP slot or
// container IP gets it, and a VM restarted or resumed there has a fresh
// kernel. A pooled keep-alive connection to the old sandbox would be sent to
// the new one and reset (live: 72 of 80 concurrent execs into a fresh
// Firecracker sandbox, and a quarter of a create/exec/destroy churn, failed
// with 502 "connection reset by peer"). A local handshake per call costs
// tens of microseconds. WebSocket upgrades are unaffected: Go never marks a
// protocol switch "Connection: close", and an upgraded connection is never
// pooled.
var Transport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableKeepAlives = true
	return t
}()

// Client is an http.Client over Transport (timeout 0: none).
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: Transport, Timeout: timeout}
}
