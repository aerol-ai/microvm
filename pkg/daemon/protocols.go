package daemon

import "net/http"

// apiListenerProtocols is the protocol set of the public API listener:
// HTTP/1.1 plus HTTP/2 over cleartext with prior knowledge (h2c). The
// Runloop TS SDK on Node speaks HTTP/2 by default and, on an http:// base
// URL, opens with the HTTP/2 preface instead of an Upgrade — an
// HTTP/1.1-only listener fails every one of its calls. Clients that speak
// HTTP/1.1 are untouched: Go only serves h2c to a connection that starts
// with the preface. TLS in front (Caddy) negotiates h2 itself via ALPN.
func apiListenerProtocols() *http.Protocols {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	return &protocols
}
