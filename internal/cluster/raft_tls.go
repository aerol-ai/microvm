package cluster

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/raft"
)

// tlsStreamLayer is the raft.StreamLayer that wraps the raw TCP transport in
// mTLS. It satisfies both raft.StreamLayer (Accept/Close/Addr/Dial) and
// net.Listener — same surface, different package.
//
// We cannot use raft.NewTCPTransport here because that helper builds its own
// listener and gives us no seam to add TLS. Instead we listen + dial ourselves
// and hand the resulting StreamLayer to raft.NewNetworkTransport.
type tlsStreamLayer struct {
	listener  net.Listener
	advertise net.Addr
	tlsConfig *tls.Config // client config — the listener already wraps server-side
}

// Dial opens an outbound TLS connection to addr. The peer must present a cert
// chained to the cluster CA (the *tls.Config carries RootCAs); failures here
// surface to raft as "could not contact peer", which it retries.
func (s *tlsStreamLayer) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(dialer, "tcp", string(addr), s.tlsConfig)
}

func (s *tlsStreamLayer) Accept() (net.Conn, error) { return s.listener.Accept() }
func (s *tlsStreamLayer) Close() error              { return s.listener.Close() }
func (s *tlsStreamLayer) Addr() net.Addr            { return s.advertise }

// newTLSStreamLayer binds a TLS listener on bindAddr (server-side mTLS via
// serverCfg) and returns a StreamLayer suitable for
// raft.NewNetworkTransportWithConfig.
func newTLSStreamLayer(bindAddr string, advertise net.Addr, serverCfg, clientCfg *tls.Config) (*tlsStreamLayer, error) {
	if serverCfg == nil || clientCfg == nil {
		return nil, errors.New("cluster raft tls: server and client TLS configs are required")
	}
	ln, err := tls.Listen("tcp", bindAddr, serverCfg)
	if err != nil {
		return nil, fmt.Errorf("cluster raft tls: listen on %q: %w", bindAddr, err)
	}
	return &tlsStreamLayer{
		listener:  ln,
		advertise: advertise,
		tlsConfig: clientCfg,
	}, nil
}
