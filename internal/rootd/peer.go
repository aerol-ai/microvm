package rootd

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/credentials"

	"github.com/aerol-ai/microvm/internal/egress"
)

// peerCreds runs the peer check as gRPC's transport handshake. gRPC calls
// it once per connection, on that connection's own goroutine and before it
// reads a byte, so a refused peer never reaches a handler, and a slow one
// does not hold up the accept loop. There is nothing to encrypt on a local
// socket; this only decides who may talk.
type peerCreds struct {
	check   egress.PeerCheck
	refused func(error)
}

func (p peerCreds) ServerHandshake(c net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if err := p.check(c); err != nil {
		p.refused(err)
		return nil, nil, fmt.Errorf("root helper: %w", err)
	}
	return c, peerInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity}}, nil
}

func (peerCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("root helper: these credentials are for the server")
}

func (peerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

func (p peerCreds) Clone() credentials.TransportCredentials { return p }

func (peerCreds) OverrideServerName(string) error { return nil }

type peerInfo struct{ credentials.CommonAuthInfo }

func (peerInfo) AuthType() string { return "peercred" }
