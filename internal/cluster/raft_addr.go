package cluster

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
)

// nameAddr is a Raft advertise address kept as a DNS name (C4). On
// Kubernetes a server pod gets a new IP when it moves; the name its headless
// Service gives it keeps pointing at it, where an IP written into the Raft
// configuration would point at nothing. The configuration records the name,
// and every connection the transport opens resolves it again, so peers
// follow the pod. TLS does not care: peers are checked against the fixed
// clusterServerName, not the dialed host.
type nameAddr string

func (a nameAddr) Network() string { return "tcp" }
func (a nameAddr) String() string  { return string(a) }

// raftAdvertiseAddr is the address Raft records for this node. A DNS name
// with a fixed port stays a name; anything else (an IP, an empty value, a
// malformed one) goes through net.ResolveTCPAddr exactly as before, so an
// install that advertises an IP sees no change.
func raftAdvertiseAddr(hostport string) (net.Addr, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || net.ParseIP(host) != nil {
		return net.ResolveTCPAddr("tcp", hostport)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return net.ResolveTCPAddr("tcp", hostport)
	}
	if p == 0 {
		// The bound port is only known after listening, and a name cannot
		// carry it the way a resolved TCPAddr does (newTLSStreamLayer).
		return nil, fmt.Errorf("raft advertise %q: a DNS name needs a fixed port", hostport)
	}
	return nameAddr(net.JoinHostPort(host, port)), nil
}

// tcpStreamLayer is raft's plain TCP stream layer with an advertise address
// that need not be an IP: raft.NewTCPTransport refuses anything but a
// resolved *net.TCPAddr. Dial is the same net.DialTimeout raft's own layer
// uses, which resolves a name on every new connection. Only isolated tests
// run Raft without TLS; a cluster always has it (raftSetupConfig.TLS).
type tcpStreamLayer struct {
	listener  net.Listener
	advertise net.Addr
}

func newTCPStreamLayer(bindAddr string, advertise net.Addr) (*tcpStreamLayer, error) {
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	return &tcpStreamLayer{listener: ln, advertise: advertise}, nil
}

func (s *tcpStreamLayer) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", string(addr), timeout)
}
func (s *tcpStreamLayer) Accept() (net.Conn, error) { return s.listener.Accept() }
func (s *tcpStreamLayer) Close() error              { return s.listener.Close() }
func (s *tcpStreamLayer) Addr() net.Addr            { return s.advertise }
