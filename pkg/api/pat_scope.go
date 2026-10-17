package api

// Where a request came from, and where the operator token (PAT) may come
// from (plans/identity-and-access.md §5.11, CEO review D4, D5, D12).
//
//	listener                  origin   PAT under SB_PAT_SCOPE=host
//	mTLS internal listener    peer     yes; a forward must say X-Cluster-PAT-Origin: host
//	API TCP, loopback peer    host     yes (setup scripts, runbooks, the SSH gateway)
//	API TCP, any other peer   public   no
//	public Unix socket        public   no (Caddy's upstream under host scope)
//
// With SB_L4_FALLBACK_PROXY_PROTOCOL on, Caddy also stamps
// X-AerolVM-Client-IP with the address the caddy-l4 PROXY header gave it. A
// loopback request carrying that header is Caddy relaying a public caller,
// so it is public too, and the header becomes the client address in
// auth_denied records. It is trusted only from the public socket or a
// loopback peer: from anywhere else it is dropped and counted (finding 3.4).

import (
	"context"
	"errors"
	"expvar"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// Origin labels: aerolvm_auth_requests_total's key2 and the PAT scope rule.
const (
	originHost   = "host"
	originPeer   = "peer"
	originPublic = "public"
)

// HeaderClientIP is the client address Caddy sets on every request it
// proxies to sandboxd (`header_up X-AerolVM-Client-IP {remote_host}`,
// written by install.sh with the PROXY-protocol wrapper). Caddy overwrites
// whatever the client sent, so it is the peer Caddy saw, never a client
// claim; sandboxd never reads X-Forwarded-For.
const HeaderClientIP = "X-AerolVM-Client-IP"

// headerClientIPKey is HeaderClientIP in Go's canonical form, so Header.Get
// does not allocate a canonical copy per request.
var headerClientIPKey = http.CanonicalHeaderKey(HeaderClientIP)

// authClientIPDropped counts X-AerolVM-Client-IP headers sandboxd ignored:
// sent by a peer that is neither Caddy's socket nor loopback (a remote
// caller on 0.0.0.0:21212 trying to pick its own address), or not an IP.
var authClientIPDropped = expvar.NewInt("aerolvm_auth_client_ip_dropped_total")

// patScopeMessage is the 401 text for a PAT refused under host scope. It
// tells the caller what to use instead; it names no listener detail.
const patScopeMessage = "the operator token works only on this host; sign in with `aerolvm login --sso` or use a named token"

var (
	// errPATScope refuses a PAT that arrived from a public origin under
	// SB_PAT_SCOPE=host.
	errPATScope = errors.New("operator token refused: SB_PAT_SCOPE=host")
	// errPATOrigin refuses a PAT a peer forwarded without
	// X-Cluster-PAT-Origin: host, under SB_PAT_SCOPE=host: a node left on
	// scope any (or an older build) cannot launder a remote PAT.
	errPATOrigin = errors.New("forwarded operator token refused: origin not host")
)

type publicListenerKey struct{}

// PublicHandler is the API handler for the public Unix socket
// (SB_PUBLIC_API_SOCKET) Caddy uses under SB_PAT_SCOPE=host. Every request
// on it is public, whatever its RemoteAddr says, so a PAT there is refused.
// The mark rides the request context, which no client can set.
func (s *Server) PublicHandler() http.Handler {
	next := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), publicListenerKey{}, true)))
	})
}

func onPublicSocket(r *http.Request) bool {
	public, _ := r.Context().Value(publicListenerKey{}).(bool)
	return public
}

// loopbackPeer reports whether the TCP peer is a loopback address.
func loopbackPeer(r *http.Request) bool {
	if addr, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return addr.Addr().Unmap().IsLoopback()
	}
	addr, err := netip.ParseAddr(r.RemoteAddr)
	return err == nil && addr.Unmap().IsLoopback()
}

// requestOrigin classifies a request: peer (a verified mTLS cluster peer),
// host (a loopback TCP peer that is not Caddy relaying a public caller) or
// public (everything else, the public socket included). trustClientIP is
// SB_L4_FALLBACK_PROXY_PROTOCOL: only then does Caddy stamp
// X-AerolVM-Client-IP, so only then does the header mark Caddy's traffic.
func requestOrigin(r *http.Request, trustClientIP bool) string {
	if _, ok := mtlsPeer(r); ok {
		return originPeer
	}
	if onPublicSocket(r) || !loopbackPeer(r) {
		return originPublic
	}
	if trustClientIP && r.Header.Get(headerClientIPKey) != "" {
		return originPublic
	}
	return originHost
}

// authOrigin is the aerolvm_auth_requests_total origin label of r.
func (s *Server) authOrigin(r *http.Request) string {
	return requestOrigin(r, s.l4ProxyProtocol)
}

// patOrigin is the X-Cluster-PAT-Origin this node stamps when it forwards a
// PAT request it accepted (cluster.StampForward): host for a loopback peer
// or a cluster peer acting for itself, the received origin for a request a
// peer forwarded here, public for everything else.
func patOrigin(r *http.Request, trustClientIP bool) string {
	switch requestOrigin(r, trustClientIP) {
	case originHost:
		return cluster.PATOriginHost
	case originPeer:
		if !isForwarded(r) || r.Header.Get(cluster.HeaderPATOrigin) == cluster.PATOriginHost {
			return cluster.PATOriginHost
		}
	}
	return cluster.PATOriginPublic
}

// clientAddress is the address auth_denied records and their per-address
// limit use. It is the TCP peer, except that with
// SB_L4_FALLBACK_PROXY_PROTOCOL on, a valid X-AerolVM-Client-IP from the
// public socket or a loopback peer (Caddy) names the real client. The
// header from any other peer, or one that is not an IP, is dropped and
// counted.
func (s *Server) clientAddress(r *http.Request) string {
	peer := tcpPeerAddress(r)
	if !s.l4ProxyProtocol {
		return peer
	}
	raw := strings.TrimSpace(r.Header.Get(headerClientIPKey))
	if raw == "" {
		return peer
	}
	_, isPeer := mtlsPeer(r)
	if isPeer || !(onPublicSocket(r) || loopbackPeer(r)) {
		authClientIPDropped.Add(1)
		return peer
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		authClientIPDropped.Add(1)
		return peer
	}
	return addr.Unmap().String()
}

// tcpPeerAddress is the request's TCP peer without the port.
func tcpPeerAddress(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
