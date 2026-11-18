package cluster

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// CustomDomainsBound is what a server bound for one call: the custom
// hostnames it bound to one sandbox (or found the sandbox already holds)
// after the caller's DNS proof. A worker or gateway proposes a custom
// hostname only when the sandbox holds it already (peerMayPropose), so a new
// name is bound by a server, which the attach and create routes reach
// first; the owner that then runs the call does not look the proof up
// again for these names.
type CustomDomainsBound struct {
	SandboxID string
	Hostnames []string
}

// Covers reports whether b names hostname for sandboxID.
func (b CustomDomainsBound) Covers(sandboxID, hostname string) bool {
	if strings.TrimSpace(sandboxID) == "" || b.SandboxID != strings.TrimSpace(sandboxID) {
		return false
	}
	for _, h := range b.Hostnames {
		if h == hostname {
			return true
		}
	}
	return false
}

// encode is the header value: the sandbox id, a space, and the hostnames
// separated by commas. Neither a sandbox id nor a hostname has a space or
// a comma.
func (b CustomDomainsBound) encode() string {
	return b.SandboxID + " " + strings.Join(b.Hostnames, ",")
}

// ParseCustomDomainsBound reads HeaderCustomDomainsBound. Anything that is
// not a valid sandbox id and canonical hostnames is no marker at all.
func ParseCustomDomainsBound(v string) (CustomDomainsBound, bool) {
	id, list, ok := strings.Cut(strings.TrimSpace(v), " ")
	if !ok || models.ValidateSandboxID(id) != nil || list == "" {
		return CustomDomainsBound{}, false
	}
	hosts := strings.Split(list, ",")
	if len(hosts) > models.MaxCustomDomainsPerSandbox {
		return CustomDomainsBound{}, false
	}
	for _, h := range hosts {
		if canon, err := models.NormalizeCustomDomain(h, ""); err != nil || canon != h {
			return CustomDomainsBound{}, false
		}
	}
	return CustomDomainsBound{SandboxID: id, Hostnames: hosts}, true
}

type customDomainsBoundKey struct{}

// ContextWithCustomDomainsBound records what a server bound for the call
// made under ctx: the server's own handler reads it, and StampForward sends
// it to the owner. An empty b records nothing.
func ContextWithCustomDomainsBound(ctx context.Context, b CustomDomainsBound) context.Context {
	if strings.TrimSpace(b.SandboxID) == "" || len(b.Hostnames) == 0 {
		return ctx
	}
	return context.WithValue(ctx, customDomainsBoundKey{}, b)
}

// CustomDomainsBoundFromContext is what ContextWithCustomDomainsBound
// recorded.
func CustomDomainsBoundFromContext(ctx context.Context) (CustomDomainsBound, bool) {
	b, ok := ctx.Value(customDomainsBoundKey{}).(CustomDomainsBound)
	return b, ok
}

// SentOnByNonServer reports whether r is a call a worker or gateway sent on
// to this node with the caller's credential (Agent.ForwardToServer): a
// forward over a verified mTLS connection from a peer whose role is not
// server. A server it reaches is then the call's edge, which routes it,
// and not the owner's half of it, which only a server sends.
func SentOnByNonServer(c Client, r *http.Request) bool {
	if r == nil || r.Header.Get(HeaderForwarded) != "1" {
		return false
	}
	peer, err := AuthenticatedPeerNodeID(r)
	if err != nil {
		return false
	}
	var leaf *x509.Certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf = r.TLS.PeerCertificates[0]
	}
	return PeerRole(c, peer, leaf) != JoinRoleServer
}
