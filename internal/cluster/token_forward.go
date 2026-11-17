package cluster

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Token writes come only from servers and gateways (defense in depth): a
// worker that takes a caller's POST or DELETE /v1/tokens sends the call,
// with the caller's own credential, on to a server, which authenticates
// the caller itself.

// ErrNoServerForward is a call a worker or gateway could not hand to a
// server.
var ErrNoServerForward = errors.New("cluster: no server to send the call to")

// ServerClientForPeer is ClientForPeer that also requires the peer's
// certificate to name the server role (DNS:role:server). A caller's
// credential is forwarded only to a node that proves it is a server, never
// to one that merely says so in gossip. A certificate signed before roles
// were (cluster-sign-node.sh) names none and is refused.
func ServerClientForPeer(base *http.Client, nodeID string) *http.Client {
	client := ClientForPeer(base, nodeID)
	if client == nil || client == base {
		return nil
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr == nil || tr.TLSClientConfig == nil {
		return nil
	}
	tlsCfg := tr.TLSClientConfig.Clone()
	pinned := tlsCfg.VerifyPeerCertificate
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if pinned != nil {
			if err := pinned(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("cluster tls: parse peer certificate: %w", err)
		}
		if role := ExtractPeerRole(cert); role != JoinRoleServer {
			return fmt.Errorf("cluster tls: node:%s holds a %q certificate, not a server's", strings.TrimSpace(nodeID), role)
		}
		return nil
	}
	cloned := tr.Clone()
	cloned.TLSClientConfig = tlsCfg
	return &http.Client{Transport: cloned, CheckRedirect: client.CheckRedirect, Jar: client.Jar, Timeout: client.Timeout}
}

// maxTokenForwardBody bounds the call a worker holds to resend: the API's
// own body cap (apihttp.MaxJSONBodyBytes). A token write is a few hundred
// bytes; a sandbox create with custom domains is the largest call sent.
const maxTokenForwardBody = 1 << 20

// ForwardToServer reverse-proxies r, a caller's token write with the
// caller's own credential, to a server the gossip index lists, pinned to
// that server's certificate and role. The server answers the caller. The
// forward carries the X-Cluster-Forwarded marker, so the server takes the
// caller's credential and never this node's own identity for it. A server
// that cannot be reached or answers 5xx hands the call to the next one; a
// 4xx is the answer (a server authenticated the caller and refused it, so
// asking the others would only repeat that). A create retried after a 5xx
// whose write did land meets name_taken (409) on the next server.
func (a *Agent) ForwardToServer(w http.ResponseWriter, r *http.Request) {
	a.forwardToServer(w, r, true)
}

// ForwardToServerOnce is ForwardToServer for a call that is not safe to run
// twice: a sandbox create with no Idempotency-Key. Only a server that could
// not be reached at all hands it to the next one; any answer, a 5xx
// included, is the caller's, since the create may have landed.
func (a *Agent) ForwardToServerOnce(w http.ResponseWriter, r *http.Request) {
	a.forwardToServer(w, r, false)
}

func (a *Agent) forwardToServer(w http.ResponseWriter, r *http.Request, retry5xx bool) {
	if a == nil {
		http.Error(w, ErrNoServerForward.Error(), http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get(HeaderForwarded) == "1" {
		// A server never sends a token write to a worker; one that arrives
		// forwarded would only bounce.
		http.Error(w, "cluster: forwarding loop detected", http.StatusMisdirectedRequest)
		return
	}
	var body []byte
	if r.Body != nil {
		var err error
		if body, err = io.ReadAll(io.LimitReader(r.Body, maxTokenForwardBody+1)); err != nil || len(body) > maxTokenForwardBody {
			http.Error(w, "cluster: token write body unreadable or too large", http.StatusBadRequest)
			return
		}
	}
	SetPeerNodeIDHeader(r, a.nodeID)
	var lastErr error
	tried := 0
	for _, m := range a.controlPlaneMembers() {
		client := ServerClientForPeer(a.internalClient, m.NodeID)
		if client == nil || validatePeerInternalURL(m.InternalURL) != nil {
			continue
		}
		proxy, err := newPeerReverseProxy(m.InternalURL, client.Transport)
		if err != nil {
			continue
		}
		failed, node := false, m.NodeID
		proxy.ModifyResponse = func(resp *http.Response) error {
			if retry5xx && resp.StatusCode >= http.StatusInternalServerError {
				return fmt.Errorf("server %s answered %d", node, resp.StatusCode)
			}
			return nil
		}
		// Nothing is written to w on a failed try: ModifyResponse runs
		// before the proxy copies a response, so the next server may answer.
		// A call not safe to run twice moves on only if this server never
		// got it (it was not written: no connection, or no TLS handshake).
		var sent atomic.Bool
		proxy.ErrorHandler = func(ew http.ResponseWriter, _ *http.Request, err error) {
			if !retry5xx && sent.Load() {
				auditlog.MarkForwardFailed(r.Context())
				http.Error(ew, fmt.Sprintf("cluster: server %s took the call and gave no answer, so it may have run: %v", node, err), http.StatusBadGateway)
				return
			}
			failed, lastErr = true, err
		}
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		tried++
		proxy.ServeHTTP(w, r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
			WroteRequest: func(httptrace.WroteRequestInfo) { sent.Store(true) },
		})))
		if !failed {
			return
		}
	}
	if tried == 0 {
		http.Error(w, ErrNoServerForward.Error(), http.StatusServiceUnavailable)
		return
	}
	// No server ran the call: the edge records the failed forward.
	auditlog.MarkForwardFailed(r.Context())
	http.Error(w, fmt.Sprintf("%v: %d tried, the last: %v", ErrNoServerForward, tried, lastErr), http.StatusBadGateway)
}
