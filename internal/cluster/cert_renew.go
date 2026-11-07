package cluster

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Node cert renewal (plans/kubectl-style-cluster-ops.md D6, §4.2).
//
//	every node ─► ticker: is the served cert past 2/3 of its life?
//	           ─► CSR for the same key ─► a server with the CA key
//	              (POST /v1/cluster/internal/renew-cert over 7002 mTLS,
//	               or in-process on a server that holds the key itself)
//	           ─► verify the answer ─► write node.crt atomically
//	           ─► tls.go loads it on the next handshake
//
// The key stays the same, so only node.crt changes and the pair on disk is
// always consistent. A cert that already expired can't renew: mTLS refuses
// it, and the node needs a new join token. On purpose.

// certRenewCheckMax is the longest gap between checks; a short-lived cert
// (SB_CLUSTER_NODE_CERT_TTL=10m) is checked every 1/20 of its life.
const (
	certRenewCheckMax = 10 * time.Minute
	certRenewCheckMin = 5 * time.Second
)

// certRenewer runs the renewal for one node.
type certRenewer struct {
	tls    *ClusterTLS
	nodeID string
	logger *slog.Logger
	now    func() time.Time
	// renew sends a CSR to a signer and returns the PEM cert.
	renew func(ctx context.Context, csrPEM []byte) ([]byte, error)
}

// renewDue reports whether leaf is past two thirds of its life at now.
func renewDue(leaf *x509.Certificate, now time.Time) bool {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return !now.Before(leaf.NotBefore.Add(life * 2 / 3))
}

// renewCheckEvery is how often to look at leaf.
func renewCheckEvery(leaf *x509.Certificate) time.Duration {
	if leaf == nil {
		return certRenewCheckMax
	}
	every := leaf.NotAfter.Sub(leaf.NotBefore) / 20
	return min(max(every, certRenewCheckMin), certRenewCheckMax)
}

// tick renews the served cert when it is due. It returns the served leaf
// (renewed or not) so the loop can pace the next check.
func (r *certRenewer) tick(ctx context.Context) (*x509.Certificate, error) {
	current, err := r.tls.certificateForHandshake()
	if err != nil {
		return nil, err
	}
	leaf, err := leafCertificate(current)
	if err != nil {
		return nil, err
	}
	if !renewDue(leaf, r.now()) {
		return leaf, nil
	}
	signer, ok := current.PrivateKey.(crypto.Signer)
	if !ok {
		return leaf, r.failed(fmt.Errorf("node key of type %T cannot sign a CSR", current.PrivateKey))
	}
	csr, err := NewNodeCSR(signer, r.nodeID)
	if err != nil {
		return leaf, r.failed(err)
	}
	certPEM, err := r.renew(ctx, csr)
	if errors.Is(err, ErrNotAdmitted) {
		// A scripted cluster before `sandboxd adopt`: nothing can sign for
		// this node yet. Not a failure of renewal; the cert-expiry alert
		// still fires 14 days out.
		certRenewSkipped.Add(1)
		if r.logger != nil {
			r.logger.Warn("cluster: node cert is due for renewal but this cluster has not been adopted; run `sandboxd adopt` on the seed", "not_after", leaf.NotAfter)
		}
		return leaf, nil
	}
	if err != nil {
		return leaf, r.failed(err)
	}
	renewed, err := r.install(certPEM, signer.Public())
	if err != nil {
		return leaf, r.failed(err)
	}
	certRenewals.Add(1)
	certRenewFailingSince.Set(0)
	if r.logger != nil {
		r.logger.Info("cluster: node cert renewed", "node_id", r.nodeID, "not_after", renewed.NotAfter)
	}
	return renewed, nil
}

// install checks a renewed cert (chains to the cluster CA, names this node,
// carries this key) and writes node.crt atomically.
func (r *certRenewer) install(certPEM []byte, pub crypto.PublicKey) (*x509.Certificate, error) {
	leaf, err := firstPEMCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("renewed cert: %w", err)
	}
	if !publicKeysEqual(pub, leaf.PublicKey) {
		return nil, errors.New("renewed cert carries another key")
	}
	pair := tlsPair(leaf)
	if nodeID, _, err := validateClusterNodeCertificate(&pair, r.tls.caPool); err != nil {
		return nil, err
	} else if nodeID != r.nodeID {
		return nil, fmt.Errorf("renewed cert names %q, not %q", nodeID, r.nodeID)
	}
	if r.tls.certPath == "" {
		return nil, errors.New("no node.crt path to write")
	}
	if err := WriteFileAtomic(r.tls.certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	return leaf, nil
}

func (r *certRenewer) failed(err error) error {
	certRenewFailures.Add(1)
	if certRenewFailingSince.Value() == 0 {
		certRenewFailingSince.Set(r.now().Unix())
	}
	if r.logger != nil {
		r.logger.Warn("cluster: node cert renewal failed; will retry", "node_id", r.nodeID, "err", err)
	}
	return err
}

// run checks until ctx ends.
func (r *certRenewer) run(ctx context.Context) {
	for {
		leaf, _ := r.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(renewCheckEvery(leaf)):
		}
	}
}

// startCertRenewer starts the loop on a node with cluster TLS; the returned
// func stops it.
func startCertRenewer(r *certRenewer) context.CancelFunc {
	if r == nil || r.tls == nil {
		return func() {}
	}
	if r.now == nil {
		r.now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	go r.run(ctx)
	return cancel
}

// renewViaServers is a server's renewal: in-process when it holds the CA
// key, else another server.
func (c *Cluster) renewViaServers(ctx context.Context, csrPEM []byte) ([]byte, error) {
	if c.ca.get() != nil {
		leaf, err := c.currentLeaf()
		if err != nil {
			return nil, err
		}
		resp, err := c.RenewNodeCert(ctx, c.nodeID, leaf, csrPEM)
		if err == nil {
			return []byte(resp.NodeCert), nil
		}
		if !isPeerRetryable(err) {
			return nil, err
		}
	}
	var resp RenewCertResponse
	if err := c.postToServerPeers(ctx, PublicInternalRenewCertPath, RenewCertRequest{CSR: string(csrPEM)}, &resp); err != nil {
		return nil, err
	}
	return []byte(resp.NodeCert), nil
}

// renewViaServers is a worker's renewal: the server tier, which retries the
// next server on a 503 (no CA key there).
func (a *Agent) renewViaServers(ctx context.Context, csrPEM []byte) ([]byte, error) {
	var resp RenewCertResponse
	err := a.doControlPlaneJSON(ctx, "POST", PublicInternalRenewCertPath, PublicInternalRenewCertPath, RenewCertRequest{CSR: string(csrPEM)}, &resp)
	if err != nil {
		var se statusError
		if errors.As(err, &se) {
			return nil, peerJoinError(se.status, se.message)
		}
		return nil, err
	}
	return []byte(resp.NodeCert), nil
}

// tlsPair wraps a parsed leaf for validateClusterNodeCertificate.
func tlsPair(leaf *x509.Certificate) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}
}
