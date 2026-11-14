package nodejoin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// Join by certificate (external-CA mode, C23, plan §15.2.1). The pod's
// certificate came from the bank's issuer through cert-manager and sits in
// the TLS dir with the bank's CA, mounted from the pod's Secret. It is the
// credential: no token, no discovery (the bank's CA is the trust), no key
// or CSR made here.
//
//	TLS dir: ca.crt, node.crt, node.key ─► node:<id> and the role from node.crt
//	  ─► dial-back listeners ─► POST /v1/join/by-certificate with node.crt
//	  ─► cluster.env: the bundle and SB_CLUSTER_EXTERNAL_CA=true; the TLS dir
//	     is left as the Secret made it

// externalCAIdentity reads the TLS dir: the bank's CA, the pod's pair, and
// the node ID and role its certificate names.
func externalCAIdentity(tlsDir string) (*x509.CertPool, tls.Certificate, string, string, error) {
	caPEM, err := os.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	if err != nil {
		return nil, tls.Certificate{}, "", "", fmt.Errorf("the external CA's ca.crt: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, tls.Certificate{}, "", "", errors.New("the external CA's ca.crt holds no certificate")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(tlsDir, "node.crt"), filepath.Join(tlsDir, "node.key"))
	if err != nil {
		return nil, tls.Certificate{}, "", "", fmt.Errorf("this node's certificate (node.crt, node.key): %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, tls.Certificate{}, "", "", err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, tls.Certificate{}, "", "", fmt.Errorf("node.crt does not chain to ca.crt: %w", err)
	}
	nodeID := cluster.ExtractPeerNodeID(leaf)
	if !cluster.ValidJoinNodeID(nodeID) {
		return nil, tls.Certificate{}, "", "", fmt.Errorf("node.crt names no valid node:<id> (%q)", nodeID)
	}
	roles := cluster.ExtractCertRoles(leaf)
	if len(roles) != 1 || !cluster.ValidJoinRole(roles[0]) {
		return nil, tls.Certificate{}, "", "", fmt.Errorf("node.crt must name exactly one role (aerolvm-role:server, worker or ingress), not %v", roles)
	}
	pair.Leaf = leaf
	return pool, pair, nodeID, roles[0], nil
}

// certClient trusts the bank's CA for the join port and shows the pod's
// certificate.
func certClient(pool *x509.CertPool, pair tls.Certificate) *http.Client {
	return &http.Client{Timeout: joinTimeout, Transport: joinTransport(&tls.Config{
		RootCAs: pool, ServerName: clusterServerName, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
	})}
}

func (j *Joiner) runByCert(ctx context.Context, o JoinOptions) (JoinResult, error) {
	if !o.FilesOnly && !j.Host.IsRoot() {
		return JoinResult{}, errors.New("run sandboxd join as root (sudo)")
	}
	if o.Token != "" || o.CACertHash != "" {
		return JoinResult{}, errors.New("--by-certificate takes no --token or --ca-cert-hash: the certificate and the external CA are the trust")
	}
	if err := installed(j.Paths); err != nil {
		return JoinResult{}, err
	}
	env, err := loadNodeEnv(j.Paths)
	if err != nil {
		return JoinResult{}, err
	}
	joinURL, err := normalizeJoinURL(o.URL)
	if err != nil {
		return JoinResult{}, err
	}
	advertise, err := pickAdvertise(j.Host, o.Advertise)
	if err != nil {
		return JoinResult{}, err
	}
	pool, pair, nodeID, role, err := externalCAIdentity(env.tlsDir(j.Paths))
	if err != nil {
		return JoinResult{}, err
	}
	if o.NodeID != "" && o.NodeID != nodeID {
		return JoinResult{}, fmt.Errorf("--node-id %s, but the certificate names %s", o.NodeID, nodeID)
	}
	if o.Address.NodeRole != "" {
		if r, err := joinRoleOf(o.Address.NodeRole); err != nil {
			return JoinResult{}, err
		} else if r != role {
			return JoinResult{}, fmt.Errorf("--role %s, but the certificate's role is %s", o.Address.NodeRole, role)
		}
	}
	closeListeners, err := dialBackListeners(j.Host, rolePorts(role, false))
	if err != nil {
		return JoinResult{}, err
	}
	defer closeListeners()
	client := j.Client
	if client == nil {
		client = certClient(pool, pair)
	}
	j.printf("[join] joining as %s (%s) by its certificate\n", nodeID, role)
	var resp cluster.JoinResponse
	err = postJoin(ctx, client, joinURL, cluster.JoinByCertPath, cluster.JoinByCertRequest{
		Version: j.Version, FSMOpsVersion: cluster.FSMOpsVersion(),
	}, &resp)
	var refusal *JoinRefusal
	if errors.As(err, &refusal) && refusal.Reason == "dial_back" {
		j.printf("fix dial-back: %s\n", dialBackCheck(refusal.DialBack).Detail)
	}
	if err != nil {
		return JoinResult{}, err
	}
	if resp.NodeID != nodeID || resp.Role != role {
		return JoinResult{}, fmt.Errorf("the join answer is for %s (%s), not %s (%s)", resp.NodeID, resp.Role, nodeID, role)
	}
	if resp.NodeCert != "" || resp.CAKey != "" {
		return JoinResult{}, errors.New("the join answer carries a certificate or a CA key, which an external-CA cluster never sends")
	}
	return j.finish(ctx, o, env, resp, nodeID, advertise, joinURL, true)
}
