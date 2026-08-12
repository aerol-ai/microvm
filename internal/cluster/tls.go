package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TLS material lives on disk under SB_CLUSTER_TLS_DIR with these names.
// cluster-init.sh produces the CA + this node's cert; cluster-join.sh signs a
// fresh node cert from the bundled CA. The daemon never writes these files —
// it loads them at boot and keeps them in memory.
const (
	tlsCAFile       = "ca.crt"
	tlsCAKeyFile    = "ca.key" // present only on bootstrap node + joiners that received the bundle; not required at runtime
	tlsNodeCertFile = "node.crt"
	tlsNodeKeyFile  = "node.key"
)

// clusterServerName is the fixed SAN every node cert carries (and the
// ServerName the client TLS config asks for on dial). Decoupling cert identity
// from the network address lets cluster-init/join generate one cert per node
// without knowing the operator's eventual hostname/IP, while still letting
// Go's stdlib hostname verification pass. The cluster CA is the actual trust
// anchor — this string just satisfies stdlib's "the cert has to claim it
// serves the name you dialed" rule.
const clusterServerName = "aerolvm-cluster-node"

// nodeIDSANprefix is the DNS/URI SAN form minted by cluster-init/join
// (DNS:node:${NODE_ID}) so peers can bind mTLS identity to a gossip node id.
const nodeIDSANprefix = "node:"

// ClusterTLS is the loaded TLS material the daemon uses for cluster-internal
// channels (raft transport + leader-forwarded HTTP applies). Built once at
// boot from the on-disk files and shared by the raft StreamLayer and the
// internal HTTPS listener / client.
type ClusterTLS struct {
	caPool   *x509.CertPool
	nodeCert tls.Certificate
	// nodeID is extracted from the local node cert when a DNS/URI SAN of the
	// form node:<id> is present, or when CN equals a non-legacy node id.
	// Empty for legacy aerolvm-cluster-node-only certs.
	nodeID string
}

// NodeID returns the node-bound identity extracted from the local node cert,
// or empty when the cert carries only the legacy clusterServerName SAN.
func (t *ClusterTLS) NodeID() string {
	if t == nil {
		return ""
	}
	return t.nodeID
}

// loadClusterTLS reads ca.crt + node.crt/node.key from dir. Returns
// (nil, nil) when dir is empty so the caller can treat TLS as opt-in: an
// unset SB_CLUSTER_TLS_DIR keeps the legacy plaintext behaviour for operators
// who run cluster mode strictly on a private overlay.
func loadClusterTLS(dir string) (*ClusterTLS, error) {
	if dir == "" {
		return nil, nil
	}
	caBytes, err := os.ReadFile(filepath.Join(dir, tlsCAFile))
	if err != nil {
		return nil, fmt.Errorf("cluster tls: read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("cluster tls: ca.crt did not contain any PEM certificates")
	}
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, tlsNodeCertFile),
		filepath.Join(dir, tlsNodeKeyFile),
	)
	if err != nil {
		return nil, fmt.Errorf("cluster tls: load node keypair: %w", err)
	}
	nodeID := ""
	if leaf, err := leafCertificate(&cert); err == nil {
		nodeID, _ = ExtractPeerNodeID(leaf)
	}
	return &ClusterTLS{caPool: pool, nodeCert: cert, nodeID: nodeID}, nil
}

func leafCertificate(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("cluster tls: empty certificate")
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

// ExtractPeerNodeID returns the node-bound identity from a peer certificate.
// Prefer DNS/URI SAN `node:<id>`; otherwise accept CN when it is not the
// legacy clusterServerName. legacyOnly is true when the cert only carries
// aerolvm-cluster-node (no node:<id> identity).
func ExtractPeerNodeID(cert *x509.Certificate) (nodeID string, legacyOnly bool) {
	if cert == nil {
		return "", false
	}
	for _, name := range cert.DNSNames {
		if id := parseNodeIDSAN(name); id != "" {
			return id, false
		}
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		if id := parseNodeIDSAN(uri.String()); id != "" {
			return id, false
		}
		if id := parseNodeIDSAN(uri.Opaque); id != "" {
			return id, false
		}
		if id := parseNodeIDSAN(strings.TrimPrefix(uri.Path, "/")); id != "" {
			return id, false
		}
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn != "" && cn != clusterServerName {
		if id := parseNodeIDSAN(cn); id != "" {
			return id, false
		}
		return cn, false
	}
	if hasLegacyClusterSAN(cert) {
		return "", true
	}
	return "", false
}

func parseNodeIDSAN(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, nodeIDSANprefix) {
		return ""
	}
	id := strings.TrimSpace(strings.TrimPrefix(s, nodeIDSANprefix))
	if id == "" || id == clusterServerName {
		return ""
	}
	return id
}

func hasLegacyClusterSAN(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if strings.TrimSpace(cert.Subject.CommonName) == clusterServerName {
		return true
	}
	for _, name := range cert.DNSNames {
		if strings.TrimSpace(name) == clusterServerName {
			return true
		}
	}
	return false
}

// VerifyPeerNodeID reports whether expected matches the peer cert's node-bound
// identity. Empty expected is a no-op (returns true). Used by withInternalMTLS
// when the caller supplies an expected peer id.
func VerifyPeerNodeID(cert *x509.Certificate, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	got, _ := ExtractPeerNodeID(cert)
	return got != "" && got == expected
}

// serverConfig builds the *tls.Config used by both the raft TLS StreamLayer
// and the cluster-internal HTTPS listener. mTLS is mandatory: a peer that
// can't present a cert chained to the cluster CA is refused at the handshake,
// before any application-layer auth (PAT) is consulted. This is the property
// that closes the "internal apply rides over HTTP with only a shared bearer
// token" gap — possession of the PAT is no longer sufficient to forge an
// internal apply.
func (t *ClusterTLS) serverConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{t.nodeCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    t.caPool,
		MinVersion:   tls.VersionTLS12,
	}
}

// clientConfig builds the *tls.Config used when this node dials another peer
// for raft replication or a leader-forwarded apply. The client cert is the
// same node cert (mTLS is symmetric in cluster-internal traffic), and the
// peer's cert must chain to the cluster CA — public CAs are never trusted on
// these channels.
func (t *ClusterTLS) clientConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{t.nodeCert},
		RootCAs:      t.caPool,
		MinVersion:   tls.VersionTLS12,
		// Decouple cert verification from network address: every node cert
		// carries the same fixed SAN (clusterServerName), so dialing by IP or
		// hostname both verify against that one name.
		ServerName: clusterServerName,
	}
}
