package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// ClusterTLS is the loaded TLS material the daemon uses for cluster-internal
// channels (raft transport + leader-forwarded HTTP applies). Built once at
// boot from the on-disk files and shared by the raft StreamLayer and the
// internal HTTPS listener / client.
type ClusterTLS struct {
	caPool   *x509.CertPool
	nodeCert tls.Certificate
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
	return &ClusterTLS{caPool: pool, nodeCert: cert}, nil
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
