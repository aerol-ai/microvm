package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"expvar"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PeerNodeIDHeader is set by production peer callers so the receiver can bind
// the mTLS leaf to the claimed gossip node id.
const PeerNodeIDHeader = "X-Cluster-Peer-Node-ID"

var clusterTLSReloadFailures = expvar.NewInt("aerolvm_cluster_mtls_reload_failures_total")

// SetPeerNodeIDHeader attaches this node's id for inbound withInternalMTLS checks.
func SetPeerNodeIDHeader(req *http.Request, selfNodeID string) {
	if req == nil {
		return
	}
	selfNodeID = strings.TrimSpace(selfNodeID)
	if selfNodeID == "" {
		return
	}
	req.Header.Set(PeerNodeIDHeader, selfNodeID)
}

// AuthenticatedPeerNodeID returns the node identity authenticated by the
// request's verified mTLS leaf. Cluster-control headers are not credentials:
// callers must first prove possession of a CA-signed node certificate, and an
// optional explicit node claim must match that certificate.
func AuthenticatedPeerNodeID(r *http.Request) (string, error) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return "", errors.New("cluster internal endpoint requires mTLS")
	}
	peerID := ExtractPeerNodeID(r.TLS.PeerCertificates[0])
	if peerID == "" {
		return "", errors.New("cluster peer requires node identity SAN")
	}
	if claimed := strings.TrimSpace(r.Header.Get(PeerNodeIDHeader)); claimed != "" && claimed != peerID {
		return "", errors.New("cluster peer node id mismatch")
	}
	return peerID, nil
}

// IsLivePeer reports whether nodeID is present and alive in the caller's
// current gossip view. It deliberately uses the local view: authenticating a
// forwarded request must not recurse through another cluster HTTP request.
func IsLivePeer(c Client, nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	if c == nil || nodeID == "" {
		return false
	}
	if lookup, ok := c.(interface {
		LookupMember(string) (Member, bool)
	}); ok {
		member, found := lookup.LookupMember(nodeID)
		return found && member.Alive
	}
	for _, member := range c.LocalMembers() {
		if member.NodeID == nodeID {
			return member.Alive
		}
	}
	return false
}

// TLS material lives on disk under SB_CLUSTER_TLS_DIR with these names.
// cluster-init.sh produces the CA + this node's cert; cluster-join.sh signs a
// fresh node cert from the bundled CA. The daemon never writes these files —
// it loads them at boot and keeps them in memory.
const (
	tlsCAFile       = "ca.crt"
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
	certPath string
	keyPath  string
	certMu   sync.RWMutex
	certMark string
	current  atomic.Pointer[tls.Certificate]
	// nodeID is extracted from the local node cert's required DNS/URI SAN of
	// the form node:<id>.
	nodeID string
}

// NodeID returns the node-bound identity extracted from the local node cert.
func (t *ClusterTLS) NodeID() string {
	if t == nil {
		return ""
	}
	return t.nodeID
}

// loadClusterTLS reads ca.crt + node.crt/node.key from dir. Returns
// (nil, nil) when dir is empty. Cluster configuration validation rejects an
// empty directory; single-node callers can leave it unset.
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
	certPath := filepath.Join(dir, tlsNodeCertFile)
	keyPath := filepath.Join(dir, tlsNodeKeyFile)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("cluster tls: load node keypair: %w", err)
	}
	nodeID, leafExpiry, err := validateClusterNodeCertificate(&cert, pool)
	if err != nil {
		return nil, err
	}
	caExpiry, err := earliestPEMCertificateExpiry(caBytes)
	if err != nil {
		return nil, fmt.Errorf("cluster tls: parse CA certificate: %w", err)
	}
	recordClusterTLSExpiry(leafExpiry, caExpiry)
	loaded := &ClusterTLS{
		caPool: pool, nodeCert: cert, nodeID: nodeID,
		certPath: certPath, keyPath: keyPath,
	}
	loaded.current.Store(&loaded.nodeCert)
	return loaded, nil
}

func validateClusterNodeCertificate(cert *tls.Certificate, pool *x509.CertPool) (string, time.Time, error) {
	leaf, err := leafCertificate(cert)
	if err != nil {
		return "", time.Time{}, err
	}
	intermediates := x509.NewCertPool()
	for _, raw := range cert.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(raw)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("cluster tls: parse node certificate chain: %w", err)
		}
		intermediates.AddCert(intermediate)
	}
	verify := func(usage x509.ExtKeyUsage) error {
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
			DNSName:       clusterServerName,
			CurrentTime:   time.Now(),
			KeyUsages:     []x509.ExtKeyUsage{usage},
		})
		return err
	}
	if err := verify(x509.ExtKeyUsageServerAuth); err != nil {
		return "", time.Time{}, fmt.Errorf("cluster tls: verify node certificate for server authentication: %w", err)
	}
	if err := verify(x509.ExtKeyUsageClientAuth); err != nil {
		return "", time.Time{}, fmt.Errorf("cluster tls: verify node certificate for client authentication: %w", err)
	}
	nodeID := ExtractPeerNodeID(leaf)
	if nodeID == "" {
		return "", time.Time{}, errors.New("cluster tls: node certificate requires a node:<id> SAN")
	}
	return nodeID, leaf.NotAfter, nil
}

func earliestPEMCertificateExpiry(raw []byte) (time.Time, error) {
	var earliest time.Time
	for len(raw) > 0 {
		block, rest := pem.Decode(raw)
		raw = rest
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		if earliest.IsZero() || cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
	}
	if earliest.IsZero() {
		return time.Time{}, errors.New("no PEM certificates")
	}
	return earliest, nil
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
// Only DNS/URI SAN `node:<id>` is authoritative; common-name and shared-SAN
// fallbacks are intentionally unsupported.
func ExtractPeerNodeID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, name := range cert.DNSNames {
		if id := parseNodeIDSAN(name); id != "" {
			return id
		}
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		if id := parseNodeIDSAN(uri.String()); id != "" {
			return id
		}
		if id := parseNodeIDSAN(uri.Opaque); id != "" {
			return id
		}
		if id := parseNodeIDSAN(strings.TrimPrefix(uri.Path, "/")); id != "" {
			return id
		}
	}
	return ""
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

// VerifyPeerNodeID reports whether expected matches the peer cert's node-bound
// identity. Empty expected is a no-op (returns true). Used by withInternalMTLS
// when the caller supplies an expected peer id.
func VerifyPeerNodeID(cert *x509.Certificate, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return true
	}
	got := ExtractPeerNodeID(cert)
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
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return t.certificateForHandshake()
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  t.caPool,
		MinVersion: tls.VersionTLS12,
		// Apply to both HTTP and Raft listeners: a CA-valid generic client
		// certificate is not a node credential. Higher HTTP layers additionally
		// bind this identity to live membership in enterprise mode.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || ExtractPeerNodeID(cs.PeerCertificates[0]) == "" {
				return errors.New("cluster tls: peer certificate requires a node:<id> SAN")
			}
			return nil
		},
	}
}

// clientConfig builds the *tls.Config used when this node dials another peer
// for raft replication or a leader-forwarded apply. The client cert is the
// same node cert (mTLS is symmetric in cluster-internal traffic), and the
// peer's cert must chain to the cluster CA — public CAs are never trusted on
// these channels.
func (t *ClusterTLS) clientConfig() *tls.Config {
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return t.certificateForHandshake()
		},
		RootCAs:    t.caPool,
		MinVersion: tls.VersionTLS12,
		// Decouple cert verification from network address: every node cert
		// carries the same fixed SAN (clusterServerName), so dialing by IP or
		// hostname both verify against that one name. Per-peer node:<id>
		// binding is added by ClientForPeer when dialing a known member.
		ServerName: clusterServerName,
	}
}

// certificateForHandshake reloads an atomically replaced node.crt/node.key on
// the next TLS handshake. Existing connections drain naturally; malformed,
// expired, wrong-usage, or wrong-node replacements fail closed.
func (t *ClusterTLS) certificateForHandshake() (*tls.Certificate, error) {
	if t == nil {
		return nil, errors.New("cluster tls: unavailable")
	}
	if t.certPath == "" || t.keyPath == "" {
		return &t.nodeCert, nil
	}
	certInfo, err := os.Stat(t.certPath)
	if err != nil {
		return t.lastGoodCertificate(fmt.Errorf("cluster tls: stat node certificate: %w", err))
	}
	keyInfo, err := os.Stat(t.keyPath)
	if err != nil {
		return t.lastGoodCertificate(fmt.Errorf("cluster tls: stat node key: %w", err))
	}
	mark := fmt.Sprintf("%d:%d:%v:%d:%d:%v",
		certInfo.ModTime().UnixNano(), certInfo.Size(), certInfo.Sys(),
		keyInfo.ModTime().UnixNano(), keyInfo.Size(), keyInfo.Sys())
	t.certMu.RLock()
	if mark == t.certMark {
		cert := t.current.Load()
		t.certMu.RUnlock()
		if cert != nil {
			return cert, nil
		}
		return &t.nodeCert, nil
	}
	t.certMu.RUnlock()

	cert, err := tls.LoadX509KeyPair(t.certPath, t.keyPath)
	if err != nil {
		return t.lastGoodCertificate(fmt.Errorf("cluster tls: reload node keypair: %w", err))
	}
	nodeID, expiry, err := validateClusterNodeCertificate(&cert, t.caPool)
	if err != nil {
		return t.lastGoodCertificate(err)
	}
	if nodeID != t.nodeID {
		return t.lastGoodCertificate(fmt.Errorf("cluster tls: rotated certificate identity %q does not match node id %q", nodeID, t.nodeID))
	}
	t.certMu.Lock()
	t.current.Store(&cert)
	t.certMark = mark
	t.certMu.Unlock()
	clusterMTLSCertNotAfterUnix.Set(expiry.Unix())
	return &cert, nil
}

// lastGoodCertificate keeps new handshakes available while an operator is in
// the unavoidable two-rename window of node.crt/node.key replacement. Invalid
// material is never served; the last fully validated pair remains active and
// the failure counter makes a stuck rotation alertable.
func (t *ClusterTLS) lastGoodCertificate(reloadErr error) (*tls.Certificate, error) {
	clusterTLSReloadFailures.Add(1)
	if current := t.current.Load(); current != nil {
		return current, nil
	}
	return nil, reloadErr
}

// ClientForPeer returns an HTTP client that verifies the dialed peer presents
// DNS SAN node:<expectedNodeID> (in addition to the shared clusterServerName
// hostname check).
// Empty expected or a non-TLS base is a no-op.
func ClientForPeer(base *http.Client, expectedNodeID string) *http.Client {
	expectedNodeID = strings.TrimSpace(expectedNodeID)
	if base == nil || expectedNodeID == "" {
		return base
	}
	tr, ok := base.Transport.(*http.Transport)
	if !ok || tr == nil || tr.TLSClientConfig == nil {
		return base
	}
	tlsCfg := tr.TLSClientConfig.Clone()
	parent := tlsCfg.VerifyPeerCertificate
	want := expectedNodeID
	tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if parent != nil {
			if err := parent(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		if len(rawCerts) == 0 {
			return fmt.Errorf("cluster tls: missing peer certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("cluster tls: parse peer certificate: %w", err)
		}
		if VerifyPeerNodeID(cert, want) {
			return nil
		}
		return fmt.Errorf("cluster tls: peer node id mismatch: want node:%s", want)
	}
	cloned := tr.Clone()
	cloned.TLSClientConfig = tlsCfg
	return &http.Client{
		Transport:     cloned,
		CheckRedirect: base.CheckRedirect,
		Jar:           base.Jar,
		Timeout:       base.Timeout,
	}
}
