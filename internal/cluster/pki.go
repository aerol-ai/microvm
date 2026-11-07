package cluster

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Cluster PKI for one-line joins (plans/kubectl-style-cluster-ops.md D3-D6,
// §4, §8). This file is pure: token shapes, hashes, the discovery MAC and
// the CA that signs node certs. Nothing here touches Raft or the network,
// so the node side of a join (sandboxd join, Phase 2b) imports the same
// functions and derives the same values.

// Join tokens are kubeadm-shaped, `<id>.<secret>`, with a longer secret: 32
// characters of [a-z0-9] carry 32*log2(36) ≈ 165 bits, past the plan's 128
// bit floor (§8). The id is public (it names the token in lists, audit and
// the cluster-info query); only the secret authenticates.
const (
	joinTokenIDLen     = 6
	joinTokenSecretLen = 32
	joinTokenAlphabet  = "abcdefghijklmnopqrstuvwxyz0123456789"
)

var joinTokenPattern = regexp.MustCompile(`^[a-z0-9]{6}\.[a-z0-9]{32}$`)
var joinTokenIDPattern = regexp.MustCompile(`^[a-z0-9]{6}$`)

// ErrJoinTokenFormat is a token that is not `<6 chars>.<32 chars>` of
// [a-z0-9].
var ErrJoinTokenFormat = errors.New("cluster: join token must look like <6 chars>.<32 chars>, lowercase letters and digits")

// NodeCertLifetime is how long a node cert signed by the join service or a
// renewal lasts: the 90 days cluster-sign-node.sh used (§4.2).
const NodeCertLifetime = 90 * 24 * time.Hour

// caCertLifetime is a new cluster CA's life, like cluster-init.sh's.
const caCertLifetime = 10 * 365 * 24 * time.Hour

// nodeCertBackdate absorbs clock skew between the signer and the node.
const nodeCertBackdate = 5 * time.Minute

// nodeRoleSANprefix names the admitted role in a signed node cert
// (DNS:role:<role>), next to DNS:node:<id> (Codex eng finding 1).
const nodeRoleSANprefix = "role:"

// The CA store on server nodes. cluster-init.sh already keeps the CA there
// (ca.key never in SB_CLUSTER_TLS_DIR, which enterprise mode refuses).
const (
	caStoreCertFile = "ca.crt"
	caStoreKeyFile  = "ca.key"
)

// Join roles: what a token admits. "server" covers every role set that
// includes server (server, mixed, server+worker); the others never enter
// Raft and never get the CA key.
const (
	JoinRoleServer  = "server"
	JoinRoleWorker  = "worker"
	JoinRoleIngress = "ingress"
)

// ValidJoinRole reports whether role is one a join token can carry.
func ValidJoinRole(role string) bool {
	switch role {
	case JoinRoleServer, JoinRoleWorker, JoinRoleIngress:
		return true
	}
	return false
}

// GenerateJoinToken returns a fresh `<id>.<secret>` token from crypto/rand.
func GenerateJoinToken() (string, error) {
	id, err := randomJoinString(joinTokenIDLen)
	if err != nil {
		return "", err
	}
	secret, err := randomJoinString(joinTokenSecretLen)
	if err != nil {
		return "", err
	}
	return id + "." + secret, nil
}

// randomJoinString draws n characters uniformly from joinTokenAlphabet.
// Rejection sampling keeps every character equally likely: 252 is the
// largest multiple of 36 below 256.
func randomJoinString(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := io.ReadFull(pkiRandom, buf); err != nil {
			return "", fmt.Errorf("cluster: read random: %w", err)
		}
		for _, b := range buf {
			if b >= 252 {
				continue
			}
			out = append(out, joinTokenAlphabet[int(b)%len(joinTokenAlphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out), nil
}

// ParseJoinToken splits a token into its id and secret.
func ParseJoinToken(token string) (id, secret string, err error) {
	token = strings.TrimSpace(token)
	if !joinTokenPattern.MatchString(token) {
		return "", "", ErrJoinTokenFormat
	}
	id, secret, _ = strings.Cut(token, ".")
	return id, secret, nil
}

// ValidJoinTokenID reports whether id is a token id's shape.
func ValidJoinTokenID(id string) bool { return joinTokenIDPattern.MatchString(id) }

// joinTokenSecretHash is what Raft keeps to check a join. The secret is 165
// random bits, so a fast hash is enough: there is nothing to brute-force
// that a slow hash would protect. The id is mixed in so two tokens never
// share a hash.
func joinTokenSecretHash(id, secret string) []byte {
	sum := sha256.Sum256([]byte("aerolvm-join-token-v1\x00" + id + "." + secret))
	return sum[:]
}

// JoinDiscoveryKey derives the key that signs a token's cluster-info
// answer (D4). Raft keeps it next to the secret's hash. It can produce the
// discovery MAC but is not the secret, so a server that leaks it leaks no
// way to join. The new machine derives the same key from its token.
func JoinDiscoveryKey(token string) ([]byte, error) {
	id, secret, err := ParseJoinToken(token)
	if err != nil {
		return nil, err
	}
	return joinDiscoveryKey(id, secret)
}

func joinDiscoveryKey(id, secret string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(secret), []byte("aerolvm-join:"+id), "aerolvm join discovery v1", 32)
}

// JoinDiscoveryMAC is HMAC-SHA256(discovery key, ca.crt PEM), the proof
// that the answering server knows the token (kubeadm's signed cluster-info).
func JoinDiscoveryMAC(discoveryKey, caPEM []byte) []byte {
	mac := hmac.New(sha256.New, discoveryKey)
	mac.Write(caPEM)
	return mac.Sum(nil)
}

// VerifyJoinDiscovery is the new machine's check of a cluster-info answer:
// the MAC over caPEM must come from the discovery key of token.
func VerifyJoinDiscovery(token string, caPEM, mac []byte) bool {
	key, err := JoinDiscoveryKey(token)
	if err != nil {
		return false
	}
	return hmac.Equal(JoinDiscoveryMAC(key, caPEM), mac)
}

// constantTimeEqual compares two hashes without leaking where they differ.
func constantTimeEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// CACertHash is `sha256:<hex>` over the CA's SubjectPublicKeyInfo, the pin
// `--ca-cert-hash` carries (kubeadm's discovery-token-ca-cert-hash). It is
// also the cluster ID: it never changes while the CA lives.
func CACertHash(ca *x509.Certificate) string {
	if ca == nil {
		return ""
	}
	sum := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CertKeyHash is the hex SHA-256 of a cert's SubjectPublicKeyInfo: the
// "cert key" admitted records, deny tombstones and renewals compare.
func CertKeyHash(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// PublicKeyHash is CertKeyHash for a bare public key (a CSR's).
func PublicKeyHash(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("cluster: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// validKeyHash reports whether s is a hex SHA-256.
func validKeyHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ExtractPeerRole returns the role a node cert was signed for (DNS:role:x),
// or "" for a cert signed before the join service (cluster-sign-node.sh).
func ExtractPeerRole(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, name := range cert.DNSNames {
		if role, ok := strings.CutPrefix(strings.TrimSpace(name), nodeRoleSANprefix); ok && ValidJoinRole(role) {
			return role
		}
	}
	return ""
}

// ParseCertificateRequestPEM parses and verifies one PEM CSR: the signature
// proves the caller holds the private key whose public half it names.
func ParseCertificateRequestPEM(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, errors.New("cluster: csr must be one PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cluster: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("cluster: csr signature: %w", err)
	}
	if err := checkNodeKey(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr, nil
}

// checkNodeKey refuses node keys too weak to trust: RSA below 2048 bits and
// curves other than P-256/P-384.
func checkNodeKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("cluster: csr RSA key is %d bits; need at least 2048", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return errors.New("cluster: csr ECDSA key must use P-256 or P-384")
		}
	default:
		return fmt.Errorf("cluster: csr key type %T is not supported (use ECDSA P-256 or RSA)", pub)
	}
	return nil
}

// NewNodeCSR makes a CSR for key. The signer ignores its names (it builds
// the cert from the token and the requested node ID), so this only proves
// possession of key. The node side of join and the renewal ticker use it.
func NewNodeCSR(key crypto.Signer, nodeID string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeID},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("cluster: create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// NewNodeKey makes a node private key (ECDSA P-256) and its PKCS#8 PEM.
func NewNodeKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: generate node key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: marshal node key: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ClusterCA is the CA that signs node certs, held on server nodes (D5).
type ClusterCA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	keyPEM  []byte
}

// Certificate returns the CA cert.
func (ca *ClusterCA) Certificate() *x509.Certificate {
	if ca == nil {
		return nil
	}
	return ca.cert
}

// CertPEM returns the CA cert as PEM.
func (ca *ClusterCA) CertPEM() []byte {
	if ca == nil {
		return nil
	}
	return ca.certPEM
}

// KeyPEM returns the CA private key as PEM, for a server's join answer
// and the adopt fetch only.
func (ca *ClusterCA) KeyPEM() []byte {
	if ca == nil {
		return nil
	}
	return ca.keyPEM
}

// GenerateClusterCA makes a new ECDSA P-256 CA valid for ten years. The
// daemon only checks chains and names (tls.go), so a cluster whose old
// nodes carry RSA certs from cluster-init.sh can add P-256 ones.
// `sandboxd init` (Phase 2b) calls it.
func GenerateClusterCA(commonName string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(commonName) == "" {
		commonName = "aerolvm-cluster-ca"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"AerolVM"}},
		NotBefore:             now.Add(-nodeCertBackdate),
		NotAfter:              now.Add(caCertLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: create CA cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: marshal CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// ParseClusterCA pairs a CA cert with its private key and refuses a key
// that does not match, or a cert that is not a CA.
func ParseClusterCA(certPEM, keyPEM []byte) (*ClusterCA, error) {
	cert, err := firstPEMCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("cluster: CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("cluster: CA cert is not a CA (basicConstraints CA:FALSE)")
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("cluster: CA key: %w", err)
	}
	if !publicKeysEqual(key.Public(), cert.PublicKey) {
		return nil, errors.New("cluster: CA key does not match the CA cert")
	}
	return &ClusterCA{cert: cert, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), key: key, keyPEM: keyPEM}, nil
}

// LoadClusterCA reads ca.crt + ca.key from dir. A missing ca.key is
// (nil, nil): this server holds no signer yet (a pre-adopt server).
func LoadClusterCA(dir string) (*ClusterCA, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caStoreKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cluster: read CA key: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, caStoreCertFile))
	if err != nil {
		return nil, fmt.Errorf("cluster: read CA cert: %w", err)
	}
	return ParseClusterCA(certPEM, keyPEM)
}

// SaveClusterCA writes ca.crt and ca.key into dir (0700 dir, 0600 key),
// each atomically.
func SaveClusterCA(dir string, ca *ClusterCA) error {
	if ca == nil || strings.TrimSpace(dir) == "" {
		return errors.New("cluster: SaveClusterCA needs a CA and a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cluster: create CA dir: %w", err)
	}
	if err := WriteFileAtomic(filepath.Join(dir, caStoreCertFile), ca.certPEM, 0o644); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(dir, caStoreKeyFile), ca.keyPEM, 0o600)
}

// NodeCertRequest is what the signer needs: the CSR's key, the node ID and
// role it admits, and the cert's life. Names in the CSR are never read.
type NodeCertRequest struct {
	PublicKey crypto.PublicKey
	NodeID    string
	Role      string
	Lifetime  time.Duration
	Now       time.Time
}

// SignNodeCert builds a node cert from the request (never from the CSR's
// names, the rule cluster-sign-node.sh follows): SANs aerolvm-cluster-node,
// node:<id> and role:<role>, server and client auth, valid for Lifetime but
// never past the CA's own expiry.
func (ca *ClusterCA) SignNodeCert(req NodeCertRequest) ([]byte, *x509.Certificate, error) {
	if ca == nil || ca.key == nil {
		return nil, nil, ErrNoCASigner
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if !ValidJoinNodeID(nodeID) {
		return nil, nil, fmt.Errorf("%w: %q", ErrJoinNodeIDInvalid, req.NodeID)
	}
	if !ValidJoinRole(req.Role) {
		return nil, nil, fmt.Errorf("cluster: role %q is not server, worker or ingress", req.Role)
	}
	if err := checkNodeKey(req.PublicKey); err != nil {
		return nil, nil, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	life := req.Lifetime
	if life <= 0 {
		life = NodeCertLifetime
	}
	notAfter := now.Add(life)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	usage := x509.KeyUsageDigitalSignature
	if _, ok := req.PublicKey.(*rsa.PublicKey); ok {
		usage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID, Organization: []string{"AerolVM Cluster Node"}},
		NotBefore:    now.Add(-nodeCertBackdate),
		NotAfter:     notAfter,
		KeyUsage:     usage,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{clusterServerName, nodeIDSANprefix + nodeID, nodeRoleSANprefix + req.Role},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, req.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: sign node cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: parse signed cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), leaf, nil
}

// joinNodeIDPattern bounds node IDs to what a DNS SAN, a gossip name and a
// Raft server ID all accept.
var joinNodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidJoinNodeID reports whether id may name a joining node.
func ValidJoinNodeID(id string) bool { return joinNodeIDPattern.MatchString(id) }

// pkiRandom is where token secrets and cert serials come from. A var so a
// test can make it fail; always crypto/rand in production.
var pkiRandom io.Reader = rand.Reader

// randomSerial is a positive 127-bit serial (RFC 5280 allows 20 octets).
func randomSerial() (*big.Int, error) {
	var buf [16]byte
	if _, err := io.ReadFull(pkiRandom, buf[:]); err != nil {
		return nil, fmt.Errorf("cluster: serial: %w", err)
	}
	buf[0] &= 0x7f
	serial := new(big.Int).SetBytes(buf[:])
	return serial.Add(serial, big.NewInt(1)), nil
}

func firstPEMCertificate(raw []byte) (*x509.Certificate, error) {
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
	return nil, errors.New("no PEM CERTIFICATE")
}

// parsePrivateKeyPEM reads PKCS#8, PKCS#1 (RSA, cluster-init.sh's openssl
// genrsa) or SEC1 (EC) keys.
func parsePrivateKeyPEM(raw []byte) (crypto.Signer, error) {
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			signer, ok := key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("key type %T cannot sign", key)
			}
			return signer, nil
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}
	return nil, errors.New("no PEM private key")
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ea, ok := a.(equaler)
	return ok && ea.Equal(b)
}

// WriteFileAtomic writes data to path through a temp file in the same
// directory and a rename, so a reader (tls.go's reload on handshake) sees
// the old file or the new one, never half of either.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("cluster: write %s: %w", path, err)
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("cluster: write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("cluster: chmod %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("cluster: sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("cluster: close %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return fmt.Errorf("cluster: rename %s: %w", path, err)
	}
	return nil
}

// caSigner is the server's CA, loaded once at boot from the CA store and
// replaced by adopt. Reads are a pointer load under a read lock.
type caSigner struct {
	mu sync.RWMutex
	ca *ClusterCA
}

func (s *caSigner) get() *ClusterCA {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ca
}

func (s *caSigner) set(ca *ClusterCA) {
	s.mu.Lock()
	s.ca = ca
	s.mu.Unlock()
}
