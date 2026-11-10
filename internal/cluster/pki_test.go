package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJoinTokenFormatAndEntropy(t *testing.T) {
	seen := map[string]bool{}
	counts := map[rune]int{}
	const n = 2000
	for i := 0; i < n; i++ {
		tok, err := GenerateJoinToken()
		if err != nil {
			t.Fatal(err)
		}
		if !joinTokenPattern.MatchString(tok) {
			t.Fatalf("token %q does not match [a-z0-9]{6}.[a-z0-9]{32}", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
		id, secret, err := ParseJoinToken(tok)
		if err != nil || len(id) != 6 || len(secret) != 32 || !ValidJoinTokenID(id) {
			t.Fatalf("parse %q = %q %q %v", tok, id, secret, err)
		}
		for _, r := range secret {
			counts[r]++
		}
	}
	// 32 characters from a 36-character alphabet: at least 128 bits.
	if bits := float64(joinTokenSecretLen) * 5.169; bits < 128 {
		t.Fatalf("secret carries %.0f bits", bits)
	}
	// Every character turns up, none wildly more than its share: a crude
	// check that rejection sampling keeps the draw uniform.
	if len(counts) != len(joinTokenAlphabet) {
		t.Fatalf("only %d of %d characters drawn", len(counts), len(joinTokenAlphabet))
	}
	expected := float64(n*joinTokenSecretLen) / float64(len(joinTokenAlphabet))
	for r, c := range counts {
		if float64(c) < expected*0.8 || float64(c) > expected*1.2 {
			t.Fatalf("character %q drawn %d times, expected about %.0f", r, c, expected)
		}
	}
	for _, bad := range []string{"", "abc.def", "ABCDEF.0123456789abcdef0123456789abcdef", "abcdef0123456789abcdef0123456789abcdef", "abcdef.0123456789abcdef0123456789abcde", "abcdef.0123456789abcdef0123456789abcdef0", "abcde!.0123456789abcdef0123456789abcdef"} {
		if _, _, err := ParseJoinToken(bad); !errors.Is(err, ErrJoinTokenFormat) {
			t.Fatalf("ParseJoinToken(%q) = %v", bad, err)
		}
	}
	if _, _, err := ParseJoinToken("  abcdef.0123456789abcdef0123456789abcdef \n"); err != nil {
		t.Fatalf("surrounding space refused: %v", err)
	}
}

func TestJoinDiscoveryHMAC(t *testing.T) {
	tok, _ := GenerateJoinToken()
	other, _ := GenerateJoinToken()
	id, secret, _ := ParseJoinToken(tok)
	key, err := JoinDiscoveryKey(tok)
	if err != nil || len(key) != 32 {
		t.Fatalf("discovery key = %x %v", key, err)
	}
	// The discovery key is derived, not the secret or its hash.
	if string(key) == secret || constantTimeEqual(key, joinTokenSecretHash(id, secret)) {
		t.Fatal("discovery key equals the secret or its hash")
	}
	ca := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	mac := JoinDiscoveryMAC(key, ca)
	if !VerifyJoinDiscovery(tok, ca, mac) {
		t.Fatal("the right token failed the discovery check")
	}
	if VerifyJoinDiscovery(other, ca, mac) {
		t.Fatal("a wrong token passed the discovery check")
	}
	if VerifyJoinDiscovery(tok, append([]byte("x"), ca...), mac) {
		t.Fatal("a swapped CA passed the discovery check")
	}
	if VerifyJoinDiscovery("garbage", ca, mac) {
		t.Fatal("a malformed token passed")
	}
	if _, err := JoinDiscoveryKey("garbage"); err == nil {
		t.Fatal("discovery key from a malformed token")
	}
	if constantTimeEqual([]byte{1}, []byte{1, 2}) || !constantTimeEqual([]byte{1, 2}, []byte{1, 2}) {
		t.Fatal("constantTimeEqual")
	}
}

func mustCA(t *testing.T) *ClusterCA {
	t.Helper()
	certPEM, keyPEM, err := GenerateClusterCA("", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseClusterCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func csrWithNames(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "evil"},
		DNSNames: []string{"node:someone-else", "role:server", "aerolvm-cluster-node"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestClusterCASignsFromTheRequestNotTheCSR(t *testing.T) {
	ca := mustCA(t)
	if ca.Certificate().PublicKeyAlgorithm != x509.ECDSA || !ca.Certificate().IsCA {
		t.Fatalf("new CA is %v, CA=%v", ca.Certificate().PublicKeyAlgorithm, ca.Certificate().IsCA)
	}
	if !strings.HasPrefix(CACertHash(ca.Certificate()), "sha256:") || len(CACertHash(ca.Certificate())) != 71 {
		t.Fatalf("CA hash %q", CACertHash(ca.Certificate()))
	}
	key, _, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCertificateRequestPEM(csrWithNames(t, key))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certPEM, leaf, err := ca.SignNodeCert(NodeCertRequest{PublicKey: csr.PublicKey, NodeID: "wkr-7", Role: JoinRoleWorker, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || ExtractPeerNodeID(leaf) != "wkr-7" || ExtractPeerRole(leaf) != JoinRoleWorker {
		t.Fatalf("signed SANs = %v", leaf.DNSNames)
	}
	for _, name := range leaf.DNSNames {
		if name == "node:someone-else" || name == "role:server" {
			t.Fatalf("CSR name %q leaked into the cert", name)
		}
	}
	if got := leaf.NotAfter.Sub(now); got < NodeCertLifetime-time.Minute || got > NodeCertLifetime+time.Minute {
		t.Fatalf("cert life %v, want %v", got, NodeCertLifetime)
	}
	// The cert verifies the way tls.go checks a peer.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	pair := tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf}
	if _, _, err := validateClusterNodeCertificate(&pair, pool); err != nil {
		t.Fatalf("signed cert does not pass the daemon's check: %v", err)
	}
	pkHash, _ := PublicKeyHash(&key.PublicKey)
	if CertKeyHash(leaf) != pkHash || !validKeyHash(pkHash) {
		t.Fatal("cert key hash differs from the CSR key hash")
	}

	// Life is capped at the CA's own expiry.
	_, short, err := ca.SignNodeCert(NodeCertRequest{PublicKey: &key.PublicKey, NodeID: "wkr-7", Role: JoinRoleWorker, Lifetime: 100 * 365 * 24 * time.Hour})
	if err != nil || short.NotAfter.After(ca.Certificate().NotAfter) {
		t.Fatalf("lifetime past the CA: %v %v", short.NotAfter, err)
	}

	cases := []NodeCertRequest{
		{PublicKey: &key.PublicKey, NodeID: "bad id!", Role: JoinRoleWorker},
		{PublicKey: &key.PublicKey, NodeID: "wkr-7", Role: "admin"},
		{PublicKey: weakRSAKey(t), NodeID: "wkr-7", Role: JoinRoleWorker},
	}
	for i, req := range cases {
		if _, _, err := ca.SignNodeCert(req); err == nil {
			t.Fatalf("bad request %d signed", i)
		}
	}
	var none *ClusterCA
	if _, _, err := none.SignNodeCert(cases[0]); !errors.Is(err, ErrNoCASigner) {
		t.Fatalf("nil CA sign = %v", err)
	}
	if none.Certificate() != nil || none.CertPEM() != nil || none.KeyPEM() != nil {
		t.Fatal("nil CA accessors")
	}
}

func weakRSAKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}

// An existing RSA CA (cluster-init.sh's openssl genrsa, PKCS#1) still signs.
func TestClusterCAAcceptsExistingRSACA(t *testing.T) {
	sharedTestCAOnce.Do(initSharedTestCA)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(sharedTestCAKey)})
	ca, err := ParseClusterCA(sharedTestCAPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	key, _, _ := NewNodeKey()
	_, leaf, err := ca.SignNodeCert(NodeCertRequest{PublicKey: &key.PublicKey, NodeID: "srv-2", Role: JoinRoleServer})
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(ca.Certificate()); err != nil {
		t.Fatal(err)
	}
	// RSA node keys get keyEncipherment too.
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, leaf, err := ca.SignNodeCert(NodeCertRequest{PublicKey: &rk.PublicKey, NodeID: "srv-3", Role: JoinRoleServer}); err != nil || leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Fatalf("RSA node cert = %v %v", leaf, err)
	}
	// A key that does not match, a non-CA cert and junk are refused.
	other := mustCA(t)
	if _, err := ParseClusterCA(sharedTestCAPEM, other.KeyPEM()); err == nil {
		t.Fatal("mismatched CA key accepted")
	}
	if _, err := ParseClusterCA(pemOfLeaf(leaf), keyPEM); err == nil {
		t.Fatal("a leaf accepted as CA")
	}
	if _, err := ParseClusterCA([]byte("junk"), keyPEM); err == nil {
		t.Fatal("junk cert accepted")
	}
	if _, err := ParseClusterCA(sharedTestCAPEM, []byte("junk")); err == nil {
		t.Fatal("junk key accepted")
	}
	ecDER, _ := x509.MarshalECPrivateKey(mustECKey(t))
	if _, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})); err != nil {
		t.Fatalf("SEC1 key: %v", err)
	}
	if _, err := parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})); err == nil {
		t.Fatal("bad PKCS#8 accepted")
	}
}

func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pemOfLeaf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func TestParseCertificateRequestPEMRefusesBadInput(t *testing.T) {
	key := mustECKey(t)
	good := csrWithNames(t, key)
	if _, err := ParseCertificateRequestPEM(good); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(good)
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-3] ^= 0xff
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, weak)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	p224DER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, p224)
	for name, raw := range map[string][]byte{
		"not pem":   []byte("hello"),
		"wrong pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		"garbage":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("x")}),
		"tampered":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}),
		"weak rsa":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: weakDER}),
		"p224":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: p224DER}),
	} {
		if _, err := ParseCertificateRequestPEM(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := NewNodeCSR(key, "n1"); err != nil {
		t.Fatal(err)
	}
	if err := checkNodeKey("not a key"); err == nil {
		t.Fatal("non-key accepted")
	}
	if _, err := PublicKeyHash("not a key"); err == nil {
		t.Fatal("hash of a non-key")
	}
	if CertKeyHash(nil) != "" || CACertHash(nil) != "" || ExtractPeerRole(nil) != "" || validKeyHash("zz") {
		t.Fatal("nil helpers")
	}
}

func TestClusterCAStoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cluster-ca")
	if ca, err := LoadClusterCA(dir); ca != nil || err != nil {
		t.Fatalf("missing store = %v %v", ca, err)
	}
	if ca, err := LoadClusterCA(""); ca != nil || err != nil {
		t.Fatalf("unset store = %v %v", ca, err)
	}
	ca := mustCA(t)
	if err := SaveClusterCA(dir, ca); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, caStoreKeyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode = %v %v", info, err)
	}
	loaded, err := LoadClusterCA(dir)
	if err != nil || CACertHash(loaded.Certificate()) != CACertHash(ca.Certificate()) {
		t.Fatalf("reload = %v %v", loaded, err)
	}
	if err := SaveClusterCA("", ca); err == nil {
		t.Fatal("save without a dir")
	}
	// A key with no cert beside it is an error, not "no signer".
	if err := os.Remove(filepath.Join(dir, caStoreCertFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClusterCA(dir); err == nil {
		t.Fatal("ca.key without ca.crt loaded")
	}
	if err := WriteFileAtomic(filepath.Join(dir, "missing-dir", "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("write into a missing dir")
	}
	var signer *caSigner
	if signer.get() != nil {
		t.Fatal("nil signer")
	}
	signer = &caSigner{}
	signer.set(ca)
	if signer.get() != ca {
		t.Fatal("signer set/get")
	}
}
