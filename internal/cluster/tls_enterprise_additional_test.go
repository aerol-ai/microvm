package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type livePeerTestClient struct {
	Client
	lookupMember Member
	lookupFound  bool
	localMembers []Member
}

func (c *livePeerTestClient) LookupMember(string) (Member, bool) {
	return c.lookupMember, c.lookupFound
}

func (c *livePeerTestClient) LocalMembers() []Member { return c.localMembers }

type scanPeerTestClient struct {
	Client
	localMembers []Member
}

func (c *scanPeerTestClient) LocalMembers() []Member { return c.localMembers }

func TestClusterTLSRequestIdentityFailClosed(t *testing.T) {
	SetPeerNodeIDHeader(nil, "node-a")
	req, err := http.NewRequest(http.MethodGet, "https://cluster.internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	SetPeerNodeIDHeader(req, "   ")
	if got := req.Header.Get(PeerNodeIDHeader); got != "" {
		t.Fatalf("empty identity installed header %q", got)
	}
	SetPeerNodeIDHeader(req, " node-a ")
	if got := req.Header.Get(PeerNodeIDHeader); got != "node-a" {
		t.Fatalf("peer header = %q, want node-a", got)
	}

	if _, err := AuthenticatedPeerNodeID(nil); err == nil {
		t.Fatal("nil request authenticated")
	}
	if _, err := AuthenticatedPeerNodeID(req); err == nil {
		t.Fatal("request without TLS authenticated")
	}
	req.TLS = &tls.ConnectionState{}
	if _, err := AuthenticatedPeerNodeID(req); err == nil {
		t.Fatal("request without a peer certificate authenticated")
	}
	shared := &x509.Certificate{DNSNames: []string{clusterServerName}}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{shared}, VerifiedChains: [][]*x509.Certificate{{shared}}}
	if _, err := AuthenticatedPeerNodeID(req); err == nil || !strings.Contains(err.Error(), "identity SAN") {
		t.Fatalf("shared-SAN authentication error = %v", err)
	}
	peer := &x509.Certificate{DNSNames: []string{clusterServerName, "node:node-b"}}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}, VerifiedChains: [][]*x509.Certificate{{peer}}}
	if _, err := AuthenticatedPeerNodeID(req); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("mismatched identity error = %v", err)
	}
	req.Header.Set(PeerNodeIDHeader, "node-b")
	if got, err := AuthenticatedPeerNodeID(req); err != nil || got != "node-b" {
		t.Fatalf("authenticated peer = (%q, %v), want node-b", got, err)
	}
}

func TestIsLivePeerUsesIndexedAndFallbackMembership(t *testing.T) {
	if IsLivePeer(nil, "node-a") || IsLivePeer(&scanPeerTestClient{}, " ") {
		t.Fatal("empty peer input reported live")
	}
	indexed := &livePeerTestClient{lookupMember: Member{NodeID: "node-a", Alive: true}, lookupFound: true}
	if !IsLivePeer(indexed, " node-a ") {
		t.Fatal("indexed live peer reported dead")
	}
	indexed.lookupMember.Alive = false
	if IsLivePeer(indexed, "node-a") {
		t.Fatal("indexed dead peer reported live")
	}
	indexed.lookupFound = false
	if IsLivePeer(indexed, "node-a") {
		t.Fatal("missing indexed peer reported live")
	}
	scan := &scanPeerTestClient{localMembers: []Member{{NodeID: "node-a", Alive: true}, {NodeID: "node-b", Alive: false}}}
	if !IsLivePeer(scan, "node-a") || IsLivePeer(scan, "node-b") || IsLivePeer(scan, "node-c") {
		t.Fatal("fallback membership scan returned the wrong liveness")
	}
}

func TestClusterTLSCertificateParsingRejectsMalformedMaterial(t *testing.T) {
	var absent *ClusterTLS
	if absent.NodeID() != "" {
		t.Fatal("nil ClusterTLS returned an identity")
	}
	if _, err := leafCertificate(nil); err == nil {
		t.Fatal("nil certificate accepted")
	}
	if _, err := leafCertificate(&tls.Certificate{}); err == nil {
		t.Fatal("empty certificate accepted")
	}
	leaf := &x509.Certificate{DNSNames: []string{"node:leaf"}}
	if got, err := leafCertificate(&tls.Certificate{Certificate: [][]byte{{0x01}}, Leaf: leaf}); err != nil || got != leaf {
		t.Fatalf("cached leaf = (%p, %v), want %p", got, err, leaf)
	}
	if _, err := leafCertificate(&tls.Certificate{Certificate: [][]byte{{0x01}}}); err == nil {
		t.Fatal("malformed DER leaf accepted")
	}

	if got := ExtractPeerNodeID(nil); got != "" {
		t.Fatalf("nil certificate identity = %q", got)
	}
	uOpaque := &url.URL{Scheme: "node", Opaque: "opaque-node"}
	uPath := &url.URL{Path: "/node:path-node"}
	cert := &x509.Certificate{URIs: []*url.URL{nil, uOpaque, uPath}}
	if got := ExtractPeerNodeID(cert); got != "opaque-node" {
		t.Fatalf("opaque URI identity = %q", got)
	}
	cert.URIs = []*url.URL{uPath}
	if got := ExtractPeerNodeID(cert); got != "path-node" {
		t.Fatalf("path URI identity = %q", got)
	}
	if !VerifyPeerNodeID(cert, " ") {
		t.Fatal("empty expected identity should be a no-op")
	}

	if _, err := earliestPEMCertificateExpiry([]byte("not pem")); err == nil {
		t.Fatal("non-PEM CA accepted")
	}
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})
	if _, err := earliestPEMCertificateExpiry(keyBlock); err == nil {
		t.Fatal("PEM without a certificate accepted")
	}
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad der")})
	if _, err := earliestPEMCertificateExpiry(badCert); err == nil {
		t.Fatal("malformed PEM certificate accepted")
	}
}

func TestPeerPinnedClientRejectsIdentityAndParserFailures(t *testing.T) {
	dir := writeTestClusterTLSDir(t, "peer-a")
	material, err := loadClusterTLS(dir)
	if err != nil {
		t.Fatalf("load peer TLS: %v", err)
	}
	raw := material.nodeCert.Certificate[0]
	base := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	pinned := ClientForPeer(base, "peer-a")
	verify := pinned.Transport.(*http.Transport).TLSClientConfig.VerifyPeerCertificate
	if err := verify(nil, nil); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing peer cert error = %v", err)
	}
	if err := verify([][]byte{{0x01}}, nil); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("malformed peer cert error = %v", err)
	}
	if err := verify([][]byte{raw}, nil); err != nil {
		t.Fatalf("matching peer rejected: %v", err)
	}
	wrong := ClientForPeer(base, "peer-b")
	if err := wrong.Transport.(*http.Transport).TLSClientConfig.VerifyPeerCertificate([][]byte{raw}, nil); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("wrong peer identity error = %v", err)
	}

	parentErr := errors.New("parent verification failed")
	withParent := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return parentErr },
	}}}
	wrapped := ClientForPeer(withParent, "peer-a")
	if err := wrapped.Transport.(*http.Transport).TLSClientConfig.VerifyPeerCertificate([][]byte{raw}, nil); !errors.Is(err, parentErr) {
		t.Fatalf("parent verification error = %v, want %v", err, parentErr)
	}
}
