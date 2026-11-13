package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/version"
)

// externalCALeaf is a certificate the way the bank's issuer would sign one
// for a pod in external-CA mode: the shared test CA (which the test
// clusters trust) signs URI SANs node:<id> and the given roles.
func externalCALeaf(t *testing.T, nodeID string, roles ...string) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	sharedTestCAOnce.Do(initSharedTestCA)
	block, _ := pem.Decode(sharedTestCAPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var uris []*url.URL
	if nodeID != "" {
		uris = append(uris, &url.URL{Scheme: "node", Opaque: nodeID})
	}
	for _, r := range roles {
		uris = append(uris, &url.URL{Scheme: "aerolvm-role", Opaque: r})
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "pod-" + nodeID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{clusterServerName},
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, sharedTestCAKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestExtractCertRoles(t *testing.T) {
	leaf, _ := externalCALeaf(t, "wkr-1", "worker")
	if got := ExtractCertRoles(leaf); len(got) != 1 || got[0] != "worker" {
		t.Fatalf("roles = %v", got)
	}
	if ExtractPeerNodeID(leaf) != "wkr-1" {
		t.Fatalf("node id = %q", ExtractPeerNodeID(leaf))
	}
	two, _ := externalCALeaf(t, "wkr-1", "worker", "server")
	if got := ExtractCertRoles(two); len(got) != 2 {
		t.Fatalf("two roles = %v", got)
	}
	none, _ := externalCALeaf(t, "wkr-1")
	if got := ExtractCertRoles(none); len(got) != 0 || ExtractCertRoles(nil) != nil {
		t.Fatalf("no role = %v", got)
	}
	for name, tc := range map[string]struct {
		leaf *x509.Certificate
		want error
	}{
		"no certificate": {nil, ErrJoinBadRequest},
		"no role":        {none, ErrJoinBadRequest},
		"two roles":      {two, ErrJoinBadRequest},
		"unknown role":   {func() *x509.Certificate { l, _ := externalCALeaf(t, "wkr-1", "boss"); return l }(), ErrJoinBadRequest},
		"no node id":     {func() *x509.Certificate { l, _ := externalCALeaf(t, "", "worker"); return l }(), ErrJoinNodeIDInvalid},
	} {
		if _, _, err := certJoinIdentity(tc.leaf); !errors.Is(err, tc.want) {
			t.Errorf("%s = %v, want %v", name, err, tc.want)
		}
	}
}

// A node joins by its certificate in external-CA mode: admitted, its key
// pinned, and no certificate or CA key in the answer. Everything that would
// sign a certificate is refused in this mode.
func TestJoinByCert(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "eca-seed", true, nil, joinClusterOpts{
		mutate: func(c *config.Config) { c.ClusterExternalCA = true },
	})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	ports := dialBackListeners(t, 2)
	jp := &JoinPorts{Gossip: ports[0], Internal: ports[1]}
	src := netip.MustParseAddr("127.0.0.1")
	leaf, _ := externalCALeaf(t, "wkr-eca", JoinRoleWorker)
	req := JoinByCertRequest{Version: version.Version, Ports: jp, FSMOpsVersion: fsmOpsVersion}
	out, err := leader.JoinByCert(context.Background(), leaf, req, src)
	if err != nil {
		t.Fatal(err)
	}
	if out.NodeID != "wkr-eca" || out.Role != JoinRoleWorker || out.NodeCert != "" || out.CAKey != "" || out.ClusterID == "" || out.Replay {
		t.Fatalf("answer = %+v", out)
	}
	keyHash, _ := PublicKeyHash(leaf.PublicKey)
	if rec, ok := leader.fsm.admittedNode("wkr-eca"); !ok || rec.KeyHash != keyHash || rec.TokenID != "" {
		t.Fatalf("admitted = %+v %v", rec, ok)
	}
	if again, err := leader.JoinByCert(context.Background(), leaf, req, src); err != nil || !again.Replay {
		t.Fatalf("retry = %+v, %v", again, err)
	}
	// A second certificate for the ID (another key) waits for a delete.
	other, _ := externalCALeaf(t, "wkr-eca", JoinRoleWorker)
	if _, err := leader.JoinByCert(context.Background(), other, req, src); !errors.Is(err, ErrNodeIDInUse) {
		t.Fatalf("a second key = %v", err)
	}
	if _, err := leader.JoinByCert(context.Background(), leaf, JoinByCertRequest{Version: "v0.0.1", Ports: jp}, src); !errors.Is(err, ErrJoinVersion) {
		t.Fatalf("an old build = %v", err)
	}
	// What would need a CA key is refused, with the reason.
	_, csr := newCSR(t, "tok-1")
	if _, err := leader.Join(context.Background(), JoinRequest{Token: "abcdef.secret", NodeID: "tok-1", CSR: csr, Version: version.Version}, src); !errors.Is(err, ErrExternalCAMode) {
		t.Fatalf("a token join = %v", err)
	}
	if _, err := leader.CreateJoinToken(context.Background(), JoinTokenCreateRequest{Role: JoinRoleWorker}); !errors.Is(err, ErrExternalCAMode) {
		t.Fatalf("a join token = %v", err)
	}
	if JoinErrorStatus(ErrExternalCAMode) != http.StatusPreconditionFailed || JoinReason(ErrExternalCAMode) != "ca_mode" {
		t.Fatal("the mode refusal's answer")
	}
	// Out of the mode, a join by certificate is refused.
	leader.cfg.ClusterExternalCA = false
	if _, err := leader.JoinByCert(context.Background(), leaf, req, src); !errors.Is(err, ErrJoinByCertOff) {
		t.Fatalf("out of the mode = %v", err)
	}
}

// Over the join port: the handshake verifies the client certificate
// against the cluster's CA, and a call without one is refused.
func TestJoinByCertOverTheJoinPort(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	leader, cleanup := newJoinTestCluster(t, "eca-port", true, nil, joinClusterOpts{
		joinAddr: "127.0.0.1:0",
		mutate:   func(c *config.Config) { c.ClusterExternalCA = true },
	})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	if leader.joinServer == nil {
		t.Fatal("no join listener")
	}
	ports := dialBackListeners(t, 2)
	body, _ := json.Marshal(JoinByCertRequest{Version: version.Version, Ports: &JoinPorts{Gossip: ports[0], Internal: ports[1]}, FSMOpsVersion: fsmOpsVersion})
	call := func(certs []tls.Certificate) (int, JoinResponse) {
		client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // the test pins nothing; the server's check is what is under test
			Certificates:       certs,
		}}}
		resp, err := client.Post("https://"+leader.joinServer.Addr()+JoinByCertPath, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out JoinResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	_, pair := externalCALeaf(t, "ing-eca", JoinRoleIngress)
	if code, out := call([]tls.Certificate{pair}); code != http.StatusOK || out.NodeID != "ing-eca" || out.Role != JoinRoleIngress {
		t.Fatalf("join by certificate = %d %+v", code, out)
	}
	if code, _ := call(nil); code != http.StatusUnauthorized {
		t.Fatalf("no client certificate = %d", code)
	}
	// A certificate another CA signed is never taken: the server asks only
	// for its CA's certificates, so a Go client does not even send it, and
	// a certificate sent anyway fails the handshake.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "rogue"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{{Scheme: "node", Opaque: "rogue"}, {Scheme: "aerolvm-role", Opaque: JoinRoleServer}}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	rogue := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{rogue}}}}
	if resp, err := client.Post("https://"+leader.joinServer.Addr()+JoinByCertPath, "application/json", bytes.NewReader(body)); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a certificate from another CA was answered %d", resp.StatusCode)
		}
	}
	if _, ok := leader.fsm.admittedNode("rogue"); ok {
		t.Fatal("a certificate from another CA was admitted")
	}
}

// writeExternalCATLSDir writes a node's TLS dir as its cert-manager Secret
// would in external-CA mode: the CA, and a certificate with node:<id> and
// the role.
func writeExternalCATLSDir(t *testing.T, nodeID, role string) string {
	t.Helper()
	_, pair := externalCALeaf(t, nodeID, role)
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "eca-tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		tlsCAFile:       sharedTestCAPEM,
		tlsNodeCertFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}),
		tlsNodeKeyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// In external-CA mode the seed has no CA key to adopt with: Adopt admits it
// by the certificate it serves, and again changes nothing.
func TestAdoptSelfByCert(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a raft node")
	}
	tlsDir := writeExternalCATLSDir(t, "eca-adopt", JoinRoleServer)
	leader, cleanup := newJoinTestCluster(t, "eca-adopt", true, nil, joinClusterOpts{
		mutate: func(c *config.Config) { c.ClusterExternalCA, c.ClusterTLSDir = true, tlsDir },
	})
	defer cleanup()
	waitForLeader(t, leader, 10*time.Second)
	// Only the key this server serves with passes the live-member check for
	// its own ID: another key for it is still refused.
	if _, err := leader.WriteJoin(context.Background(), JoinWriteRequest{Kind: joinWriteAdmitByCert, Admit: &JoinAdmitCommand{
		NodeID: "eca-adopt", Role: JoinRoleServer, KeyHash: testKey("not-mine"), NotAfterUnixNano: time.Now().Add(time.Hour).UnixNano(),
	}}); !errors.Is(err, ErrNodeIDInUse) {
		t.Fatalf("another key for the leader's own ID = %v", err)
	}
	out, err := leader.Adopt(context.Background(), AdoptRequest{})
	if err != nil || len(out.Admitted) != 1 || out.Admitted[0] != "eca-adopt" || out.CASource != "external" || out.ClusterID == "" {
		t.Fatalf("adopt = %+v, %v", out, err)
	}
	if rec, ok := leader.fsm.admittedNode("eca-adopt"); !ok || rec.Role != JoinRoleServer || rec.TokenID != "" {
		t.Fatalf("admitted = %+v %v", rec, ok)
	}
	again, err := leader.Adopt(context.Background(), AdoptRequest{})
	if err != nil || len(again.Already) != 1 || len(again.Admitted) != 0 {
		t.Fatalf("adopt again = %+v, %v", again, err)
	}
}
