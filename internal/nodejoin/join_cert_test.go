package nodejoin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// writeExternalCATLS puts in the TLS dir what a pod's cert-manager Secret
// holds in external-CA mode: the CA, and a certificate it signed for
// node:<nodeID> with the given roles.
func writeExternalCATLS(t *testing.T, r *joinRig, nodeID string, roles ...string) {
	t.Helper()
	writeExternalCATLSDir(t, r.paths.TLSDir, r.srv.ca, nodeID, roles...)
}

// writeExternalCATLSDir is writeExternalCATLS for any TLS dir and CA.
func writeExternalCATLSDir(t *testing.T, tlsDir string, ca *cluster.ClusterCA, nodeID string, roles ...string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uris := []*url.URL{{Scheme: "node", Opaque: nodeID}}
	for _, role := range roles {
		uris = append(uris, &url.URL{Scheme: "aerolvm-role", Opaque: role})
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: nodeID},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs: uris,
	}
	caKeyBlock, _ := pem.Decode(ca.KeyPEM())
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		if k, err2 := x509.ParseECPrivateKey(caKeyBlock.Bytes); err2 == nil {
			caKey = k
		} else {
			t.Fatalf("CA key: %v / %v", err, err2)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate(), &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(tlsDir, "ca.crt"), string(ca.CertPEM()))
	mustWrite(t, filepath.Join(tlsDir, "node.crt"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	mustWrite(t, filepath.Join(tlsDir, "node.key"), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
}

// A pod in external-CA mode joins with its certificate: no token, the ID
// and role from the certificate, the bundle written to cluster.env, and the
// TLS dir left as the Secret made it.
func TestJoinByCertificateFilesOnly(t *testing.T) {
	r := newJoinRig(t)
	r.host.notRoot = true
	writeExternalCATLS(t, r, "pod-w1", cluster.JoinRoleWorker)
	before := readFile(t, filepath.Join(r.paths.TLSDir, "node.crt"))
	res, err := r.run(t, JoinOptions{ByCertificate: true, FilesOnly: true})
	if err != nil {
		t.Fatalf("join by certificate: %v\n%s", err, r.out.String())
	}
	if res.NodeID != "pod-w1" || res.Role != cluster.JoinRoleWorker {
		t.Fatalf("result = %+v", res)
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	for k, want := range map[string]string{
		"SB_ENABLE_CLUSTER": "true", "SB_CLUSTER_BOOTSTRAP": "false", "SB_CLUSTER_EXTERNAL_CA": "true",
		"SB_NODE_ID": "pod-w1", "SB_GOSSIP_SECRET_KEY": "Z29zc2lwLWtleS0xNi1ieXRlcw==", "SB_BOOTSTRAP_PEERS": "10.0.0.5:7001",
	} {
		if env[k] != want {
			t.Fatalf("cluster.env %s = %q, want %q", k, env[k], want)
		}
	}
	if readFile(t, filepath.Join(r.paths.TLSDir, "node.crt")) != before {
		t.Fatal("the join rewrote the Secret's certificate")
	}
	if exists(filepath.Join(r.paths.CADir, "ca.key")) || exists(r.paths.DropIn) || r.host.restarts != 0 {
		t.Fatal("wrote a CA key or a drop-in, or restarted")
	}
	if !strings.Contains(r.out.String(), "by its certificate") {
		t.Fatalf("output: %s", r.out.String())
	}
}

func TestJoinByCertificateRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		roles []string
		opts  JoinOptions
		want  string
	}{
		"a token too":     {[]string{cluster.JoinRoleWorker}, JoinOptions{Token: "abcdef.0123456789abcdef"}, "takes no --token"},
		"another node id": {[]string{cluster.JoinRoleWorker}, JoinOptions{NodeID: "someone-else"}, "the certificate names pod-w1"},
		"another role":    {[]string{cluster.JoinRoleWorker}, JoinOptions{Address: AddressOptions{NodeRole: "ingress"}}, "the certificate's role is worker"},
		"no role":         {nil, JoinOptions{}, "exactly one role"},
		"two roles":       {[]string{cluster.JoinRoleWorker, cluster.JoinRoleServer}, JoinOptions{}, "exactly one role"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newJoinRig(t)
			r.host.notRoot = true
			writeExternalCATLS(t, r, "pod-w1", tc.roles...)
			tc.opts.ByCertificate, tc.opts.FilesOnly = true, true
			if _, err := r.run(t, tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if exists(r.paths.ClusterEnv) {
				t.Fatal("a refused join wrote cluster.env")
			}
		})
	}
	// No certificate in the TLS dir at all.
	r := newJoinRig(t)
	r.host.notRoot = true
	_ = os.RemoveAll(r.paths.TLSDir)
	if _, err := r.run(t, JoinOptions{ByCertificate: true, FilesOnly: true}); err == nil || !strings.Contains(err.Error(), "ca.crt") {
		t.Fatalf("no TLS dir = %v", err)
	}
}

// testExternalCA is a CA standing in for the bank's issuer.
func testExternalCA(t *testing.T) *cluster.ClusterCA {
	t.Helper()
	certPEM, keyPEM, err := cluster.GenerateClusterCA("bank issuer", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := cluster.ParseClusterCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// The seed of an external-CA cluster writes cluster.env only: no CA made,
// no certificate signed, no token.
func TestInitExternalCA(t *testing.T) {
	r := newInitRig(t)
	r.host.notRoot = true
	ca := testExternalCA(t)
	writeExternalCATLSDir(t, r.paths.TLSDir, ca, "srv-seed", cluster.JoinRoleServer)
	before := readFile(t, filepath.Join(r.paths.TLSDir, "node.crt"))
	res, err := r.run(t, InitOptions{ExternalCA: true, FilesOnly: true})
	if err != nil {
		t.Fatalf("init --external-ca: %v\n%s", err, r.out.String())
	}
	if res.NodeID != "srv-seed" || res.ClusterID != cluster.CACertHash(ca.Certificate()) || res.Again {
		t.Fatalf("result = %+v", res)
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	for k, want := range map[string]string{"SB_ENABLE_CLUSTER": "true", "SB_CLUSTER_BOOTSTRAP": "true", "SB_CLUSTER_EXTERNAL_CA": "true", "SB_NODE_ID": "srv-seed"} {
		if env[k] != want {
			t.Fatalf("cluster.env %s = %q, want %q", k, env[k], want)
		}
	}
	if env["SB_GOSSIP_SECRET_KEY"] == "" {
		t.Fatal("no gossip key")
	}
	if exists(filepath.Join(r.paths.CADir, "ca.key")) || readFile(t, filepath.Join(r.paths.TLSDir, "node.crt")) != before {
		t.Fatal("made a CA or rewrote the Secret's certificate")
	}
	if len(r.api.tokens) != 0 || r.host.restarts != 0 {
		t.Fatal("made a token or restarted")
	}
	again, err := r.run(t, InitOptions{ExternalCA: true, FilesOnly: true})
	if err != nil || !again.Again || again.ClusterID != res.ClusterID {
		t.Fatalf("a re-run = %+v %v", again, err)
	}
}

func TestInitExternalCARefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		role string
		opts InitOptions
		want string
	}{
		"not files-only": {cluster.JoinRoleServer, InitOptions{}, "needs --files-only"},
		"tokens":         {cluster.JoinRoleServer, InitOptions{FilesOnly: true, Tokens: []TokenSpec{{Role: cluster.JoinRoleWorker}}}, "takes no --token"},
		"a worker cert":  {cluster.JoinRoleWorker, InitOptions{FilesOnly: true}, "aerolvm-role:server"},
		"another id":     {cluster.JoinRoleServer, InitOptions{FilesOnly: true, NodeID: "other"}, "the certificate names srv-seed"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newInitRig(t)
			r.host.notRoot = true
			writeExternalCATLSDir(t, r.paths.TLSDir, testExternalCA(t), "srv-seed", tc.role)
			tc.opts.ExternalCA = true
			if _, err := r.run(t, tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// Another cluster's cluster.env is never overwritten.
	r := newInitRig(t)
	r.host.notRoot = true
	writeExternalCATLSDir(t, r.paths.TLSDir, testExternalCA(t), "srv-seed", cluster.JoinRoleServer)
	mustWrite(t, r.paths.ClusterEnv, "SB_ENABLE_CLUSTER=true\nSB_NODE_ID=someone\n")
	if _, err := r.run(t, InitOptions{ExternalCA: true, FilesOnly: true}); err == nil || !strings.Contains(err.Error(), "another cluster") {
		t.Fatalf("over another cluster.env = %v", err)
	}
}
