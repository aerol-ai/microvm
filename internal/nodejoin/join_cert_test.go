package nodejoin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
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

// Every way a join by certificate stops before writing a file: the host,
// the arguments, the server's refusal, and an answer an external-CA cluster
// never gives.
func TestJoinByCertificateStops(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(r *joinRig, o *JoinOptions)
		want string
	}{
		"not root, not files-only": {func(r *joinRig, o *JoinOptions) { o.FilesOnly = false }, "as root"},
		"not installed":            {func(r *joinRig, o *JoinOptions) { _ = os.Remove(r.paths.EnvFile) }, "is missing"},
		"a URL that is not one":    {func(r *joinRig, o *JoinOptions) { o.URL = "https://" }, "is not a URL"},
		"a bad --advertise":        {func(r *joinRig, o *JoinOptions) { o.Advertise = "not an address!" }, "not an IP address or a DNS name"},
		"a role that is none":      {func(r *joinRig, o *JoinOptions) { o.Address.NodeRole = "boss" }, "boss"},
		"a dial-back port held": {func(r *joinRig, o *JoinOptions) {
			r.host.listenErr = errors.New("permission denied")
		}, "for the dial-back"},
		"the server refuses": {func(r *joinRig, o *JoinOptions) {
			r.srv.refuse = map[string]joinRefuseSpec{cluster.JoinByCertPath: {http.StatusConflict, "node_id_in_use"}}
		}, "node_id_in_use"},
		"an answer for another node": {func(r *joinRig, o *JoinOptions) {
			r.srv.certAnswer = func(a *cluster.JoinResponse) { a.NodeID = "someone-else" }
		}, "the join answer is for someone-else"},
		"an answer with a CA key": {func(r *joinRig, o *JoinOptions) {
			r.srv.certAnswer = func(a *cluster.JoinResponse) { a.CAKey = "-----BEGIN PRIVATE KEY-----" }
		}, "never sends"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newJoinRig(t)
			r.host.notRoot = true
			writeExternalCATLS(t, r, "pod-w1", cluster.JoinRoleWorker)
			o := JoinOptions{ByCertificate: true, FilesOnly: true}
			tc.set(r, &o)
			if _, err := r.run(t, o); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if exists(r.paths.ClusterEnv) {
				t.Fatal("a stopped join wrote cluster.env")
			}
		})
	}
	// A dial-back refusal says how to fix it.
	r := newJoinRig(t)
	r.host.notRoot = true
	writeExternalCATLS(t, r, "pod-w1", cluster.JoinRoleWorker)
	r.srv.refuse = map[string]joinRefuseSpec{cluster.JoinByCertPath: {http.StatusPreconditionFailed, "dial_back"}}
	if _, err := r.run(t, JoinOptions{ByCertificate: true, FilesOnly: true}); err == nil || !strings.Contains(r.out.String(), "fix dial-back") {
		t.Fatalf("dial-back = %v; output %s", err, r.out.String())
	}
}

// The TLS dir is checked before anything is sent: a CA that is not one, a
// missing pair, a certificate another CA signed, and one with no node ID.
func TestExternalCAIdentity(t *testing.T) {
	ca := testExternalCA(t)
	for name, tc := range map[string]struct {
		set  func(dir string)
		want string
	}{
		"ca.crt holds no certificate": {func(dir string) { mustWrite(t, filepath.Join(dir, "ca.crt"), "junk") }, "holds no certificate"},
		"no key":                      {func(dir string) { _ = os.Remove(filepath.Join(dir, "node.key")) }, "node.crt, node.key"},
		"another CA": {func(dir string) {
			mustWrite(t, filepath.Join(dir, "ca.crt"), string(testExternalCA(t).CertPEM()))
		}, "does not chain"},
		"no node id": {func(dir string) { writeExternalCATLSDir(t, dir, ca, "", cluster.JoinRoleWorker) }, "no valid node:<id>"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeExternalCATLSDir(t, dir, ca, "pod-w1", cluster.JoinRoleWorker)
			tc.set(dir)
			if _, _, _, _, err := externalCAIdentity(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if _, _, _, _, err := externalCAIdentity(filepath.Join(t.TempDir(), "none")); err == nil || !strings.Contains(err.Error(), "ca.crt") {
		t.Fatalf("no TLS dir = %v", err)
	}
}

func TestInitExternalCAStops(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(r *initRig, o *InitOptions)
		want string
	}{
		"not installed":            {func(r *initRig, o *InitOptions) { _ = os.Remove(r.paths.EnvFile) }, "is missing"},
		"a bad --advertise":        {func(r *initRig, o *InitOptions) { o.Advertise = "not an address!" }, "not an IP address or a DNS name"},
		"no certificate":           {func(r *initRig, o *InitOptions) { _ = os.Remove(filepath.Join(r.paths.TLSDir, "node.crt")) }, "node.crt"},
		"a bad custody":            {func(r *initRig, o *InitOptions) { o.KeyCustody = "vault" }, "--key-custody must be file or wrapped"},
		"a bad gossip key":         {func(r *initRig, o *InitOptions) { o.GossipKey = "c2hvcnQ=" }, "--gossip-key must be base64"},
		"ca.crt not a certificate": {func(r *initRig, o *InitOptions) { corruptCADER(t, r.paths.TLSDir) }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			r := newInitRig(t)
			r.host.notRoot = true
			writeExternalCATLSDir(t, r.paths.TLSDir, testExternalCA(t), "srv-seed", cluster.JoinRoleServer)
			o := InitOptions{ExternalCA: true, FilesOnly: true}
			tc.set(r, &o)
			if _, err := r.run(t, o); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if exists(r.paths.ClusterEnv) {
				t.Fatal("a stopped init wrote cluster.env")
			}
		})
	}
	// A given gossip key is used as it is.
	r := newInitRig(t)
	r.host.notRoot = true
	writeExternalCATLSDir(t, r.paths.TLSDir, testExternalCA(t), "srv-seed", cluster.JoinRoleServer)
	const key = "MDEyMzQ1Njc4OWFiY2RlZg==" // 16 bytes
	if _, err := r.run(t, InitOptions{ExternalCA: true, FilesOnly: true, GossipKey: key}); err != nil {
		t.Fatal(err)
	}
	if env, _ := readEnvFile(r.paths.ClusterEnv); env["SB_GOSSIP_SECRET_KEY"] != key {
		t.Fatalf("gossip key = %q", env["SB_GOSSIP_SECRET_KEY"])
	}
}

// corruptCADER keeps ca.crt a PEM block whose bytes are not a certificate:
// the identity check, which reads the pool, fails first.
func corruptCADER(t *testing.T, dir string) {
	t.Helper()
	mustWrite(t, filepath.Join(dir, "ca.crt"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})))
}

func TestExternalClusterID(t *testing.T) {
	dir := t.TempDir()
	if _, err := externalClusterID(dir); err == nil {
		t.Fatal("no ca.crt")
	}
	mustWrite(t, filepath.Join(dir, "ca.crt"), "junk")
	if _, err := externalClusterID(dir); err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Fatalf("no PEM = %v", err)
	}
	corruptCADER(t, dir)
	if _, err := externalClusterID(dir); err == nil {
		t.Fatal("a PEM block that is not a certificate")
	}
	ca := testExternalCA(t)
	mustWrite(t, filepath.Join(dir, "ca.crt"), string(ca.CertPEM()))
	if id, err := externalClusterID(dir); err != nil || id != cluster.CACertHash(ca.Certificate()) {
		t.Fatalf("id = %q %v", id, err)
	}
}
