// Package podtrust is how a pod-mode sandbox's toolboxd knows a caller is
// its own worker (plans/security-gaps-m1-m4.md §6.2, eng review D8).
//
// In pod mode a sandbox is a Kubernetes pod, and anything in a pod spec is
// stored in etcd, readable by anyone who may read pods in the namespace. So
// the spec carries no secret: no toolbox token, no env. toolboxd starts with
// none and trusts two public facts its spec does carry: the cell's worker
// CA (a public certificate, mounted from a ConfigMap) and the node ID of the
// one worker that made the pod. It serves one mTLS listener; only a client
// certificate that CA signed, naming that node, gets through. Over it the
// worker hands toolboxd the token and env (the adopt call). Read access to
// pods reveals no credential.
//
// Worker certificates are the cluster's node certificates
// (internal/cluster SignNodeCert): a DNS (or URI) SAN "node:<id>" names the
// node. This package reads that SAN the same way internal/cluster's
// ExtractPeerNodeID does (a test holds the two to the same answers) without
// importing it: toolboxd runs inside every sandbox and stays small.
package podtrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// AdoptPath is the adopt call: POST a readyproto.AdoptFrame, get a
	// readyproto.ReadySignal back.
	AdoptPath = "/v1/pod/adopt"
	// DefaultAdoptPort is the mTLS listener's port, next to the toolbox
	// API's 2280.
	DefaultAdoptPort = 2281

	nodeIDPrefix = "node:"
	// clusterServerName is the name every node certificate also carries
	// (internal/cluster tls.go): shared by all nodes, never a node ID.
	clusterServerName = "aerolvm-cluster-node"
)

// ErrNotThisWorker is a client certificate the CA signed for another node,
// or for none.
var ErrNotThisWorker = errors.New("podtrust: the client certificate does not name this sandbox's worker")

// NodeIDOf returns the node a certificate names: its first DNS or URI SAN
// of the form node:<id>. "" when it names none. Common names are never
// read.
func NodeIDOf(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, name := range cert.DNSNames {
		if id := parseNodeID(name); id != "" {
			return id
		}
	}
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		for _, s := range []string{uri.String(), uri.Opaque, strings.TrimPrefix(uri.Path, "/")} {
			if id := parseNodeID(s); id != "" {
				return id
			}
		}
	}
	return ""
}

func parseNodeID(s string) string {
	id, ok := strings.CutPrefix(strings.TrimSpace(s), nodeIDPrefix)
	if !ok {
		return ""
	}
	id = strings.TrimSpace(id)
	if id == clusterServerName {
		return ""
	}
	return id
}

// LoadCAs reads PEM certificates into a pool; it refuses PEM with none.
func LoadCAs(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("podtrust: the worker CA file holds no certificate")
	}
	return pool, nil
}

// ServerConfig is the TLS config of toolboxd's adopt listener: a client
// must present a certificate cas signed for client use (Go checks the
// chain and the key usage) whose node is worker; any other is refused in
// the handshake, before a byte of the call is read.
//
// toolboxd's own certificate is made here, in memory, and signed by no
// one: nothing can sign for a pod's toolbox before the pod exists. So this
// listener proves who the client is, not who the server is; how the worker
// knows it reached its own pod is the worker side's question (M4 PR 4).
func ServerConfig(cas *x509.CertPool, worker string) (*tls.Config, error) {
	worker = strings.TrimSpace(worker)
	if cas == nil || worker == "" {
		return nil, errors.New("podtrust: a worker CA and a worker node ID are required")
	}
	cert, err := ephemeralCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cas,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return checkWorker(cs.VerifiedChains, worker)
		},
	}, nil
}

// checkWorker accepts only a verified chain whose leaf names worker.
func checkWorker(chains [][]*x509.Certificate, worker string) error {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return ErrNotThisWorker
	}
	if got := NodeIDOf(chains[0][0]); got != worker {
		return fmt.Errorf("%w (it names %q)", ErrNotThisWorker, got)
	}
	return nil
}

// ephemeralCertLife covers the longest a sandbox pod runs: the certificate
// lives as long as the toolboxd process that made it.
const ephemeralCertLife = 10 * 365 * 24 * time.Hour

func ephemeralCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("podtrust: key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("podtrust: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "aerolvm-toolbox"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ephemeralCertLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("podtrust: certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
