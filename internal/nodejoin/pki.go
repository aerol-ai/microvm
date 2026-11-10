package nodejoin

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// firstCert parses the first CERTIFICATE block in raw.
func firstCert(raw []byte) (*x509.Certificate, error) {
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
	return nil, errors.New("no PEM certificate")
}

// parseKey reads a PKCS#8, PKCS#1 (cluster-join.sh's openssl genrsa) or
// SEC1 private key.
func parseKey(raw []byte) (crypto.Signer, error) {
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			s, ok := k.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("key type %T can't sign", k)
			}
			return s, nil
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}
	return nil, errors.New("no PEM private key")
}

// nodeKeyFile is node.key in a TLS dir.
func nodeKeyFile(tlsDir string) string { return filepath.Join(tlsDir, "node.key") }

// loadNodeKey reads tlsDir/node.key; ok is false when there is none.
func loadNodeKey(tlsDir string) (crypto.Signer, bool, error) {
	raw, err := os.ReadFile(nodeKeyFile(tlsDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	key, err := parseKey(raw)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", nodeKeyFile(tlsDir), err)
	}
	return key, true, nil
}

// keyHash is the hex SHA-256 the cluster compares keys by.
func keyHash(key crypto.Signer) string {
	h, err := cluster.PublicKeyHash(key.Public())
	if err != nil {
		return ""
	}
	return h
}

// checkNodeCert checks a cert the cluster signed for this node: it chains
// to ca, names nodeID and carries key.
func checkNodeCert(certPEM []byte, ca *x509.Certificate, nodeID string, key crypto.Signer) (*x509.Certificate, error) {
	leaf, err := firstCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("node cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("node cert does not chain to the cluster CA: %w", err)
	}
	if got := cluster.ExtractPeerNodeID(leaf); got != nodeID {
		return nil, fmt.Errorf("node cert names %q, not %q", got, nodeID)
	}
	if key != nil && cluster.CertKeyHash(leaf) != keyHash(key) {
		return nil, errors.New("node cert carries another key")
	}
	return leaf, nil
}
