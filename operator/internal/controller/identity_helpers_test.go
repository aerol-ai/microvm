package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testJoinURL and testJoinCA are what the chart gives the operator: where
// a joining pod asks, and the CA it trusts the answer by.
const testJoinURL = "https://aerolvm-operator.aerolvm-system.svc/v1/join-token"

var testJoinCA = newJoinCA()

// otherJoinCA is a CA the operator renewed to.
func otherJoinCA(t *testing.T) []byte {
	t.Helper()
	return newJoinCA()
}

func newJoinCA() []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "aerolvm-operator-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
