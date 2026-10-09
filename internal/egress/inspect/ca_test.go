package inspect

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestAuthorityMintsTrustedLeaves(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	certPEM, keyPEM, err := GenerateCA("node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	a, err := New(certPEM, keyPEM, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.CertPEM()) {
		t.Fatal("CA PEM")
	}
	leaf, err := a.Leaf("API.Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: pool, CurrentTime: now}); err != nil {
		t.Fatalf("leaf must verify under the CA: %v", err)
	}
	if again, _ := a.Leaf("api.example.com"); again != leaf {
		t.Fatal("a fresh leaf must come from the cache")
	}
	clock = now.Add(leafLifetime - leafRenew + time.Minute)
	if renewed, _ := a.Leaf("api.example.com"); renewed == leaf {
		t.Fatal("a leaf close to expiry must be reissued")
	}
	ipLeaf, err := a.Leaf("10.1.2.3")
	if err != nil || len(ipLeaf.Leaf.IPAddresses) != 1 {
		t.Fatalf("IP leaf = %v %v", ipLeaf, err)
	}
	if _, err := a.Leaf(""); err == nil {
		t.Fatal("no name, no leaf")
	}
	// The chain carries the CA, so tls.Config can serve it as is.
	if len(leaf.Certificate) != 2 {
		t.Fatalf("chain = %d", len(leaf.Certificate))
	}
	var _ = tls.Certificate{}
	for i := 0; i < maxCachedLeaves+1; i++ {
		if _, err := a.Leaf("h" + strings.Repeat("x", i%7) + ".example.com"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewRejectsBadCA(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, _ := GenerateCA("a", now)
	otherCert, otherKey, _ := GenerateCA("b", now)
	for name, tc := range map[string][2][]byte{
		"no cert":      {nil, keyPEM},
		"bad cert":     {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), keyPEM},
		"no key":       {certPEM, nil},
		"bad key":      {certPEM, []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n")},
		"mismatch":     {certPEM, otherKey},
		"other ok key": {otherCert, keyPEM},
	} {
		if _, err := New(tc[0], tc[1], nil); err == nil {
			t.Fatalf("%s: must fail", name)
		}
	}
	if _, err := New(certPEM, keyPEM, nil); err != nil {
		t.Fatal(err)
	}
}
