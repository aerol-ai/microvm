package inspect

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// starveEntropy makes key generation fail for the rest of the test. Since Go
// 1.26 crypto ignores a custom reader unless cryptocustomrand=1, and the
// runtime re-reads GODEBUG on Setenv.
func starveEntropy(t *testing.T) {
	t.Setenv("GODEBUG", strings.TrimPrefix(os.Getenv("GODEBUG")+",cryptocustomrand=1", ","))
	old := rand.Reader
	rand.Reader = failingReader{}
	t.Cleanup(func() { rand.Reader = old })
}

func TestKeyGenerationFailuresSurface(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("node-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	starveEntropy(t)
	if _, _, err := GenerateCA("node-a", time.Now()); err == nil || !strings.Contains(err.Error(), "inspection CA key") {
		t.Fatalf("GenerateCA without entropy = %v", err)
	}
	if _, err := New(certPEM, keyPEM, nil); err == nil || !strings.Contains(err.Error(), "inspection leaf key") {
		t.Fatalf("New without entropy = %v", err)
	}
}

// TestValidityPastYear9999 drives CreateCertificate's only reachable failure
// on these fixed templates: GeneralizedTime can't encode a year past 9999.
func TestValidityPastYear9999(t *testing.T) {
	far := time.Date(9999, 12, 31, 12, 0, 0, 0, time.UTC)
	if _, _, err := GenerateCA("node-a", far); err == nil || !strings.Contains(err.Error(), "inspection CA certificate") {
		t.Fatalf("GenerateCA past 9999 = %v", err)
	}
	certPEM, keyPEM, err := GenerateCA("node-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(certPEM, keyPEM, func() time.Time { return far })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Leaf("api.example.com"); err == nil || !strings.Contains(err.Error(), "inspection leaf for api.example.com") {
		t.Fatalf("Leaf past 9999 = %v", err)
	}
}

// TestNewRejectsALeafAsCA: a leaf the CA minted parses cleanly, so the IsCA
// check is what keeps it from becoming an issuer.
func TestNewRejectsALeafAsCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("node-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(certPEM, keyPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.Leaf("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	if _, err := New(leafPEM, keyPEM, nil); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("leaf as CA = %v", err)
	}
}

func TestLeafCacheStartsOverWhenFull(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("node-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(certPEM, keyPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Filling the map directly keeps the test from minting 4096 leaves.
	for i := 0; i < maxCachedLeaves; i++ {
		a.cache[fmt.Sprintf("h%d.example.com", i)] = &tls.Certificate{}
	}
	c, err := a.Leaf("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.cache) != 1 || a.cache["api.example.com"] != c {
		t.Fatalf("cache after overflow holds %d leaves", len(a.cache))
	}
}
