//go:build itestwitness

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/daemon"
)

// With no witness URL the tagged binary must behave exactly like the shipped
// one, so a single artifact can serve both enterprise and non-enterprise
// scenarios without the harness juggling two builds.
func TestTaggedBuildFallsBackToNoopWithoutURL(t *testing.T) {
	t.Setenv("AEROL_ITEST_WITNESS_URL", "")
	p, err := itestProviderFactory(context.Background(), daemon.FleetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if p.HasExternalWitness() {
		t.Fatal("no witness URL configured but the provider reports an external witness")
	}
}

// With a URL it must report a REAL witness — that is the entire point, and
// pkg/daemon gates enterprise boot on exactly this predicate.
func TestTaggedBuildProvidesExternalWitness(t *testing.T) {
	t.Setenv("AEROL_ITEST_WITNESS_URL", "http://127.0.0.1:1/")
	p, err := itestProviderFactory(context.Background(), daemon.FleetConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasExternalWitness() {
		t.Fatal("witness URL configured but daemon.Run would still refuse to boot enterprise")
	}
}

func TestHTTPWitnessRoundTrip(t *testing.T) {
	var gotAuth string
	var gotHeads []controlplane.AuditHead
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/witness":
			_ = json.NewDecoder(r.Body).Decode(&gotHeads)
			_ = json.NewEncoder(w).Encode(controlplane.WitnessReceipt{ReceiptID: "rcpt-1"})
		case r.URL.Path == "/witness/node-known":
			_ = json.NewEncoder(w).Encode(controlplane.AuditHead{NodeID: "node-known", HeadHex: "cafe"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	wit := &httpWitness{base: srv.URL, token: "tok", client: srv.Client()}

	rcpt, err := wit.WitnessHeads(context.Background(), []controlplane.AuditHead{{NodeID: "n1", HeadHex: "beef"}})
	if err != nil {
		t.Fatalf("WitnessHeads() error = %v", err)
	}
	if rcpt.ReceiptID != "rcpt-1" {
		t.Fatalf("receipt = %q, want rcpt-1", rcpt.ReceiptID)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if len(gotHeads) != 1 || gotHeads[0].HeadHex != "beef" {
		t.Errorf("heads not transmitted: %+v", gotHeads)
	}

	head, ok, err := wit.LastWitnessedHead(context.Background(), "node-known")
	if err != nil || !ok || head != "cafe" {
		t.Fatalf("LastWitnessedHead(known) = %q,%v,%v", head, ok, err)
	}

	// 404 is "never recorded", which the interface requires be distinct from a
	// transport error — a scenario asserts it before the first witness tick.
	if _, ok, err := wit.LastWitnessedHead(context.Background(), "node-unknown"); err != nil || ok {
		t.Fatalf("unknown node = ok %v, err %v; want ok=false, err=nil", ok, err)
	}
}

// A witness that swallowed an error would let a scenario claim tamper-evidence
// it never had — the one lie this mechanism exists to prevent.
func TestHTTPWitnessSurfacesServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wit := &httpWitness{base: srv.URL, client: srv.Client()}
	if _, err := wit.WitnessHeads(context.Background(), nil); err == nil {
		t.Fatal("WitnessHeads swallowed a 500")
	}
	if _, _, err := wit.LastWitnessedHead(context.Background(), "n"); err == nil {
		t.Fatal("LastWitnessedHead swallowed a 500")
	}
}

// The receiver serves a self-signed certificate, so the witness client must
// trust the CA the exporter is already configured with. Without this the
// daemon passes the enterprise https gate and the KMS canary and THEN
// crash-loops on boot-time witness verification with "certificate signed by
// unknown authority" — which is how this was found, on a live box.
func TestWitnessClientTrustsConfiguredCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(controlplane.AuditHead{NodeID: "n1", HeadHex: "cafe"})
	}))
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("without the CA the handshake is refused", func(t *testing.T) {
		t.Setenv("AEROL_ITEST_WITNESS_CA_FILE", "")
		t.Setenv("SB_AUDIT_EXPORT_WEBHOOK_CA_FILE", "")
		c, err := witnessClient()
		if err != nil {
			t.Fatal(err)
		}
		w := &httpWitness{base: srv.URL, client: c}
		if _, _, err := w.LastWitnessedHead(context.Background(), "n1"); err == nil {
			t.Fatal("expected an untrusted-certificate error")
		}
	})

	t.Run("the exporter's CA file is reused", func(t *testing.T) {
		t.Setenv("AEROL_ITEST_WITNESS_CA_FILE", "")
		t.Setenv("SB_AUDIT_EXPORT_WEBHOOK_CA_FILE", caPath)
		c, err := witnessClient()
		if err != nil {
			t.Fatal(err)
		}
		w := &httpWitness{base: srv.URL, client: c}
		head, ok, err := w.LastWitnessedHead(context.Background(), "n1")
		if err != nil || !ok || head != "cafe" {
			t.Fatalf("got %q,%v,%v; want cafe,true,nil", head, ok, err)
		}
	})

	t.Run("an unreadable CA file fails loudly", func(t *testing.T) {
		t.Setenv("AEROL_ITEST_WITNESS_CA_FILE", filepath.Join(t.TempDir(), "missing.pem"))
		if _, err := witnessClient(); err == nil {
			t.Fatal("a missing CA file must fail rather than silently fall back to the system pool")
		}
	})
}
