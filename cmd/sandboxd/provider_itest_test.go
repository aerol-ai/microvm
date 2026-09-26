//go:build itestwitness

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
