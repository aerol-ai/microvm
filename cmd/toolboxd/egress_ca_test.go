package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEgressCABundle (P3-1): the bundle is the image's trust store plus the
// gateway CA; with no store it is the CA alone; without the variables
// nothing is written.
func TestEgressCABundle(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "egress-ca.pem")
	if err := os.WriteFile(ca, []byte("NODE-CA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "store.crt")
	if err := os.WriteFile(store, []byte("PUBLIC-ROOTS"), 0o644); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "run", "aerolvm", "ca-bundle.pem")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	buildEgressCABundle(log, []string{store})
	if _, err := os.Stat(bundle); err == nil {
		t.Fatal("no variables, no bundle")
	}
	t.Setenv("AEROLVM_EGRESS_CA", ca)
	t.Setenv("AEROLVM_EGRESS_CA_BUNDLE", bundle)
	buildEgressCABundle(log, []string{filepath.Join(dir, "missing"), store})
	if b, _ := os.ReadFile(bundle); string(b) != "PUBLIC-ROOTS\nNODE-CA\n" {
		t.Fatalf("bundle = %q", b)
	}
	if err := writeEgressCABundle(ca, bundle, []string{filepath.Join(dir, "missing")}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bundle); string(b) != "NODE-CA\n" {
		t.Fatalf("CA-only bundle = %q", b)
	}
	// A store that can't be read (a directory here) is an error, not a
	// silent CA-only bundle that would break every public host.
	if err := writeEgressCABundle(ca, bundle, []string{dir}); err == nil || !strings.Contains(err.Error(), "trust store") {
		t.Fatalf("unreadable store: %v", err)
	}
	t.Setenv("AEROLVM_EGRESS_CA", filepath.Join(dir, "gone.pem"))
	buildEgressCABundle(log, []string{store}) // logged, not fatal
	if err := writeEgressCABundle(ca, filepath.Join(ca, "x", "bundle.pem"), []string{store}); err == nil {
		t.Fatal("an unwritable bundle path must fail")
	}
}
