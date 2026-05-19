package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// newRegistryHarness builds a minimal Service wired to a real cipher and store.
// Just enough surface to exercise sealRegistry / UnsealRegistry against a
// persisted Sandbox row — no docker, no caddy beyond the constructor.
func newRegistryHarness(t *testing.T) (*Service, *store.Store) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	keyB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	cipher, err := secrets.NewCipher(keyB64, "")
	if err != nil {
		t.Fatalf("secrets.NewCipher: %v", err)
	}

	svc := &Service{
		cfg:    config.Config{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		caddy: caddy.New(config.Config{
			EnableCaddy:       false,
			HTTPClientTimeout: time.Second,
		}),
		mounts:   mgr,
		cipher:   cipher,
		admitter: capacity.New(capacity.HostInfo{CPUCores: 1, MemoryTotalMB: 1024}, capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil),
	}
	return svc, st
}

// TestRegistrySealUnsealRoundTrip is the core invariant: the bytes written to
// the sandbox row by sealRegistry survive a List/Get and decrypt back to the
// original RegistryAuth. This is the contract that makes private-image
// failover work — without it, the new owner's docker pull hits 401.
func TestRegistrySealUnsealRoundTrip(t *testing.T) {
	ctx := context.Background()
	svc, st := newRegistryHarness(t)

	auth := &models.RegistryAuth{
		Server:   "ghcr.io",
		Username: "robot$pull-only",
		Password: "ghp_supersecret_token_value",
	}

	sealed, err := svc.sealRegistry(auth)
	if err != nil {
		t.Fatalf("sealRegistry: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("sealRegistry returned empty bytes for a populated auth")
	}
	if bytes.Contains(sealed, []byte(auth.Password)) {
		t.Fatal("sealed bytes contained plaintext password — encryption is broken")
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:                 "sb-private",
		Image:              "ghcr.io/example/private:latest",
		Status:             models.SandboxStatusStarted,
		CPU:                1,
		MemoryMB:           512,
		Runtime:            models.RuntimeDocker,
		CreatedAt:          now,
		UpdatedAt:          now,
		LastActiveAt:       now,
		RegistryAuthSealed: sealed,
	}); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	got, err := st.Get(ctx, "sb-private")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !bytes.Equal(got.RegistryAuthSealed, sealed) {
		t.Fatal("sealed bytes did not survive the round-trip through SQLite")
	}

	unsealed, err := svc.UnsealRegistry(got.RegistryAuthSealed)
	if err != nil {
		t.Fatalf("UnsealRegistry: %v", err)
	}
	if unsealed == nil {
		t.Fatal("UnsealRegistry returned nil for a populated row")
	}
	if *unsealed != *auth {
		t.Fatalf("round-trip differs: got %+v, want %+v", *unsealed, *auth)
	}
}

// TestRegistrySealEmptyAuthIsNil pins down the no-credentials path: a nil or
// all-zero RegistryAuth must seal to nil so the sandbox row stores the
// empty-blob default. Without this, every public-image sandbox would carry a
// pointless ciphertext and the recreate spec would have a non-nil Registry
// with empty fields (which the runtime treats as a real "auth required" hint
// and rejects).
func TestRegistrySealEmptyAuthIsNil(t *testing.T) {
	svc, _ := newRegistryHarness(t)

	for name, auth := range map[string]*models.RegistryAuth{
		"nil":      nil,
		"all-zero": {Server: "", Username: "", Password: ""},
	} {
		sealed, err := svc.sealRegistry(auth)
		if err != nil {
			t.Fatalf("%s: sealRegistry: %v", name, err)
		}
		if sealed != nil {
			t.Fatalf("%s: expected nil, got %d bytes", name, len(sealed))
		}
	}
}

// TestUnsealRegistryEmptyInputIsNil is the symmetric guarantee: a row with
// no sealed bytes (the empty-blob default for the column, or a sandbox
// created before this column was added) decrypts to (nil, nil), not an error.
// Backfill relies on this to walk every sandbox without faulting on the ones
// that never had registry creds.
func TestUnsealRegistryEmptyInputIsNil(t *testing.T) {
	svc, _ := newRegistryHarness(t)

	for name, in := range map[string][]byte{
		"nil":   nil,
		"empty": {},
	} {
		got, err := svc.UnsealRegistry(in)
		if err != nil {
			t.Fatalf("%s: UnsealRegistry: %v", name, err)
		}
		if got != nil {
			t.Fatalf("%s: expected nil RegistryAuth, got %+v", name, got)
		}
	}
}
