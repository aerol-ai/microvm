package service

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// newTestCipher gives us a real Cipher backed by a fresh keyfile. We bind to
// a temp dir so each test gets isolated key material — important because
// SealClusterSecrets / UnsealClusterSecrets are Service methods and we want
// to assert real round-tripping, not just that we wired the JSON.
func newTestCipher(t *testing.T) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestSealClusterSecretsRoundTrip(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	req := models.CreateSandboxRequest{
		Image: "alpine",
		Registry: &models.RegistryAuth{
			Server:   "ghcr.io",
			Username: "alice",
			Password: "supersecret",
		},
		Mounts: []models.MountSpec{
			{Type: models.MountTypeS3, Target: "/data", Source: "bucket",
				Credentials: map[string]string{"AWS_ACCESS_KEY_ID": "AKIA", "AWS_SECRET_ACCESS_KEY": "shh"}},
			{Type: models.MountTypeNFS, Target: "/srv", Source: "nfs.example:/export"},
		},
	}

	sealed, err := s.SealClusterSecrets(req)
	if err != nil {
		t.Fatalf("SealClusterSecrets: %v", err)
	}
	if len(sealed) == 0 {
		t.Fatal("sealed bag empty for request with credentials")
	}
	// The sealed payload must NOT contain plaintext credentials anywhere — this
	// is the headline guarantee, so test it directly. AES-GCM can't return a
	// ciphertext containing the literal plaintext, but a regression that
	// accidentally returned the marshaled JSON would be silent without this.
	if bytes.Contains(sealed, []byte("supersecret")) {
		t.Fatal("sealed bag leaks registry password as plaintext")
	}
	if bytes.Contains(sealed, []byte("AKIA")) || bytes.Contains(sealed, []byte("shh")) {
		t.Fatal("sealed bag leaks mount credentials as plaintext")
	}

	redacted := RedactClusterSecrets(req)
	if redacted.Registry == nil || redacted.Registry.Password != "" {
		t.Fatalf("redacted registry must keep server/username and clear password: %+v", redacted.Registry)
	}
	if redacted.Registry.Server != "ghcr.io" || redacted.Registry.Username != "alice" {
		t.Fatalf("redacted registry should preserve non-secret fields: %+v", redacted.Registry)
	}
	for _, m := range redacted.Mounts {
		if len(m.Credentials) > 0 {
			t.Fatalf("redacted mount %s still has credentials: %v", m.Target, m.Credentials)
		}
	}

	// Source request must be untouched — RedactClusterSecrets returns a copy.
	if req.Registry.Password != "supersecret" {
		t.Fatal("Redact mutated the source request's registry password")
	}
	if req.Mounts[0].Credentials["AWS_ACCESS_KEY_ID"] != "AKIA" {
		t.Fatal("Redact mutated the source request's mount credentials")
	}

	merged, err := s.UnsealClusterSecrets(redacted, sealed)
	if err != nil {
		t.Fatalf("UnsealClusterSecrets: %v", err)
	}
	if merged.Registry == nil || merged.Registry.Password != "supersecret" {
		t.Fatalf("merged registry password lost: %+v", merged.Registry)
	}
	if merged.Mounts[0].Credentials["AWS_SECRET_ACCESS_KEY"] != "shh" {
		t.Fatalf("merged mount creds lost: %+v", merged.Mounts[0].Credentials)
	}
	// Mount #1 had no credentials originally; unseal must not invent any.
	if len(merged.Mounts[1].Credentials) != 0 {
		t.Fatalf("merged credential-less mount picked up creds: %+v", merged.Mounts[1].Credentials)
	}
}

// SealClusterSecrets must return nil/nil for credential-free requests so we
// don't end up with a non-empty FSM column for every plain-public-image
// sandbox.
func TestSealClusterSecretsEmpty(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	cases := []models.CreateSandboxRequest{
		{Image: "alpine"},
		{Image: "alpine", Registry: &models.RegistryAuth{Server: "ghcr.io"}}, // no password
		{Image: "alpine", Mounts: []models.MountSpec{{Type: models.MountTypeNFS, Target: "/srv", Source: "x:/y"}}},
	}
	for i, req := range cases {
		sealed, err := s.SealClusterSecrets(req)
		if err != nil {
			t.Fatalf("case %d: SealClusterSecrets: %v", i, err)
		}
		if sealed != nil {
			t.Fatalf("case %d: expected nil sealed bag for credential-free req, got %d bytes", i, len(sealed))
		}
	}
}

func TestSealClusterSecretsRecipientBound(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	req := models.CreateSandboxRequest{
		Image:    "private.example.com/app:latest",
		Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: "super-secret-password"},
	}
	sealed, err := s.SealClusterSecretsForRecipient(req, "node-a")
	if err != nil {
		t.Fatalf("SealClusterSecretsForRecipient: %v", err)
	}
	redacted := RedactClusterSecrets(req)
	if _, err := s.UnsealClusterSecretsForNode(redacted, sealed, "node-b"); err == nil {
		t.Fatal("wrong recipient opened sealed cluster secrets")
	}
	merged, err := s.UnsealClusterSecretsForNode(redacted, sealed, "node-a")
	if err != nil {
		t.Fatalf("recipient failed to open sealed cluster secrets: %v", err)
	}
	if merged.Registry == nil || merged.Registry.Password != "super-secret-password" {
		t.Fatalf("recipient merge lost registry password: %+v", merged.Registry)
	}
}

func TestClusterSecretRefRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	defer st.Close()

	s := &Service{cipher: newTestCipher(t), store: st}
	req := models.CreateSandboxRequest{
		Image:    "private.example.com/app:latest",
		Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: "super-secret-password"},
		Mounts: []models.MountSpec{{
			Type:        models.MountTypeS3,
			Target:      "/data",
			Source:      "bucket",
			Credentials: map[string]string{"AWS_SECRET_ACCESS_KEY": "shh-secret-token"},
		}},
	}

	handle, err := s.PutClusterSecretsForRecipient(ctx, "sb-secret-ref", req, "node-a")
	if err != nil {
		t.Fatalf("PutClusterSecretsForRecipient: %v", err)
	}
	if handle.Ref == "" || handle.Version != clusterSecretVersion || len(handle.LegacySealed) != 0 {
		t.Fatalf("handle = %+v, want ref/version without legacy sealed payload", handle)
	}

	rec, err := st.GetClusterSecret(ctx, handle.Ref)
	if err != nil {
		t.Fatalf("GetClusterSecret: %v", err)
	}
	if bytes.Contains(rec.SealedPayload, []byte("super-secret-password")) || bytes.Contains(rec.SealedPayload, []byte("shh-secret-token")) {
		t.Fatal("stored cluster secret payload leaks plaintext credentials")
	}
	var env clusterSealedSecretsEnvelope
	if err := json.Unmarshal(rec.SealedPayload, &env); err != nil {
		t.Fatalf("unmarshal stored envelope: %v", err)
	}
	if env.Version != clusterSecretEnvelopeVersion || len(env.WrappedKey) == 0 || len(env.Payload) == 0 {
		t.Fatalf("envelope = %+v, want v3 with wrapped per-secret key and payload", env)
	}

	redacted := RedactClusterSecrets(req)
	if _, err := s.OpenClusterSecretsForNode(ctx, redacted, handle, "node-b"); err == nil {
		t.Fatal("wrong recipient opened cluster secret ref")
	}
	merged, err := s.OpenClusterSecretsForNode(ctx, redacted, handle, "node-a")
	if err != nil {
		t.Fatalf("OpenClusterSecretsForNode: %v", err)
	}
	if merged.Registry == nil || merged.Registry.Password != "super-secret-password" {
		t.Fatalf("registry password not restored: %+v", merged.Registry)
	}
	if got := merged.Mounts[0].Credentials["AWS_SECRET_ACCESS_KEY"]; got != "shh-secret-token" {
		t.Fatalf("mount credential = %q, want shh-secret-token", got)
	}
}

// UnsealClusterSecrets with empty input must be a passthrough — callers
// shouldn't have to short-circuit themselves.
func TestUnsealClusterSecretsEmpty(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	in := models.CreateSandboxRequest{Image: "alpine"}
	out, err := s.UnsealClusterSecrets(in, nil)
	if err != nil {
		t.Fatalf("UnsealClusterSecrets nil: %v", err)
	}
	if out.Image != "alpine" {
		t.Fatalf("passthrough lost spec: %+v", out)
	}
}
