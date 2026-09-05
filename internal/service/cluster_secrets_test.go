package service

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// newTestCipher gives each test isolated key material.
func newTestCipher(t *testing.T) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

type pruneRecordingCluster struct {
	*cluster.Noop
	calls int
	err   error
}

func (c *pruneRecordingCluster) PruneAuditACL(context.Context, time.Time) error {
	c.calls++
	return c.err
}

func TestSecretLifecyclePruneAndReconcileStartup(t *testing.T) {
	ctx := context.Background()
	if err := (*Service)(nil).pruneClusterSecretTombs(ctx); err != nil {
		t.Fatalf("nil tomb prune: %v", err)
	}
	if err := (&Service{}).pruneClusterAuditACL(ctx); err != nil {
		t.Fatalf("disabled ACL prune: %v", err)
	}
	(*Service)(nil).StartSecretDeleteOutboxReconcile(ctx)

	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.ApplyPeerSecretDelete(ctx, "sb-tomb", 1); err != nil {
		t.Fatal(err)
	}
	recorder := &pruneRecordingCluster{Noop: cluster.NewNoop("self", "", "")}
	svc := &Service{
		cfg: config.Config{
			SecretTombRetentionDays:  1,
			SecretAuditRetentionDays: 30,
		},
		store:   st,
		cluster: recorder,
	}
	if err := svc.pruneClusterSecretTombs(ctx); err != nil {
		t.Fatalf("tomb prune: %v", err)
	}
	if err := svc.pruneClusterAuditACL(ctx); err != nil || recorder.calls != 1 {
		t.Fatalf("ACL prune calls=%d err=%v", recorder.calls, err)
	}
	recorder.err = errors.New("raft unavailable")
	if err := svc.pruneClusterAuditACL(ctx); !errors.Is(err, recorder.err) {
		t.Fatalf("ACL prune error = %v", err)
	}

	// A pre-cancelled context exercises startup maintenance and deterministic
	// loop shutdown without waiting for the 30-second production ticker.
	loopCtx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.StartSecretDeleteOutboxReconcile(loopCtx)
	time.Sleep(20 * time.Millisecond)
}

func TestClusterSecretEnvelopeAndRedactionRoundTrip(t *testing.T) {
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
		PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/workspace"}},
	}

	binding := secrets.SealBinding{SandboxID: "sb-roundtrip", Ref: secrets.FormatRef("sb-roundtrip", secrets.RefVersion), Version: secrets.RefVersion, Generation: 1}
	sealed, err := secrets.SealEnvelopeBound(s.cipher, s.secretsFromRequest(req), []string{"node-a"}, binding)
	if err != nil {
		t.Fatalf("SealEnvelopeBound: %v", err)
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
	redacted.PlatformVolumes[0].Path = "/mutated"
	if req.PlatformVolumes[0].Path != "/workspace" {
		t.Fatal("Redact mutated the source request's platform volumes")
	}

	bag, err := secrets.OpenEnvelopeBound(s.cipher, sealed, "node-a", binding)
	if err != nil {
		t.Fatalf("OpenEnvelopeBound: %v", err)
	}
	merged := mergeClusterSecrets(redacted, bag)
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

func TestClusterSecretEnvelopeEmpty(t *testing.T) {
	s := &Service{cipher: newTestCipher(t)}
	cases := []models.CreateSandboxRequest{
		{Image: "alpine"},
		{Image: "alpine", Registry: &models.RegistryAuth{Server: "ghcr.io"}}, // no password
		{Image: "alpine", Mounts: []models.MountSpec{{Type: models.MountTypeNFS, Target: "/srv", Source: "x:/y"}}},
	}
	for i, req := range cases {
		binding := secrets.SealBinding{SandboxID: "sb-empty", Ref: secrets.FormatRef("sb-empty", secrets.RefVersion), Version: secrets.RefVersion, Generation: 1}
		sealed, err := secrets.SealEnvelopeBound(s.cipher, s.secretsFromRequest(req), []string{"node-a"}, binding)
		if err != nil {
			t.Fatalf("case %d: SealEnvelopeBound: %v", i, err)
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
	binding := secrets.SealBinding{SandboxID: "sb-recipient", Ref: secrets.FormatRef("sb-recipient", secrets.RefVersion), Version: secrets.RefVersion, Generation: 1}
	sealed, err := secrets.SealEnvelopeBound(s.cipher, s.secretsFromRequest(req), []string{"node-a"}, binding)
	if err != nil {
		t.Fatalf("SealEnvelopeBound: %v", err)
	}
	redacted := RedactClusterSecrets(req)
	if _, err := secrets.OpenEnvelopeBound(s.cipher, sealed, "node-b", binding); err == nil {
		t.Fatal("wrong recipient opened sealed cluster secrets")
	}
	bag, err := secrets.OpenEnvelopeBound(s.cipher, sealed, "node-a", binding)
	if err != nil {
		t.Fatalf("recipient failed to open sealed cluster secrets: %v", err)
	}
	merged := mergeClusterSecrets(redacted, bag)
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

	cipher := newTestCipher(t)
	s := &Service{cipher: cipher, store: st, secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st))}
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

	handle, err := s.SealAndDistribute(ctx, "sb-secret-ref", req, []string{"node-a"}, SealStrict)
	if err != nil {
		t.Fatalf("SealAndDistribute: %v", err)
	}
	if handle.Ref == "" || handle.Version != secrets.RefVersion {
		t.Fatalf("handle = %+v, want ref/version handle", handle)
	}

	rec, err := st.GetClusterSecret(ctx, handle.Ref)
	if err != nil {
		t.Fatalf("GetClusterSecret: %v", err)
	}
	if bytes.Contains(rec.SealedPayload, []byte("super-secret-password")) || bytes.Contains(rec.SealedPayload, []byte("shh-secret-token")) {
		t.Fatal("stored cluster secret payload leaks plaintext credentials")
	}
	meta, err := secrets.EnvelopeBinding(rec.SealedPayload)
	if err != nil {
		t.Fatalf("EnvelopeBinding: %v", err)
	}
	if meta.Version != secrets.EnvelopeVersion || meta.SandboxID != "sb-secret-ref" || meta.Ref != handle.Ref {
		t.Fatalf("envelope binding = %+v, want current identity-bound envelope", meta)
	}

	redacted := RedactClusterSecrets(req)
	beforeDenied := clusterSecretRecipientDenies.Value()
	if _, err := s.OpenClusterSecretsForNode(ctx, "sb-secret-ref", redacted, handle, "node-b"); err == nil {
		t.Fatal("wrong recipient opened cluster secret ref")
	}
	if got := clusterSecretRecipientDenies.Value() - beforeDenied; got != 1 {
		t.Fatalf("recipient denied metric delta = %d, want 1", got)
	}
	mismatched := handle
	mismatched.Version++
	beforeMismatch := clusterSecretKeyMismatches.Value()
	if _, err := s.OpenClusterSecretsForNode(ctx, "sb-secret-ref", redacted, mismatched, "node-a"); err == nil {
		t.Fatal("version mismatch opened cluster secret ref")
	}
	if got := clusterSecretKeyMismatches.Value() - beforeMismatch; got != 1 {
		t.Fatalf("key mismatch metric delta = %d, want 1", got)
	}
	merged, err := s.OpenClusterSecretsForNode(ctx, "sb-secret-ref", redacted, handle, "node-a")
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

func TestDeleteClusterSecretsStandaloneLeavesNoTomb(t *testing.T) {
	ctx := context.Background()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	s := &Service{
		cfg:            config.Config{},
		cipher:         newTestCipher(t),
		store:          st,
		secretProvider: secrets.NewLocalProvider(newTestCipher(t), newSecretBlobStore(st)),
		cluster:        cluster.NewNoop("standalone", "http://localhost", ""),
	}
	if _, err := s.SealAndDistribute(ctx, "sb-solo", models.CreateSandboxRequest{
		Image:    "alpine",
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "p"},
	}, []string{"standalone"}, SealStrict); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteClusterSecrets(ctx, "sb-solo"); err != nil {
		t.Fatal(err)
	}
	tomb, err := st.HasClusterSecretTomb(ctx, "sb-solo")
	if err != nil || tomb {
		t.Fatalf("standalone delete must not leave tomb: %v %v", tomb, err)
	}
	outbox, err := st.GetSecretDeleteOutbox(ctx, "sb-solo")
	if err != nil || outbox != nil {
		t.Fatalf("standalone delete must not leave outbox: %+v %v", outbox, err)
	}
}

func TestDeleteClusterSecretsRemovesProviderRecord(t *testing.T) {
	ctx := context.Background()
	st, err := storepkg.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	defer st.Close()

	cipher := newTestCipher(t)
	s := &Service{cipher: cipher, store: st, secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st))}
	handle, err := s.SealAndDistribute(ctx, "sb-delete-secrets", models.CreateSandboxRequest{
		Image:    "private.example.com/app:latest",
		Registry: &models.RegistryAuth{Server: "private.example.com", Username: "alice", Password: "super-secret-password"},
	}, []string{"node-a"}, SealStrict)
	if err != nil {
		t.Fatalf("SealAndDistribute: %v", err)
	}
	if err := s.DeleteClusterSecrets(ctx, "sb-delete-secrets"); err != nil {
		t.Fatalf("DeleteClusterSecrets: %v", err)
	}
	if _, err := st.GetClusterSecret(ctx, handle.Ref); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("GetClusterSecret() error = %v, want ErrNotFound after delete", err)
	}

	var nilService *Service
	if err := nilService.DeleteClusterSecrets(ctx, "ignored"); err != nil {
		t.Fatalf("nil service DeleteClusterSecrets() error = %v", err)
	}
	if err := (&Service{}).DeleteClusterSecrets(ctx, "ignored"); err != nil {
		t.Fatalf("storeless DeleteClusterSecrets() error = %v", err)
	}
}

func TestClusterSecretRedactionCopiesNonSecretFields(t *testing.T) {
	req := models.CreateSandboxRequest{
		Image: "alpine",
		Env:   map[string]string{"A": "1"},
		Mounts: []models.MountSpec{{
			Type:    models.MountTypeNFS,
			Target:  "/srv",
			Source:  "nfs.example:/export",
			Options: map[string]string{"ro": "true"},
		}},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	redacted := RedactClusterSecrets(req)
	if redacted.Failover == nil || redacted.Failover == req.Failover || redacted.Failover.Policy != models.FailoverPolicyRecreate {
		t.Fatalf("failover not deep-copied correctly: %+v", redacted.Failover)
	}
	if len(redacted.Env) != 0 {
		t.Fatalf("env was not redacted: %+v", redacted.Env)
	}
	if redacted.Mounts[0].Options["ro"] != "true" {
		t.Fatalf("mount options not preserved: %+v", redacted.Mounts[0].Options)
	}
}
