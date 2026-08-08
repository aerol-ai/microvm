package secrets

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Handle is a log-safe reference to sealed secrets. Safe to replicate through
// Raft; it never carries ciphertext or plaintext.
type Handle struct {
	Ref     string
	Version int
}

// Secrets is the cleartext credential bag (NOT the CreateSandboxRequest).
// MountCreds is keyed by MountSpec.Target.
type Secrets struct {
	Registry   *models.RegistryAuth         `json:"registry,omitempty"`
	MountCreds map[string]map[string]string `json:"mount_creds,omitempty"`
	// Env is reserved for T7/T9 env sealing; unused by LocalProvider.Put emptiness.
	Env map[string]string `json:"env,omitempty"`
}

// IsEmpty reports whether Secrets carries nothing that LocalProvider should
// persist. Registry password, mount credentials, or Env (when populated —
// service only copies Env into the bag when SB_SECRET_ENV_SEAL_ENABLED) count
// as content. When the env-seal flag is off, secretsFromRequest leaves Env
// nil so default creates still short-circuit with no secret ref.
func (s Secrets) IsEmpty() bool {
	hasRegistry := s.Registry != nil && s.Registry.Password != ""
	return !hasRegistry && len(s.MountCreds) == 0 && len(s.Env) == 0
}

// Provider resolves ref → plaintext. Backends differ in how a node reaches
// plaintext (local row, peer fetch, KMS), not in the wire handle shape.
type Provider interface {
	Put(ctx context.Context, sandboxID string, s Secrets, recipients []string) (Handle, error)
	Open(ctx context.Context, sandboxID string, h Handle, nodeID string) (Secrets, error)
	Delete(ctx context.Context, sandboxID string) error
}

// BlobStore persists sealed secret rows. Defined here so pkg/secrets never
// imports internal/store — the service layer adapts Store ↔ BlobStore.
type BlobStore interface {
	Put(ctx context.Context, rec SecretBlob) error
	Get(ctx context.Context, ref string) (*SecretBlob, error)
	DeleteForSandbox(ctx context.Context, sandboxID string) error
	NextSealGeneration(ctx context.Context, sandboxID string) (int64, error)
}

// SecretBlob is one sealed cluster-secret row addressed by ref.
type SecretBlob struct {
	Ref            string
	SandboxID      string
	Version        int
	Recipients     []string
	SealedPayload  []byte
	SealGeneration int64
}
