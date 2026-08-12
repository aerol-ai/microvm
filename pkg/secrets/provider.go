package secrets

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

type incarnationCtxKey struct{}
type putOutboxCtxKey struct{}

type putOutboxHint struct {
	IncarnationID string
	Recipients    []string
}

// ContextWithIncarnationID attaches a placement incarnation to ctx for Put.
func ContextWithIncarnationID(ctx context.Context, incarnationID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, incarnationCtxKey{}, strings.TrimSpace(incarnationID))
}

// IncarnationIDFromContext returns the Put-time incarnation, or "".
func IncarnationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(incarnationCtxKey{}).(string)
	return strings.TrimSpace(v)
}

// ContextWithPutOutbox attaches remaining peer PUT targets to journal
// atomically with the sealed row (crash-vacuum fix). Recipients should exclude
// the originator; empty clears any prior outbox for the sandbox on Put.
func ContextWithPutOutbox(ctx context.Context, incarnationID string, recipients []string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, putOutboxCtxKey{}, putOutboxHint{
		IncarnationID: strings.TrimSpace(incarnationID),
		Recipients:    NormalizeRecipients(recipients),
	})
}

// PutOutboxFromContext returns optional put-outbox recipients for an originator Put.
func PutOutboxFromContext(ctx context.Context) (incarnationID string, recipients []string, ok bool) {
	if ctx == nil {
		return "", nil, false
	}
	v, ok := ctx.Value(putOutboxCtxKey{}).(putOutboxHint)
	if !ok {
		return "", nil, false
	}
	return v.IncarnationID, append([]string(nil), v.Recipients...), true
}

// Handle is a log-safe reference to sealed secrets. Safe to replicate through
// Raft; it never carries ciphertext or plaintext.
type Handle struct {
	Ref            string
	Version        int
	SealGeneration int64 // set by Put so callers can journal put-outbox without a reload
}

// Secrets is the cleartext credential bag (NOT the CreateSandboxRequest).
// MountCreds is keyed by MountSpec.Target.
type Secrets struct {
	Registry   *models.RegistryAuth         `json:"registry,omitempty"`
	MountCreds map[string]map[string]string `json:"mount_creds,omitempty"`
	// Env carries the sealed sandbox environment.
	Env map[string]string `json:"env,omitempty"`
}

// IsEmpty reports whether Secrets carries nothing that LocalProvider should
// persist. Registry password, mount credentials, or Env count as content.
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
	IncarnationID  string
	Version        int
	Recipients     []string
	SealedPayload  []byte
	SealGeneration int64
	// OutboxRecipients, when non-nil (including empty), is journaled in the
	// same SQLite transaction as the sealed row. Nil means "do not touch
	// put-outbox beyond the default clear-on-put". Empty slice clears pending
	// peers after a fully-local seal.
	OutboxRecipients *[]string
}
