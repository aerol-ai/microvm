package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// replicateSpecPatch keeps the FSM-replicated spec in sync after a local
// mutation (resize, lifecycle update). It is a best-effort write-through that
// mirrors the v1 wrapper of the same name: on failure it warns and returns
// without surfacing the error to the caller, because the local sandbox is
// already authoritative and the next mutation will refresh the FSM.
//
// No-op when the cluster doesn't carry a spec for this sandbox yet
// (pre-cluster sandbox; Noop client in single-node mode also returns nil).
// Same-sandbox concurrent mutations can clobber each other in the FSM, but
// the worst case is a stale spec on a node that hasn't died — the next
// mutating call fixes it. Single-sandbox mutations serialize at the docker
// layer anyway.
func (s *Service) replicateSpecPatch(ctx context.Context, id string, patch func(*models.CreateSandboxRequest)) {
	c := s.Cluster()
	if c == nil {
		return
	}
	spec := c.SpecOf(id)
	if spec == nil {
		return
	}
	patch(spec)
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.UpsertSpec(commitCtx, id, spec, cluster.PlacementSecrets{}); err != nil && s.logger != nil {
		s.logger.Warn("cluster: spec write-through failed; FSM spec stale until next mutation",
			"sandbox_id", id, "err", err)
	}
}

// clusterSealedSecrets is the cleartext schema stored behind a cluster secret
// ref. It only carries the parts of CreateSandboxRequest that are actually
// secret — registry password and per-mount credential maps. Everything else
// (image, env, mount Source/Target, etc.) rides on the redacted Spec, which
// the cluster replicates in plaintext.
//
// MountCreds is keyed by MountSpec.Target (the in-container mount path). Target
// is required + unique per mount per service.createSandbox validation, so it
// works as a stable join key when re-merging on the receiving end.
type clusterSealedSecrets struct {
	Registry   *models.RegistryAuth         `json:"registry,omitempty"`
	MountCreds map[string]map[string]string `json:"mount_creds,omitempty"`
}

type clusterSealedSecretsEnvelope struct {
	Version    int      `json:"version"`
	Recipients []string `json:"recipients,omitempty"`
	WrappedKey []byte   `json:"wrapped_key,omitempty"`
	Payload    []byte   `json:"payload"`
}

const clusterSecretVersion = 1
const clusterSecretEnvelopeVersion = 3

// SealClusterSecrets extracts the secret-bearing portions of req, marshals
// them as JSON, and encrypts the result with the service cipher. The output
// is opaque bytes safe to put in the raft log. Returns nil/nil when there
// are no secrets to seal so the FSM column stays empty for sandboxes that
// don't need it.
//
// The legacy method emits a wildcard-recipient v2 envelope for compatibility.
// New cluster placement paths should prefer SealClusterSecretsForRecipient so
// the encrypted payload is authenticated to the specific owner node ID.
func (s *Service) SealClusterSecrets(req models.CreateSandboxRequest) ([]byte, error) {
	return s.sealClusterSecrets(req, []string{"*"})
}

func (s *Service) SealClusterSecretsForRecipient(req models.CreateSandboxRequest, recipient string) ([]byte, error) {
	return s.sealClusterSecrets(req, []string{recipient})
}

func (s *Service) sealClusterSecrets(req models.CreateSandboxRequest, recipients []string) ([]byte, error) {
	var bag clusterSealedSecrets
	if req.Registry != nil && req.Registry.Password != "" {
		regCopy := *req.Registry
		bag.Registry = &regCopy
	}
	for _, m := range req.Mounts {
		if len(m.Credentials) == 0 {
			continue
		}
		if bag.MountCreds == nil {
			bag.MountCreds = make(map[string]map[string]string, len(req.Mounts))
		}
		cp := make(map[string]string, len(m.Credentials))
		for k, v := range m.Credentials {
			cp[k] = v
		}
		bag.MountCreds[m.Target] = cp
	}
	if bag.Registry == nil && len(bag.MountCreds) == 0 {
		return nil, nil
	}
	if s.cipher == nil {
		return nil, errors.New("cluster secrets cipher is not configured")
	}
	plain, err := json.Marshal(bag)
	if err != nil {
		return nil, fmt.Errorf("marshal cluster secrets: %w", err)
	}
	recipients = normalizeClusterSecretRecipients(recipients)
	return s.sealClusterSecretEnvelope(plain, recipients)
}

func (s *Service) sealClusterSecretEnvelope(plain []byte, recipients []string) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate cluster secret data key: %w", err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("cluster secret data cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cluster secret data gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cluster secret data nonce: %w", err)
	}
	payload := append(nonce, gcm.Seal(nil, nonce, plain, clusterSecretPayloadAAD(recipients))...)
	wrappedKey, err := s.cipher.EncryptWithAAD(dek, clusterSecretKeyAAD(recipients))
	if err != nil {
		return nil, fmt.Errorf("wrap cluster secret data key: %w", err)
	}
	envelope, err := json.Marshal(clusterSealedSecretsEnvelope{
		Version:    clusterSecretEnvelopeVersion,
		Recipients: recipients,
		WrappedKey: wrappedKey,
		Payload:    payload,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal cluster secrets envelope: %w", err)
	}
	return envelope, nil
}

// PutClusterSecretsForRecipient stores the credential-bearing parts of req
// behind a provider ref and returns the handle safe to replicate through Raft.
// The local provider stores an encrypted recipient-bound envelope in SQLite;
// external KMS/secret-store providers can replace this boundary without
// changing cluster placement state.
func (s *Service) PutClusterSecretsForRecipient(ctx context.Context, sandboxID string, req models.CreateSandboxRequest, recipient string) (cluster.PlacementSecrets, error) {
	sealed, err := s.SealClusterSecretsForRecipient(req, recipient)
	if err != nil {
		return cluster.PlacementSecrets{}, err
	}
	if len(sealed) == 0 {
		return cluster.PlacementSecrets{}, nil
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return cluster.PlacementSecrets{}, errors.New("cluster secret sandbox id is required")
	}
	if s.store == nil {
		return cluster.PlacementSecrets{}, errors.New("cluster secret store is not configured")
	}
	ref := clusterSecretRef(sandboxID, clusterSecretVersion)
	if err := s.store.PutClusterSecret(ctx, store.ClusterSecretRecord{
		Ref:           ref,
		SandboxID:     sandboxID,
		Version:       clusterSecretVersion,
		Recipients:    normalizeClusterSecretRecipients([]string{recipient}),
		SealedPayload: sealed,
	}); err != nil {
		return cluster.PlacementSecrets{}, err
	}
	return cluster.PlacementSecrets{Ref: ref, Version: clusterSecretVersion}, nil
}

// OpenClusterSecretsForNode resolves a replicated secret handle and merges the
// decrypted credentials back into a redacted spec. LegacySealed is still
// honored for placements written before the ref model.
func (s *Service) OpenClusterSecretsForNode(ctx context.Context, redacted models.CreateSandboxRequest, secrets cluster.PlacementSecrets, nodeID string) (out models.CreateSandboxRequest, err error) {
	if secrets.Ref == "" && len(secrets.LegacySealed) == 0 {
		return redacted, nil
	}
	done := beginClusterSecretOpen()
	defer func() { done(err) }()
	if secrets.Ref != "" {
		if s.store == nil {
			return redacted, errors.New("cluster secret store is not configured")
		}
		rec, err := s.store.GetClusterSecret(ctx, secrets.Ref)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return redacted, fmt.Errorf("cluster secret ref %q not found", secrets.Ref)
			}
			return redacted, err
		}
		if secrets.Version != 0 && rec.Version != secrets.Version {
			recordClusterSecretKeyMismatch()
			return redacted, fmt.Errorf("cluster secret ref %q version mismatch: placement=%d store=%d", secrets.Ref, secrets.Version, rec.Version)
		}
		return s.UnsealClusterSecretsForNode(redacted, rec.SealedPayload, nodeID)
	}
	return s.UnsealClusterSecretsForNode(redacted, secrets.LegacySealed, nodeID)
}

func (s *Service) OpenClusterSecrets(ctx context.Context, redacted models.CreateSandboxRequest, secrets cluster.PlacementSecrets) (models.CreateSandboxRequest, error) {
	return s.OpenClusterSecretsForNode(ctx, redacted, secrets, "")
}

func (s *Service) DeleteClusterSecrets(ctx context.Context, sandboxID string) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.DeleteClusterSecretsForSandbox(ctx, sandboxID)
}

// RedactClusterSecrets returns a copy of req with credentials stripped — safe
// to replicate via raft. The Registry field's Server/Username are preserved
// (not secret) but Password is cleared; mount Credentials maps are dropped
// per-entry. Maps and slices that the caller might mutate are deep-copied so
// the original req is left untouched.
//
// Lives next to SealClusterSecrets because the two are always called as a
// pair: seal returns the encrypted bag, redact returns the safe-to-replicate
// spec, and writing one without the other would either leak secrets (no
// redact) or lose them on failover (no seal).
func RedactClusterSecrets(req models.CreateSandboxRequest) models.CreateSandboxRequest {
	out := req
	if out.Registry != nil {
		regCopy := *out.Registry
		regCopy.Password = ""
		out.Registry = &regCopy
	}
	if len(out.Mounts) > 0 {
		ms := make([]models.MountSpec, len(out.Mounts))
		for i, m := range out.Mounts {
			mc := m
			mc.Credentials = nil
			if len(m.Options) > 0 {
				opt := make(map[string]string, len(m.Options))
				for k, v := range m.Options {
					opt[k] = v
				}
				mc.Options = opt
			}
			ms[i] = mc
		}
		out.Mounts = ms
	}
	if len(out.Env) > 0 {
		env := make(map[string]string, len(out.Env))
		for k, v := range out.Env {
			env[k] = v
		}
		out.Env = env
	}
	if out.Failover != nil {
		failover := *out.Failover
		out.Failover = &failover
	}
	return out
}

// UnsealClusterSecrets opens a sealed bag and merges the credentials back
// into the previously-redacted spec. Returns the merged spec; the input
// is not mutated. An empty sealed payload returns redacted unchanged so
// callers don't have to short-circuit themselves.
//
// The merge prefers the redacted spec for non-secret fields (Registry
// Server/Username, mount Source/Target/Options) and overlays only the
// secret bits — so a future credential rotation that re-seals doesn't
// stomp on whatever the latest replicated metadata is.
func (s *Service) UnsealClusterSecrets(redacted models.CreateSandboxRequest, sealed []byte) (models.CreateSandboxRequest, error) {
	return s.UnsealClusterSecretsForNode(redacted, sealed, "")
}

func (s *Service) UnsealClusterSecretsForNode(redacted models.CreateSandboxRequest, sealed []byte, nodeID string) (models.CreateSandboxRequest, error) {
	if len(sealed) == 0 {
		return redacted, nil
	}
	plain, err := s.openClusterSecretPayload(sealed, nodeID)
	if err != nil {
		return redacted, fmt.Errorf("decrypt cluster secrets: %w", err)
	}
	var bag clusterSealedSecrets
	if err := json.Unmarshal(plain, &bag); err != nil {
		return redacted, fmt.Errorf("unmarshal cluster secrets: %w", err)
	}
	out := redacted
	if bag.Registry != nil {
		if out.Registry != nil {
			ra := *out.Registry
			if bag.Registry.Password != "" {
				ra.Password = bag.Registry.Password
			}
			// Sealed payload usually mirrors Server/Username for completeness;
			// fall back to it if redacted dropped them (older replication).
			if ra.Server == "" {
				ra.Server = bag.Registry.Server
			}
			if ra.Username == "" {
				ra.Username = bag.Registry.Username
			}
			out.Registry = &ra
		} else {
			regCopy := *bag.Registry
			out.Registry = &regCopy
		}
	}
	if len(bag.MountCreds) > 0 && len(out.Mounts) > 0 {
		ms := make([]models.MountSpec, len(out.Mounts))
		for i, m := range out.Mounts {
			mc := m
			if creds, ok := bag.MountCreds[m.Target]; ok {
				cp := make(map[string]string, len(creds))
				for k, v := range creds {
					cp[k] = v
				}
				mc.Credentials = cp
			}
			ms[i] = mc
		}
		out.Mounts = ms
	}
	return out, nil
}

func (s *Service) openClusterSecretPayload(sealed []byte, nodeID string) ([]byte, error) {
	var envelope clusterSealedSecretsEnvelope
	if err := json.Unmarshal(sealed, &envelope); err == nil && len(envelope.Payload) > 0 {
		recipients := normalizeClusterSecretRecipients(envelope.Recipients)
		if !clusterSecretRecipientAllowed(recipients, nodeID) {
			return nil, fmt.Errorf("recipient %q is not allowed to open this cluster secret", nodeID)
		}
		switch envelope.Version {
		case clusterSecretEnvelopeVersion:
			if len(envelope.WrappedKey) == 0 {
				return nil, errors.New("cluster secret envelope missing wrapped data key")
			}
			dek, err := s.cipher.DecryptWithAAD(envelope.WrappedKey, clusterSecretKeyAAD(recipients))
			if err != nil {
				return nil, fmt.Errorf("unwrap cluster secret data key: %w", err)
			}
			return openClusterSecretEnvelopePayload(dek, envelope.Payload, recipients)
		case 2:
			return s.cipher.DecryptWithAAD(envelope.Payload, clusterSecretAAD(recipients))
		}
	}
	// Legacy raw nonce||ciphertext blob. Kept for rolling upgrades and
	// snapshots/raft logs written before v2 recipient envelopes existed.
	return s.cipher.Decrypt(sealed)
}

func openClusterSecretEnvelopePayload(dek []byte, sealed []byte, recipients []string) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("cluster secret data cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cluster secret data gcm: %w", err)
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("cluster secret payload too short")
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, body, clusterSecretPayloadAAD(recipients))
	if err != nil {
		return nil, fmt.Errorf("decrypt cluster secret payload: %w", err)
	}
	return plain, nil
}

func normalizeClusterSecretRecipients(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	if len(out) == 0 {
		out = append(out, "*")
	}
	sort.Strings(out)
	return out
}

func clusterSecretRecipientAllowed(recipients []string, nodeID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	for _, r := range recipients {
		if r == "*" || (nodeID != "" && r == nodeID) {
			return true
		}
	}
	return false
}

func clusterSecretAAD(recipients []string) []byte {
	return []byte("aerolvm-cluster-secrets-v2\x00" + strings.Join(normalizeClusterSecretRecipients(recipients), "\x00"))
}

func clusterSecretKeyAAD(recipients []string) []byte {
	return []byte("aerolvm-cluster-secrets-v3-key\x00" + strings.Join(normalizeClusterSecretRecipients(recipients), "\x00"))
}

func clusterSecretPayloadAAD(recipients []string) []byte {
	return []byte("aerolvm-cluster-secrets-v3-payload\x00" + strings.Join(normalizeClusterSecretRecipients(recipients), "\x00"))
}

func clusterSecretRef(sandboxID string, version int) string {
	return fmt.Sprintf("cluster-secret://sandbox/%s/v%d", strings.TrimSpace(sandboxID), version)
}
