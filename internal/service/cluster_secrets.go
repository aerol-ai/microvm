package service

import (
	"encoding/json"
	"fmt"

	"github.com/aerol-ai/microvm/pkg/models"
)

// clusterSealedSecrets is the cleartext schema of the encrypted blob the
// cluster layer stores in Placement.SealedSecrets. It only carries the parts
// of CreateSandboxRequest that are actually secret — registry password and
// per-mount credential maps. Everything else (image, env, mount Source/Target,
// etc.) rides on the redacted Spec, which the cluster replicates in plaintext.
//
// MountCreds is keyed by MountSpec.Target (the in-container mount path). Target
// is required + unique per mount per service.createSandbox validation, so it
// works as a stable join key when re-merging on the receiving end.
type clusterSealedSecrets struct {
	Registry   *models.RegistryAuth         `json:"registry,omitempty"`
	MountCreds map[string]map[string]string `json:"mount_creds,omitempty"`
}

// SealClusterSecrets extracts the secret-bearing portions of req, marshals
// them as JSON, and encrypts the result with the service cipher. The output
// is opaque bytes safe to put in the raft log. Returns nil/nil when there
// are no secrets to seal so the FSM column stays empty for sandboxes that
// don't need it.
//
// Cluster mode requires operators to share the same SB_CREDENTIAL_ENCRYPTION_KEY
// across nodes — without it, the receiving owner can't decrypt the bag and
// the recreated sandbox loses access to its private registry / mount creds.
// This is the same key already used for at-rest sealing in SQLite, so the
// requirement is implicit rather than newly imposed.
func (s *Service) SealClusterSecrets(req models.CreateSandboxRequest) ([]byte, error) {
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
	plain, err := json.Marshal(bag)
	if err != nil {
		return nil, fmt.Errorf("marshal cluster secrets: %w", err)
	}
	sealed, err := s.cipher.Encrypt(plain)
	if err != nil {
		return nil, fmt.Errorf("encrypt cluster secrets: %w", err)
	}
	return sealed, nil
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
	if len(sealed) == 0 {
		return redacted, nil
	}
	plain, err := s.cipher.Decrypt(sealed)
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
