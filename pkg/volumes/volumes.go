// Package volumes translates a named, tenant-scoped platform volume into a
// concrete mount the existing pkg/mounts pipeline already knows how to realize.
//
// A platform volume is NOT a new storage primitive. The operator configures one
// shared backend (S3 or NFS); a volume named "data" for tenant T becomes a
// synthesized models.MountSpec pointing at a deterministic, per-tenant path:
//
//	s3   →  s3://<bucket>/<prefix>/<tenant>/<name>/      (operator creds)
//	nfs  →  <server>:/<export>/<tenant>/<name>           (no creds, kernel mount)
//
// Because the path is keyed by an operator-derived tenant segment plus a
// sanitized name, the *backing store* is the single source of truth: any node
// (cluster or not) that mounts the same coordinates sees the same data. That is
// what makes platform volumes correct under cluster placement, where a sandbox
// can land on a different host than the one that first created the volume.
//
// This package is deliberately free of dependencies on internal/config and the
// auth layer so it stays pure and offline-testable. The daemon maps its config
// into Backend; the service extracts the caller identity into Caller.
package volumes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Backend is the operator-configured storage that platform volumes live on. It
// mirrors the relevant fields of config.PlatformVolumesConfig without importing
// it (which would couple this pure package to the env loader).
type Backend struct {
	Kind string // "s3" or "nfs"

	// S3 backend.
	S3Bucket          string
	S3Prefix          string
	S3Region          string
	S3Endpoint        string
	S3AccessKeyID     string
	S3SecretAccessKey string

	// NFS backend.
	NFSServer  string
	NFSExport  string
	NFSOptions string
}

const (
	BackendS3  = "s3"
	BackendNFS = "nfs"
)

// Caller carries the authenticated identity the tenant scope is derived from.
// The service builds this from controlplane.AccessFromContext; we take
// primitives so this package never imports the auth layer.
//
//   - Operator/no-access (the open-source PAT path) has no per-tenant identity,
//     so we fall back to a stable hash of the operator token. That collapses to
//     a single self-host tenant, which is correct for single-tenant deploys.
//   - A validated user token carries a stable OwnerRef = the tenant key.
type Caller struct {
	OwnerRef  string // stable per-tenant account key (managed build)
	Operator  bool   // true for the operator PAT path (no per-tenant identity)
	HasAccess bool   // false for background/internal calls with no auth edge
	PATToken  string // operator token, hashed as the fallback scope segment
}

// MaxVolumeNameLen bounds a volume name so it can never blow up a storage path.
const MaxVolumeNameLen = 64

var errEmptyName = errors.New("volume name is required")

// SanitizeVolumeName normalizes a user-supplied volume name to a single, safe
// path segment. It lowercases, permits only [a-z0-9._-], and rejects anything
// that could escape its path component (separators, traversal, over-length, or
// the reserved "." / ".." names). The returned name is guaranteed to round-trip
// to exactly one path segment.
func SanitizeVolumeName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", errEmptyName
	}
	if len(trimmed) > MaxVolumeNameLen {
		return "", fmt.Errorf("volume name %q exceeds %d characters", trimmed, MaxVolumeNameLen)
	}
	lower := strings.ToLower(trimmed)
	if lower == "." || lower == ".." {
		return "", fmt.Errorf("volume name %q is reserved", trimmed)
	}
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.' || r == '_' || r == '-':
		default:
			return "", fmt.Errorf("volume name %q contains an illegal character %q (allowed: a-z 0-9 . _ -)", trimmed, r)
		}
	}
	// Defense in depth: even with the charset filter above, a name like ".."
	// is already rejected; confirm it really is one clean segment.
	if cleaned := path.Clean(lower); cleaned != lower || strings.Contains(cleaned, "/") {
		return "", fmt.Errorf("volume name %q does not resolve to a single path segment", trimmed)
	}
	return lower, nil
}

// TenantScope returns the path segment that isolates one tenant's volumes from
// another's. This is the load-bearing security boundary: two tenants using the
// name "data" MUST map to disjoint paths. It is derived entirely server-side and
// is stable across restarts.
func TenantScope(c Caller) (string, error) {
	if c.HasAccess && !c.Operator {
		ref := strings.TrimSpace(c.OwnerRef)
		if ref == "" {
			return "", errors.New("authenticated caller has no owner ref; cannot scope volume")
		}
		return "t-" + hashSegment(ref), nil
	}
	// Operator PAT / no-access path: no per-tenant identity. Fall back to a
	// stable hash of the operator token so a single-tenant self-host deploy
	// gets one deterministic scope. An empty token here is unscopeable.
	if strings.TrimSpace(c.PATToken) == "" {
		return "", errors.New("no tenant identity and no operator token; cannot scope volume")
	}
	return "op-" + hashSegment(c.PATToken), nil
}

// hashSegment returns a stable, path-safe 16-hex-char digest of s. We hash
// rather than embed the raw value so arbitrary owner refs / tokens can never
// inject path separators and so the operator token is never exposed in a bucket
// path.
func hashSegment(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// BuildMountSpec synthesizes the MountSpec for one volume reference. tenant must
// already be a TenantScope result; name is sanitized here. The returned spec is
// fed straight into the existing seal + MountAll path; full target-path policy
// (blocked dirs, dup targets, count cap) is enforced by MountSpec.Validate in
// the service, not duplicated here.
func BuildMountSpec(b Backend, tenant, name, target string, readOnly bool) (models.MountSpec, error) {
	if strings.TrimSpace(tenant) == "" {
		return models.MountSpec{}, errors.New("tenant scope is required")
	}
	if strings.TrimSpace(target) == "" {
		return models.MountSpec{}, errors.New("volume mount path is required")
	}
	safeName, err := SanitizeVolumeName(name)
	if err != nil {
		return models.MountSpec{}, err
	}

	switch b.Kind {
	case BackendS3:
		if strings.TrimSpace(b.S3Bucket) == "" {
			return models.MountSpec{}, errors.New("s3 backend is missing a bucket")
		}
		// Source is "bucket/prefix/tenant/name" — parseS3Source in the adapter
		// splits on the first "/" into bucket + key prefix.
		source := path.Join(b.S3Bucket, strings.Trim(b.S3Prefix, "/"), tenant, safeName)
		spec := models.MountSpec{
			Type:     models.MountTypeS3,
			Source:   source,
			Target:   target,
			ReadOnly: readOnly,
		}
		if opts := s3Options(b); len(opts) > 0 {
			spec.Options = opts
		}
		if creds := s3Credentials(b); len(creds) > 0 {
			spec.Credentials = creds
		}
		return spec, nil

	case BackendNFS:
		if strings.TrimSpace(b.NFSServer) == "" || strings.TrimSpace(b.NFSExport) == "" {
			return models.MountSpec{}, errors.New("nfs backend is missing server or export")
		}
		// Source must look like host:/path (validateSource enforces ":/" and no
		// leading "/"). The NFS adapter reads mount options from Options["opts"].
		exportPath := "/" + path.Join(strings.Trim(b.NFSExport, "/"), tenant, safeName)
		spec := models.MountSpec{
			Type:     models.MountTypeNFS,
			Source:   b.NFSServer + ":" + exportPath,
			Target:   target,
			ReadOnly: readOnly,
		}
		if strings.TrimSpace(b.NFSOptions) != "" {
			spec.Options = map[string]string{"opts": b.NFSOptions}
		}
		return spec, nil

	default:
		return models.MountSpec{}, fmt.Errorf("unknown platform-volume backend %q", b.Kind)
	}
}

func s3Options(b Backend) map[string]string {
	opts := map[string]string{}
	if v := strings.TrimSpace(b.S3Region); v != "" {
		opts["region"] = v
	}
	if v := strings.TrimSpace(b.S3Endpoint); v != "" {
		opts["endpoint"] = v
	}
	if len(opts) == 0 {
		return nil
	}
	return opts
}

func s3Credentials(b Backend) map[string]string {
	// No static keys means the operator relies on an instance role; mount-s3
	// resolves that from the ambient environment, so we send no profile.
	if strings.TrimSpace(b.S3AccessKeyID) == "" && strings.TrimSpace(b.S3SecretAccessKey) == "" {
		return nil
	}
	return map[string]string{
		"access_key_id":     b.S3AccessKeyID,
		"secret_access_key": b.S3SecretAccessKey,
	}
}

// CheckQuota enforces the per-tenant volume-count cap at create/attach time.
// maxPerTenant <= 0 means unlimited. currentCount is the tenant's existing
// distinct volume count; creating one more must not exceed the cap.
func CheckQuota(currentCount, maxPerTenant int) error {
	if maxPerTenant <= 0 {
		return nil
	}
	if currentCount >= maxPerTenant {
		return fmt.Errorf("tenant volume quota reached (%d/%d)", currentCount, maxPerTenant)
	}
	return nil
}
