package jsbundle

import (
	"context"
	"strings"
)

// Resolver turns a bundle reference into a concrete Bundle. It is the
// production BundleResolver behind the isolate driver (adapted in
// internal/runtime/isolate). Reference shapes, in precedence order:
//
//   - "sha256:<hex>" or a bare 64-hex string — a content digest; loaded from
//     the store. This is the idempotent create path: the sandbox row pins the
//     digest, so a retry or a failover peer resolves the exact same bytes.
//   - "file://<path>" or a filesystem path ending .js/.mjs/.ts — an operator/
//     self-host entrypoint file, built into a one-module bundle.
//   - any other non-empty token — an uploaded bundle NAME, looked up in the
//     store for the resolving tenant (the "no image, no registry" remote path
//     via POST /v1/js-bundles).
//
// The store may be nil for an operator-only deployment that resolves file
// paths exclusively; name/digest refs then return ErrBundleNotFound.
type Resolver struct {
	store *Store
}

// NewResolver builds a resolver over an optional content-addressed store.
func NewResolver(store *Store) *Resolver {
	return &Resolver{store: store}
}

// Resolve resolves ref for tenant (tenant scopes uploaded-name lookups; it is
// ignored for digest and file refs). The returned bundle always has Digest set.
func (r *Resolver) Resolve(ctx context.Context, tenant, ref string) (*Bundle, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, ErrUnsupportedRef
	}

	if digest, ok := asDigest(ref); ok {
		if r.store == nil {
			return nil, ErrBundleNotFound
		}
		return r.store.GetByDigest(digest)
	}

	if path, ok := asFilePath(ref); ok {
		return BuildFromFile(path)
	}

	// Uploaded name.
	if r.store == nil {
		return nil, ErrBundleNotFound
	}
	return r.store.GetByName(tenant, ref)
}

// asDigest recognizes "sha256:<64hex>" or a bare 64-hex string and returns the
// bare hex.
func asDigest(ref string) (string, bool) {
	hex := ref
	if rest, ok := strings.CutPrefix(ref, "sha256:"); ok {
		hex = rest
	} else if !isHex64(ref) {
		return "", false
	}
	if !isHex64(hex) {
		return "", false
	}
	return hex, true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsFileRef reports whether ref is a filesystem/file:// entrypoint (as opposed
// to a digest or an uploaded name). The service uses it to gate host-filesystem
// reads to operator/unscoped callers — a scoped tenant must not be able to make
// the daemon read an arbitrary host file via module_ref:"file:///…".
func IsFileRef(ref string) bool {
	_, ok := asFilePath(strings.TrimSpace(ref))
	return ok
}

// asFilePath recognizes a file:// URL or a bare path with a JS/TS extension.
func asFilePath(ref string) (string, bool) {
	if rest, ok := strings.CutPrefix(ref, "file://"); ok {
		return rest, true
	}
	lower := strings.ToLower(ref)
	for ext := range jsSourceExtensions {
		if strings.HasSuffix(lower, ext) {
			return ref, true
		}
	}
	return "", false
}
