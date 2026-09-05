package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The /v1/js-bundles catalogue (plans/isolate-runtime.md §8): the "no image,
// no registry" upload path for the isolate runtime. Bundles are stored
// content-addressed and scoped to the caller's identity (owner_ref), so a
// user-scoped token only ever sees, resolves, and deletes its own bundles;
// the operator/null tenant is the global scope. All owner scoping funnels
// through ownerRefForCreate/ownerScope — the same audited seam create uses.
//
// EXPERIMENTAL until the §10.1 demand checkpoint passes; no SDK helper beyond
// raw HTTP until then.

// SetIsolateBundleStore registers the content-addressed bundle store. Called
// from pkg/daemon when cfg.EnableIsolate is true (the same store instance the
// isolate driver's resolver reads).
func (s *Service) SetIsolateBundleStore(bundleStore *jsbundle.Store) {
	s.isolateBundles = bundleStore
}

// bundleFromCreateRequest builds a validated jsbundle.Bundle from the upload
// request: a one-file bundle from Source, or a multi-module map from Modules.
func bundleFromCreateRequest(req models.CreateJSBundleRequest) (*jsbundle.Bundle, error) {
	hasSource := strings.TrimSpace(req.Source) != ""
	if hasSource == (len(req.Modules) > 0) {
		return nil, errors.New("exactly one of source or modules must be set")
	}
	if hasSource {
		return jsbundle.BuildFromSource(req.MainModule, req.Source, req.CompatibilityDate)
	}
	main := req.MainModule
	if main == "" {
		main = jsbundle.DefaultMainModule
	}
	compat := req.CompatibilityDate
	if compat == "" {
		compat = jsbundle.DefaultCompatibilityDate
	}
	b := &jsbundle.Bundle{MainModule: main, Modules: req.Modules, CompatibilityDate: compat}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if _, err := b.ComputeDigest(); err != nil {
		return nil, err
	}
	return b, nil
}

// CreateJSBundle stores a bundle under the caller's identity and returns its
// catalogue view. Idempotent: re-uploading identical bytes yields the same
// digest with no error; re-using a name repoints it. The digest is the stable
// reference a create request passes as module_ref ("sha256:<digest>").
func (s *Service) CreateJSBundle(ctx context.Context, req models.CreateJSBundleRequest) (*models.JSBundle, error) {
	if s.isolateBundles == nil {
		return nil, fmt.Errorf("js-bundles require the isolate runtime (SB_ENABLE_ISOLATE=true): %w", models.ErrRuntimeNotImplemented)
	}
	bundle, err := bundleFromCreateRequest(req)
	if err != nil {
		return nil, err
	}
	owner := ownerRefForCreate(ctx)
	digest, err := s.isolateBundles.Put(owner, strings.TrimSpace(req.Name), bundle)
	if err != nil {
		return nil, err
	}
	return s.jsBundleView(digest, strings.TrimSpace(req.Name), bundle), nil
}

// ListJSBundles returns the caller's stored bundles.
func (s *Service) ListJSBundles(ctx context.Context) ([]*models.JSBundle, error) {
	if s.isolateBundles == nil {
		return nil, fmt.Errorf("js-bundles require the isolate runtime (SB_ENABLE_ISOLATE=true): %w", models.ErrRuntimeNotImplemented)
	}
	owner := ownerRefForCreate(ctx)
	// Invert name pointers so each digest reports its alias (if any).
	nameByDigest := make(map[string]string)
	for name, d := range s.isolateBundles.NamesForTenant(owner) {
		nameByDigest[d] = name
	}
	digests := s.isolateBundles.ListDigests(owner)
	out := make([]*models.JSBundle, 0, len(digests))
	for _, d := range digests {
		b, err := s.isolateBundles.GetByDigest(d)
		if err != nil {
			continue // a concurrently-deleted blob; skip rather than fail the list
		}
		out = append(out, s.jsBundleView(d, nameByDigest[d], b))
	}
	return out, nil
}

// GetJSBundle returns one bundle by digest, refusing digests the caller does
// not own (a 404, not a 403, so a user token cannot probe others' digests).
func (s *Service) GetJSBundle(ctx context.Context, digest string) (*models.JSBundle, error) {
	if s.isolateBundles == nil {
		return nil, fmt.Errorf("js-bundles require the isolate runtime (SB_ENABLE_ISOLATE=true): %w", models.ErrRuntimeNotImplemented)
	}
	if _, localRef, ok := models.ParseJSBundleNodeRef(digest); ok {
		digest = localRef
	}
	digest = normalizeBundleDigest(digest)
	owner := ownerRefForCreate(ctx)
	if _, scoped := ownerScope(ctx); scoped && !s.isolateBundles.TenantOwns(owner, digest) {
		return nil, store.ErrNotFound
	}
	b, err := s.isolateBundles.GetByDigest(digest)
	if err != nil {
		if errors.Is(err, jsbundle.ErrBundleNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	name := ""
	for n, d := range s.isolateBundles.NamesForTenant(owner) {
		if d == digest {
			name = n
			break
		}
	}
	return s.jsBundleView(digest, name, b), nil
}

// DeleteJSBundle removes a bundle the caller owns, refusing when a live sandbox
// still pins its digest (mirrors DeleteWasmModule — a referenced artifact is
// not garbage).
func (s *Service) DeleteJSBundle(ctx context.Context, digest string) error {
	if s.isolateBundles == nil {
		return fmt.Errorf("js-bundles require the isolate runtime (SB_ENABLE_ISOLATE=true): %w", models.ErrRuntimeNotImplemented)
	}
	if _, localRef, ok := models.ParseJSBundleNodeRef(digest); ok {
		digest = localRef
	}
	digest = normalizeBundleDigest(digest)
	owner := ownerRefForCreate(ctx)
	if _, scoped := ownerScope(ctx); scoped && !s.isolateBundles.TenantOwns(owner, digest) {
		return store.ErrNotFound
	}
	sandboxes, err := s.store.ListByRuntime(ctx, models.RuntimeIsolate)
	if err != nil {
		return fmt.Errorf("check bundle references: %w", err)
	}
	for _, sb := range sandboxes {
		if sb.ModuleDigest == digest {
			return fmt.Errorf("bundle %s is in use by sandbox %s: %w", digest, sb.ID, store.ErrJSBundleInUse)
		}
	}
	// Owner-scoped, ref-counted delete: removes only this owner's ownership and
	// drops the shared blob only when no tenant still owns it. Maps the store's
	// not-found to the API 404.
	if err := s.isolateBundles.Delete(owner, digest); err != nil {
		if errors.Is(err, jsbundle.ErrBundleNotFound) {
			return store.ErrNotFound
		}
		return err
	}
	return nil
}

// jsBundleView builds the catalogue DTO for a stored bundle.
func jsBundleView(digest, name string, b *jsbundle.Bundle) *models.JSBundle {
	return &models.JSBundle{
		Digest:     digest,
		ModuleRef:  "sha256:" + digest,
		Name:       name,
		MainModule: b.MainModule,
		SizeBytes:  b.SizeBytes(),
	}
}

func (s *Service) jsBundleView(digest, name string, b *jsbundle.Bundle) *models.JSBundle {
	view := jsBundleView(digest, name, b)
	if s != nil && s.ClusterEnabled() {
		if c := s.Cluster(); c != nil {
			view.ModuleRef = models.JSBundleRefForNode(view.ModuleRef, c.SelfNodeID())
		}
	}
	return view
}

// normalizeBundleDigest strips an optional "sha256:" prefix so callers may
// pass either form as the {id} path segment.
func normalizeBundleDigest(id string) string {
	id = strings.TrimSpace(id)
	if rest, ok := strings.CutPrefix(id, "sha256:"); ok {
		return rest
	}
	return id
}
