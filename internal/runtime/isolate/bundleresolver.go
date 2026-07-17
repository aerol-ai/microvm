package isolate

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// jsbundleResolver adapts *pkg/jsbundle.Resolver to the driver's BundleResolver
// seam. It lives in the driver package (not pkg/jsbundle) so pkg/jsbundle stays
// free of the driver's interface — the same direction as the wasm resolver
// adapter.
type jsbundleResolver struct {
	inner *jsbundle.Resolver
}

// NewBundleResolver wraps a jsbundle.Resolver as a driver BundleResolver.
func NewBundleResolver(inner *jsbundle.Resolver) BundleResolver {
	return &jsbundleResolver{inner: inner}
}

func (r *jsbundleResolver) Resolve(ctx context.Context, tenant, ref string) (*jsbundle.Bundle, error) {
	return r.inner.Resolve(ctx, tenant, ref)
}
