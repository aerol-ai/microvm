package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// An Idempotency-Key create derives its sandbox ID from the owner and the key
// alone (clustercreate.DeterministicSandboxID), so a retry finds the sandbox
// the first call made. Without more, a retry that reused the key for a
// different request (a rotated API key in env, another image) was handed the
// old sandbox and its new request silently dropped. The API edge therefore
// digests the request as the client sent it (CreateRequestDigests), the
// sandbox keeps that digest (sandbox_create_digests), and a create under an
// ID that already has one, or is being created right now, must match it.

// createRequestDigestPurpose names the keyed digest of a facade's create
// request. Each facade digests its own wire shape, so the purpose is per
// facade: a key reused across facades never matches.
func createRequestDigestPurpose(facade string) string {
	return "idempotency-key/" + facade + "/create-request/v1"
}

// CreateRequestDigests returns the keyed digests of a create request's
// canonical encoding, one per server key, the current key's first, written
// "hmac:<key id>:<hex>". canonical must not depend on map order (encoding/json
// sorts map keys). No server key configured means no digest: such a server
// replays a keyed create as before, unchecked.
func (s *Service) CreateRequestDigests(facade string, canonical []byte) ([]string, error) {
	if s == nil || s.cipher == nil {
		return nil, nil
	}
	digests, err := s.RequestDigests(createRequestDigestPurpose(facade), canonical)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(digests))
	for _, d := range digests {
		out = append(out, d.String())
	}
	return out, nil
}

type idempotencyKeyCtxKey struct{}
type createDigestsCtxKey struct{}

// WithIdempotencyKey names the client's Idempotency-Key for the create on ctx,
// so a refusal can say which key was reused.
func WithIdempotencyKey(ctx context.Context, key string) context.Context {
	if key = strings.TrimSpace(key); key == "" {
		return ctx
	}
	return context.WithValue(ctx, idempotencyKeyCtxKey{}, key)
}

func keyReusedError(ctx context.Context) error {
	key, _ := ctx.Value(idempotencyKeyCtxKey{}).(string)
	return &models.IdempotencyKeyReusedError{Key: key}
}

// withCreateRequestDigests carries a keyed create's digests to the row write
// (persistSandboxCreate) and to the duplicate-create replays.
func withCreateRequestDigests(ctx context.Context, digests []string) context.Context {
	if len(digests) == 0 {
		return ctx
	}
	return context.WithValue(ctx, createDigestsCtxKey{}, digests)
}

func createRequestDigestsFrom(ctx context.Context) []string {
	digests, _ := ctx.Value(createDigestsCtxKey{}).([]string)
	return digests
}

// createDigestsMatch compares the digest a sandbox was created with against
// a request's digests. Only a key both sides hold can decide: the same key
// with another digest is a different request; no key in common (the stored
// digest's key was retired since) cannot be checked and counts as a match,
// the replay every keyed create got before digests were kept.
func createDigestsMatch(stored string, request []string) bool {
	storedID, storedSum, ok := splitCreateDigest(stored)
	if !ok {
		return true
	}
	for _, d := range request {
		if id, sum, ok := splitCreateDigest(d); ok && id == storedID {
			return sum == storedSum
		}
	}
	return true
}

func splitCreateDigest(d string) (keyID, sum string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(d), "hmac:")
	if !found {
		return "", "", false
	}
	keyID, sum, ok = strings.Cut(rest, ":")
	return keyID, sum, ok && keyID != "" && sum != ""
}

// checkStoredCreateDigest refuses a duplicate create (one that found the
// sandbox only once its runtime or row insert collided) made with a different
// request than the sandbox's.
func (s *Service) checkStoredCreateDigest(ctx context.Context, id string) error {
	digests := createRequestDigestsFrom(ctx)
	if len(digests) == 0 {
		return nil
	}
	stored, err := s.store.GetCreateRequestDigest(ctx, id)
	if err != nil {
		return err
	}
	if stored != "" && !createDigestsMatch(stored, digests) {
		return keyReusedError(ctx)
	}
	return nil
}
