package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// UpstreamCredentials is the plaintext shape AOCR's auth service expects
// inside a wrapped blob. Field names are JSON-serialized as-is; they must
// match `auth/src/upstreamAuth/wrap.ts` exactly or the round-trip breaks.
//
// `Scope` pins the wrap to a specific Distribution token-server scope
// string (e.g. `repository:_/ghcr/org/repo:pull`). AOCR cross-checks the
// scope inside the blob against the scope on the `/v2/token` request, so
// a leaked blob cannot be reused for a different repo.
type UpstreamCredentials struct {
	UpstreamHost string `json:"upstreamHost"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Scope        string `json:"scope"`
}

// IdentityTokenPrefix is the sentinel AOCR's auth service uses to route
// `aocrwrap:<blob>` strings through the wrap-validation path rather than
// the static-PAT or cluster-PAT paths. Anything starting with this prefix
// is treated as a wrapped upstream credential.
const IdentityTokenPrefix = "aocrwrap:"

// envelopeVersion matches `ENVELOPE_VERSION` in the AOCR-side wrap.ts.
// Bump only with a coordinated rollout that teaches both sides about the
// new version.
const envelopeVersion = 1

type wrapEnvelope struct {
	V     int                 `json:"v"`
	Ts    int64               `json:"ts"` // unix milliseconds, matching JS Date.getTime()
	Creds UpstreamCredentials `json:"creds"`
}

// WrapUpstreamCreds seals `creds` with the current key in `ring` and
// returns a Docker `identitytoken` value of the form `aocrwrap:<base64url>`.
// AOCR's auth service unwraps and probes the upstream registry with the
// embedded credentials.
//
// The blob layout is AES-256-GCM `nonce(12) || ciphertext || tag(16)`,
// then base64url. AOCR's `unwrap` reads exactly this format.
func WrapUpstreamCreds(ring *UpstreamWrapKeyRing, creds UpstreamCredentials) (string, error) {
	return wrapWithClock(ring, creds, time.Now)
}

func wrapWithClock(ring *UpstreamWrapKeyRing, creds UpstreamCredentials, now func() time.Time) (string, error) {
	current, ok := ring.Current()
	if !ok {
		return "", errors.New("upstream wrap key ring is empty")
	}
	if creds.UpstreamHost == "" {
		return "", errors.New("upstream host is required")
	}

	envelope := wrapEnvelope{
		V:     envelopeVersion,
		Ts:    now().UnixMilli(),
		Creds: creds,
	}
	plaintext, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal wrap envelope: %w", err)
	}

	block, err := aes.NewCipher(current.Bytes)
	if err != nil {
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm wrap: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	// gcm.Seal returns ciphertext || tag — exactly the layout AOCR's
	// `crypto.createDecipheriv('aes-256-gcm', ...).setAuthTag(tag)` expects
	// when given the same nonce. No AAD: matches the JS side, which also
	// passes no AAD to `setAuthTag`.
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	blob := append(append([]byte{}, nonce...), sealed...)

	return IdentityTokenPrefix + base64.RawURLEncoding.EncodeToString(blob), nil
}
