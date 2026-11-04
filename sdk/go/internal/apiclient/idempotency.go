package apiclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// HeaderIdempotencyKey is the header a sandbox create carries so the server
// can recognise a retry of it. Keep in sync with
// clustercreate.HeaderIdempotencyKey on the server.
const HeaderIdempotencyKey = "Idempotency-Key"

// newIdempotencyKey is a fresh create key: 128 random bits as 32 lowercase
// hex characters.
func newIdempotencyKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails: crypto/rand.Read panics instead.
	return hex.EncodeToString(b[:])
}

// CreateWithIdempotencyKey creates a sandbox with key as its Idempotency-Key.
// A blank key gets a fresh random one. Either way the key is fixed for this
// call and sent unchanged on each of its automatic retries, so a create
// retried after a timeout gets back the sandbox the first attempt made
// instead of making a second one. A key the server already holds for a
// different request fails with an *APIError whose Code is
// "idempotency_key_reused"; that 422 is not retried.
func (c *Client) CreateWithIdempotencyKey(ctx context.Context, opts CreateOptions, key string) (*Sandbox, string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = newIdempotencyKey()
	}
	header := http.Header{}
	header.Set(HeaderIdempotencyKey, key)
	var response models.CreateSandboxResponse
	if _, err := c.doJSONRequest(ctx, http.MethodPost, c.versionPrefix+"/sandboxes", opts, &response, retryIdempotent, header); err != nil {
		return nil, "", err
	}
	return c.wrap(response.Sandbox), response.SSHPrivateKey, nil
}
