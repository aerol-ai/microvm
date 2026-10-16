package docker

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// With VerifyRegistryAccess set (the owner-scoped-caller path), a cached
// private image must still be authorized against its registry: a caller with
// no/invalid credentials cannot start another tenant's private image straight
// from the shared local cache.
func TestCreate_VerifyRegistryAccessReauthorizesCachedPrivateImage(t *testing.T) {
	const private = "registry.example/acme/private-app:1"
	var mu sync.Mutex
	local := map[string]bool{private: true} // already cached on the node
	pulls := 0

	base := &fakeDaemon{t: t,
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	inner := base.transport()
	c := newCreateClient(t, base, true, nil)
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		p := r.URL.Path
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
			if local[private] {
				return jsonResponse(http.StatusOK, map[string]any{"Config": map[string]any{"WorkingDir": "/app"}}), nil
			}
			return textResponse(http.StatusNotFound, "no such image"), nil
		case r.Method == http.MethodPost && p == "/images/create":
			pulls++
			// Private registry: anonymous pull is refused.
			if r.Header.Get("X-Registry-Auth") == "" {
				return textResponse(http.StatusUnauthorized, `{"message":"pull access denied"}`), nil
			}
			return textResponse(http.StatusOK, `{"status":"done"}`), nil
		}
		return inner(r)
	})
	c.httpClient = &http.Client{Transport: rt}
	c.streamClient = &http.Client{Transport: rt}

	// Owner-scoped caller, no creds, image already cached: must be refused
	// because the registry re-auth (a pull) is forced and 401s.
	_, err := c.Create(context.Background(), models.CreateSandboxRequest{
		Image: private, VerifyRegistryAccess: true,
	}, "sb-b", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "verify image access") {
		t.Fatalf("owner-scoped create of cached private image = %v, want a verify-image-access failure", err)
	}
	if pulls == 0 {
		t.Fatal("expected a registry authorization round-trip on the cache hit")
	}

	// Without VerifyRegistryAccess (operator/internal), the cache is trusted:
	// no pull, create proceeds.
	pullsBefore := pulls
	if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: private}, "sb-op", "tok", nil); err != nil {
		t.Fatalf("operator create of cached image = %v, want success", err)
	}
	if pulls != pullsBefore {
		t.Fatalf("operator path re-pulled a cached image (pulls %d->%d)", pullsBefore, pulls)
	}
}
