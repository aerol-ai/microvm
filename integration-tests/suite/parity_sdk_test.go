//go:build integration

package suite

// Live checks for the SDK-experience lane of
// plans/agent-sandbox-feature-parity.md (section 5.3, S1-S7). The suite
// drives the Go SDK; each case checks the server behaviour the SDK feature
// relies on.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-446 — typed errors (plan S3): the live server's answers match the SDK's
// status sentinels, so a caller can branch with errors.Is instead of
// comparing numbers: a missing sandbox is ErrNotFound, a second create with
// a name already in use is ErrConflict, a wrong token is ErrAuth, and
// errors.As still reads the *APIError behind each.
func TestParitySDKTypedErrorsLive(t *testing.T) {
	harness.Require(t, sc, "UC-446")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := client(t)

	_, err := c.SDK().Get(ctx, "sb-0000000000000000")
	var apiErr *microvm.APIError
	if !errors.Is(err, microvm.ErrNotFound) || !errors.As(err, &apiErr) || apiErr.StatusCode != 404 {
		t.Fatalf("Get(missing) error = %v, want ErrNotFound with an *APIError 404", err)
	}

	sb := paritySandbox(t)
	public := true
	dup, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Name: sb.Name, Image: harness.DefaultImage, AllowPublicTraffic: &public})
	if dup != nil {
		_ = c.SDK().Destroy(context.Background(), dup.ID)
	}
	if !errors.Is(err, microvm.ErrConflict) || errors.Is(err, microvm.ErrNotFound) {
		t.Fatalf("create with a name in use error = %v, want ErrConflict", err)
	}

	stranger, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: sc.BaseURL, PATToken: "not-a-real-token", HTTPClient: harness.HTTPClient(0)})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	if _, err := stranger.Get(ctx, sb.ID); !errors.Is(err, microvm.ErrAuth) || !errors.As(err, &apiErr) || apiErr.StatusCode != 401 {
		t.Fatalf("Get with a wrong token error = %v, want ErrAuth (401)", err)
	}
}
