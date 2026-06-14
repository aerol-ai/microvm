package harness

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// DefaultImage is the small, always-available image used by lifecycle/network
// use cases that don't care what runs inside.
const DefaultImage = "alpine:3.20"

// Client wraps the Go SDK so every test shares one configured client and the
// resource-hygiene helpers (unique naming + guaranteed cleanup). Using the
// real SDK is deliberate: the suite doubles as Go-SDK integration coverage.
type Client struct {
	sc  *Scenario
	sdk *microvm.Client
}

// NewClient builds a Client for the scenario. Fails the test immediately if the
// SDK can't be constructed — there's no point continuing without an API client.
func NewClient(t *testing.T, sc *Scenario) *Client {
	t.Helper()
	sdk, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl:   sc.BaseURL,
		PATToken: sc.PAT,
	})
	if err != nil {
		t.Fatalf("build SDK client: %v", err)
	}
	return &Client{sc: sc, sdk: sdk}
}

// SDK exposes the underlying client for use cases that need a method this
// wrapper doesn't surface yet.
func (c *Client) SDK() *microvm.Client { return c.sdk }

// Require skips the test unless the scenario satisfies the use case's
// capabilities. The skip message names the missing capabilities so the report
// (and a human) can see exactly why it didn't run.
func Require(t *testing.T, sc *Scenario, ucID string, alsoCovers ...string) UseCase {
	t.Helper()
	uc, ok := Lookup(ucID)
	if !ok {
		t.Fatalf("unknown use case %q (not in registry)", ucID)
	}
	// Emit a stable marker so the report generator can map this (flat-named)
	// test back to its UC id. The tests aren't named TestX/UC-NN subtests, so
	// the id never reaches the test-event name; this log line — captured by
	// `go test -json` for pass/fail/skip alike — is how report/gen.go joins a
	// result row to its UC. Keep the "ucid=" prefix in sync with gen.go's regex.
	//
	// alsoCovers lets a parent test that fans out into UC-named subtests claim
	// those UCs too. Otherwise, when the parent is capability-skipped on its
	// primary UC, the subtests never run and their UCs read as "missing" (a
	// hard-fail) instead of "skip". The gate below still keys off the primary.
	t.Logf("ucid=%s", ucID)
	for _, id := range alsoCovers {
		t.Logf("ucid=%s", id)
	}
	if !sc.Satisfies(uc) {
		t.Skipf("scenario %q lacks capabilities %v for %s", sc.Name, sc.MissingCaps(uc), ucID)
	}
	return uc
}

// NewSandbox creates a sandbox with a unique, scenario-scoped name and
// registers a t.Cleanup that destroys it. This is the hygiene contract: no test
// leaks a sandbox into the shared deployment. Returns the running sandbox.
func (c *Client) NewSandbox(t *testing.T, opts sdktypes.CreateSandboxOptions) *microvm.Sandbox {
	t.Helper()
	if opts.Image == "" {
		opts.Image = DefaultImage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sb, err := c.sdk.Create(ctx, opts)
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort: a leaked sandbox skews later tests and costs money, but a
		// cleanup failure shouldn't itself fail an otherwise-green test — log it.
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if derr := c.sdk.Destroy(cctx, sb.ID); derr != nil {
			t.Logf("cleanup: destroy sandbox %s: %v", sb.ID, derr)
		}
	})
	return sb
}

// UniqueName returns a deployment-unique sandbox name for a test, so parallel
// or repeated runs never collide: "<scenario>-<test>-<unixnano>".
func UniqueName(sc *Scenario, t *testing.T) string {
	t.Helper()
	// Lowercased and slash-free: the name flows into sandbox names AND snapshot
	// image refs, and Docker rejects an image repository with uppercase or '/'
	// segments ("invalid reference format ... must be lowercase"). t.Name() is
	// CamelCase (and '/'-separated for subtests), so sanitize here once.
	raw := fmt.Sprintf("%s-%s-%d", sc.Name, t.Name(), time.Now().UnixNano())
	return strings.ToLower(strings.ReplaceAll(raw, "/", "-"))
}
