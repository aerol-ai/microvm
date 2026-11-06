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

// UC-447 — get or create by name (plan S4, CEO review R4): eight
// GetOrCreate calls for one new name, sent at once through the live server,
// all return the same sandbox and exactly one reports that it created it;
// the name then maps to that one sandbox, and a later call returns it
// without creating.
func TestParitySDKGetOrCreateLive(t *testing.T) {
	harness.Require(t, sc, "UC-447")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sdk := client(t).SDK()
	name := harness.UniqueName(sc, t)
	public := true
	opts := sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, AllowPublicTraffic: &public}

	const callers = 8
	type result struct {
		id      string
		created bool
		err     error
	}
	results := make(chan result, callers)
	for range callers {
		go func() {
			sb, created, err := sdk.GetOrCreate(ctx, name, opts)
			r := result{created: created, err: err}
			if sb != nil {
				r.id = sb.ID
			}
			results <- r
		}()
	}
	ids := map[string]bool{}
	made := 0
	var firstErr error
	for range callers {
		r := <-results
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		if r.id != "" {
			ids[r.id] = true
		}
		if r.created {
			made++
		}
	}
	for id := range ids {
		t.Cleanup(func() { _ = sdk.Destroy(context.Background(), id) })
	}
	if firstErr != nil {
		t.Fatalf("GetOrCreate: %v", firstErr)
	}
	if len(ids) != 1 || made != 1 {
		t.Fatalf("%d concurrent GetOrCreate calls gave sandboxes %v with %d created, want one sandbox created once", callers, ids, made)
	}
	byName, err := sdk.GetByName(ctx, name)
	if err != nil || !ids[byName.ID] {
		t.Fatalf("GetByName(%s) = (%v, %v), want one of %v", name, byName, err, ids)
	}
	again, created, err := sdk.GetOrCreate(ctx, name, opts)
	if err != nil || created || again.ID != byName.ID {
		t.Fatalf("second GetOrCreate = (%v, %v, %v), want %s not created", again, created, err, byName.ID)
	}
}

// UC-448 — delete many by tag (plan S5): DestroyAll with a tag unique to
// this run deletes the three sandboxes carrying it (and returns their IDs),
// leaves a sandbox with another tag value alone, and a second call finds
// nothing and returns no IDs.
func TestParitySDKDestroyAllLive(t *testing.T) {
	harness.Require(t, sc, "UC-448")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	c := client(t)
	run := harness.UniqueName(sc, t)
	var doomed []string
	for range 3 {
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Tags: map[string]string{"uc448": run}})
		doomed = append(doomed, sb.ID)
	}
	kept := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Tags: map[string]string{"uc448": run + "-keep"}})

	gone, err := c.SDK().DestroyAll(ctx, map[string]string{"uc448": run})
	if err != nil {
		t.Fatalf("DestroyAll: %v", err)
	}
	if len(gone) != len(doomed) {
		t.Fatalf("DestroyAll returned %v, want the three sandboxes %v", gone, doomed)
	}
	want := map[string]bool{}
	for _, id := range doomed {
		want[id] = true
	}
	for _, id := range gone {
		if !want[id] {
			t.Fatalf("DestroyAll deleted %s, which does not carry the tag", id)
		}
		if _, err := c.SDK().Get(ctx, id); !errors.Is(err, microvm.ErrNotFound) {
			t.Fatalf("Get(%s) after DestroyAll = %v, want ErrNotFound", id, err)
		}
	}
	if _, err := c.SDK().Get(ctx, kept.ID); err != nil {
		t.Fatalf("the sandbox with another tag value is gone: %v", err)
	}
	again, err := c.SDK().DestroyAll(ctx, map[string]string{"uc448": run})
	if err != nil || len(again) != 0 {
		t.Fatalf("second DestroyAll = (%v, %v), want nothing to delete", again, err)
	}
}

// UC-449 — auto-cleanup (plan S2): Close on a sandbox without
// DestroyOnClose leaves it running and usable; with DestroyOnClose it
// deletes the sandbox, even when the ctx it is given is already cancelled
// (the usual state of a deferred Close), and a second Close is a no-op.
func TestParitySDKCloseLive(t *testing.T) {
	harness.Require(t, sc, "UC-449")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sdk := client(t).SDK()

	sb := paritySandbox(t)
	if err := sb.Close(ctx); err != nil {
		t.Fatalf("Close without DestroyOnClose: %v", err)
	}
	if got := parityExec(t, ctx, sb, "echo still-here"); got != "still-here" {
		t.Fatalf("sandbox after a plain Close answered %q", got)
	}

	sb.DestroyOnClose = true
	done, stop := context.WithCancel(ctx)
	stop()
	if err := sb.Close(done); err != nil {
		t.Fatalf("Close with DestroyOnClose and a cancelled ctx: %v", err)
	}
	if _, err := sdk.Get(ctx, sb.ID); !errors.Is(err, microvm.ErrNotFound) {
		t.Fatalf("Get after Close = %v, want ErrNotFound", err)
	}
	if err := sb.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// UC-450 — per-call timeouts (plan S6, a Python and TypeScript feature):
// the server behaviour a per-call timeout leans on. A create whose caller
// gives up after 50 ms (often after the request reached the server) and is
// then sent again with the same Idempotency-Key ends with exactly one
// sandbox of that name, and the retry returns it. The SDK side is covered
// by unit tests in sdk/python/tests/test_timeouts.py and
// sdk/typescript/src/callOptions.test.ts.
func TestParitySDKTimedOutCreateRetriesOntoOneSandboxLive(t *testing.T) {
	harness.Require(t, sc, "UC-450")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sdk := client(t).SDK()
	name := harness.UniqueName(sc, t)
	key := "uc450-" + name
	public := true
	opts := sdktypes.CreateSandboxOptions{Name: name, Image: harness.DefaultImage, AllowPublicTraffic: &public}

	short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	first, firstErr := sdk.CreateWithIdempotencyKey(short, opts, key)
	stop()
	if first != nil {
		t.Cleanup(func() { _ = sdk.Destroy(context.Background(), first.ID) })
		t.Logf("the create finished inside 50 ms (%s); the retry must still return it", first.ID)
	} else if !errors.Is(firstErr, context.DeadlineExceeded) {
		t.Fatalf("short create error = %v, want a deadline error", firstErr)
	}

	again, err := sdk.CreateWithIdempotencyKey(ctx, opts, key)
	if err != nil {
		t.Fatalf("retried create: %v", err)
	}
	t.Cleanup(func() { _ = sdk.Destroy(context.Background(), again.ID) })
	if first != nil && first.ID != again.ID {
		t.Fatalf("retry made %s, want the first create's %s", again.ID, first.ID)
	}
	byName, err := sdk.GetByName(ctx, name)
	if err != nil || byName.ID != again.ID {
		t.Fatalf("GetByName(%s) = (%v, %v), want the one sandbox %s", name, byName, err, again.ID)
	}
}
