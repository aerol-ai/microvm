//go:build integration

package suite

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// The isolate runtime (plans/isolate-runtime.md) has no image and no registry —
// a sandbox references a JS/TS bundle uploaded to the /v1/js-bundles catalogue,
// and its fetch handler is driven by mapping a toolbox exec command to a fetch
// URL path (internal/runtime/isolate/exec.go). These UCs are the repeatable live
// coverage that make the runtime — and specifically the per-sandbox egress
// attribution shipped in v0.7.16 — non-experimental. They gate on CapIsolate, so
// they skip (not-applicable) on any scenario whose node was not provisioned
// --with-isolate.

// uploadBundle uploads a JS bundle to the owner-scoped catalogue and returns the
// reference the create path accepts (the bundle name). Upload is content-
// addressed and idempotent, so re-running with the same name+source resolves to
// the same digest rather than accumulating bundles.
func uploadBundle(t *testing.T, c *harness.Client, name, source string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out models.JSBundle
	if err := c.PostJSON(ctx, "/v1/js-bundles", models.CreateJSBundleRequest{
		Name:   name,
		Source: source,
	}, &out); err != nil {
		t.Fatalf("upload bundle %q: %v", name, err)
	}
	if out.Digest == "" {
		t.Fatalf("upload bundle %q: empty digest in response", name)
	}
	return name
}

// newIsolateSandbox creates a runtime=isolate sandbox referencing a bundle and
// registers cleanup. It deliberately does NOT go through harness.NewSandbox:
// that helper injects a default docker Image and flips AllowPublicTraffic on,
// neither of which fits the host-mediated isolate boot path (the bundle IS the
// image; ingress is a separate expose_port call). Mirrors the proven API recipe
// in pkg/daemon/isolate_api_integration_test.go.
func newIsolateSandbox(t *testing.T, c *harness.Client, moduleRef, tenant string, opts sdktypes.CreateSandboxOptions) *microvm.Sandbox {
	t.Helper()
	opts.Runtime = models.RuntimeIsolate
	opts.ModuleRef = moduleRef
	opts.TenantID = tenant
	if opts.Name == "" {
		opts.Name = harness.UniqueName(sc, t)
	}
	if opts.MemoryMB == 0 {
		opts.MemoryMB = 128
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, opts)
	if err != nil {
		t.Fatalf("create isolate sandbox: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if derr := c.SDK().Destroy(cctx, sb.ID); derr != nil {
			t.Logf("cleanup: destroy isolate sandbox %s: %v", sb.ID, derr)
		}
	})
	return sb
}

// execFetch drives the sandbox's fetch handler: the isolate driver maps an exec
// command to a GET on http://isolate<command>, returning the handler's response
// body as stdout. Returns the stdout.
func execFetch(t *testing.T, sb *microvm.Sandbox, urlPath string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	res, err := sb.ExecCommand(ctx, urlPath)
	if err != nil {
		t.Fatalf("exec-fetch %q on %s: %v", urlPath, sb.ID, err)
	}
	return res.Stdout
}

// UC-103 — an isolate sandbox runs end-to-end: upload a bundle, create a
// runtime=isolate sandbox referencing it, and confirm its fetch handler serves
// via toolbox exec. Proves workerd installed + group spawned + bundle loaded.
func TestIsolateRuntimeRuns(t *testing.T) {
	harness.Require(t, sc, "UC-103")
	c := client(t)

	ref := uploadBundle(t, c, "itest-isolate-hello",
		`export default { async fetch() { return new Response("isolate-ok"); } };`)

	sb := newIsolateSandbox(t, c, ref, "itest-runs", sdktypes.CreateSandboxOptions{})
	waitRunning(t, sb)

	if got := execFetch(t, sb, "/"); got != "isolate-ok" {
		t.Fatalf("fetch handler = %q, want %q", got, "isolate-ok")
	}
}

// egressProbeBundle returns the searchParam target ("t") and reports the inner
// fetch's HTTP status (or the thrown error). A policy denial surfaces as an
// upstream 403 from the egress proxy → body "status=403"; an allowed fetch is
// 200 (reachable) or a throw/502 (allowed but unreachable), never 403.
const egressProbeBundle = `export default { async fetch(req) {
  const u = new URL(req.url);
  try {
    const r = await fetch(u.searchParams.get("t"));
    return new Response("status=" + r.status);
  } catch (e) {
    return new Response("throw=" + (e && e.message ? e.message : String(e)));
  }
}};`

// UC-104 — per-sandbox egress attribution (the §4 redesign, v0.7.16 / PR #340).
// Two isolate sandboxes in the SAME tenant group get DIFFERENT egress policies
// enforced: an allow-listed sandbox reaches its allowed host but is refused a
// non-allowed one, while a block-all sandbox in the same group is refused
// everything. Attribution is the egress slot socket — a forged header on the
// outbound is irrelevant — so this is the live proof that egress is enforced
// per sandbox, not group-wide, and is no longer deny-all.
func TestIsolatePerSandboxEgress(t *testing.T) {
	harness.Require(t, sc, "UC-104")
	c := client(t)

	ref := uploadBundle(t, c, "itest-isolate-egress", egressProbeBundle)

	const tenant = "itest-egress" // both sandboxes share ONE workerd group
	allow := newIsolateSandbox(t, c, ref, tenant, sdktypes.CreateSandboxOptions{
		NetworkAllowOut: []string{"example.com"},
	})
	block := newIsolateSandbox(t, c, ref, tenant, sdktypes.CreateSandboxOptions{
		NetworkBlockAll: true,
	})
	waitRunning(t, allow)
	waitRunning(t, block)

	probe := func(sb *microvm.Sandbox, target string) string {
		return execFetch(t, sb, "/?t="+url.QueryEscape(target))
	}

	// Allow-listed sandbox → allowed host: PERMITTED (never a 403 policy denial).
	if got := probe(allow, "https://example.com/"); strings.Contains(got, "status=403") {
		t.Fatalf("allow→example.com = %q, want permitted (not a 403 policy denial)", got)
	}
	// Allow-listed sandbox → NON-allowed host: DENIED by its own allowlist.
	if got := probe(allow, "https://not-allowed.example/"); !strings.Contains(got, "status=403") {
		t.Fatalf("allow→not-allowed = %q, want status=403 (allowlist enforced)", got)
	}
	// Block-all sandbox in the SAME group → allowed host still DENIED, proving
	// the policy is attributed per sandbox, not applied group-wide.
	if got := probe(block, "https://example.com/"); !strings.Contains(got, "status=403") {
		t.Fatalf("block→example.com = %q, want status=403 (block-all)", got)
	}
}

// UC-105 — the js-bundle catalogue CRUD the isolate runtime uploads through:
// upload returns a digest, list + get surface it, delete removes it (and a
// follow-up get 404s). Owner-scoping + in-use-refusal edges are covered offline;
// this is the live round-trip.
func TestIsolateJSBundleCatalogue(t *testing.T) {
	harness.Require(t, sc, "UC-105")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Unique name so the delete at the end is unconditional (no live sandbox
	// pins it) and repeated runs don't fight over one catalogue entry.
	name := harness.UniqueName(sc, t)
	var created models.JSBundle
	if err := c.PostJSON(ctx, "/v1/js-bundles", models.CreateJSBundleRequest{
		Name:   name,
		Source: `export default { async fetch() { return new Response("catalogue"); } };`,
	}, &created); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if created.Digest == "" {
		t.Fatal("upload returned empty digest")
	}

	// List includes it.
	var list []models.JSBundle
	if err := c.GetJSON(ctx, "/v1/js-bundles", &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, b := range list {
		if b.Digest == created.Digest {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("list %d bundles, none matched digest %s", len(list), created.Digest)
	}

	// Get by digest round-trips.
	var got models.JSBundle
	if err := c.GetJSON(ctx, "/v1/js-bundles/"+created.Digest, &got); err != nil {
		t.Fatalf("get %s: %v", created.Digest, err)
	}
	if got.Digest != created.Digest {
		t.Fatalf("get digest = %s, want %s", got.Digest, created.Digest)
	}

	// Delete removes it; a follow-up get must 404.
	if err := c.Delete(ctx, "/v1/js-bundles/"+created.Digest); err != nil {
		t.Fatalf("delete %s: %v", created.Digest, err)
	}
	if err := c.GetJSON(ctx, "/v1/js-bundles/"+created.Digest, &models.JSBundle{}); err == nil {
		t.Fatalf("get after delete succeeded; want not-found for %s", created.Digest)
	}
}
