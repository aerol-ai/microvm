//go:build integration

package sims

import (
	"context"
	"net/url"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const egressProbeBundle = `export default { async fetch(req) {
  const u = new URL(req.url);
  try {
    const r = await fetch(u.searchParams.get("t"));
    return new Response("status=" + r.status);
  } catch (e) {
    return new Response("throw=" + (e && e.message ? e.message : String(e)));
  }
}};`

func uploadProbeBundle(ctx *RunContext) string {
	t := ctx.T
	var created models.JSBundle
	cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ctx.Client.PostJSON(cctx, "/v1/js-bundles", models.CreateJSBundleRequest{
		Name:   harness.UniqueName(ctx.Scenario, t),
		Source: egressProbeBundle,
	}, &created); err != nil {
		t.Fatalf("upload bundle: %v", err)
	}
	if created.Name != "" {
		return created.Name
	}
	return harness.UniqueName(ctx.Scenario, t)
}

func newIsolate(ctx *RunContext, moduleRef, tenant string, opts sdktypes.CreateSandboxOptions) *microvm.Sandbox {
	t := ctx.T
	opts.Runtime = models.RuntimeIsolate
	opts.ModuleRef = moduleRef
	opts.TenantID = tenant
	if opts.Name == "" {
		opts.Name = harness.UniqueName(ctx.Scenario, t)
	}
	if opts.MemoryMB == 0 {
		opts.MemoryMB = 128
	}
	cctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := ctx.Client.SDK().Create(cctx, opts)
	if err != nil {
		t.Fatalf("create isolate: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
		defer dcancel()
		_ = ctx.Client.SDK().Destroy(dctx, sb.ID)
	})
	return sb
}

func execFetch(ctx *RunContext, sb *microvm.Sandbox, path string) string {
	ectx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := sb.ExecCommand(ectx, path)
	if err != nil {
		ctx.T.Fatalf("exec-fetch: %v", err)
	}
	return out.Stdout
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}
