package service

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// scopeUse is one reviewed function that asks ownerScope or hostCapable, and
// how many times.
type scopeUse struct {
	calls int
	why   string
}

// Why classes for reviewedOwnerScopeUses.
const (
	whyVisibility = "visibility: which owners the caller sees or writes; fleet scope answers it"
	whyNamespace  = "namespace: the owner a create, name or catalogue row lives under"
	whyHelper     = "owner_scope.go helper: the one place Access is interpreted"
)

// reviewedOwnerScopeUses lists every function in this package that calls
// ownerScope, with the number of calls. ownerScope answers WHICH OWNERS a
// caller sees (eng review D3): a runner bound to every team is unscoped
// there. A check that gates a host or trust power (raw host mounts, host
// file reads, skipping a proof) must ask hostCapable instead, so a new
// ownerScope use fails this test until a reviewer has classified it.
var reviewedOwnerScopeUses = map[string]scopeUse{
	"ownerScope":                               {0, whyHelper},
	"enforceOwner":                             {1, whyHelper},
	"snapshotVisible":                          {1, whyHelper},
	"snapshotResolvableForCreate":              {1, whyHelper},
	"ownerRefForCreate":                        {1, whyHelper},
	"filterByOwnerScope":                       {1, whyHelper},
	"Service.AuthorizeSandboxAuditAccess":      {1, whyVisibility + ": unscoped callers still need an existence proof"},
	"Service.GetDeletedSandboxView":            {1, whyVisibility},
	"Service.PutEgressProfile":                 {1, whyNamespace},
	"Service.GetEgressProfile":                 {1, whyNamespace},
	"Service.DeleteEgressProfile":              {1, whyNamespace},
	"Service.ListEgressProfiles":               {1, whyNamespace},
	"Service.ListCompatState":                  {1, whyVisibility},
	"Service.UpsertSnapshotAlias":              {1, whyVisibility + " (eng review D7: stays on fleet visibility)"},
	"Service.ListSnapshotAliases":              {1, whyVisibility},
	"Service.DeleteSnapshotAlias":              {1, whyVisibility},
	"Service.requireVisibleSnapshot":           {1, whyVisibility + " (eng review D7: stays on fleet visibility)"},
	"Service.BuildImage":                       {1, whyVisibility + ": a tenant may not build FROM another tenant's image"},
	"Service.resolveSnapshotChain":             {1, whyVisibility},
	"Service.NormalizeCreateImageDistribution": {1, whyVisibility},
	"Service.createIsolateSandbox":             {1, whyVisibility + ": a digest ref must be a bundle the caller owns"},
	"Service.GetJSBundle":                      {1, whyVisibility},
	"Service.DeleteJSBundle":                   {2, whyVisibility},
	"Service.createSandbox":                    {1, whyVisibility + ": a tenant re-checks registry access on a cache hit"},
	"Service.loadEnv":                          {1, whyVisibility},
	"Service.RegisterSnapshot":                 {1, whyVisibility + ": a tenant may only name images it may use"},
	"Service.authorizeIsolateTenantID":         {1, whyNamespace + ": a fleet caller creates for every team, so it may pick any team's isolate group"},
	"Service.ListSnapshots":                    {1, whyVisibility},
	"Service.ListSnapshotPage":                 {1, whyVisibility},
	"Service.CountSnapshots":                   {1, whyVisibility},
	"wasmModuleVisible":                        {1, whyVisibility},
}

// reviewedHostCapableUses lists every function that asks hostCapable: the
// four operator-only gates of eng review D3/D7 and nothing else.
var reviewedHostCapableUses = map[string]scopeUse{
	"hostCapable":                          {0, "the predicate"},
	"Service.validateCreateMounts":         {1, "raw host-side mounts"},
	"Service.createIsolateSandbox":         {1, "file:// bundle refs read off the host"},
	"Service.persistCustomDomainsOnCreate": {1, "custom domains on create without a DNS proof"},
	"customDomainProofToken":               {1, "the owner-less legacy DNS proof on attach"},
}

// reviewedFleetReads lists every function that reads Access.Fleet directly
// instead of going through ownerScope. Fleet is scope, never power.
var reviewedFleetReads = map[string]scopeUse{
	"ownerScope":        {1, whyHelper},
	"callerFromContext": {1, whyNamespace + ": a fleet caller's volumes live where its owner-\"\" sandboxes mount them"},
}

// TestOwnerScopeCallSitesAreReviewed is the eng review D3 call-site test.
func TestOwnerScopeCallSitesAreReviewed(t *testing.T) {
	ownerScopeUses, hostCapableUses, fleetReads := scanScopeCalls(t)
	diffUses(t, "ownerScope", ownerScopeUses, reviewedOwnerScopeUses,
		"if it gates a host or trust power, use hostCapable(ctx); if it decides which owners the caller sees, add it to reviewedOwnerScopeUses with the reason")
	diffUses(t, "hostCapable", hostCapableUses, reviewedHostCapableUses,
		"hostCapable guards exactly the four D3 host powers; a new one needs the plan's sign-off and a row in reviewedHostCapableUses and TestHostCapableGates")
	diffUses(t, "Access.Fleet", fleetReads, reviewedFleetReads,
		"go through ownerScope for scope and hostCapable for host powers instead of reading Fleet")
}

// scanScopeCalls counts ownerScope(...) and hostCapable(...) calls, and
// .Fleet reads, per enclosing function across the package's non-test files.
func scanScopeCalls(t *testing.T) (ownerScopeUses, hostCapableUses, fleetReads map[string]int) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	ownerScopeUses, hostCapableUses, fleetReads = map[string]int{}, map[string]int{}, map[string]int{}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				key = receiverName(fn.Recv.List[0].Type) + "." + key
			}
			ownerScopeUses[key] += 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Fleet" {
					fleetReads[key]++
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := call.Fun.(*ast.Ident); ok {
					switch ident.Name {
					case "ownerScope":
						ownerScopeUses[key]++
					case "hostCapable":
						hostCapableUses[key]++
					}
				}
				return true
			})
			if ownerScopeUses[key] == 0 {
				delete(ownerScopeUses, key)
			}
		}
	}
	// The predicates themselves are declared, not called, in their bodies.
	ownerScopeUses["ownerScope"] += 0
	hostCapableUses["hostCapable"] += 0
	return ownerScopeUses, hostCapableUses, fleetReads
}

func receiverName(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.StarExpr:
		return receiverName(v.X)
	case *ast.Ident:
		return v.Name
	}
	return "?"
}

func diffUses(t *testing.T, what string, got map[string]int, reviewed map[string]scopeUse, advice string) {
	t.Helper()
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	for k := range reviewed {
		if _, ok := got[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		n, present := got[k]
		r, ok := reviewed[k]
		switch {
		case !ok:
			t.Errorf("unreviewed %s use in %s (%d call(s)): %s", what, k, n, advice)
		case !present:
			t.Errorf("%s no longer calls %s; drop it from the reviewed list", k, what)
		case n != r.calls:
			t.Errorf("%s calls %s %d time(s), reviewed for %d (%s): %s", k, what, n, r.calls, r.why, advice)
		}
	}
}
