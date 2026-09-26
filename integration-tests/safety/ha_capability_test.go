package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// harness.CreateHASandbox waits for failover_ready, which a single-node
// deployment can NEVER report: the server omits the field entirely, because
// failover.policy=recreate needs a peer. So a use case that reaches for the
// HA helper without requiring CapCluster does not skip on a single-node
// scenario — it runs, burns its entire timeout, and fails for a reason that
// has nothing to do with what it tests.
//
// UC-169 (the leak sweep, CapSecrets only) was exactly this, caught before
// the live run reached it. The rule is cheap to check statically, so it is.
func TestHASandboxHelperImpliesAClusterCapability(t *testing.T) {
	fset := token.NewFileSet()
	dir := filepath.Join("..", "suite")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	var offenders []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		// The suite is behind the `integration` build tag, so parse the file
		// directly rather than relying on the build context.
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			ucs, usesHA := scanTestBody(fn)
			if !usesHA || len(ucs) == 0 {
				continue
			}
			checked++
			// The PRIMARY claim is what Require gates on; alsoCovers ids do
			// not gate anything, so only the first one matters here.
			uc, found := harness.Lookup(ucs[0])
			if !found {
				continue // the registry-claims test reports unknown ids
			}
			if !slices.Contains(uc.Requires, harness.CapCluster) {
				offenders = append(offenders, fn.Name.Name+" ("+ucs[0]+")")
			}
		}
	}

	if checked == 0 {
		t.Fatal("no test was found calling CreateHASandbox; this guard would pass having checked nothing")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("these tests build an HA sandbox but their use case does not require CapCluster, so on a single-node scenario they will burn their timeout waiting for a failover_ready the server never sends: %s",
			strings.Join(offenders, ", "))
	}
}

// scanTestBody returns the UC ids a test claims and whether it builds an HA
// sandbox, directly or through a helper that does.
func scanTestBody(fn *ast.FuncDecl) (ucs []string, usesHA bool) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if ok {
			pkg, isIdent := sel.X.(*ast.Ident)
			if isIdent && pkg.Name == "harness" {
				switch sel.Sel.Name {
				case "CreateHASandbox":
					usesHA = true
				case "Require":
					for _, arg := range call.Args {
						if lit, isLit := arg.(*ast.BasicLit); isLit && lit.Kind == token.STRING {
							if v := strings.Trim(lit.Value, `"`); strings.HasPrefix(v, "UC-") {
								ucs = append(ucs, v)
							}
						}
					}
				}
			}
			return true
		}
		// A local helper that wraps the HA path counts too — createSecretSandbox
		// is deliberately NOT one of these, because it branches on CapCluster.
		if ident, isIdent := call.Fun.(*ast.Ident); isIdent && ident.Name == "restoreViaOwnerKill" {
			usesHA = true
		}
		return true
	})
	return ucs, usesHA
}
