package runloop

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestToolboxCallsCoverEveryCallSite parses this package and checks that
// every toolboxCall and RoundTripToolbox call site is listed in
// ToolboxCalls, so the toolboxd route inventory (plan X2) cannot miss a path
// added here later.
func TestToolboxCallsCoverEveryCallSite(t *testing.T) {
	listed := map[string]bool{}
	sampleID := regexp.MustCompile(`/(s1|c1)(/|$)`)
	for _, call := range ToolboxCalls() {
		listed[call.Method+" "+sampleID.ReplaceAllString(call.Path, "/{}$2")] = true
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// toolboxCall(ctx, devboxID, method, path, ...) and
			// RoundTripToolbox(ctx, devboxID, method, path, ...).
			if sel.Sel.Name != "toolboxCall" && sel.Sel.Name != "RoundTripToolbox" {
				return true
			}
			if len(call.Args) < 4 {
				return true
			}
			method, ok := methodName(call.Args[2])
			if !ok {
				return true // the helper's own body forwards its method parameter
			}
			path := pathPattern(call.Args[3])
			found++
			if !listed[method+" "+path] {
				t.Errorf("%s: toolbox call %s %s is not in ToolboxCalls()", fset.Position(call.Pos()), method, path)
			}
			return true
		})
	}
	if found < len(ToolboxCalls()) {
		t.Fatalf("found %d call sites, fewer than the %d listed; the scan is broken", found, len(ToolboxCalls()))
	}
}

// methodName reads http.MethodGet and friends.
func methodName(expr ast.Expr) (string, bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "http" || !strings.HasPrefix(sel.Sel.Name, "Method") {
		return "", false
	}
	return strings.ToUpper(strings.TrimPrefix(sel.Sel.Name, "Method")), true
}

// pathPattern renders a path expression with every non-literal part as {}.
func pathPattern(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		value, err := strconv.Unquote(e.Value)
		if err != nil {
			return "{}"
		}
		return value
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return pathPattern(e.X) + pathPattern(e.Y)
		}
	}
	return "{}"
}
