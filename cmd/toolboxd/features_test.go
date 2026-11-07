package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestVersionListsFeatures(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/version", nil))
	var body struct {
		Version  string   `json:"version"`
		Features []string `json:"features"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("/version = %d %s (%v)", rr.Code, rr.Body.String(), err)
	}
	// Present even when empty: an SDK tells "no such feature" from "an agent
	// too old to list features" only by the field, and fails closed on both.
	if body.Features == nil {
		t.Fatal("/version has no features field")
	}
	if !sort.StringsAreSorted(body.Features) {
		t.Fatalf("features not sorted: %v", body.Features)
	}
	if len(body.Features) != len(toolboxFeatures) {
		t.Fatalf("/version lists %v, want every key of toolboxFeatures", body.Features)
	}
}

// ET7: every request option a handler reads is either a baseline option or
// belongs to a listed feature. A new option that is not listed would be
// sent by the SDKs to an older agent, which drops it silently.
func TestEveryRequestOptionIsListed(t *testing.T) {
	known := map[string]bool{}
	for _, name := range baselineRequestOptions {
		known[name] = true
	}
	owner := map[string]string{}
	for feature, options := range toolboxFeatures {
		if len(options) == 0 {
			t.Errorf("feature %q names no option", feature)
		}
		for _, option := range options {
			if prev, ok := owner[option]; ok {
				t.Errorf("option %q belongs to both %q and %q", option, prev, feature)
			}
			owner[option] = feature
			known[option] = true
		}
	}

	for _, option := range requestOptionsInSource(t) {
		if !known[option] {
			t.Errorf("handler reads option %q, but no /version feature lists it; add it to toolboxFeatures", option)
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(models.ExecRequest{}), reflect.TypeOf(execStreamStartMsg{})} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if name != "" && name != "-" && !known[name] {
				t.Errorf("%s field %q is not listed on /version; add it to toolboxFeatures", typ.Name(), name)
			}
		}
	}
}

// requestOptionsInSource returns the string literals the package's handlers
// read as query parameters: r.URL.Query().Get("x"), query.Get("x") on a
// url.Values, and r.FormValue("x").
func requestOptionsInSource(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			isQuery := false
			switch sel.Sel.Name {
			case "FormValue":
				isQuery = true
			case "Get":
				switch x := sel.X.(type) {
				case *ast.CallExpr:
					inner, ok := x.Fun.(*ast.SelectorExpr)
					isQuery = ok && inner.Sel.Name == "Query"
				case *ast.Ident:
					isQuery = x.Name == "query" || x.Name == "q" || x.Name == "values"
				}
			}
			if !isQuery {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if value, err := strconv.Unquote(lit.Value); err == nil {
					seen[value] = true
				}
			}
			return true
		})
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("found no query options; the source scan is broken")
	}
	return out
}
