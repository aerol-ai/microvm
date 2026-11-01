package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every client that talks to the scenario's API domain must dial through the
// harness's shared API pool (harness.SharedTransport, HTTPClient,
// NewTransport). That pool is how a case that stops a node's daemon
// (KillNodeDaemon, WithNodeEnv) takes the node out of rotation, the way a
// health-checked load balancer would. A client on http.DefaultTransport keeps
// its keep-alive connection to the stopped node's Caddy and reads 502 for the
// whole outage: on cluster-3-mixed-secrets UC-135 and UC-118 polled for 8
// minutes and reported a failover that had finished in 40 seconds.
//
// So the default client and transport, bare transports, clients with no
// transport of their own and SDK configs with no client are refused
// outright, except in the functions named
// here. Each entry talks to something that is NOT the API domain, or needs the
// raw behaviour on purpose; a new entry needs the same kind of reason.
var nonAPIClients = map[string]string{
	"harness/lb_transport.go:newTransport":                                               "clones http.DefaultTransport to build the pool's own transports",
	"networking_more_test.go:reachableHTTP":                                              "a sandbox's public route, not the API domain",
	"networking_more_test.go:assertNoSandboxRoute":                                       "a sandbox's public route, not the API domain",
	"networking_more_test.go:probeStatus":                                                "a sandbox's public route, not the API domain",
	"networking_test.go:TestPreviewURLReachable":                                         "a sandbox's public route, not the API domain",
	"agent_cli_mcp_test.go:fetchEventually":                                              "a sandbox's public route, not the API domain",
	"sims/expose.go:waitHTTP200":                                                         "a sandbox's public route, not the API domain",
	"ingress_routing_test.go:TestIngressRoutingChurnGate":                                "a sandbox's public route, one new connection per request",
	"z_ingress_routing_restart_test.go:TestIngressRoutingSessionsSurviveSandboxdRestart": "the subject is a keep-alive connection surviving a restart",
	"z_identity_chaos_test.go:TestIdentityTokenSpray":                                    "one node's loopback through an SSH forward",
	"observability_test.go:TestUC106_GrafanaReachable":                                   "the observability node, not the API domain",
}

func TestAPIDomainClientsUseTheSharedPool(t *testing.T) {
	suite := filepath.Join("..", "suite")
	var files []string
	for _, pattern := range []string{"*.go", filepath.Join("sims", "*.go"), filepath.Join("harness", "*.go")} {
		m, err := filepath.Glob(filepath.Join(suite, pattern))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}

	fset := token.NewFileSet()
	var offenders []string
	inspected := 0
	seenAllowed := map[string]bool{}
	for _, path := range files {
		rel, _ := filepath.Rel(suite, path)
		rel = filepath.ToSlash(rel)
		// The harness's own unit tests build throwaway transports against
		// local test servers.
		if strings.HasPrefix(rel, "harness/") && strings.HasSuffix(rel, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		httpName := importName(f, "net/http")
		if httpName == "" {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inspected++
			key := rel + ":" + fn.Name.Name
			for _, why := range rawClientUses(fn.Body, httpName) {
				if _, ok := nonAPIClients[key]; ok {
					seenAllowed[key] = true
					continue
				}
				offenders = append(offenders, key+" ("+why+")")
			}
		}
	}
	if inspected == 0 {
		t.Fatal("no function was inspected; this guard would pass having checked nothing")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("these functions make HTTP requests outside the harness's shared API pool, so a node a case takes down stays in their rotation and they read 502 through its Caddy for the whole outage:\n  %s\nUse harness.HTTPClient, harness.SharedTransport or harness.NewTransport. If the target is not the API domain, add the function to nonAPIClients with the reason.",
			strings.Join(offenders, "\n  "))
	}
	// A stale entry would quietly allow a future function of the same name.
	for key := range nonAPIClients {
		if !seenAllowed[key] {
			t.Errorf("nonAPIClients lists %s, which no longer makes a raw request; remove the entry", key)
		}
	}
}

// importName is the local name of an import in f, or "" if f does not import it.
func importName(f *ast.File, path string) string {
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return filepath.Base(path)
	}
	return ""
}

// rawClientUses lists the ways body reaches the network without the pool:
// the default client or transport, the package-level helpers that use them,
// a bare http.Transport, and an http.Client with no Transport (which falls
// back to the default one).
func rawClientUses(body *ast.BlockStmt, httpName string) []string {
	var out []string
	isHTTP := func(e ast.Expr, names ...string) (string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != httpName {
			return "", false
		}
		for _, n := range names {
			if sel.Sel.Name == n {
				return n, true
			}
		}
		return "", false
	}
	hasField := func(lit *ast.CompositeLit, field string) bool {
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == field {
					return true
				}
			}
		}
		return false
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if name, ok := isHTTP(n, "DefaultClient", "DefaultTransport", "Get", "Post", "Head", "PostForm"); ok {
				out = append(out, "http."+name)
			}
		case *ast.CompositeLit:
			// The Go SDK falls back to its own client on the default
			// transport when the config names none.
			if sel, ok := n.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "MicroVMConfig" && !hasField(n, "HTTPClient") {
				out = append(out, "an SDK config with no HTTPClient")
				return true
			}
			name, ok := isHTTP(n.Type, "Transport", "Client")
			switch {
			case !ok:
			case name == "Transport":
				out = append(out, "a bare http.Transport")
			case !hasField(n, "Transport"):
				out = append(out, "an http.Client with no Transport")
			}
		}
		return true
	})
	return out
}
