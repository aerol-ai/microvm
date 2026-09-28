package service

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// recordingRouteWriter records which choke-point methods were called and
// writes nothing to Caddy.
type recordingRouteWriter struct {
	noopRouteWriter
	mu    sync.Mutex
	calls []string
}

func (r *recordingRouteWriter) rec(m string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, m)
}

func (r *recordingRouteWriter) seen() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]bool{}
	for _, c := range r.calls {
		out[c] = true
	}
	return out
}

func (r *recordingRouteWriter) UpsertSandboxRoute(context.Context, string, string, int, []caddy.CustomHostnameRoute) error {
	r.rec("UpsertSandboxRoute")
	return nil
}
func (r *recordingRouteWriter) DeleteSandboxRoute(context.Context, string) error {
	r.rec("DeleteSandboxRoute")
	return nil
}
func (r *recordingRouteWriter) UpsertPortRoute(context.Context, string, string, int, ...caddy.HTTPRouteOptions) error {
	r.rec("UpsertPortRoute")
	return nil
}
func (r *recordingRouteWriter) UpsertPortRouteWithRetry(context.Context, string, string, int, time.Duration, ...caddy.HTTPRouteOptions) error {
	r.rec("UpsertPortRoute")
	return nil
}
func (r *recordingRouteWriter) UpsertPortRouteWithDial(context.Context, string, int, string, ...caddy.HTTPRouteOptions) error {
	r.rec("UpsertPortRoute")
	return nil
}
func (r *recordingRouteWriter) DeletePortRoute(context.Context, string, int) error {
	r.rec("DeletePortRoute")
	return nil
}

// adminWriteCounter is a fake Caddy admin API that counts config-MUTATING
// requests: each one is a full-config reload in real Caddy. Reads are served
// so bootstrap probes still work.
type adminWriteCounter struct {
	mu     sync.Mutex
	writes []string
}

func (a *adminWriteCounter) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			a.mu.Lock()
			a.writes = append(a.writes, r.Method+" "+r.URL.Path)
			a.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("null"))
	})
}

func (a *adminWriteCounter) snapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := append([]string(nil), a.writes...)
	sort.Strings(out)
	return out
}

func newPublicRouteHarness(t *testing.T) (*Service, *adminWriteCounter) {
	t.Helper()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.probeContainerPortFn = func(context.Context, string, int) error { return nil }
	admin := &adminWriteCounter{}
	server := httptest.NewServer(admin.handler())
	t.Cleanup(server.Close)
	svc.cfg.EnableCaddy = true
	svc.cfg.CaddyAdminURL = server.URL
	svc.cfg.CaddyServerID = "srv0"
	svc.cfg.Domain = "sandbox.test"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0",
		Domain: "sandbox.test", HTTPClientTimeout: time.Second,
	})
	return svc, admin
}

// driveLifecycle runs the per-sandbox paths that used to write Caddy routes:
// a public create, an HTTP expose, an unexpose, a stop, a start and a destroy.
func driveLifecycle(t *testing.T, svc *Service) {
	t.Helper()
	ctx := context.Background()
	allow := true
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", AllowPublicTraffic: &allow})
	if err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if _, err := svc.ExposePort(ctx, resp.ID, 8080, "http"); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if err := svc.UnexposePort(ctx, resp.ID, 8080); err != nil {
		t.Fatalf("UnexposePort: %v", err)
	}
	if _, err := svc.StopSandbox(ctx, resp.ID); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	if _, err := svc.StartSandbox(ctx, resp.ID); err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if err := svc.DestroySandbox(ctx, resp.ID); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
}

func TestPublicRoutesDefaultsToTheCaddyClient(t *testing.T) {
	svc := &Service{caddy: caddy.New(config.Config{})}
	if got, ok := svc.publicRoutes().(*caddy.Client); !ok || got != svc.caddy {
		t.Fatalf("publicRoutes() = %T, want the concrete caddy client with no writer installed", svc.publicRoutes())
	}
	w := noopRouteWriter{}
	svc.routeWriter = w
	if svc.publicRoutes() != publicRouteWriter(w) {
		t.Fatal("publicRoutes() ignored the installed writer")
	}
}

// Without a writer the lifecycle still writes Caddy as before, so this
// refactor changes nothing by itself. The zero-writes test below would pass
// trivially if these paths had stopped writing for some other reason.
func TestLifecycleWritesCaddyWithoutAWriterInstalled(t *testing.T) {
	svc, admin := newPublicRouteHarness(t)
	driveLifecycle(t, svc)
	if len(admin.snapshot()) == 0 {
		t.Fatal("no Caddy admin writes across a public lifecycle: harness no longer exercises the route paths")
	}
}

// The 4A guarantee: with a no-op writer installed, a full public lifecycle
// makes ZERO config-mutating Caddy admin calls, so no reloads. Every write
// has to go through publicRoutes(); one call site still on s.caddy fails
// this test.
func TestNoopRouteWriterMakesZeroCaddyWritesAcrossTheLifecycle(t *testing.T) {
	svc, admin := newPublicRouteHarness(t)
	svc.routeWriter = noopRouteWriter{}
	driveLifecycle(t, svc)
	if got := admin.snapshot(); len(got) != 0 {
		t.Fatalf("Caddy admin writes with the no-op route writer (each is a full reload): %v", got)
	}
}

// Writes reach the installed writer: the seam is really on the path.
func TestLifecycleRoutesWritesThroughTheInstalledWriter(t *testing.T) {
	svc, admin := newPublicRouteHarness(t)
	rec := &recordingRouteWriter{}
	svc.routeWriter = rec
	driveLifecycle(t, svc)
	seen := rec.seen()
	for _, want := range []string{"UpsertSandboxRoute", "UpsertPortRoute", "DeletePortRoute", "DeleteSandboxRoute"} {
		if !seen[want] {
			t.Errorf("writer never saw %s; calls=%v", want, rec.calls)
		}
	}
	if got := admin.snapshot(); len(got) != 0 {
		t.Fatalf("writes bypassed the installed writer and hit Caddy: %v", got)
	}
}

// TestNoDirectCaddyRouteWrites is the structural half of 4A: no non-test file
// in this package may call a publicRouteWriter method on s.caddy directly.
// The lifecycle tests above can only reach some of the call sites; this
// check covers all of them, including future ones. The method set comes from
// the interface via reflection, so it cannot drift from the interface.
func TestNoDirectCaddyRouteWrites(t *testing.T) {
	iface := reflect.TypeOf((*publicRouteWriter)(nil)).Elem()
	writes := map[string]bool{}
	for i := 0; i < iface.NumMethod(); i++ {
		writes[iface.Method(i).Name] = true
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !writes[method.Sel.Name] {
				return true
			}
			recv, ok := method.X.(*ast.SelectorExpr) // s.caddy
			if !ok || recv.Sel.Name != "caddy" {
				return true
			}
			offenders = append(offenders, fmt.Sprintf("%s: %s.caddy.%s", fset.Position(call.Pos()), exprName(recv.X), method.Sel.Name))
			return true
		})
	}
	if len(offenders) > 0 {
		t.Fatalf("per-sandbox route writes bypass publicRoutes() (each is a full Caddy reload):\n%s", strings.Join(offenders, "\n"))
	}
}

func exprName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

// Every noopRouteWriter method returns nil and touches nothing. The methods
// are called by reflection over the interface, so a method added to
// publicRouteWriter is covered automatically.
func TestNoopRouteWriterEveryMethodIsANilNoop(t *testing.T) {
	iface := reflect.TypeOf((*publicRouteWriter)(nil)).Elem()
	w := reflect.ValueOf(noopRouteWriter{})
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		m := w.MethodByName(name)
		mt := m.Type()
		args := make([]reflect.Value, mt.NumIn())
		for j := 0; j < mt.NumIn(); j++ {
			in := mt.In(j)
			if mt.IsVariadic() && j == mt.NumIn()-1 {
				args[j] = reflect.MakeSlice(in, 0, 0)
				continue
			}
			if in.String() == "context.Context" {
				args[j] = reflect.ValueOf(context.Background())
				continue
			}
			args[j] = reflect.Zero(in)
		}
		var out []reflect.Value
		if mt.IsVariadic() {
			out = m.CallSlice(args)
		} else {
			out = m.Call(args)
		}
		if len(out) != 1 || !out[0].IsNil() {
			t.Errorf("noopRouteWriter.%s returned %v, want nil error", name, out)
		}
	}
}
