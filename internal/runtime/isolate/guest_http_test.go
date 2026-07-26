package isolate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestGuestHTTPProxy(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	host := sup.hosts[0]
	host.invokeFn = func(_ context.Context, id string, r *http.Request) (*http.Response, error) {
		h := make(http.Header)
		h.Set("X-Test", id)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("fetch-" + r.URL.Path)),
			Header:     h,
		}, nil
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	if err := d.guestHTTPProxy("sb-1", 8080, rec, req); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "fetch-/api" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Test") != "sb-1" {
		t.Fatalf("header = %q", rec.Header().Get("X-Test"))
	}
}

func TestGuestHTTPProxyErrors(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	host := sup.hosts[0]

	t.Run("invoke_error", func(t *testing.T) {
		host.invokeFn = func(context.Context, string, *http.Request) (*http.Response, error) {
			return nil, errors.New("proxy invoke failed")
		}
		rec := httptest.NewRecorder()
		err := d.guestHTTPProxy("sb-1", 8080, rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if err == nil || err.Error() != "proxy invoke failed" {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unknown_sandbox", func(t *testing.T) {
		err := d.guestHTTPProxy("sb-missing", 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("group_gone", func(t *testing.T) {
		d.mu.Lock()
		rec := d.byID["sb-1"]
		rec.groupKey = "vanished"
		d.mu.Unlock()
		err := d.guestHTTPProxy("sb-1", 8080, httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		if err == nil || !strings.Contains(err.Error(), "gone") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestReloadSandbox(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{
		ModuleRef:       "a.js",
		TenantID:        "acme",
		NetworkBlockAll: false,
		NetworkAllowOut: []string{"api.example.com"},
	}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}

	// Simulate idle reap: group torn down but record retained.
	d.groupsMu.Lock()
	for k := range d.groups {
		delete(d.groups, k)
	}
	d.groupsMu.Unlock()
	d.mu.Lock()
	rec := d.byID["sb-1"]
	rec.groupKey = ""
	rec.needsReload = true
	rec.state.Status = models.SandboxStatusStopped
	d.mu.Unlock()

	if err := d.reloadSandbox(ctx, "sb-1"); err != nil {
		t.Fatalf("reloadSandbox: %v", err)
	}
	d.mu.Lock()
	rec = d.byID["sb-1"]
	d.mu.Unlock()
	if rec.groupKey == "" || rec.needsReload || rec.state.Status != models.SandboxStatusStarted {
		t.Fatalf("after reload: %+v", rec)
	}
	if len(sup.hosts[0].egress) == 0 {
		t.Fatal("egress policy not pushed on reload")
	}
}

func TestReloadSandboxErrors(t *testing.T) {
	d := New(Config{}, nil)
	if err := d.reloadSandbox(context.Background(), "sb-1"); err == nil {
		t.Fatal("unknown sandbox should error")
	}

	d2 := New(Config{GroupGranularity: GroupPerTenant, JailUID: 1000, JailGID: 1000, JailChrootBase: "/srv/jail"}, nil)
	d2.mu.Lock()
	d2.byID["sb-1"] = &sandboxRecord{
		tenantID:  "acme",
		bundleRef: "a.js",
		state:     &models.SandboxRuntimeState{SandboxID: "sb-1"},
	}
	d2.mu.Unlock()
	if err := d2.reloadSandbox(context.Background(), "sb-1"); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Fatalf("no resolver: %v", err)
	}
}

func TestEnsureLoadedNoOp(t *testing.T) {
	sup := &fakeSupervisor{}
	d := newCreateDriver(t, GroupPerTenant, sup)
	ctx := context.Background()
	if _, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := d.ensureLoaded(ctx, "sb-1"); err != nil {
		t.Fatalf("loaded sandbox: %v", err)
	}
	if err := d.ensureLoaded(ctx, "sb-missing"); err != nil {
		t.Fatalf("missing sandbox should no-op: %v", err)
	}
}
