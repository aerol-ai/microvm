package isolate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

type errResolver struct{ err error }

func (e errResolver) Resolve(ctx context.Context, tenant, ref string) (*jsbundle.Bundle, error) {
	return nil, e.err
}

func TestCreateErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("missing_module_ref", func(t *testing.T) {
		d := newCreateDriver(t, GroupPerTenant, &fakeSupervisor{})
		_, err := d.Create(ctx, models.CreateSandboxRequest{TenantID: "acme"}, "sb-1", "", nil)
		if err == nil || !strings.Contains(err.Error(), "module_ref") {
			t.Fatalf("Create = %v", err)
		}
	})

	t.Run("resolve_error", func(t *testing.T) {
		d := New(Config{JailUID: 1000, JailGID: 1000, JailChrootBase: "/srv/jail"}, nil)
		d.SetBundleResolver(errResolver{err: errors.New("resolve boom")})
		d.SetHostSupervisor(&fakeSupervisor{})
		_, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil)
		if err == nil || !strings.Contains(err.Error(), "resolve boom") {
			t.Fatalf("Create = %v", err)
		}
	})

	t.Run("spawn_error", func(t *testing.T) {
		d := newCreateDriver(t, GroupPerTenant, &fakeSupervisor{spawnErr: errors.New("spawn boom")})
		_, err := d.Create(ctx, models.CreateSandboxRequest{ModuleRef: "a.js", TenantID: "acme"}, "sb-1", "", nil)
		if err == nil || !strings.Contains(err.Error(), "spawn boom") {
			t.Fatalf("Create = %v", err)
		}
	})

	t.Run("egress_policy_on_create", func(t *testing.T) {
		sup := &fakeSupervisor{}
		d := newCreateDriver(t, GroupPerTenant, sup)
		_, err := d.Create(ctx, models.CreateSandboxRequest{
			ModuleRef:       "a.js",
			TenantID:        "acme",
			NetworkAllowOut: []string{"api.example.com"},
		}, "sb-1", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := sup.hosts[0].egress["sb-1"]; !ok {
			t.Fatal("egress policy not set on create")
		}
	})
}
