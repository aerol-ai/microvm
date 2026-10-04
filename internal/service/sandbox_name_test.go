package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateSandboxRejectsReservedNames(t *testing.T) {
	for _, name := range []string{"owner:abc/agent", "sb-0123456789abcdef"} {
		t.Run(name, func(t *testing.T) {
			rt := &recordingRuntime{}
			svc, _, _ := newServiceRuntimeHarness(t, rt)
			_, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Name: name})
			if !errors.Is(err, models.ErrInvalidSandboxName) {
				t.Fatalf("CreateSandbox(name=%q) error = %v, want ErrInvalidSandboxName", name, err)
			}
			if rt.createCalls != 0 {
				t.Fatalf("runtime create ran %d times for a rejected name", rt.createCalls)
			}
		})
	}
}

// TestRecreateSandboxDecodesOwnerQualifiedName pins the D9 decode choke
// point: the replicated spec carries the owner-qualified name key, and the
// failover recreate writes the user's name to the local store. A legacy name
// that already started with "owner:" is replayed as-is rather than rejected.
func TestRecreateSandboxDecodesOwnerQualifiedName(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	for id, tc := range map[string]struct{ specName, want string }{
		"sb-recreate-qualified": {specName: cluster.QualifiedSandboxName("acct-a", "agent"), want: "agent"},
		"sb-recreate-legacy":    {specName: "owner:legacy", want: "owner:legacy"},
		"sb-recreate-operator":  {specName: "ops-agent", want: "ops-agent"},
	} {
		if err := svc.RecreateSandbox(ctx, id, models.CreateSandboxRequest{Image: "alpine:3.20", Name: tc.specName}, cluster.PlacementSecrets{}, nil); err != nil {
			t.Fatalf("RecreateSandbox(%s) error = %v", id, err)
		}
		stored, err := st.Get(ctx, id)
		if err != nil {
			t.Fatalf("store.Get(%s): %v", id, err)
		}
		if stored.Name != tc.want {
			t.Fatalf("recreated %s name = %q, want %q", id, stored.Name, tc.want)
		}
	}
}

// TestResolveSandboxIDByNameIsOwnerScoped pins the scoping rule shared by the
// Daytona facade and the v1 ?name= lookup: a user token resolves names in its
// own account, operator and internal callers in the "" namespace, and another
// owner's name reads as not found.
func TestResolveSandboxIDByNameIsOwnerScoped(t *testing.T) {
	ctx := context.Background()
	svc, st := newFacadeStateTestService(t)
	now := time.Now().UTC()
	for id, ownerRef := range map[string]string{"sb-name-a": "acct-a", "sb-name-b": "acct-b", "sb-name-op": ""} {
		if err := st.Create(ctx, &models.Sandbox{
			ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
			PublicURL: "https://" + id + ".example.test", ContainerID: "ctr-" + id, ContainerIP: "10.0.0.10",
			CPU: 1, MemoryMB: 512, DiskGB: 10, OSUser: "root", Name: "agent", OwnerRef: ownerRef,
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	tenant := func(ownerRef string) context.Context {
		return controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{OwnerRef: ownerRef}})
	}
	tests := []struct {
		name    string
		ctx     context.Context
		want    string
		wantErr error
	}{
		{name: "tenant a", ctx: tenant("acct-a"), want: "sb-name-a"},
		{name: "tenant b", ctx: tenant("acct-b"), want: "sb-name-b"},
		{name: "operator", ctx: controlplane.ContextWithAccess(ctx, controlplane.Access{Operator: true}), want: "sb-name-op"},
		{name: "internal caller", ctx: ctx, want: "sb-name-op"},
		{name: "tenant without the name", ctx: tenant("acct-c"), wantErr: storepkg.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := svc.ResolveSandboxIDByName(tt.ctx, "agent")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ResolveSandboxIDByName = (%q, %v), want %q", got, err, tt.want)
			}
		})
	}
}
