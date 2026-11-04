package service

import (
	"context"
	"errors"
	"testing"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestListSandboxesByNameFiltersAndErrors(t *testing.T) {
	ctx := context.Background()
	svc, st := newFacadeStateTestService(t)
	now := time.Now().UTC()
	row := &models.Sandbox{
		ID: "sb-by-name", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		PublicURL: "https://sb-by-name.example.test", ContainerID: "ctr", ContainerIP: "10.0.0.10",
		CPU: 1, MemoryMB: 512, DiskGB: 10, OSUser: "root", Name: "agent",
		Tags:      map[string]string{"env": "test"},
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(ctx, row); err != nil {
		t.Fatal(err)
	}

	missing, err := svc.ListSandboxesByName(ctx, "nobody", nil, GetSandboxOptions{})
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing name = %v %v", missing, err)
	}
	got, err := svc.ListSandboxesByName(ctx, "agent", map[string]string{"env": "test"}, GetSandboxOptions{})
	if err != nil || len(got) != 1 || got[0].ID != row.ID {
		t.Fatalf("matching tags = %+v %v", got, err)
	}
	filtered, err := svc.ListSandboxesByName(ctx, "agent", map[string]string{"env": "other"}, GetSandboxOptions{})
	if err != nil || len(filtered) != 0 {
		t.Fatalf("tag miss = %+v %v", filtered, err)
	}

	st.Close()
	if _, err := svc.ListSandboxesByName(ctx, "agent", nil, GetSandboxOptions{}); err == nil || errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("closed store = %v, want a lookup error", err)
	}
}
