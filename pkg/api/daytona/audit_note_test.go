package daytona

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestResolveByNameNamesTheSandboxInTheRecord: a Daytona call addressed by
// sandbox name tells the api record the resolved id, so the record lands in
// that sandbox's own audit history (plans/identity-and-access.md §5.9). A
// call addressed by id needs no note: the path already carries it.
func TestResolveByNameNamesTheSandboxInTheRecord(t *testing.T) {
	env := newDaytonaContractEnv(t)
	now := time.Now().UTC()
	if err := env.store.Create(context.Background(), &models.Sandbox{
		ID: "sb-named", Name: "agent-box", Image: "alpine", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	ctx, st := auditlog.ContextWithCallState(context.Background())
	if _, id, err := h.resolveSandbox(ctx, "agent-box"); err != nil || id != "sb-named" {
		t.Fatalf("resolve by name = %q, %v", id, err)
	}
	if st.SandboxID() != "sb-named" {
		t.Fatalf("record names %q, want the resolved id", st.SandboxID())
	}

	ctx, st = auditlog.ContextWithCallState(context.Background())
	if _, _, err := h.resolveSandbox(ctx, "sb-named"); err != nil {
		t.Fatal(err)
	}
	if st.SandboxID() != "" {
		t.Fatalf("a call by id noted %q; the path already names it", st.SandboxID())
	}
}
