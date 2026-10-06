package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSetNetworkPolicy(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb", Image: "alpine", Status: models.SandboxStatusStarted, NetworkBlockAll: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNetworkPolicy(ctx, "sb", false, []string{"pypi.org"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "sb")
	if err != nil {
		t.Fatal(err)
	}
	if got.NetworkBlockAll || len(got.NetworkAllowOut) != 1 || got.NetworkAllowOut[0] != "pypi.org" || got.NetworkDenyOut[0] != "10.0.0.0/8" {
		t.Fatalf("stored = %+v", got)
	}
	if err := st.SetNetworkPolicy(ctx, "sb", true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, "sb"); !got.NetworkBlockAll || len(got.NetworkAllowOut) != 0 {
		t.Fatalf("replace = %+v", got)
	}
	if err := st.SetNetworkPolicy(ctx, "missing", false, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}
