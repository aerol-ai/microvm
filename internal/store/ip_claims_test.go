package store

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSandboxIDsClaimingContainerIP(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()
	mk := func(id, ip string, status models.SandboxStatus) {
		t.Helper()
		if err := st.Upsert(ctx, &models.Sandbox{
			ID: id, Image: "img", Status: status, ContainerIP: ip,
			CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}
	mk("sb-started", "10.88.0.5", models.SandboxStatusStarted)
	mk("sb-creating", "10.88.0.6", models.SandboxStatusCreating)
	mk("sb-stopped", "10.88.0.7", models.SandboxStatusStopped)
	mk("sb-old", "10.88.0.5", models.SandboxStatusStopped)

	// A pooled netns claimed by a sandbox whose row isn't persisted yet.
	if err := st.SeedContainerNetnsSlot(ctx, "slot-1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReserveContainerNetnsSlot(ctx, "sb-fresh", now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.MarkContainerNetnsSlotRealized(ctx, "sb-fresh", "/run/netns/x", "10.88.0.8", now); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip   string
		want []string
	}{
		{"10.88.0.5", []string{"sb-started"}},
		{"10.88.0.6", []string{"sb-creating"}},
		{"10.88.0.7", nil},
		{"10.88.0.8", []string{"sb-fresh"}},
		{"10.88.0.9", nil},
		{"", nil},
	}
	for _, tc := range cases {
		got, err := st.SandboxIDsClaimingContainerIP(ctx, tc.ip)
		if err != nil {
			t.Fatalf("%s: %v", tc.ip, err)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Fatalf("claimants(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	_ = st.Close()
	if _, err := st.SandboxIDsClaimingContainerIP(ctx, "10.88.0.5"); err == nil {
		t.Fatal("want error on closed store")
	}
}
