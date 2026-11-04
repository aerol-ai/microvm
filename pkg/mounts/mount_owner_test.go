package mounts

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// A sandbox has one mount set. A second MountAll for an ID whose mounts are
// established, or being established, is refused before it touches anything:
// it used to replace the first set's state and, on its create's rollback,
// tear the first set's storage down.
func TestMountAllRefusesAnEstablishedID(t *testing.T) {
	spec := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/data"}}
	tests := []struct {
		name  string
		setup func(m *Manager)
	}{
		{name: "mounts established", setup: func(m *Manager) {
			if _, err := m.MountAll(context.Background(), "sb-owner", spec); err != nil {
				t.Fatalf("first MountAll: %v", err)
			}
		}},
		{name: "another MountAll of the id running", setup: func(m *Manager) {
			m.mu.Lock()
			m.mounting["sb-owner"]++
			m.mu.Unlock()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: fakeAdapter{}})
			tt.setup(m)
			before := m.HostBindsFor("sb-owner")

			_, err := m.MountAll(context.Background(), "sb-owner", spec)
			if !errors.Is(err, ErrMountsEstablished) || !errors.Is(err, models.ErrSandboxExists) {
				t.Fatalf("second MountAll = %v, want ErrMountsEstablished (ErrSandboxExists)", err)
			}
			after := m.HostBindsFor("sb-owner")
			if len(after) != len(before) {
				t.Fatalf("the refused MountAll changed the holder's mounts: %d binds, want %d", len(after), len(before))
			}
			for _, b := range before {
				if _, err := os.Stat(b.HostPath); err != nil {
					t.Fatalf("the holder's mount path went: %v", err)
				}
			}
		})
	}

	// Once the holder's mounts are gone the ID can mount again.
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: fakeAdapter{}})
	if _, err := m.MountAll(context.Background(), "sb-owner", spec); err != nil {
		t.Fatal(err)
	}
	if err := m.UnmountAll("sb-owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.MountAll(context.Background(), "sb-owner", spec); err != nil {
		t.Fatalf("MountAll after UnmountAll = %v", err)
	}
}
