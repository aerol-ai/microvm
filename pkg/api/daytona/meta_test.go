package daytona

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDefaultSandboxMetaAndCloneMeta(t *testing.T) {
	t.Run("default_nil_sandbox", func(t *testing.T) {
		meta := defaultSandboxMeta(nil)
		if meta.Labels == nil {
			t.Fatalf("Labels should be initialized")
		}
		if len(meta.Labels) != 0 {
			t.Fatalf("Labels should be empty, got %+v", meta.Labels)
		}
	})

	t.Run("from_native_and_clone_are_independent", func(t *testing.T) {
		stop := 5 * time.Minute
		destroy := 10 * time.Minute
		snapshot := "snap-1"
		netAllow := "github.com"
		archive := float32(30)

		meta := sandboxMetaFromNative(&models.Sandbox{
			ID:     "sb-1",
			Name:   "sandbox-1",
			OSUser: "ubuntu",
			Tags:   map[string]string{"env": "dev"},
			Lifecycle: models.Lifecycle{
				StopIfIdleFor:    stop,
				DestroyIfIdleFor: destroy,
			},
		}, compatBlob{
			Snapshot:            snapshot,
			Target:              "project",
			NetworkAllowList:    netAllow,
			AutoArchiveInterval: archive,
		})
		if meta.Name != "sandbox-1" || meta.User != "ubuntu" {
			t.Fatalf("unexpected meta basics: %+v", meta)
		}
		if meta.Snapshot == nil || *meta.Snapshot != snapshot {
			t.Fatalf("unexpected snapshot: %+v", meta.Snapshot)
		}
		if meta.NetworkAllowList == nil || *meta.NetworkAllowList != netAllow {
			t.Fatalf("unexpected network allow list: %+v", meta.NetworkAllowList)
		}

		cloned := cloneMeta(meta)
		cloned.Labels["env"] = "prod"
		if meta.Labels["env"] != "dev" {
			t.Fatalf("clone mutated original labels: %+v", meta.Labels)
		}

		if cloned.AutoStopInterval == nil || *cloned.AutoStopInterval <= 0 {
			t.Fatalf("expected auto stop interval")
		}
		if cloned.AutoDeleteInterval == nil || *cloned.AutoDeleteInterval <= 0 {
			t.Fatalf("expected auto delete interval")
		}
		if cloned.AutoArchiveInterval == nil || *cloned.AutoArchiveInterval != archive {
			t.Fatalf("expected auto archive interval")
		}
	})
}
