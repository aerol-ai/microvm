package daytona

import (
	"strings"
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

func TestMetaExtraCoverage(t *testing.T) {
	t.Run("default_non_nil_sandbox", func(t *testing.T) {
		sb := &models.Sandbox{
			ID:   "sb-123",
			Name: "test-sb",
		}
		meta := defaultSandboxMeta(sb)
		if meta.Name != "test-sb" {
			t.Fatalf("unexpected name: %s", meta.Name)
		}
	})

	t.Run("from_native_nil_tags", func(t *testing.T) {
		sb := &models.Sandbox{
			ID:   "sb-123",
			Tags: nil,
		}
		meta := sandboxMetaFromNative(sb, compatBlob{})
		if meta.Labels == nil {
			t.Fatalf("expected non-nil Labels map")
		}
	})

	t.Run("from_state_nil_sandbox", func(t *testing.T) {
		state := &models.SandboxCompatState{StateJSON: `{"target":"x"}`}
		meta, err := sandboxMetaFromState(state, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Labels == nil {
			t.Fatalf("expected non-nil Labels map")
		}
	})

	t.Run("from_state_nil_state_or_empty_json", func(t *testing.T) {
		sb := &models.Sandbox{ID: "sb-123"}
		meta, err := sandboxMetaFromState(nil, sb)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta.Name != "sb-123" {
			t.Fatalf("unexpected name: %s", meta.Name)
		}

		state := &models.SandboxCompatState{StateJSON: "   "}
		meta2, err := sandboxMetaFromState(state, sb)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if meta2.Name != "sb-123" {
			t.Fatalf("unexpected name: %s", meta2.Name)
		}
	})

	t.Run("from_state_invalid_json", func(t *testing.T) {
		sb := &models.Sandbox{ID: "sb-123"}
		state := &models.SandboxCompatState{StateJSON: "{bad_json}"}
		_, err := sandboxMetaFromState(state, sb)
		if err == nil {
			t.Fatal("expected json unmarshal error")
		}
	})

	t.Run("meta_to_state_and_edge_cases", func(t *testing.T) {
		val := "val"
		archive := float32(1.5)
		meta := sandboxMeta{
			Snapshot:            &val,
			NetworkAllowList:    &val,
			AutoArchiveInterval: &archive,
		}
		stateJSON, err := sandboxMetaToState(meta)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(stateJSON, `"snapshot":"val"`) || !strings.Contains(stateJSON, `"auto_archive_interval_minutes":1.5`) {
			t.Fatalf("unexpected json: %s", stateJSON)
		}

		meta2 := sandboxMeta{
			Snapshot:            nil,
			NetworkAllowList:    nil,
			AutoArchiveInterval: nil,
		}
		stateJSON2, err := sandboxMetaToState(meta2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stateJSON2 != "{}" {
			t.Fatalf("expected empty json, got %s", stateJSON2)
		}
	})
}
