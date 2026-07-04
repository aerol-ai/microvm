package v1

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// TestSetCreateServerTiming_FirecrackerStages is the Phase 0 regression
// (plans/firecracker-create-latency.md): fc_* stages recorded on the
// context recorder must surface as Server-Timing entries, absent stages
// must be omitted, and the pre-existing docker fields must render
// exactly as before — the UC-96 readiness assertions and the bench's
// create;dur= parser both depend on that stability.
func TestSetCreateServerTiming_FirecrackerStages(t *testing.T) {
	t.Run("fc_stages_render_in_order", func(t *testing.T) {
		_, timing := docker.WithCreateTiming(t.Context())
		timing.RecordStage("fc_verify", 1650*time.Millisecond)
		timing.RecordStage("fc_spawn", 95*time.Millisecond)
		timing.RecordStageDesc("fc_warm", 142*time.Millisecond, "hit")
		timing.RecordStage("fc_driver", 3120*time.Millisecond)

		rr := httptest.NewRecorder()
		setCreateServerTiming(rr, time.Now(), timing)
		st := rr.Header().Get("Server-Timing")

		for _, want := range []string{
			"create;dur=",
			"fc_verify;dur=1650.0",
			"fc_spawn;dur=95.0",
			"fc_warm;dur=142.0;desc=hit",
			"fc_driver;dur=3120.0",
		} {
			if !strings.Contains(st, want) {
				t.Fatalf("Server-Timing = %q, missing %q", st, want)
			}
		}
		// Stages render in record order so the header reads as the boot
		// sequence, not map-iteration noise.
		if strings.Index(st, "fc_verify") > strings.Index(st, "fc_driver") {
			t.Fatalf("Server-Timing = %q, stages out of record order", st)
		}
	})

	t.Run("absent_stages_omitted", func(t *testing.T) {
		_, timing := docker.WithCreateTiming(t.Context())
		rr := httptest.NewRecorder()
		setCreateServerTiming(rr, time.Now(), timing)
		st := rr.Header().Get("Server-Timing")
		if strings.Contains(st, "fc_") {
			t.Fatalf("Server-Timing = %q, must carry no fc_ entries when none recorded", st)
		}
		if !strings.HasPrefix(st, "create;dur=") {
			t.Fatalf("Server-Timing = %q, want the bare create;dur= header", st)
		}
	})

	t.Run("docker_fields_unchanged", func(t *testing.T) {
		_, timing := docker.WithCreateTiming(t.Context())
		timing.RecordDockerWaits(120*time.Millisecond, 88*time.Millisecond, "socket")
		timing.RecordStage("fc_driver", 300*time.Millisecond)

		rr := httptest.NewRecorder()
		setCreateServerTiming(rr, time.Now(), timing)
		st := rr.Header().Get("Server-Timing")
		for _, want := range []string{
			"runtime_wait;dur=120.0",
			"toolbox_wait;dur=88.0",
			"readiness;desc=socket",
			"fc_driver;dur=300.0",
		} {
			if !strings.Contains(st, want) {
				t.Fatalf("Server-Timing = %q, missing %q", st, want)
			}
		}
	})

	t.Run("nil_recorder_still_writes_create", func(t *testing.T) {
		rr := httptest.NewRecorder()
		setCreateServerTiming(rr, time.Now(), nil)
		if st := rr.Header().Get("Server-Timing"); !strings.HasPrefix(st, "create;dur=") {
			t.Fatalf("Server-Timing = %q, want create;dur= with nil recorder", st)
		}
	})
}

// Compile-time proof the docker alias and the neutral package share one
// type: a recorder built by either constructor is usable with both.
var _ *docker.CreateTiming = (*createtiming.CreateTiming)(nil)
