package createtiming

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWith_ReusesExistingRecorder(t *testing.T) {
	ctx, first := With(context.Background())
	ctx2, second := With(ctx)
	if first != second {
		t.Fatal("nested With must reuse the existing recorder, not shadow it")
	}
	if ctx2 != ctx {
		t.Fatal("nested With must return the same context when a recorder exists")
	}
}

func TestWith_NilParent(t *testing.T) {
	ctx, timing := With(nil) //nolint:staticcheck // nil-parent tolerance is the contract under test
	if timing == nil || From(ctx) != timing {
		t.Fatal("With(nil) must still produce a usable recorder")
	}
}

func TestFrom_AbsentAndNil(t *testing.T) {
	if From(context.Background()) != nil {
		t.Fatal("From on a bare context must return nil")
	}
	if From(nil) != nil { //nolint:staticcheck // nil-ctx tolerance is the contract under test
		t.Fatal("From(nil) must return nil")
	}
}

func TestRecordStage_OrderClampAndCopy(t *testing.T) {
	timing := &CreateTiming{}
	timing.RecordStage("fc_verify", 1500*time.Millisecond)
	timing.RecordStage("fc_spawn", -5*time.Millisecond) // clock skew clamps to 0
	timing.RecordStage("", time.Second)                 // nameless: dropped
	timing.RecordStageDesc("fc_warm", 42*time.Millisecond, "hit")

	stages := timing.Stages()
	if len(stages) != 3 {
		t.Fatalf("Stages() len = %d, want 3 (nameless dropped): %v", len(stages), stages)
	}
	if stages[0].Name != "fc_verify" || stages[0].DurMS != 1500 {
		t.Errorf("stages[0] = %+v, want fc_verify 1500ms", stages[0])
	}
	if stages[1].Name != "fc_spawn" || stages[1].DurMS != 0 {
		t.Errorf("stages[1] = %+v, want fc_spawn clamped to 0", stages[1])
	}
	if stages[2].Name != "fc_warm" || stages[2].Desc != "hit" || stages[2].DurMS != 42 {
		t.Errorf("stages[2] = %+v, want fc_warm 42ms desc=hit", stages[2])
	}

	// Stages returns a copy: mutating it must not corrupt the recorder.
	stages[0].Name = "mutated"
	if timing.Stages()[0].Name != "fc_verify" {
		t.Fatal("Stages() must return a copy, not the backing slice")
	}
}

func TestRecordDockerWaits(t *testing.T) {
	timing := &CreateTiming{}
	timing.RecordDockerWaits(120*time.Millisecond, 88*time.Millisecond, "socket")
	if timing.RuntimeWaitMS != 120 || timing.ToolboxWaitMS != 88 || timing.Source != "socket" {
		t.Fatalf("docker waits = %+v, want 120/88/socket", timing)
	}
}

func TestNilRecorderIsSafe(t *testing.T) {
	var timing *CreateTiming
	timing.RecordStage("fc_driver", time.Second)
	timing.RecordStageDesc("fc_warm", time.Second, "hit")
	timing.RecordDockerWaits(time.Second, time.Second, "socket")
	if got := timing.Stages(); got != nil {
		t.Fatalf("nil recorder Stages() = %v, want nil", got)
	}
}

// TestConcurrentRecording: the async tcp-probe goroutine may record a
// late stage while the handler reads — no torn reads or data races
// (run under -race in CI).
func TestConcurrentRecording(t *testing.T) {
	timing := &CreateTiming{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			timing.RecordStage("fc_stage", time.Millisecond)
			_ = timing.Stages()
		}()
	}
	wg.Wait()
	if got := len(timing.Stages()); got != 8 {
		t.Fatalf("recorded %d stages, want 8", got)
	}
}
