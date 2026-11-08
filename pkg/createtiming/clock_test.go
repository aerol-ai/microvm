package createtiming

import (
	"context"
	"testing"
	"time"
)

// A Clock's marks are back to back: each covers the time since the one
// before, so a run of marks adds up to the time the run took.
func TestClockMarksAreBackToBack(t *testing.T) {
	ctx, timing := With(context.Background())
	start := time.Now()
	clock := StartClock(ctx)
	time.Sleep(15 * time.Millisecond)
	clock.Mark("first")
	time.Sleep(15 * time.Millisecond)
	clock.Mark("second")
	elapsed := time.Since(start)

	stages := timing.Stages()
	if len(stages) != 2 || stages[0].Name != "first" || stages[1].Name != "second" {
		t.Fatalf("stages = %+v, want first then second", stages)
	}
	for _, st := range stages {
		if st.DurMS < 15 {
			t.Fatalf("%s = %.1f ms, want at least the 15 ms slept before it", st.Name, st.DurMS)
		}
	}
	if sum := stages[0].DurMS + stages[1].DurMS; sum > float64(elapsed.Microseconds())/1000+0.1 {
		t.Fatalf("marks add up to %.1f ms, more than the %v the run took: they overlap", sum, elapsed)
	}
}

// With no recorder on the context there is nothing to time: StartClock
// returns nil and a nil Clock's Mark does nothing.
func TestClockWithoutRecorderIsNil(t *testing.T) {
	clock := StartClock(context.Background())
	if clock != nil {
		t.Fatalf("StartClock without a recorder = %+v, want nil", clock)
	}
	clock.Mark("ignored") // must not panic
}

func TestFormatStage(t *testing.T) {
	cases := []struct {
		st   Stage
		want string
	}{
		{Stage{Name: "containerd_spec", DurMS: 6.04}, "containerd_spec;dur=6.0"},
		{Stage{Name: "containerd_netns", DurMS: 31.25, Desc: "miss"}, "containerd_netns;dur=31.2;desc=miss"},
		{Stage{Name: "cluster_reserve", DurMS: 0}, "cluster_reserve;dur=0.0"},
	}
	for _, tc := range cases {
		if got := FormatStage(tc.st); got != tc.want {
			t.Errorf("FormatStage(%+v) = %q, want %q", tc.st, got, tc.want)
		}
	}
}
