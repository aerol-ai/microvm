package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestFailoverRecreateKeepsFirstCreatedAt: a failover recreate writes the
// sandbox's row with the time the cluster first placed it, not the recreate
// time. Age timers count from created_at and come back unchanged in the
// replicated spec, so before this a recreate moved every deadline out by the
// sandbox's age: an E2B sandbox 5h old given setTimeout(300) stores
// StopAtAge 5h5m, and after a failover it ran for 5h5m more, not 5m.
func TestFailoverRecreateKeepsFirstCreatedAt(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	fiveHoursAgo := now.Add(-5 * time.Hour).Unix()
	cases := []struct {
		name        string
		createdUnix int64         // the placement's first-create time (0: unknown)
		stopAtAge   time.Duration // the replicated lifecycle
		wantCreated time.Time     // zero: the recreate time
		wantAction  lifecycleAction
	}{
		{
			name:        "E2B timeout set at age 5h stops 5m after the recreate",
			createdUnix: fiveHoursAgo, stopAtAge: 5*time.Hour + 5*time.Minute,
			wantCreated: time.Unix(fiveHoursAgo, 0).UTC(), wantAction: lifecycleNone,
		},
		{
			name:        "a deadline that passed during the outage stops it at once",
			createdUnix: fiveHoursAgo, stopAtAge: 4 * time.Hour,
			wantCreated: time.Unix(fiveHoursAgo, 0).UTC(), wantAction: lifecycleStop,
		},
		{
			name:        "unknown first create keeps the recreate time",
			createdUnix: 0, stopAtAge: time.Hour, wantAction: lifecycleNone,
		},
		{
			// A leader clock ahead of this node's: never a created_at in the future.
			name:        "first create after this node's clock keeps the recreate time",
			createdUnix: now.Add(time.Hour).Unix(), stopAtAge: time.Hour, wantAction: lifecycleNone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const id = "sb-failover-created-at"
			svc, st, rt, fc := newFailoverWindowHarness(t, id)
			reporter := &captureReporter{}
			svc.SetUsageReporter(reporter)
			p, _ := fc.get(id)
			p.CreatedUnix = tc.createdUnix
			p.Spec.Lifecycle = &models.Lifecycle{StopAtAge: tc.stopAtAge}
			fc.put(p)

			before := time.Now().UTC()
			attempted, err := svc.RecreateSandboxReport(ctx, id, *p.Spec, cluster.PlacementSecrets{IncarnationID: p.IncarnationID}, nil, 0)
			after := time.Now().UTC()
			if err != nil || !attempted || rt.createCalls != 1 {
				t.Fatalf("RecreateSandboxReport = attempted %v, err %v, creates %d", attempted, err, rt.createCalls)
			}
			row, err := st.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantCreated.IsZero() {
				if row.CreatedAt.Before(before.Truncate(time.Second)) || row.CreatedAt.After(after) {
					t.Errorf("created_at = %s, want the recreate time (%s .. %s)", row.CreatedAt, before, after)
				}
			} else if !row.CreatedAt.Equal(tc.wantCreated) {
				t.Errorf("created_at = %s, want the first create %s", row.CreatedAt, tc.wantCreated)
			}
			if row.Lifecycle.StopAtAge != tc.stopAtAge {
				t.Errorf("StopAtAge = %s, want %s replayed unchanged", row.Lifecycle.StopAtAge, tc.stopAtAge)
			}
			if action, _ := lifecycleDecision(row, after, 0, time.Time{}); action != tc.wantAction {
				t.Errorf("lifecycle action = %v, want %v", action, tc.wantAction)
			}

			// Billing starts at the recreate, not at the first create: the
			// first window must not reach back into the outage.
			if start := svc.usageWindowStart(id, svc.reconcileFallbackWindowStart(row, after)); start.Before(before.Truncate(time.Second)) {
				t.Errorf("first usage window starts %s, want no earlier than the recreate (%s)", start, before)
			}
		})
	}
}

// TestPersistSandboxCreateKeepsCreatedAtOutsideFailover: only a failover
// recreate carries a first-create time; every other create stamps its row
// with its own time, and no usage cursor is seeded.
func TestPersistSandboxCreateKeepsCreatedAtOutsideFailover(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.SetUsageReporter(&captureReporter{})
	made := time.Now().UTC().Truncate(time.Second)
	sb := &models.Sandbox{ID: "sb-plain-create", Image: "alpine:3.20", Status: models.SandboxStatusStarted, CreatedAt: made, UpdatedAt: made, LastActiveAt: made}
	if err := svc.persistSandboxCreate(contextWithFailoverCreatedAt(ctx, time.Time{}), sb); err != nil {
		t.Fatal(err)
	}
	row, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.CreatedAt.Equal(made) {
		t.Fatalf("created_at = %s, want %s", row.CreatedAt, made)
	}
	if _, seeded := svc.usageCursor[sb.ID]; seeded {
		t.Fatal("a plain create seeded a usage cursor")
	}
	if got := failoverCreatedAtFrom(nil); !got.IsZero() { //nolint:staticcheck // nil context is the guarded case
		t.Fatalf("failoverCreatedAtFrom(nil) = %s, want zero", got)
	}
}
