package models

import (
	"strings"
	"testing"
	"time"
)

// TestResolveDestroyAt is plan L6: a clock time becomes the age the sandbox
// has at that time, and a time in the past, a time with an age, or a time
// past the 30-day cap is refused.
func TestResolveDestroyAt(t *testing.T) {
	created := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	now := created.Add(time.Hour)
	at := func(d time.Duration) *time.Time { v := created.Add(d); return &v }
	cases := []struct {
		name    string
		in      Lifecycle
		wantAge time.Duration
		wantErr string
	}{
		{name: "no destroy_at", in: Lifecycle{StopAtAge: time.Minute}},
		{name: "future", in: Lifecycle{DestroyAt: at(3 * time.Hour)}, wantAge: 3 * time.Hour},
		{name: "future in another zone", in: Lifecycle{DestroyAt: func() *time.Time {
			v := created.Add(2 * time.Hour).In(time.FixedZone("IST", 5*3600+1800))
			return &v
		}()}, wantAge: 2 * time.Hour},
		{name: "now is not the future", in: Lifecycle{DestroyAt: at(time.Hour)}, wantErr: "not in the future"},
		{name: "past", in: Lifecycle{DestroyAt: at(30 * time.Minute)}, wantErr: "not in the future"},
		{name: "with an age too", in: Lifecycle{DestroyAt: at(3 * time.Hour), DestroyAtAge: time.Hour}, wantErr: "not both"},
		{name: "past the cap", in: Lifecycle{DestroyAt: at(MaxLifecycleDuration + time.Second)}, wantErr: "more than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := tc.in
			err := l.ResolveDestroyAt(created, now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if l.DestroyAt != nil {
				t.Fatal("destroy_at left set")
			}
			if tc.wantAge != 0 && l.DestroyAtAge != tc.wantAge {
				t.Fatalf("destroy_at_age = %s, want %s", l.DestroyAtAge, tc.wantAge)
			}
			if err := l.Validate(); err != nil {
				t.Fatalf("resolved lifecycle invalid: %v", err)
			}
		})
	}
	var nilLifecycle *Lifecycle
	if err := nilLifecycle.ResolveDestroyAt(created, now); err != nil {
		t.Fatalf("nil lifecycle: %v", err)
	}
	if err := (Lifecycle{DestroyAt: at(3 * time.Hour)}).Validate(); err == nil || !strings.Contains(err.Error(), "destroy_at") {
		t.Fatalf("Validate accepted an unconverted destroy_at: %v", err)
	}
}
