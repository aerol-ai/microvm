package models

import (
	"strings"
	"testing"
	"time"
)

func TestLifecycleValidate(t *testing.T) {
	cases := []struct {
		name    string
		l       Lifecycle
		wantErr string
	}{
		{
			name: "all_zero_is_valid",
			l:    Lifecycle{},
		},
		{
			name: "single_field_set_is_valid",
			l:    Lifecycle{StopIfIdleFor: time.Hour},
		},
		{
			name: "all_four_set_consistently_is_valid",
			l: Lifecycle{
				StopIfIdleFor:    time.Hour,
				DestroyIfIdleFor: 4 * time.Hour,
				StopAtAge:        2 * time.Hour,
				DestroyAtAge:     24 * time.Hour,
			},
		},
		{
			name:    "negative_stop_if_idle_rejected",
			l:       Lifecycle{StopIfIdleFor: -time.Second},
			wantErr: "non-negative",
		},
		{
			name:    "negative_destroy_at_age_rejected",
			l:       Lifecycle{DestroyAtAge: -time.Second},
			wantErr: "non-negative",
		},
		{
			name:    "exceeds_max_rejected",
			l:       Lifecycle{StopAtAge: MaxLifecycleDuration + time.Second},
			wantErr: "exceeds maximum",
		},
		{
			name: "destroy_idle_smaller_than_stop_idle_rejected",
			l: Lifecycle{
				StopIfIdleFor:    2 * time.Hour,
				DestroyIfIdleFor: time.Hour,
			},
			wantErr: "destroy_if_idle_for must be >=",
		},
		{
			name: "destroy_age_smaller_than_stop_age_rejected",
			l: Lifecycle{
				StopAtAge:    2 * time.Hour,
				DestroyAtAge: time.Hour,
			},
			wantErr: "destroy_at_age must be >=",
		},
		{
			name: "stop_idle_alone_no_constraint",
			l:    Lifecycle{StopIfIdleFor: 2 * time.Hour},
		},
		{
			name: "destroy_idle_alone_no_constraint",
			l:    Lifecycle{DestroyIfIdleFor: time.Hour},
		},
		{
			// Serverless requires an explicit idle timer — we reject
			// rather than substitute a default so callers can't get
			// surprised by an invisible policy choice.
			name:    "serverless_without_idle_timer_rejected",
			l:       Lifecycle{Serverless: true},
			wantErr: "serverless requires stop_if_idle_for",
		},
		{
			name: "serverless_with_idle_timer_is_valid",
			l: Lifecycle{
				Serverless:    true,
				StopIfIdleFor: 5 * time.Minute,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.l.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestLifecycleIsZero(t *testing.T) {
	if !(Lifecycle{}).IsZero() {
		t.Fatal("zero Lifecycle should be IsZero()")
	}
	if (Lifecycle{StopIfIdleFor: time.Second}).IsZero() {
		t.Fatal("Lifecycle with one field set should not be IsZero()")
	}
	if (Lifecycle{DestroyAtAge: time.Second}).IsZero() {
		t.Fatal("Lifecycle with DestroyAtAge set should not be IsZero()")
	}
	// Serverless flag must keep the lifecycle live for the sweep so the
	// sweep does not skip lifecycle inspection on a serverless sandbox.
	if (Lifecycle{Serverless: true}).IsZero() {
		t.Fatal("Lifecycle with Serverless=true should not be IsZero()")
	}
}

func TestLifecycleValidateWithBypassFloor(t *testing.T) {
	poll := 15 * time.Second
	reconcile := 30 * time.Second
	floor := 2*poll + reconcile // 60s

	cases := []struct {
		name      string
		lifecycle Lifecycle
		wantErr   string // substring; empty means must succeed
	}{
		{
			// Non-serverless lifecycles bypass the floor entirely — they
			// still bump LastActiveAt through sandboxd, so the netstats
			// dependency does not apply.
			name:      "non_serverless_below_floor_passes",
			lifecycle: Lifecycle{StopIfIdleFor: time.Second},
		},
		{
			// Validate already requires Serverless lifecycles to set
			// StopIfIdleFor; we surface that upstream error rather than
			// silently passing the floor check.
			name:      "serverless_no_idle_timer_fails_validate",
			lifecycle: Lifecycle{Serverless: true},
			wantErr:   "stop_if_idle_for",
		},
		{
			name:      "serverless_above_floor_passes",
			lifecycle: Lifecycle{Serverless: true, StopIfIdleFor: floor + time.Second},
		},
		{
			name:      "serverless_at_floor_passes",
			lifecycle: Lifecycle{Serverless: true, StopIfIdleFor: floor},
		},
		{
			name:      "serverless_one_ns_below_floor_fails",
			lifecycle: Lifecycle{Serverless: true, StopIfIdleFor: floor - time.Nanosecond},
			wantErr:   "below the 1m0s floor",
		},
		{
			name:      "serverless_well_below_floor_fails",
			lifecycle: Lifecycle{Serverless: true, StopIfIdleFor: 5 * time.Second},
			wantErr:   "stop_if_idle_for",
		},
		{
			// Validate failure (negative timer) is surfaced ahead of the
			// floor check, so the user sees the more fundamental error
			// first.
			name:      "validate_failure_takes_precedence",
			lifecycle: Lifecycle{Serverless: true, StopIfIdleFor: -time.Second},
			wantErr:   "non-negative",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.lifecycle.ValidateWithBypassFloor(poll, reconcile)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
