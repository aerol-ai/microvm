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
}
