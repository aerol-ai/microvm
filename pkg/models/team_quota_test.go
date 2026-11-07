package models

import (
	"errors"
	"strings"
	"testing"
)

func TestTeamQuotaRequestValidate(t *testing.T) {
	for _, tc := range []struct {
		req     TeamQuotaRequest
		wantErr bool
	}{
		{req: TeamQuotaRequest{MaxSandboxes: 1}},
		{req: TeamQuotaRequest{MaxCPU: 0.5}},
		{req: TeamQuotaRequest{MaxMemoryMB: 512}},
		{req: TeamQuotaRequest{}, wantErr: true},
		{req: TeamQuotaRequest{MaxSandboxes: -1, MaxCPU: 1}, wantErr: true},
		{req: TeamQuotaRequest{MaxCPU: -0.1}, wantErr: true},
		{req: TeamQuotaRequest{MaxMemoryMB: -1}, wantErr: true},
	} {
		err := tc.req.Validate()
		if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, ErrInvalidTeamQuota)) {
			t.Fatalf("Validate(%+v) = %v, wantErr %v", tc.req, err, tc.wantErr)
		}
	}
}

func TestCheckTeamQuota(t *testing.T) {
	limits := TeamQuotaRequest{MaxSandboxes: 2, MaxCPU: 0.3, MaxMemoryMB: 1024}
	cases := []struct {
		name  string
		usage TeamQuotaUsage
		add   TeamQuotaUsage
		want  string
	}{
		{name: "fits", usage: TeamQuotaUsage{Sandboxes: 1, CPU: 0.1, MemoryMB: 512}, add: TeamQuotaUsage{Sandboxes: 1, CPU: 0.2, MemoryMB: 512}},
		{name: "count", usage: TeamQuotaUsage{Sandboxes: 2}, add: TeamQuotaUsage{Sandboxes: 1}, want: "2 of its 2 sandboxes"},
		{name: "cpu", usage: TeamQuotaUsage{CPU: 0.2}, add: TeamQuotaUsage{CPU: 0.2}, want: "CPU"},
		{name: "memory", usage: TeamQuotaUsage{MemoryMB: 1000}, add: TeamQuotaUsage{MemoryMB: 100}, want: "memory"},
		// A start adds nothing: refused only when already over.
		{name: "at the limit, adding nothing", usage: TeamQuotaUsage{Sandboxes: 2}},
		{name: "over a lowered limit", usage: TeamQuotaUsage{Sandboxes: 3}, want: "sandboxes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckTeamQuota("risk", limits, tc.usage, tc.add)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrTeamQuotaExceeded) || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), `"risk"`) {
				t.Fatalf("err = %v, want one naming %q and the team", err, tc.want)
			}
		})
	}
	if err := CheckTeamQuota("t", TeamQuotaRequest{}, TeamQuotaUsage{Sandboxes: 1000, CPU: 1e6}, TeamQuotaUsage{Sandboxes: 1}); err != nil {
		t.Fatalf("zero limits limit nothing: %v", err)
	}
}

func TestTeamQuotaHelpers(t *testing.T) {
	if TeamOfOwnerRef("team:risk") != "risk" || TeamOfOwnerRef(" team:risk ") != "risk" || TeamOfOwnerRef("acct-1") != "" || TeamOfOwnerRef("") != "" {
		t.Fatal("TeamOfOwnerRef")
	}
	if cpu, mem := QuotaSize(0, 0); cpu != DefaultCPU || mem != DefaultMemoryMB {
		t.Fatalf("defaults = %v %v", cpu, mem)
	}
	if cpu, mem := QuotaSize(2, 64); cpu != 2 || mem != 64 {
		t.Fatalf("given = %v %v", cpu, mem)
	}
	q := TeamQuota{MaxSandboxes: 1, MaxCPU: 2, MaxMemoryMB: 3}
	if q.Limits() != (TeamQuotaRequest{MaxSandboxes: 1, MaxCPU: 2, MaxMemoryMB: 3}) {
		t.Fatal("Limits")
	}
}
