package models

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Per-team quotas (plan item P2). An admin caps how many sandboxes a team
// may hold and how much CPU and memory they may ask for in total. A team is
// the open-source "team:<name>" owner every team-bound credential creates
// under; operator and other unscoped creates belong to no team and are never
// limited.

// ErrorCodeTeamQuotaExceeded is the API code of a create, resize or start a
// team quota refuses (HTTP 429).
const ErrorCodeTeamQuotaExceeded = "team_quota_exceeded"

var (
	// ErrTeamQuotaExceeded is a request that would take a team past one of
	// its quota limits. The message names the team, the limit and the usage.
	ErrTeamQuotaExceeded = errors.New("team_quota_exceeded")
	// ErrTeamQuotaNotFound is a GET or a usage read for a team with no quota.
	ErrTeamQuotaNotFound = errors.New("team quota not found")
	// ErrInvalidTeamQuota is a malformed quota body (HTTP 400).
	ErrInvalidTeamQuota = errors.New("invalid team quota")
)

// TeamQuotaRequest is the PUT /v1/teams/{team}/quota body. A zero (or
// omitted) limit means "no limit on that axis".
type TeamQuotaRequest struct {
	MaxSandboxes int     `json:"max_sandboxes,omitempty"`
	MaxCPU       float64 `json:"max_cpu,omitempty"`
	MaxMemoryMB  int     `json:"max_memory_mb,omitempty"`
}

// Validate refuses negative limits and a quota with no limit at all, which
// would be a quota that limits nothing (DELETE removes a quota).
func (r TeamQuotaRequest) Validate() error {
	if r.MaxSandboxes < 0 || r.MaxCPU < 0 || r.MaxMemoryMB < 0 {
		return fmt.Errorf("%w: limits must not be negative", ErrInvalidTeamQuota)
	}
	if r.MaxSandboxes == 0 && r.MaxCPU == 0 && r.MaxMemoryMB == 0 {
		return fmt.Errorf("%w: set at least one of max_sandboxes, max_cpu or max_memory_mb", ErrInvalidTeamQuota)
	}
	return nil
}

// TeamQuotaUsage is what a team holds now: every sandbox that is not
// deleted, running or stopped, at the CPU and memory it asked for.
type TeamQuotaUsage struct {
	Sandboxes int     `json:"sandboxes"`
	CPU       float64 `json:"cpu"`
	MemoryMB  int     `json:"memory_mb"`
}

// TeamQuota is one team's quota, and its usage when read back.
type TeamQuota struct {
	Team         string          `json:"team"`
	MaxSandboxes int             `json:"max_sandboxes,omitempty"`
	MaxCPU       float64         `json:"max_cpu,omitempty"`
	MaxMemoryMB  int             `json:"max_memory_mb,omitempty"`
	Generation   int64           `json:"generation"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	Usage        *TeamQuotaUsage `json:"usage,omitempty"`
}

// Limits returns the request form of the quota's limits.
func (q TeamQuota) Limits() TeamQuotaRequest {
	return TeamQuotaRequest{MaxSandboxes: q.MaxSandboxes, MaxCPU: q.MaxCPU, MaxMemoryMB: q.MaxMemoryMB}
}

// TeamOwnerPrefix is the owner-ref prefix of a team (controlplane keeps the
// authoritative copy; models cannot import it).
const TeamOwnerPrefix = "team:"

// TeamOfOwnerRef returns the team an owner ref names, or "" for an owner
// that is not a team (operator, managed account).
func TeamOfOwnerRef(ownerRef string) string {
	team, ok := strings.CutPrefix(strings.TrimSpace(ownerRef), TeamOwnerPrefix)
	if !ok {
		return ""
	}
	return team
}

// QuotaSize is the CPU and memory one sandbox counts for: what it asked for,
// with the server defaults when it asked for nothing. The FSM and the
// single-node ledger both use it, so a team's usage reads the same in either.
func QuotaSize(cpu float64, memoryMB int) (float64, int) {
	if cpu <= 0 {
		cpu = DefaultCPU
	}
	if memoryMB <= 0 {
		memoryMB = DefaultMemoryMB
	}
	return cpu, memoryMB
}

// CheckTeamQuota reports whether usage plus add stays inside limits. The
// refusal names the team, the limit it would break and the usage, so a
// caller knows which knob to turn. A zero limit is no limit.
func CheckTeamQuota(team string, limits TeamQuotaRequest, usage TeamQuotaUsage, add TeamQuotaUsage) error {
	if limits.MaxSandboxes > 0 && usage.Sandboxes+add.Sandboxes > limits.MaxSandboxes {
		return fmt.Errorf("%w: team %q holds %d of its %d sandboxes", ErrTeamQuotaExceeded, team, usage.Sandboxes, limits.MaxSandboxes)
	}
	// A small epsilon keeps 0.1+0.2 from reading as over a 0.3 limit.
	if limits.MaxCPU > 0 && usage.CPU+add.CPU > limits.MaxCPU+1e-9 {
		return fmt.Errorf("%w: team %q uses %g of its %g CPU and asks for %g more", ErrTeamQuotaExceeded, team, usage.CPU, limits.MaxCPU, add.CPU)
	}
	if limits.MaxMemoryMB > 0 && usage.MemoryMB+add.MemoryMB > limits.MaxMemoryMB {
		return fmt.Errorf("%w: team %q uses %d of its %d MB of memory and asks for %d MB more", ErrTeamQuotaExceeded, team, usage.MemoryMB, limits.MaxMemoryMB, add.MemoryMB)
	}
	return nil
}
