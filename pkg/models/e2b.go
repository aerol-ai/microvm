package models

import "time"

// E2BSandboxMetadata stores compatibility-only fields for the /e2b facade
// without changing the native sandbox contract.
type E2BSandboxMetadata struct {
	SandboxID           string
	TemplateID          string
	TemplateAlias       string
	Metadata            map[string]string
	TimeoutSeconds      int
	OnTimeout           string
	AutoResume          bool
	Secure              bool
	AllowInternetAccess *bool
	NetworkAllowOut     []string
	NetworkDenyOut      []string
	AllowPublicTraffic  *bool
	MaskRequestHost     string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// E2BSnapshotMetadata stores the E2B-facing snapshot identifier for a native
// snapshot so create/list/delete flows can round-trip through /e2b.
type E2BSnapshotMetadata struct {
	SnapshotID      string
	SnapshotName    string
	Names           []string
	SourceSandboxID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

const (
	E2BCreateRequestStatePending = "pending"
	E2BCreateRequestStateReady   = "ready"
)

// E2BCreateRequestRecord tracks create-path idempotency for the /e2b facade.
// Fingerprint keys are short-lived for body-hash-based dedupe and may be
// longer-lived when an explicit Idempotency-Key is supplied.
type E2BCreateRequestRecord struct {
	Fingerprint string
	SandboxID   string
	State       string
	LockedUntil time.Time
	ReplayUntil time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
