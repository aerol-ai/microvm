package models

// DaytonaSandboxMetadata stores compatibility-only fields for the /daytona
// facade without changing the native sandbox contract.
type DaytonaSandboxMetadata struct {
	SandboxID                  string
	Name                       string
	Snapshot                   string
	User                       string
	Labels                     map[string]string
	Target                     string
	NetworkAllowList           string
	AutoStopIntervalMinutes    *float32
	AutoArchiveIntervalMinutes *float32
	AutoDeleteIntervalMinutes  *float32
}
