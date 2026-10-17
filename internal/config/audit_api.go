package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Settings for the API action records (plans/identity-and-access.md §5.9,
// §10). Their values are a wire contract with operators, so they are named
// constants the service layer switches on.
const (
	AuditAPIRecordsOff       = "off"
	AuditAPIRecordsMutations = "mutations"
	AuditAPIRecordsAll       = "all"

	AuditAPIFloodBudget   = "budget"
	AuditAPIFloodCoalesce = "coalesce"
	AuditAPIFloodBoth     = "both"

	AuditExecCommandDigest = "digest"
	AuditExecCommandFull   = "full"
)

// loadAuditAPIConfig validates the api-record settings Load read and applies
// the enterprise profile: enterprise mode must record API calls and must
// make the three calls whose loss would matter most (token create, token
// revoke, sandbox delete) wait for disk.
func (cfg *Config) loadAuditAPIConfig() error {
	switch cfg.AuditAPIRecords {
	case AuditAPIRecordsOff, AuditAPIRecordsMutations, AuditAPIRecordsAll:
	default:
		return fmt.Errorf("SB_AUDIT_API_RECORDS must be off, mutations or all, got %q", cfg.AuditAPIRecords)
	}
	switch cfg.AuditAPIFloodControl {
	case AuditAPIFloodBudget, AuditAPIFloodCoalesce, AuditAPIFloodBoth:
	default:
		return fmt.Errorf("SB_AUDIT_API_FLOOD_CONTROL must be budget, coalesce or both, got %q", cfg.AuditAPIFloodControl)
	}
	switch cfg.AuditExecCommand {
	case AuditExecCommandDigest, AuditExecCommandFull:
	default:
		return fmt.Errorf("SB_AUDIT_EXEC_COMMAND must be digest or full, got %q", cfg.AuditExecCommand)
	}
	if cfg.AuditAPIRate <= 0 {
		return errors.New("SB_AUDIT_API_RATE must be > 0: the budget bounds one caller's flood of records on a sandbox")
	}
	if cfg.AuditAPIBurst < 1 {
		return errors.New("SB_AUDIT_API_BURST must be >= 1")
	}
	durable, set, err := envBoolStrict("SB_AUDIT_API_DURABLE")
	if err != nil {
		return err
	}
	cfg.AuditAPIDurable = durable
	if !cfg.EnterpriseMode {
		return nil
	}
	if cfg.AuditAPIRecords == AuditAPIRecordsOff {
		return errors.New("SB_AUDIT_API_RECORDS=off is refused when SB_ENTERPRISE_MODE=true: every mutating API call must leave a record")
	}
	if set && !durable {
		return errors.New("SB_AUDIT_API_DURABLE must be true when SB_ENTERPRISE_MODE=true: token create, token revoke and sandbox delete wait for their record to reach disk")
	}
	cfg.AuditAPIDurable = true
	return nil
}

// envBoolStrict reads a boolean that must parse when set: a typo in a
// setting that weakens evidence must not silently fall back to the default.
func envBoolStrict(key string) (value, set bool, err error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return false, false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, true, fmt.Errorf("%s must be true or false, got %q", key, raw)
	}
	return v, true, nil
}
