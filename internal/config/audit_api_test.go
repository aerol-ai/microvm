package config

import (
	"strings"
	"testing"
)

// TestAuditAPIConfig is the §10 table for the api-record settings: the
// defaults, every accepted value, the refusals, and the enterprise profile
// (records on, the three critical calls durable).
func TestAuditAPIConfig(t *testing.T) {
	type want struct {
		records, flood, exec string
		rate                 float64
		burst                int
		durable              bool
	}
	defaults := want{records: AuditAPIRecordsMutations, flood: AuditAPIFloodBudget, exec: AuditExecCommandDigest, rate: 20, burst: 100}
	cases := []struct {
		name       string
		env        map[string]string
		enterprise bool
		want       want
		wantErr    string
	}{
		{name: "defaults", want: defaults},
		{name: "every value set", env: map[string]string{
			"SB_AUDIT_API_RECORDS": "ALL", "SB_AUDIT_API_FLOOD_CONTROL": " coalesce ", "SB_AUDIT_API_RATE": "5",
			"SB_AUDIT_API_BURST": "7", "SB_AUDIT_EXEC_COMMAND": "full", "SB_AUDIT_API_DURABLE": "true",
		}, want: want{records: AuditAPIRecordsAll, flood: AuditAPIFloodCoalesce, exec: AuditExecCommandFull, rate: 5, burst: 7, durable: true}},
		{name: "off and both", env: map[string]string{"SB_AUDIT_API_RECORDS": "off", "SB_AUDIT_API_FLOOD_CONTROL": "both"},
			want: want{records: AuditAPIRecordsOff, flood: AuditAPIFloodBoth, exec: AuditExecCommandDigest, rate: 20, burst: 100}},
		{name: "unknown records", env: map[string]string{"SB_AUDIT_API_RECORDS": "some"}, wantErr: "SB_AUDIT_API_RECORDS must be"},
		{name: "unknown flood control", env: map[string]string{"SB_AUDIT_API_FLOOD_CONTROL": "drop"}, wantErr: "SB_AUDIT_API_FLOOD_CONTROL must be"},
		{name: "unknown exec command", env: map[string]string{"SB_AUDIT_EXEC_COMMAND": "argv"}, wantErr: "SB_AUDIT_EXEC_COMMAND must be"},
		{name: "zero rate", env: map[string]string{"SB_AUDIT_API_RATE": "0"}, wantErr: "SB_AUDIT_API_RATE must be > 0"},
		{name: "zero burst", env: map[string]string{"SB_AUDIT_API_BURST": "0"}, wantErr: "SB_AUDIT_API_BURST must be >= 1"},
		{name: "a durable typo is refused, not defaulted", env: map[string]string{"SB_AUDIT_API_DURABLE": "yes please"}, wantErr: "SB_AUDIT_API_DURABLE must be true or false"},
		{name: "enterprise: durable by default", enterprise: true, want: want{records: AuditAPIRecordsMutations, flood: AuditAPIFloodBudget, exec: AuditExecCommandDigest, rate: 20, burst: 100, durable: true}},
		{name: "enterprise refuses records off", enterprise: true, env: map[string]string{"SB_AUDIT_API_RECORDS": "off"}, wantErr: "SB_AUDIT_API_RECORDS=off is refused"},
		{name: "enterprise refuses durable false", enterprise: true, env: map[string]string{"SB_AUDIT_API_DURABLE": "false"}, wantErr: "SB_AUDIT_API_DURABLE must be true"},
	}
	keys := []string{"SB_AUDIT_API_RECORDS", "SB_AUDIT_API_FLOOD_CONTROL", "SB_AUDIT_API_RATE", "SB_AUDIT_API_BURST", "SB_AUDIT_EXEC_COMMAND", "SB_AUDIT_API_DURABLE"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range keys {
				t.Setenv(k, tc.env[k])
			}
			if tc.enterprise {
				setSecureEnterpriseEnv(t)
			} else {
				t.Setenv("SB_ENTERPRISE_MODE", "false")
				t.Setenv("SB_PAT_TOKEN", "pat-token")
			}
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			got := want{cfg.AuditAPIRecords, cfg.AuditAPIFloodControl, cfg.AuditExecCommand, cfg.AuditAPIRate, cfg.AuditAPIBurst, cfg.AuditAPIDurable}
			if got != tc.want {
				t.Fatalf("config = %+v, want %+v", got, tc.want)
			}
		})
	}
}
