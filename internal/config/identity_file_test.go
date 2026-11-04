package config

import (
	"strings"
	"testing"
)

// TestIdentityFileNeedsIdentity: SB_IDENTITY_FILE is read only with
// SB_IDENTITY_ENABLED=true, so Load refuses it alone rather than letting an
// operator believe SSO and the deny list are in force. Empty with identity
// on is tokens-only mode.
func TestIdentityFileNeedsIdentity(t *testing.T) {
	cases := []struct {
		name     string
		identity string
		file     string
		wantErr  string
		wantFile string
	}{
		{name: "neither", identity: ""},
		{name: "identity on, no file: tokens-only", identity: "true"},
		{name: "identity on with a file", identity: "true", file: "/etc/aerolvm/identity.yaml", wantFile: "/etc/aerolvm/identity.yaml"},
		{name: "file is trimmed", identity: "true", file: "  /etc/aerolvm/identity.yaml ", wantFile: "/etc/aerolvm/identity.yaml"},
		{name: "blank file is unset", identity: "false", file: "   "},
		{name: "file without identity", identity: "false", file: "/etc/aerolvm/identity.yaml", wantErr: "SB_IDENTITY_FILE needs SB_IDENTITY_ENABLED=true"},
		{name: "file with identity unset", identity: "", file: "/etc/aerolvm/identity.yaml", wantErr: "SB_IDENTITY_FILE needs SB_IDENTITY_ENABLED=true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_IDENTITY_ENABLED", tc.identity)
			t.Setenv("SB_IDENTITY_FILE", tc.file)
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
			if cfg.IdentityFile != tc.wantFile {
				t.Fatalf("IdentityFile = %q, want %q", cfg.IdentityFile, tc.wantFile)
			}
		})
	}
}
