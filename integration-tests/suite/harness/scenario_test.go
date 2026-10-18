package harness

import (
	"os"
	"path/filepath"
	"testing"
)

// Under SB_PAT_SCOPE=host run.sh exports an admin avm_ token as AEROL_PAT and
// the PAT as AEROL_OPERATOR_PAT; everywhere else only AEROL_PAT is set, and
// the operator token is that same token.
func TestLoadScenarioOperatorPAT(t *testing.T) {
	caps := filepath.Join(t.TempDir(), "s.caps.yml")
	if err := os.WriteFile(caps, []byte("name: s\ncapabilities: [identity, pat-scope-host]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvCaps, caps)
	t.Setenv(EnvBaseURL, "https://itest.example/")
	t.Setenv(EnvScenario, "")

	for _, tc := range []struct {
		name, pat, operator, wantOperator string
	}{
		{"host scope: two credentials", "avm_admin", "the-pat", "the-pat"},
		{"any scope: one credential", "the-pat", "", "the-pat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvPAT, tc.pat)
			t.Setenv(EnvOperatorPAT, tc.operator)
			sc, err := LoadScenario()
			if err != nil {
				t.Fatal(err)
			}
			if sc.PAT != tc.pat || sc.OperatorPAT != tc.wantOperator {
				t.Fatalf("PAT %q operator %q, want %q and %q", sc.PAT, sc.OperatorPAT, tc.pat, tc.wantOperator)
			}
			if sc.BaseURL != "https://itest.example" || sc.Name != "s" || !sc.Has(CapPATScopeHost) || !sc.Has(CapIdentity) {
				t.Fatalf("scenario = %+v", sc)
			}
		})
	}
}
