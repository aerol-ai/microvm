package config

import (
	"strings"
	"testing"
)

// E1/ER5: the operator's exec output default and maximum. Off unless set;
// a default above the maximum, a negative value or one that does not parse
// refuses the boot.
func TestExecOutputLimits(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "tok")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_DB_PATH", t.TempDir()+"/db.sqlite")
	t.Setenv("SB_CONTAINER_RUNTIME", "docker")
	t.Setenv("SB_TOOLBOX_BINARY_PATH", t.TempDir()+"/toolboxd")

	for _, tc := range []struct {
		name             string
		def, max         string
		wantDef, wantMax int64
		err              string
	}{
		{name: "off by default"},
		{name: "default only", def: "1048576", wantDef: 1 << 20},
		{name: "max only", max: "4194304", wantMax: 4 << 20},
		{name: "both", def: "65536", max: "1048576", wantDef: 65536, wantMax: 1 << 20},
		{name: "default equals max", def: "1024", max: "1024", wantDef: 1024, wantMax: 1024},
		{name: "explicit zero", def: "0", max: "0"},
		{name: "default above max", def: "2048", max: "1024", err: "must not exceed SB_EXEC_OUTPUT_MAX_BYTES"},
		{name: "negative default", def: "-1", err: "must be 0 (off) or more"},
		{name: "negative max", max: "-5", err: "must be 0 (off) or more"},
		{name: "unparsable default", def: "10MB", err: `SB_EXEC_OUTPUT_DEFAULT_BYTES must be a whole number of bytes, got "10MB"`},
		{name: "unparsable max", max: "1e6", err: `SB_EXEC_OUTPUT_MAX_BYTES must be a whole number of bytes, got "1e6"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_EXEC_OUTPUT_DEFAULT_BYTES", tc.def)
			t.Setenv("SB_EXEC_OUTPUT_MAX_BYTES", tc.max)
			cfg, err := Load()
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("Load() error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ExecOutputDefaultBytes != tc.wantDef || cfg.ExecOutputMaxBytes != tc.wantMax {
				t.Fatalf("default/max = %d/%d, want %d/%d", cfg.ExecOutputDefaultBytes, cfg.ExecOutputMaxBytes, tc.wantDef, tc.wantMax)
			}
		})
	}
}
