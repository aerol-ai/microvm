package netrules

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
)

func TestIptablesReportsLegacy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		version string
		want    bool
	}{
		{"iptables v1.8.7 (legacy)", true},
		{"iptables v1.8.9 (nf_tables)", false},
		{"iptables v1.4.21", false}, // pre-variant builds are xtables but don't say so; stay quiet
		{"", false},
	}
	for _, tc := range cases {
		if got := iptablesReportsLegacy(tc.version); got != tc.want {
			t.Errorf("iptablesReportsLegacy(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestWarnIfLegacyIptables(t *testing.T) {
	restore := iptablesVersion
	defer func() { iptablesVersion = restore }()

	logOutput := func(version string, verr error, backend string) string {
		iptablesVersion = func() (string, error) { return version, verr }
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		WarnIfLegacyIptables(backend, logger)
		return buf.String()
	}

	if out := logOutput("iptables v1.8.7 (legacy)", nil, BackendNetlink); out == "" {
		t.Fatal("legacy host + netlink backend must warn")
	}
	if out := logOutput("iptables v1.8.9 (nf_tables)", nil, BackendNetlink); out != "" {
		t.Fatalf("nf_tables host must stay quiet, got %q", out)
	}
	if out := logOutput("iptables v1.8.7 (legacy)", nil, BackendExec); out != "" {
		t.Fatalf("exec backend must stay quiet, got %q", out)
	}
	if out := logOutput("iptables v1.8.7 (legacy)", nil, "  "+BackendNetlink+"  "); out == "" {
		t.Fatal("trimmed netlink backend name must still warn on legacy hosts")
	}
	if out := logOutput("", errors.New("no iptables binary"), BackendNetlink); out != "" {
		t.Fatalf("probe failure must stay quiet, got %q", out)
	}
	// Nil logger is a no-op, not a panic.
	iptablesVersion = func() (string, error) { return "iptables v1.8.7 (legacy)", nil }
	WarnIfLegacyIptables(BackendNetlink, nil)
}
