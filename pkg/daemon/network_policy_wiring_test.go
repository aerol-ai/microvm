package daemon

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// The boot line tells the operator which of three things this node does with
// a container sandbox's network policy: enforce it, refuse it, or (opt-in)
// accept it unenforced, the last as a warning nobody can miss.
func TestLogNetworkPolicyEnforcement(t *testing.T) {
	cases := []struct {
		name       string
		firewallOn bool
		optIn      bool
		want       string // "" = nothing logged
		level      string
	}{
		{name: "firewall on", firewallOn: true},
		{name: "firewall on, opt-in ignored", firewallOn: true, optIn: true, want: "has no effect", level: "level=INFO"},
		{name: "firewall off refuses", want: "network_policy_unenforced", level: "level=INFO"},
		{name: "firewall off, opt-in", optIn: true, want: "NETWORK POLICY NOT ENFORCED", level: "level=WARN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf syncBuffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			logNetworkPolicyEnforcement(logger, config.Config{EnableNetworkRules: tc.firewallOn, AllowUnenforcedNetworkPolicy: tc.optIn}, tc.firewallOn)
			out := buf.String()
			if tc.want == "" {
				if out != "" {
					t.Fatalf("logged %q, want nothing", out)
				}
				return
			}
			if !strings.Contains(out, tc.want) || !strings.Contains(out, tc.level) {
				t.Fatalf("log = %q, want %q at %s", out, tc.want, tc.level)
			}
		})
	}
}
