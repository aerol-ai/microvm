package netrules

import (
	"strings"
	"testing"
)

// TestParseNodeGuardShapes: the node guard's port rules and jumps parse into
// what the netlink backend translates.
func TestParseNodeGuardShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		spec  []string
		proto string
		port  uint16
		ver   verdictKind
		jump  string
	}{
		{"tcp port", []string{"-s", "10.88.0.0/16", "-p", "tcp", "--dport", "15080", "-m", "comment", "--comment", nodeGuardComment, "-j", "RETURN"}, "tcp", 15080, verdictReturn, ""},
		{"udp port to one address", []string{"-s", "10.88.0.0/16", "-d", "10.0.1.5", "-p", "udp", "--dport", "53", "-j", "RETURN"}, "udp", 53, verdictReturn, ""},
		{"protocol only", []string{"-s", "10.88.0.0/16", "-p", "udp", "-j", "DROP"}, "udp", 0, verdictDrop, ""},
		{"jump to our chain", []string{"-s", "10.88.0.0/16", "-j", "AEROLVM-NODE-1a2b3c4d-A"}, "", 0, verdictJump, "AEROLVM-NODE-1a2b3c4d-A"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseRulespec(tc.spec...)
			if err != nil {
				t.Fatal(err)
			}
			if p.proto != tc.proto || p.dport != tc.port || p.verdict != tc.ver || p.jump != tc.jump {
				t.Fatalf("parsed %+v", p)
			}
		})
	}
}

func TestParseNodeGuardRejects(t *testing.T) {
	t.Parallel()
	for _, spec := range [][]string{
		{"-s", "10.88.0.0/16", "--dport", "53", "-j", "RETURN"},               // port without protocol
		{"-s", "10.88.0.0/16", "-p", "icmp", "-j", "DROP"},                    // protocol we never write
		{"-s", "10.88.0.0/16", "-p", "tcp", "--dport", "0", "-j", "RETURN"},   // no port 0
		{"-s", "10.88.0.0/16", "-p", "tcp", "--dport", "70000", "-j", "DROP"}, // out of range
		{"-s", "10.88.0.0/16", "-p", "tcp", "--dport"},                        // missing port
		{"-s", "10.88.0.0/16", "-p"},                                          // missing protocol
		{"-s", "10.88.0.0/16", "-j", "LOG"},                                   // a target, not our chain
		{"-s", "10.88.0.0/16", "-j", "DOCKER-USER"},                           // someone else's chain
		{"-s", "10.88.0.0/16", "-j", "AEROLVM-" + strings.Repeat("X", 30)},    // too long for iptables
		{"-s", "10.88.0.0/16", "-j", "AEROLVM-NODE;rm"},                       // not a chain name
	} {
		if _, err := parseRulespec(spec...); err == nil {
			t.Errorf("parseRulespec(%v) must fail", spec)
		}
	}
}
