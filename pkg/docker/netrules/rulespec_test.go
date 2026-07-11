package netrules

import "testing"

func TestParseRulespecShapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		spec []string
		src  string
		dst  string
		cmt  string
		ver  verdictKind
	}{
		{
			name: "egress_drop",
			spec: []string{"-s", "10.0.0.2", "-j", "DROP"},
			src:  "10.0.0.2/32",
			ver:  verdictDrop,
		},
		{
			name: "ingress_drop",
			spec: []string{"-d", "10.0.0.3", "-j", "DROP"},
			dst:  "10.0.0.3/32",
			ver:  verdictDrop,
		},
		{
			name: "allowlist_accept",
			spec: []string{"-s", "10.0.0.5", "-d", "1.1.1.1/32", "-m", "comment", "--comment", egressPolicyComment, "-j", "ACCEPT"},
			src:  "10.0.0.5/32",
			dst:  "1.1.1.1/32",
			cmt:  egressPolicyComment,
			ver:  verdictAccept,
		},
		{
			name: "allowlist_catchall",
			spec: []string{"-s", "10.0.0.5", "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"},
			src:  "10.0.0.5/32",
			cmt:  egressPolicyComment,
			ver:  verdictDrop,
		},
		{
			name: "denylist_cidr",
			spec: []string{"-s", "10.0.0.6", "-d", "192.168.0.0/16", "-m", "comment", "--comment", egressPolicyComment, "-j", "DROP"},
			src:  "10.0.0.6/32",
			dst:  "192.168.0.0/16",
			cmt:  egressPolicyComment,
			ver:  verdictDrop,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseRulespec(tc.spec...)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if p.verdict != tc.ver {
				t.Fatalf("verdict = %v, want %v", p.verdict, tc.ver)
			}
			if tc.src != "" {
				if p.src == nil || p.src.String() != tc.src {
					t.Fatalf("src = %v, want %s", p.src, tc.src)
				}
			}
			if tc.dst != "" {
				if p.dst == nil || p.dst.String() != tc.dst {
					t.Fatalf("dst = %v, want %s", p.dst, tc.dst)
				}
			}
			if p.comment != tc.cmt {
				t.Fatalf("comment = %q, want %q", p.comment, tc.cmt)
			}
		})
	}
}

func TestParseRulespecRejectsUnknown(t *testing.T) {
	t.Parallel()
	for _, spec := range [][]string{
		{"-p", "tcp", "-j", "DROP"},
		{"-s", "10.0.0.1"},
		{"-j", "REJECT"},
		{"-m", "state", "--state", "NEW", "-j", "DROP"},
	} {
		if _, err := parseRulespec(spec...); err == nil {
			t.Fatalf("expected error for %v", spec)
		}
	}
}
