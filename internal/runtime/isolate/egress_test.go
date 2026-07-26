package isolate

import "testing"

func TestHostMatches(t *testing.T) {
	tests := []struct {
		host, rule string
		want       bool
	}{
		{host: "api.example.com", rule: "api.example.com", want: true},
		{host: "api.example.com", rule: "other.com", want: false},
		{host: "sub.api.example.com", rule: ".example.com", want: true},
		{host: "notexample.com", rule: ".example.com", want: false},
		{host: "10.0.0.5", rule: "10.0.0.0/8", want: true},
		{host: "11.0.0.5", rule: "10.0.0.0/8", want: false},
		{host: "not-an-ip", rule: "10.0.0.0/8", want: false},
		{host: "10.0.0.5", rule: "bad/cidr", want: false},
		{host: "host", rule: "", want: false},
		{host: "host:8080", rule: "host", want: false}, // hostMatches gets host without port from egressAllowed
	}
	for _, tc := range tests {
		t.Run(tc.host+"_"+tc.rule, func(t *testing.T) {
			if got := hostMatches(tc.host, tc.rule); got != tc.want {
				t.Fatalf("hostMatches(%q, %q) = %v, want %v", tc.host, tc.rule, got, tc.want)
			}
		})
	}
}

func TestEgressAllowedWithPort(t *testing.T) {
	// egressAllowed strips host:port before matching.
	if !egressAllowed(EgressPolicy{Allow: []string{"api.example.com"}}, "api.example.com:443") {
		t.Fatal("host:port should match allow rule")
	}
	if egressAllowed(EgressPolicy{Deny: []string{"evil.com"}}, "evil.com:80") {
		t.Fatal("deny should win with port in host")
	}
}
