package proxy

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestHTTPRules (P3-1, EF-52 on port 80): each request to a ruled host is
// held to its method and path rules; a request no rule admits gets a 403
// naming the rule list, and a path an upstream could read two ways is
// refused before any rule sees it.
func TestHTTPRules(t *testing.T) {
	spec := allowSpec("api.example.com", "other.example.com")
	spec.Rules = []egresspolicy.RuleSpec{{Host: "api.example.com", Methods: []string{"GET"}, Paths: []string{"/repos/acme/*"}}}
	r := newRig(t, 80, spec, Config{})
	backend := httpBackend(t)
	for _, h := range []string{"api.example.com", "other.example.com"} {
		r.dialer.resolve[h] = "151.101.0.1"
		r.dialer.backend[h] = backend
	}
	got := httpExchange(t, r.addr,
		"GET /repos/acme/widget HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
		"POST /repos/acme/widget HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
	)
	if len(got) != 2 || !strings.HasPrefix(got[0], "200 plain-ok") ||
		!strings.HasPrefix(got[1], "403 aerolvm egress policy: POST /repos/acme/widget on api.example.com is not allowed by network_egress_rules") {
		t.Fatalf("method rule: %v", got)
	}
	if d := r.last(); d.Reason != ReasonRuleDenied || d.Allowed {
		t.Fatalf("decision = %+v", d)
	}
	got = httpExchange(t, r.addr, "GET /repos/acme/../../admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if len(got) != 1 || !strings.Contains(got[0], "403") || !strings.Contains(got[0], "dot segments") {
		t.Fatalf("dot segments: %v", got)
	}
	if d := r.last(); d.Reason != ReasonPathNotCanonical {
		t.Fatalf("decision = %+v", d)
	}
	// An unruled host keeps the allow-list decision; the allowed request is
	// audited with the rule that admitted it.
	got = httpExchange(t, r.addr, "DELETE /anything HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "200") {
		t.Fatalf("unruled host: %v", got)
	}
	got = httpExchange(t, r.addr, "GET /repos/acme/x HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "200") || r.last().Rule != "rules[0] api.example.com" {
		t.Fatalf("allowed rule audit: %v %+v", got, r.last())
	}
}
