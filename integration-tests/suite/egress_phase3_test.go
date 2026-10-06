//go:build integration

package suite

// Phase 3 egress use cases (plans/egress-domain-filtering.md §5.9, P3-1):
// method and path rules on an inspected HTTPS host, driven by a real TLS
// client that trusts the node's CA only through the environment the create
// gave it (EF-52, EF-53).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// inspectProbe makes three requests with Python's urllib, which reads
// SSL_CERT_FILE, and prints one "label code body" line each. Only double
// quotes inside, so it fits in sh's single quotes.
const inspectProbe = `
import os, urllib.request, urllib.error
print("cafile", os.environ.get("SSL_CERT_FILE", ""))
def probe(label, method, url):
    req = urllib.request.Request(url, method=method, data=b"{}" if method == "POST" else None,
                                 headers={"User-Agent": "aerolvm-itest"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            print(label, r.status, "")
    except urllib.error.HTTPError as e:
        print(label, e.code, e.read(300).decode("utf-8", "replace").replace("\n", " "))
    except Exception as e:
        print(label, "error", type(e).__name__, str(e).replace("\n", " "))
probe("get", "GET", "https://api.github.com/repos/octocat/Hello-World")
probe("post", "POST", "https://api.github.com/repos/octocat/Hello-World")
probe("users", "GET", "https://api.github.com/users/octocat")
`

// UC-201 (EF-52, EF-53, P3-1) — an inspect rule on 443: the ruled GET
// passes through the gateway's TLS termination with the sandbox trusting
// the node CA, while another method or path on the same host is refused by
// the gateway (a 403 naming network_egress_rules, not one from GitHub).
func TestEgressInspectRules(t *testing.T) {
	harness.Require(t, sc, "UC-201")
	c := client(t)
	rule := sdktypes.EgressRule{Host: "api.github.com", Inspect: true, Methods: []string{"GET"}, Paths: []string{"/repos/**"}}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:               harness.UniqueName(sc, t),
		Image:              "python:3.12-alpine",
		NetworkAllowOut:    []string{"api.github.com"},
		NetworkEgressRules: []sdktypes.EgressRule{rule},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	got, err := c.SDK().Get(ctx, sb.ID)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NetworkEgressRules) != 1 || got.NetworkEgressRules[0].Host != rule.Host || !got.NetworkEgressRules[0].Inspect {
		t.Fatalf("GET must return the rule: %+v", got.NetworkEgressRules)
	}

	out := egressExec(t, sb, "python3 -c '"+inspectProbe+"' 2>&1")
	lines := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if label, rest, ok := strings.Cut(l, " "); ok {
			lines[label] = rest
		}
	}
	status := func(label string) string {
		if f := strings.Fields(lines[label]); len(f) > 0 {
			return f[0]
		}
		return ""
	}
	if strings.TrimSpace(lines["cafile"]) != "/run/aerolvm/ca-bundle.pem" {
		t.Fatalf("SSL_CERT_FILE must point at the CA bundle:\n%s", out)
	}
	if status("get") != "200" {
		t.Fatalf("the ruled GET must pass through inspection:\n%s", out)
	}
	for _, label := range []string{"post", "users"} {
		if status(label) != "403" || !strings.Contains(lines[label], "network_egress_rules") {
			t.Fatalf("%s must get the gateway's 403 naming the rules:\n%s", label, out)
		}
	}
}
