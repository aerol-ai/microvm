//go:build integration

package suite

// Phase 3 egress use cases (plans/egress-domain-filtering.md §5.9, P3-1,
// P3-2, P3-3): method and path rules on an inspected HTTPS host, driven by a
// real TLS client that trusts the node's CA only through the environment the
// create gave it (EF-52, EF-53), credential injection into a header the
// sandbox only holds a placeholder for (EF-54), and rules limited to the
// programs that may use them (EF-55).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// injectProbe sends GET /headers to postman-echo with the env's placeholder
// as Authorization and prints the authorization header the echo received.
// Only double quotes inside, so it fits in sh's single quotes.
const injectProbe = `
import json, os, urllib.request
req = urllib.request.Request("https://postman-echo.com/headers",
                             headers={"Authorization": os.environ.get("TEST_TOKEN", ""), "User-Agent": "aerolvm-itest"})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        print("auth", json.load(r).get("headers", {}).get("authorization", ""))
except Exception as e:
    print("error", type(e).__name__, str(e).replace("\n", " "))
`

// UC-202 (EF-54, P3-2) — credential injection: the sandbox's env holds only
// the placeholder, it sends that placeholder as Authorization, and the
// upstream echoes the real token the gateway put in its place. A hijacked
// agent can't leak a key it never had.
func TestEgressInjectCredential(t *testing.T) {
	harness.Require(t, sc, "UC-202")
	c := client(t)
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	token := "Bearer aerolvm-itest-" + hex.EncodeToString(nonce)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		Image:           "python:3.12-alpine",
		Env:             map[string]string{"TEST_TOKEN": token},
		NetworkAllowOut: []string{"postman-echo.com"},
		NetworkEgressRules: []sdktypes.EgressRule{{
			Host:    "postman-echo.com",
			Inspect: true,
			Paths:   []string{"/headers"},
			Inject:  &sdktypes.EgressInject{Header: "Authorization", SecretRef: "env:TEST_TOKEN"},
		}},
	})
	waitRunning(t, sb)

	if got := strings.TrimSpace(egressExec(t, sb, "echo $TEST_TOKEN")); got != "aerolvm-placeholder:TEST_TOKEN" {
		t.Fatalf("the sandbox must hold the placeholder, not the token: %q", got)
	}
	out := egressExec(t, sb, "python3 -c '"+injectProbe+"' 2>&1")
	auth, ok := strings.CutPrefix(strings.TrimSpace(out), "auth ")
	if !ok || auth != token {
		t.Fatalf("the upstream must receive the injected token in place of the placeholder:\n%s", out)
	}
}

// UC-203 (EF-55, P3-3) — per-binary rules: binaries-only rules on 443,
// without inspection, let pip (a script of the image's python3.12, which the
// gateway names by its script) install a package from pypi.org and
// files.pythonhosted.org, while busybox wget to the same allowed host is
// refused at the TLS handshake. Tracing a connection to its program needs
// runc: the docker and containerd scenarios run runc, and the runtime is
// pinned to docker (runc under either engine) so cluster-3-mixed-gvisor
// never places this on runsc, which refuses binaries with 501.
func TestEgressBinariesRule(t *testing.T) {
	harness.Require(t, sc, "UC-203")
	c := client(t)
	pip := []string{"/usr/local/bin/pip"}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		Image:           "python:3.12-alpine",
		Runtime:         "docker",
		NetworkAllowOut: []string{"pypi.org", "files.pythonhosted.org"},
		NetworkEgressRules: []sdktypes.EgressRule{
			{Host: "pypi.org", Ports: []uint16{443}, Binaries: pip},
			{Host: "files.pythonhosted.org", Ports: []uint16{443}, Binaries: pip},
		},
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	got, err := c.SDK().Get(ctx, sb.ID)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.NetworkEgressRules) != 2 || len(got.NetworkEgressRules[0].Binaries) != 1 || got.NetworkEgressRules[0].Binaries[0] != pip[0] {
		t.Fatalf("GET must return the rules with their binaries: %+v", got.NetworkEgressRules)
	}

	if out := egressExec(t, sb, "pip install --no-cache-dir -q requests 2>&1; echo pip_rc=$?"); !strings.Contains(out, "pip_rc=0") {
		t.Fatalf("pip is a listed binary; its install from pypi.org must pass:\n%s", out)
	}
	if rc, _ := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://pypi.org/simple/"); rc == 0 {
		t.Fatal("busybox wget is not a listed binary; its connection to pypi.org must be refused")
	}
}
