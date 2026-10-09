package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/inspect"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// inspectBackend is the real host behind an inspected name: it echoes what
// it received, over h2 or HTTP/1.1.
func inspectBackend(t *testing.T) (addr string, roots *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "%s %s host=%s auth=%s body=%d", r.Method, r.URL.Path, r.Host, r.Header.Get("Authorization"), len(body))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots = x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return strings.TrimPrefix(srv.URL, "https://"), roots
}

type inspectRig struct {
	*rig
	ca *inspect.Authority
}

func newInspectRig(t *testing.T, cfg Config, rules ...egresspolicy.RuleSpec) *inspectRig {
	t.Helper()
	return newInspectRigOver(t, cfg, nil, rules...)
}

// newInspectRigOver is newInspectRig with the gateway read through wrap
// (newRigOver).
func newInspectRigOver(t *testing.T, cfg Config, wrap func(*egress.Gateway) Sources, rules ...egresspolicy.RuleSpec) *inspectRig {
	t.Helper()
	backend, roots := inspectBackend(t)
	if cfg.UpstreamRoots == nil {
		cfg.UpstreamRoots = roots
	}
	spec := allowSpec("api.example.com", "other.example.com")
	spec.Rules = rules
	r := newRigOver(t, 443, spec, cfg, wrap)
	for _, h := range []string{"api.example.com", "other.example.com"} {
		r.dialer.resolve[h] = "151.101.0.1"
		r.dialer.backend[h] = backend
	}
	certPEM, keyPEM, err := inspect.GenerateCA("test-node", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := inspect.New(certPEM, keyPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.proxy.SetInspector(ca)
	return &inspectRig{rig: r, ca: ca}
}

// client talks to the proxy as the sandbox would: trusting the node CA, and
// with h2 when asked.
func (r *inspectRig) client(h2 bool) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(r.ca.CertPEM())
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", r.addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: h2,
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func do(t *testing.T, c *http.Client, method, url, host, body string) (int, string, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if host != "" {
		req.Host = host
	}
	req.Header.Set("Authorization", "Bearer placeholder")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error(), ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b)), resp.Proto
}

var acmeRules = []egresspolicy.RuleSpec{
	{Host: "api.example.com", Inspect: true, Methods: []string{"GET"}, Paths: []string{"/repos/acme/*"}},
	{Host: "api.example.com", Inspect: true, Methods: []string{"POST"}, Paths: []string{"/upload"}},
}

// TestInspectRules (EF-52, EF-53) over HTTP/1.1 and h2: allowed requests
// reach the real host verified against its own roots; a method or path no
// rule admits, and a Host other than the TLS name, are refused per request.
func TestInspectRules(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			r := newInspectRig(t, Config{InspectMaxBody: 64}, acmeRules...)
			c := r.client(h2)
			wantProto := "HTTP/1.1"
			if h2 {
				wantProto = "HTTP/2.0"
			}
			code, body, proto := do(t, c, http.MethodGet, "https://api.example.com/repos/acme/widget", "", "")
			if code != 200 || body != "GET /repos/acme/widget host=api.example.com auth=Bearer placeholder body=0" || proto != wantProto {
				t.Fatalf("allowed: %d %q %s", code, body, proto)
			}
			if d := r.last(); !d.Allowed || d.Rule != "rules[0] api.example.com" || d.Host != "api.example.com" {
				t.Fatalf("allowed decision = %+v", d)
			}
			code, body, _ = do(t, c, http.MethodPost, "https://api.example.com/repos/acme/widget", "", "x")
			if code != 403 || !strings.Contains(body, "POST /repos/acme/widget on api.example.com is not allowed by network_egress_rules") || r.last().Reason != ReasonRuleDenied {
				t.Fatalf("method denied: %d %q", code, body)
			}
			code, body, _ = do(t, c, http.MethodGet, "https://api.example.com/repos/acme/widget", "other.example.com", "")
			if code != http.StatusMisdirectedRequest || !strings.Contains(body, "does not match the TLS server name") || r.last().Reason != ReasonHostMismatch {
				t.Fatalf("domain fronting: %d %q", code, body)
			}
			code, _, _ = do(t, c, http.MethodPost, "https://api.example.com/upload", "", strings.Repeat("x", 65))
			if code != http.StatusRequestEntityTooLarge || r.last().Reason != ReasonBodyTooLarge {
				t.Fatalf("body cap: %d", code)
			}
			if code, body, _ = do(t, c, http.MethodPost, "https://api.example.com/upload", "", "small"); code != 200 || !strings.HasSuffix(body, "body=5") {
				t.Fatalf("upload: %d %q", code, body)
			}
		})
	}
}

// TestInspectFailsClosed: no CA yet, an untrusted upstream, or a block
// arriving mid-session all refuse rather than pass traffic unchecked.
func TestInspectFailsClosed(t *testing.T) {
	r := newInspectRig(t, Config{}, acmeRules...)
	c := r.client(false)

	r.proxy.SetInspector(nil)
	if code, body, _ := do(t, c, http.MethodGet, "https://api.example.com/repos/acme/x", "", ""); code != 0 || r.last().Reason != ReasonInspectUnavailable {
		t.Fatalf("no CA: %d %q", code, body)
	}
	r.proxy.SetInspector(r.ca)

	// A session survives across requests; a block on it stops the next one.
	c = r.client(false)
	if code, _, _ := do(t, c, http.MethodGet, "https://api.example.com/repos/acme/x", "", ""); code != 200 {
		t.Fatalf("before the block: %d", code)
	}
	if err := r.gw.SetBlocked("sb", egress.BlockQuota, true); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := do(t, c, http.MethodGet, "https://api.example.com/repos/acme/x", "", ""); code == 200 {
		t.Fatal("a blocked sandbox must not reach the host")
	}

	untrusted := newInspectRig(t, Config{UpstreamRoots: x509.NewCertPool()}, acmeRules...)
	if code, body, _ := do(t, untrusted.client(false), http.MethodGet, "https://api.example.com/repos/acme/x", "", ""); code != http.StatusBadGateway || !strings.Contains(body, ReasonDialFailed) {
		t.Fatalf("untrusted upstream: %d %q", code, body)
	}
}

// TestInspectOnlyRuledHosts: a host with no inspect rule keeps the Phase 1
// passthrough, so its certificate is the real host's, not the node CA's.
func TestInspectOnlyRuledHosts(t *testing.T) {
	r := newInspectRig(t, Config{}, acmeRules...)
	conn, err := tls.Dial("tcp", r.addr, &tls.Config{ServerName: "other.example.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if issuer := conn.ConnectionState().PeerCertificates[0].Issuer.Organization; len(issuer) > 0 && issuer[0] == "AerolVM egress inspection" {
		t.Fatal("an unruled host must not be inspected")
	}
	if got, _ := inspectedHost("api.example.com:8443"); got != "api.example.com" {
		t.Fatalf("inspectedHost = %q", got)
	}
	if _, ok := inspectedHost("api.example.com:8443"); ok {
		t.Fatal("a foreign port can't be this session's")
	}
	if _, ok := inspectedHost(""); ok {
		t.Fatal("no host")
	}
}

// TestInspectInject (EF-54, P3-2): the upstream gets the real header in
// place of the sandbox's placeholder; the audit names the rule and
// secret_ref but never the value; with no value the request is refused,
// never sent with the placeholder.
func TestInspectInject(t *testing.T) {
	inject := egresspolicy.RuleSpec{Host: "api.example.com", Inspect: true, Paths: []string{"/repos/**"},
		Inject: &egresspolicy.InjectSpec{Header: "Authorization", SecretRef: "env:GITHUB_TOKEN"}}
	r := newInspectRig(t, Config{}, inject)
	spec := allowSpec("api.example.com", "other.example.com")
	spec.IP = peer
	spec.Rules = []egresspolicy.RuleSpec{inject}
	spec.Secrets = map[string]string{"GITHUB_TOKEN": "Bearer ghp_real"}
	if err := r.gw.Update(spec); err != nil {
		t.Fatal(err)
	}
	c := r.client(true)
	code, body, _ := do(t, c, http.MethodGet, "https://api.example.com/repos/acme/x", "", "")
	if code != 200 || !strings.Contains(body, "auth=Bearer ghp_real") {
		t.Fatalf("injected: %d %q", code, body)
	}
	d := r.last()
	if d.Rule != "rules[0] api.example.com (inject Authorization from env:GITHUB_TOKEN)" || strings.Contains(fmt.Sprint(d), "ghp_real") {
		t.Fatalf("audit = %+v", d)
	}

	spec.Secrets = nil
	if err := r.gw.Update(spec); err != nil {
		t.Fatal(err)
	}
	code, body, _ = do(t, c, http.MethodGet, "https://api.example.com/repos/acme/x", "", "")
	if code != 403 || !strings.Contains(body, "env:GITHUB_TOKEN") || r.last().Reason != ReasonSecretMissing {
		t.Fatalf("missing secret: %d %q", code, body)
	}
}
