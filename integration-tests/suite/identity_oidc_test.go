//go:build integration

package suite

// Identity and access, SSO half (plans/identity-and-access.md §8): tokens
// from the in-harness test issuer, verified by every node against the static
// JWKS the suite installed.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// UC-275 — a test-issuer token in group payments-eng is runner on payments;
// a wrong audience is a 401; a token signed with a key the node has never
// seen triggers exactly one key refetch, however many arrive.
func TestIdentityOIDCTokenAndKeyRefetch(t *testing.T) {
	harness.Require(t, sc, "UC-275")
	fx := oidcFixture(t)
	node := fx.targets.Nodes[0]
	base := nodeBase(t, node)
	sub := "uc275-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	tok := fx.issuer.Token(t, sub, harness.GroupPaymentsEng)

	for _, where := range []string{sc.BaseURL, base} {
		who := whoamiAs(t, where, tok)
		if who.Principal.Kind != "oidc" || who.Principal.ID != "oidc:"+harness.IssuerName+":"+sub || who.Role != "runner" || who.Team != harness.TeamPayments {
			t.Fatalf("whoami at %s = %+v, want oidc:%s:%s as runner on payments", where, who, harness.IssuerName, sub)
		}
	}

	refused := func(name, token, wantReason string) {
		t.Helper()
		_, resp, err := harness.NewAPIClient(base, token).WhoAmI(context.Background())
		if err != nil || resp.Status != http.StatusUnauthorized {
			t.Fatalf("%s = %v %s, want 401", name, err, resp)
		}
		if wantReason != "" && resp.Err().Reason != wantReason {
			t.Fatalf("%s: 401 reason %q, want %q", name, resp.Err().Reason, wantReason)
		}
	}
	refused("a token for another audience", fx.issuer.Mint(t, fx.issuer.Claims(sub, "https://someone-else.example", harness.GroupPaymentsEng)), "wrong_audience")
	refused("an HS256 token keyed with the JWKS", fx.issuer.MintHS256(t, fx.issuer.Claims(sub, harness.WorkloadAudience, harness.GroupPaymentsEng)), "")
	refused("an alg:none token", harness.MintNone(fx.issuer.Claims(sub, harness.WorkloadAudience, harness.GroupPaymentsEng)), "")

	// The key refetch is rate-limited to one a minute per issuer, and the
	// fixture's reload fetched once. Wait out that minute so the first
	// unknown kid is allowed exactly one.
	issuerLabel := map[string]string{"key": harness.IssuerName}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		last := harness.MetricValueOrZero(nodeMetrics(t, base), "aerolvm_identity_jwks_last_success_timestamp", issuerLabel)
		if last > 0 && time.Since(time.Unix(int64(last), 0)) > 70*time.Second {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the node's last key fetch for %s stayed within the last minute for 3 minutes (last=%v)", harness.IssuerName, last)
		}
		time.Sleep(5 * time.Second)
	}
	fetches := func(text string) float64 {
		return harness.MetricValueOrZero(text, "aerolvm_identity_jwks_fetch_total", map[string]string{"key": harness.IssuerName, "key2": "ok"}) +
			harness.MetricValueOrZero(text, "aerolvm_identity_jwks_fetch_total", map[string]string{"key": harness.IssuerName, "key2": "error"})
	}
	before := fetches(nodeMetrics(t, base))
	for i := 0; i < 3; i++ {
		refused("a token from an unpublished key", fx.issuer.MintUnknownKey(t, fx.issuer.Claims(sub, harness.WorkloadAudience, harness.GroupPaymentsEng)), "")
	}
	if got := fetches(nodeMetrics(t, base)) - before; got != 1 {
		t.Fatalf("three unknown-kid tokens caused %v key fetches on %s, want exactly 1 (one rate-limited refetch a minute)", got, node.Name)
	}
}

// UC-276 — a sub added to deny_subjects is refused on every node: at once on
// the nodes that get a SIGHUP, within one poll on one that does not.
func TestIdentityDenySubjectsReachesEveryNode(t *testing.T) {
	harness.Require(t, sc, "UC-276")
	fx := oidcFixture(t)
	nodes := sshNodes(t, fx.targets)
	sub := "uc276-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	tok := fx.issuer.Token(t, sub, harness.GroupPaymentsEng)

	bases := make([]string, len(nodes))
	for i, node := range nodes {
		bases[i] = nodeBase(t, node)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, err := harness.AwaitAccepted(ctx, harness.NewAPIClient(bases[i], tok), 30*time.Second)
		cancel()
		if err != nil {
			t.Fatalf("before the deny entry, %s refuses the token: %v", node.Name, err)
		}
	}

	original := fx.spec
	t.Cleanup(func() {
		if err := fx.install(t, original); err != nil {
			t.Errorf("RESTORE FAILED: the identity file with %s on its deny list is still installed, and every later OIDC case is suspect: %v", sub, err)
		}
	})
	denied := original
	denied.DenySubjects = append(append([]string(nil), original.DenySubjects...), sub)
	raw, err := harness.RenderIdentityFile(denied)
	if err != nil {
		t.Fatal(err)
	}
	// One node (the last, when there are several) is left to notice the
	// change by its own poll; the rest get a SIGHUP.
	polled := len(nodes) - 1
	if len(nodes) == 1 {
		polled = -1
	}
	for i, node := range nodes {
		if err := harness.InstallNodeFile(t, node, harness.IdentityFilePath, raw); err != nil {
			t.Fatal(err)
		}
		if i != polled {
			if err := harness.ReloadNodeIdentity(t, node); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i, node := range nodes {
		limit, how := 10*time.Second, "after a SIGHUP"
		if i == polled {
			// identity.FilePollInterval (10 s) plus a poll's worth of slack.
			limit, how = 25*time.Second, "by its own poll"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		took, resp, err := harness.AwaitRefused(ctx, harness.NewAPIClient(bases[i], tok), limit)
		cancel()
		if err != nil {
			t.Fatalf("%s still accepts a denied sub %s: %v", node.Name, how, err)
		}
		if resp.Err().Reason != "unknown_or_revoked" {
			t.Errorf("%s: a denied sub's 401 reason = %q, want unknown_or_revoked", node.Name, resp.Err().Reason)
		}
		t.Logf("%s refused the denied sub %s in %s", node.Name, how, took.Round(100*time.Millisecond))
	}
}

// UC-284 — a projected Kubernetes service-account token (the k8s issuer the
// fixture installs) is runner on the bound team. The issuer's URL never
// resolves and its keys come from a file, so the request cannot have called
// any Kubernetes API.
func TestIdentityKubernetesServiceAccountToken(t *testing.T) {
	harness.Require(t, sc, "UC-284")
	fx := oidcFixture(t)
	tok := fx.issuer.K8sToken(t, harness.K8sServiceAccount)
	who := whoamiAs(t, sc.BaseURL, tok)
	if who.Principal.ID != "oidc:"+harness.K8sIssuerName+":"+harness.K8sServiceAccount || who.Role != "runner" || who.Team != harness.TeamPayments {
		t.Fatalf("whoami for the service-account token = %+v, want runner on payments", who)
	}
	errors := func() float64 {
		return harness.MetricValueOrZero(nodeMetrics(t, nodeBase(t, fx.targets.Nodes[0])), "aerolvm_identity_jwks_fetch_total",
			map[string]string{"key": harness.K8sIssuerName, "key2": "error"})
	}
	before := errors()
	sb := sandboxAs(t, tok)
	payments := mintToken(t, "uc284-pay", "runner", harness.TeamPayments)
	if resp := statusAs(t, payments.API, http.MethodGet, "/v1/sandboxes/"+sb.ID, nil); resp.Status != http.StatusOK {
		t.Fatalf("the workload's sandbox is not the payments team's: %s", resp)
	}
	if after := errors(); after != before {
		t.Fatalf("the k8s issuer's key fetches failed %v times during the request: something tried a network fetch", after-before)
	}
}

// connectRemoteMCPAs connects an MCP client to base/mcp presenting bearer.
func connectRemoteMCPAs(t *testing.T, base, bearer, sandbox string, query url.Values) (*mcp.ClientSession, error) {
	t.Helper()
	q := url.Values{"sandbox": {sandbox}}
	for k, v := range query {
		q[k] = v
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:   base + "/mcp?" + q.Encode(),
		HTTPClient: &http.Client{Transport: bearerRoundTripper{token: bearer}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "aerolvm-itest-oauth"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, nil
}

// UC-286 — remote MCP with OAuth, the way a connector meets it: an
// unauthenticated call is told where the resource metadata is, the metadata
// names the issuer, the issuer mints an access token for the /mcp audience,
// and with it the client works as runner on its team. On a cluster a tool
// call reaches a sandbox owned by another node.
func TestIdentityRemoteMCPOAuth(t *testing.T) {
	harness.Require(t, sc, "UC-286")
	fx := oidcFixture(t)
	resource := mcpResource()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1. The challenge.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, sc.BaseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	challenge := resp.Header.Get("WWW-Authenticate")
	wantMeta := "https://" + sc.Domain + "/.well-known/oauth-protected-resource/mcp"
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(challenge, `resource_metadata="`+wantMeta+`"`) {
		t.Fatalf("unauthenticated /mcp = %d, WWW-Authenticate %q; want 401 naming %s", resp.StatusCode, challenge, wantMeta)
	}

	// 2. The protected-resource metadata, through Caddy.
	var meta struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	mresp := statusAs(t, harness.NewAPIClient("", ""), http.MethodGet, wantMeta, nil)
	if mresp.Status != http.StatusOK || mresp.JSON(&meta) != nil || meta.Resource != resource || len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != fx.issuer.URL {
		t.Fatalf("resource metadata = %s, want resource %s served by %s", mresp, resource, fx.issuer.URL)
	}

	// 3. The issuer's discovery, then a client-credentials token for the
	// resource, as a connector registered with the provider would get one.
	var disc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	dresp, err := fx.issuer.Client().Get(meta.AuthorizationServers[0] + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(dresp.Body).Decode(&disc)
	dresp.Body.Close()
	const clientID = "itest-mcp-connector"
	fx.issuer.AllowMCP(resource, clientID, harness.MCPClient{Sub: "uc286-connector", Groups: []string{harness.GroupPaymentsEng}})
	tresp, err := fx.issuer.Client().PostForm(disc.TokenEndpoint, url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "resource": {resource}})
	if err != nil {
		t.Fatal(err)
	}
	var issued struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(tresp.Body).Decode(&issued)
	tresp.Body.Close()
	if tresp.StatusCode != http.StatusOK || issued.AccessToken == "" {
		t.Fatalf("token endpoint = %d", tresp.StatusCode)
	}

	// 4. The client works, as runner on payments.
	name := harness.UniqueName(sc, t)
	c := client(t)
	destroyByNameOnCleanup(t, c, name)
	cs, err := connectRemoteMCPAs(t, sc.BaseURL, issued.AccessToken, name, url.Values{"create_if_missing": {"true"}, "image": {agentImage}})
	if err != nil {
		t.Fatalf("connect to /mcp with the OAuth access token: %v", err)
	}
	tools, err := cs.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) == 0 {
		t.Fatalf("list tools: %v (%d tools)", err, len(tools.Tools))
	}
	var ex execOut
	mcpCall(t, cs, "exec", map[string]any{"command": "echo uc286"}, &ex)
	if ex.ExitCode != 0 || strings.TrimSpace(ex.Stdout) != "uc286" {
		t.Fatalf("exec through MCP = %+v", ex)
	}
	sb, err := c.SDK().GetByName(ctx, name)
	if err != nil {
		t.Fatalf("the MCP-created sandbox: %v", err)
	}
	payments := mintToken(t, "uc286-pay", "runner", harness.TeamPayments)
	if r := statusAs(t, payments.API, http.MethodGet, "/v1/sandboxes/"+sb.ID, nil); r.Status != http.StatusOK {
		t.Fatalf("the sandbox the connector made is not the payments team's: %s", r)
	}

	// 5. Refusals: a token for another resource, an opaque token, and the
	// MCP-only token anywhere but /mcp.
	wrongAud := fx.issuer.Mint(t, fx.issuer.Claims("uc286-connector", "https://elsewhere.example/mcp", harness.GroupPaymentsEng))
	for label, bearer := range map[string]string{"a token for another resource": wrongAud, "an opaque token": "opaque-" + harness.TokenName("x")} {
		if _, err := connectRemoteMCPAs(t, sc.BaseURL, bearer, name, nil); err == nil {
			t.Errorf("/mcp accepted %s", label)
		}
	}
	if r := statusAs(t, harness.NewAPIClient(sc.BaseURL, issued.AccessToken), http.MethodGet, "/v1/sandboxes", nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("the /mcp access token on /v1/sandboxes = %s, want 401: an MCP-only token must not act on the API", r)
	}

	// 6. Cluster: a node that does not own the sandbox serves the tool call
	// by forwarding it (X-Cluster-Surface: mcp).
	if sc.Has(harness.CapCluster) {
		other := nonOwnerAPI(t, c, sb.ID)
		cs2, err := connectRemoteMCPAs(t, other, issued.AccessToken, name, nil)
		if err != nil {
			t.Fatalf("connect to a non-owner node's /mcp: %v", err)
		}
		var ex2 execOut
		mcpCall(t, cs2, "exec", map[string]any{"command": "echo uc286-forwarded"}, &ex2)
		if ex2.ExitCode != 0 || strings.TrimSpace(ex2.Stdout) != "uc286-forwarded" {
			t.Fatalf("exec through a non-owner node = %+v", ex2)
		}
	}
}

// crossBuildAerolvm builds the CLI for the node's architecture.
func crossBuildAerolvm(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, "uname -m")
	if err != nil {
		t.Fatalf("uname on %s: %v %s", node.Name, err, out)
	}
	arch := "amd64"
	if strings.Contains(out, "aarch64") || strings.Contains(out, "arm64") {
		arch = "arm64"
	}
	bin := filepath.Join(t.TempDir(), "aerolvm-linux-"+arch)
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/aerolvm")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-build aerolvm for linux/%s: %v\n%s", arch, err, b)
	}
	return bin
}

// UC-282 — `aerolvm login --sso --device` against the test issuer, run on a
// node (the operator's macOS trust store cannot be pointed at the issuer's
// certificate; Linux honors SSL_CERT_FILE) that reaches the issuer through
// a reverse forward at the URL the identity file names. The saved login
// works, and after the ID token expires the CLI refreshes it.
func TestIdentityCLIDeviceLogin(t *testing.T) {
	harness.Require(t, sc, "UC-282")
	fx := oidcFixture(t)
	node := fx.targets.Nodes[0]
	harness.RequireNodeSSH(t, node)
	target, _ := harness.SSHTarget(node)
	bin := crossBuildAerolvm(t, node)

	dir := "/tmp/aerolvm-itest-sso-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() { _, _ = harness.SSHRun(t, target, "rm -rf "+dir) })
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := harness.SSHRunStdin(t, target, "mkdir -p "+dir+"/config && cat > "+dir+"/aerolvm && chmod 0755 "+dir+"/aerolvm && echo COPIED", string(raw)); err != nil || !strings.Contains(out, "COPIED") {
		t.Fatalf("copy the CLI to %s: %v %s", node.Name, err, out)
	}
	if out, err := harness.SSHRunStdin(t, target, "cat > "+dir+"/ca.pem && echo COPIED", string(fx.issuer.CertificatePEM())); err != nil || !strings.Contains(out, "COPIED") {
		t.Fatalf("copy the issuer certificate: %v %s", err, out)
	}
	harness.SSHReverseForward(t, node, fx.issuer.Port())

	sub := "uc282-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fx.issuer.SetDeviceUser(harness.DeviceUser{Sub: sub, Groups: []string{harness.GroupPaymentsEng}})
	const ttl = 75 * time.Second
	fx.issuer.SetIDTokenTTL(ttl)
	t.Cleanup(func() { fx.issuer.SetIDTokenTTL(10 * time.Minute) })

	cli := func(args string) (string, error) {
		env := fmt.Sprintf("env -u SB_PAT_TOKEN -u SB_API_TOKEN -u SB_API_URL XDG_CONFIG_HOME=%s/config SSL_CERT_FILE=%s/ca.pem", dir, dir)
		return harness.SSHRun(t, target, "cd "+dir+" && "+env+" ./aerolvm "+args+" </dev/null 2>&1")
	}
	out, err := cli("login --sso --device --issuer " + harness.IssuerName + " http://127.0.0.1:21212")
	if err != nil {
		t.Fatalf("aerolvm login --sso --device: %v\n%s", err, out)
	}
	if fx.issuer.DeviceGrants.Load() == 0 {
		t.Fatalf("the login finished without spending a device code at the issuer:\n%s", out)
	}
	principal := "oidc:" + harness.IssuerName + ":" + sub
	out, err = cli("whoami --json")
	if err != nil || !strings.Contains(out, principal) || !strings.Contains(out, "runner") {
		t.Fatalf("whoami on the saved login: %v\n%s\nwant %s as runner", err, out, principal)
	}

	refreshes := fx.issuer.RefreshGrants.Load()
	time.Sleep(ttl + 10*time.Second)
	out, err = cli("whoami --json")
	if err != nil || !strings.Contains(out, principal) {
		t.Fatalf("whoami after the ID token expired: %v\n%s", err, out)
	}
	if fx.issuer.RefreshGrants.Load() <= refreshes {
		t.Fatalf("whoami worked after the ID token expired but the CLI never spent its refresh token:\n%s", out)
	}
}

// UC-290 — the dashboard over HTTPS with the test issuer. The browser half
// (sign-in buttons render, the plain-HTTP page shows the HTTPS pointer) is
// T8's /browse check; here every server-side piece the sign-in depends on
// is live: discovery names /ui and the issuer's dashboard client, /ui is
// served through Caddy with its CSP, the ID token the SPA would hold shows
// the bound role, and a token with no binding gets the screen's 403 fields.
func TestIdentityDashboardSignInServerSide(t *testing.T) {
	harness.Require(t, sc, "UC-290")
	fx := oidcFixture(t)
	anon := harness.NewAPIClient(sc.BaseURL, "")

	dresp := statusAs(t, anon, http.MethodGet, identitywire.AuthDiscoveryPath, nil)
	var disc identitywire.AuthDiscovery
	if dresp.Status != http.StatusOK || dresp.JSON(&disc) != nil {
		t.Fatalf("discovery = %s", dresp)
	}
	if disc.UIURL != "https://"+sc.Domain+"/ui" || !disc.IdentityEnabled {
		t.Fatalf("discovery ui_url = %q identity_enabled = %v, want https://%s/ui", disc.UIURL, disc.IdentityEnabled, sc.Domain)
	}
	found := false
	for _, iss := range disc.Issuers {
		if iss.Name == harness.IssuerName && iss.Clients.Dashboard == harness.DashboardClientID && iss.URL == fx.issuer.URL {
			found = true
		}
		if iss.Name == harness.K8sIssuerName {
			t.Errorf("discovery lists the k8s workload issuer, which has no sign-in")
		}
	}
	if !found {
		t.Fatalf("discovery does not offer the test issuer's dashboard client: %+v", disc.Issuers)
	}

	ui := statusAs(t, anon, http.MethodGet, "/ui", nil)
	csp := ui.Header.Get("Content-Security-Policy")
	if ui.Status != http.StatusOK || !bytes.Contains(ui.Body, []byte("AerolVM")) || !strings.Contains(csp, "script-src") || !strings.Contains(csp, "'sha256-") {
		t.Fatalf("/ui over HTTPS = %d, CSP %q; want the page with a hash-pinned script-src (D19)", ui.Status, csp)
	}

	admin := fx.issuer.Mint(t, fx.issuer.Claims("uc290-admin", harness.DashboardClientID, harness.GroupAdmins))
	if who := whoamiAs(t, sc.BaseURL, admin); who.Role != "admin" || who.Team != "*" {
		t.Fatalf("whoami with a dashboard ID token for %s = %+v, want admin on *", harness.GroupAdmins, who)
	}
	nobody := fx.issuer.Mint(t, fx.issuer.Claims("uc290-nobody", harness.DashboardClientID, "unbound-group"))
	resp := statusAs(t, harness.NewAPIClient(sc.BaseURL, nobody), http.MethodGet, "/v1/whoami", nil)
	e := resp.Err()
	if resp.Status != http.StatusForbidden || e.Reason != "no_binding" || e.Issuer != harness.IssuerName || len(e.Groups) != 1 || e.Groups[0] != "unbound-group" {
		t.Fatalf("a dashboard token with no binding = %s, want 403 no_binding naming issuer %s and the caller's group (DR8)", resp, harness.IssuerName)
	}
}
