package harness

import (
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/aerol-ai/microvm/internal/identity"
)

// verifyLikeANode checks token against the JWKS the suite would push, the
// way a node with a jwks_file does: no discovery, keys from the static set.
func verifyLikeANode(t *testing.T, jwks []byte, issuerURL, audience, token string) (*oidc.IDToken, error) {
	t.Helper()
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatalf("JWKS does not parse: %v", err)
	}
	var pubs []crypto.PublicKey
	for _, k := range set.Keys {
		pubs = append(pubs, k.Key)
	}
	ks := &oidc.StaticKeySet{PublicKeys: pubs}
	v := oidc.NewVerifier(issuerURL, ks, &oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})
	return v.Verify(t.Context(), token)
}

func TestTestIssuerMintsTokensTheJWKSVerifies(t *testing.T) {
	iss := NewTestIssuer(t)
	t.Cleanup(iss.Close)
	if !strings.HasPrefix(iss.URL, "https://127.0.0.1:") || iss.Port() == "" {
		t.Fatalf("issuer URL %q, port %q: the reverse forward reuses the port, so the URL must be loopback with one", iss.URL, iss.Port())
	}

	tok := iss.Token(t, "ana", GroupPaymentsEng)
	idt, err := verifyLikeANode(t, iss.JWKS(), iss.URL, WorkloadAudience, tok)
	if err != nil {
		t.Fatalf("a minted token does not verify against the pushed JWKS: %v", err)
	}
	var claims struct {
		Groups []string `json:"groups"`
		Email  string   `json:"email"`
	}
	if err := idt.Claims(&claims); err != nil || idt.Subject != "ana" || len(claims.Groups) != 1 || claims.Groups[0] != GroupPaymentsEng {
		t.Fatalf("claims = sub %q %+v (%v)", idt.Subject, claims, err)
	}

	// Rotation keeps the old key published, so tokens already out keep
	// verifying, and signs new ones with the new key.
	oldKID := iss.SigningKeyID()
	newKID := iss.Rotate(t)
	if newKID == oldKID {
		t.Fatal("rotate kept the signing key")
	}
	if _, err := verifyLikeANode(t, iss.JWKS(), iss.URL, WorkloadAudience, tok); err != nil {
		t.Fatalf("a token signed before the rotation no longer verifies: %v", err)
	}
	if _, err := verifyLikeANode(t, iss.JWKS(), iss.URL, WorkloadAudience, iss.Token(t, "ana")); err != nil {
		t.Fatalf("a token signed after the rotation does not verify: %v", err)
	}

	// The negative helpers produce what their names say.
	if _, err := verifyLikeANode(t, iss.JWKS(), iss.URL, WorkloadAudience, iss.MintUnknownKey(t, iss.Claims("ana", WorkloadAudience))); err == nil {
		t.Fatal("a token from an unpublished key verified")
	}
	if _, err := verifyLikeANode(t, iss.JWKS(), iss.URL, WorkloadAudience, iss.MintHS256(t, iss.Claims("ana", WorkloadAudience))); err == nil {
		t.Fatal("an HS256 token verified")
	}
	if none := MintNone(iss.Claims("ana", WorkloadAudience)); !strings.HasSuffix(none, ".") {
		t.Fatalf("alg:none token %q has a signature", none)
	}

	// The k8s issuer has its own key set: its tokens verify against it and
	// not against the main issuer's.
	k8s := iss.K8sToken(t, K8sServiceAccount)
	if _, err := verifyLikeANode(t, iss.K8sJWKS(), K8sIssuerURL, K8sAudience, k8s); err != nil {
		t.Fatalf("k8s token: %v", err)
	}
	if _, err := verifyLikeANode(t, iss.JWKS(), K8sIssuerURL, K8sAudience, k8s); err == nil {
		t.Fatal("a k8s token verified against the main issuer's keys")
	}
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := c.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// The device and refresh grants are what `aerolvm login --sso --device`
// spends (UC-282); the client-credentials grant is the MCP connector
// (UC-286).
func TestTestIssuerEndpoints(t *testing.T) {
	iss := NewTestIssuer(t)
	t.Cleanup(iss.Close)
	c := iss.Client()

	resp, err := c.Get(iss.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disc struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		Device        string `json:"device_authorization_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if disc.Issuer != iss.URL || disc.TokenEndpoint != iss.URL+"/token" || disc.Device != iss.URL+"/device" || disc.JWKS != iss.URL+"/jwks" {
		t.Fatalf("discovery = %+v", disc)
	}
	// The served key set is the one the suite pushes as the jwks_file.
	jresp, err := c.Get(disc.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	served, _ := io.ReadAll(jresp.Body)
	jresp.Body.Close()
	if string(served) != string(iss.JWKS()) {
		t.Fatalf("served JWKS %s differs from the pushed one %s", served, iss.JWKS())
	}

	iss.SetDeviceUser(DeviceUser{Sub: "dev", Groups: []string{GroupCheckoutEng}})
	iss.SetIDTokenTTL(90 * time.Second)
	code, da := postForm(t, c, iss.URL+"/device", url.Values{"client_id": {CLIClientID}, "scope": {"openid"}})
	if code != http.StatusOK || da["device_code"] == "" || da["user_code"] == "" || da["interval"] != float64(1) {
		t.Fatalf("device authorization = %d %v", code, da)
	}
	code, tok := postForm(t, c, iss.URL+"/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da["device_code"].(string)}, "client_id": {CLIClientID},
	})
	if code != http.StatusOK || tok["refresh_token"] == "" {
		t.Fatalf("device token = %d %v", code, tok)
	}
	idt, err := verifyLikeANode(t, iss.JWKS(), iss.URL, CLIClientID, tok["id_token"].(string))
	if err != nil || idt.Subject != "dev" || time.Until(idt.Expiry) > 2*time.Minute {
		t.Fatalf("device ID token: %v %+v", err, idt)
	}
	// A device code is good once.
	if code, _ := postForm(t, c, iss.URL+"/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da["device_code"].(string)}, "client_id": {CLIClientID},
	}); code != http.StatusBadRequest {
		t.Fatalf("a spent device code = %d", code)
	}

	refresh := tok["refresh_token"].(string)
	code, again := postForm(t, c, iss.URL+"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {CLIClientID}})
	if code != http.StatusOK || again["id_token"] == "" || again["refresh_token"] == refresh {
		t.Fatalf("refresh = %d %v", code, again)
	}
	// Refresh tokens rotate: the spent one is refused.
	if code, _ := postForm(t, c, iss.URL+"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}); code != http.StatusBadRequest {
		t.Fatalf("a spent refresh token = %d", code)
	}
	if iss.DeviceGrants.Load() != 2 || iss.RefreshGrants.Load() != 2 {
		t.Fatalf("grant counters = device %d refresh %d", iss.DeviceGrants.Load(), iss.RefreshGrants.Load())
	}

	const resource = "https://itest.example/mcp"
	iss.AllowMCP(resource, "connector", MCPClient{Sub: "connector-sub", Groups: []string{GroupPaymentsEng}})
	code, at := postForm(t, c, iss.URL+"/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {"connector"}, "resource": {resource}})
	if code != http.StatusOK {
		t.Fatalf("client credentials = %d %v", code, at)
	}
	if _, err := verifyLikeANode(t, iss.JWKS(), iss.URL, resource, at["access_token"].(string)); err != nil {
		t.Fatalf("the MCP access token's audience is not the resource: %v", err)
	}
	for name, form := range map[string]url.Values{
		"unknown client":   {"grant_type": {"client_credentials"}, "client_id": {"other"}, "resource": {resource}},
		"unknown audience": {"grant_type": {"client_credentials"}, "client_id": {"connector"}, "resource": {"https://elsewhere/mcp"}},
		"unknown grant":    {"grant_type": {"password"}},
	} {
		if code, _ := postForm(t, c, iss.URL+"/token", form); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, code)
		}
	}
	if code, _ := postForm(t, c, iss.URL+"/device", url.Values{}); code != http.StatusBadRequest {
		t.Errorf("device authorization without a client = %d", code)
	}
	if resp, err := c.Get(iss.URL + "/authorize"); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("browser sign-in = %v %v", resp, err)
	}
	if pem := iss.CertificatePEM(); !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Errorf("certificate PEM = %q", pem)
	}
}

// The identity file the suite pushes must be one the daemon loads, and must
// grant exactly the roles the use cases assert.
func TestRenderIdentityFileLoadsAndBinds(t *testing.T) {
	const issuerURL = "https://127.0.0.1:45678"
	raw, err := RenderIdentityFile(IdentityFileSpec{IssuerURL: issuerURL, MCPResource: "https://itest.example/mcp", DenySubjects: []string{"mallory"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := identity.Parse(raw)
	if err != nil {
		t.Fatalf("the daemon refuses the rendered file: %v\n%s", err, raw)
	}
	main, ok := cfg.IssuerByName(IssuerName)
	if !ok || main.URL != issuerURL || main.JWKSFile != IssuerJWKSPath || !main.MCP || main.ClientCLI != CLIClientID || main.ClientDashboard != DashboardClientID {
		t.Fatalf("issuer = %+v", main)
	}
	if k8s, ok := cfg.IssuerByName(K8sIssuerName); !ok || k8s.JWKSFile != K8sJWKSPath || k8s.URL != K8sIssuerURL {
		t.Fatalf("k8s issuer = %+v", k8s)
	}
	if cfg.MCPResource != "https://itest.example/mcp" || len(cfg.MCPAuthorizationServers()) != 1 {
		t.Fatalf("mcp = %q %v", cfg.MCPResource, cfg.MCPAuthorizationServers())
	}
	if !cfg.Denied(IssuerName, "mallory") || cfg.Denied(IssuerName, "ana") {
		t.Fatal("deny list does not hold exactly the listed sub")
	}
	want := map[string]string{
		GroupPaymentsEng:     "runner/payments",
		GroupCheckoutEng:     "runner/checkout",
		GroupPaymentsViewers: "viewer/payments",
		GroupFleetViewers:    "viewer/*",
		GroupAuditors:        "auditor/*",
		GroupAdmins:          "admin/*",
	}
	got := map[string]string{}
	var k8sBinding bool
	for _, b := range cfg.Bindings {
		if b.Issuer == K8sIssuerName {
			k8sBinding = b.Claim["sub"] == K8sServiceAccount && string(b.Role) == "runner" && b.Team == TeamPayments
			continue
		}
		got[b.Group] = string(b.Role) + "/" + b.Team
	}
	for g, rt := range want {
		if got[g] != rt {
			t.Errorf("group %s binds %q, want %q", g, got[g], rt)
		}
	}
	if !k8sBinding {
		t.Error("no claim binding grants the k8s service account runner on payments")
	}

	// No domain, no MCP section; no issuer URL, no file.
	raw, err = RenderIdentityFile(IdentityFileSpec{IssuerURL: issuerURL})
	if err != nil {
		t.Fatal(err)
	}
	if cfg, _ := identity.Parse(raw); cfg.MCPResource != "" {
		t.Fatalf("mcp configured without a resource: %q", cfg.MCPResource)
	}
	if _, err := RenderIdentityFile(IdentityFileSpec{}); err == nil {
		t.Fatal("rendered a file with no issuer URL")
	}
	// An http issuer is one the daemon refuses: the renderer must say so
	// here rather than leave every node answering 503.
	if _, err := RenderIdentityFile(IdentityFileSpec{IssuerURL: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("rendered a file the daemon would refuse")
	}
}

func TestIdentityFilePushScripts(t *testing.T) {
	fake := &fakeSSH{active: "active"}
	fake.install(t)
	var stdinScript, stdin string
	prev := sshRunnerStdin
	sshRunnerStdin = func(_ *testing.T, _ string, script, in string) (string, error) {
		stdinScript, stdin = script, in
		return "INSTALLED\n", nil
	}
	t.Cleanup(func() { sshRunnerStdin = prev })

	if err := InstallNodeFile(t, testNode(), IssuerJWKSPath, []byte(`{"keys":[]}`)); err != nil {
		t.Fatal(err)
	}
	if stdin != `{"keys":[]}` || strings.Contains(stdinScript, "keys") {
		t.Fatalf("the content must travel on stdin only: script %q stdin %q", stdinScript, stdin)
	}
	for _, want := range []string{"mktemp", "chmod 0644", `mv -f "$tmp" "` + IssuerJWKSPath + `"`} {
		if !strings.Contains(stdinScript, want) {
			t.Errorf("install script lacks %q (atomic rename): %s", want, stdinScript)
		}
	}

	// A script that never confirms is a failure, not a silent success.
	sshRunnerStdin = func(*testing.T, string, string, string) (string, error) { return "permission denied", nil }
	if err := InstallNodeFile(t, testNode(), IssuerJWKSPath, nil); err == nil {
		t.Fatal("an unconfirmed install reported success")
	}
	if err := InstallNodeFile(t, IntegrationNode{Name: "x"}, IssuerJWKSPath, nil); err == nil {
		t.Fatal("installed on a node with no address")
	}

	fake2 := &fakeSSH{active: "active"}
	fake2.install(t)
	sshRunner = func(_ *testing.T, _ string, script string) (string, error) {
		fake2.mu.Lock()
		fake2.runs = append(fake2.runs, script)
		fake2.mu.Unlock()
		return "RELOADED\n", nil
	}
	if err := ReloadNodeIdentity(t, testNode()); err != nil {
		t.Fatal(err)
	}
	if !fake2.ran("--kill-who=main --signal=HUP sandboxd") {
		t.Fatalf("reload must SIGHUP only sandboxd's main process: %v", fake2.runs)
	}
	sshRunner = func(*testing.T, string, string) (string, error) { return "", nil }
	if err := ReloadNodeIdentity(t, testNode()); err == nil {
		t.Fatal("an unconfirmed reload reported success")
	}
}
