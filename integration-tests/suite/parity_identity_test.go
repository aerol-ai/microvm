//go:build integration

package suite

// Live checks for a cloud identity per sandbox (plans/sandbox-cloud-identity.md,
// plan row D1). The token is verified against the JWKS the deployment
// publishes, which is exactly what AWS STS, Google STS and Entra ID do; the
// suite does not call a real cloud's STS, because that needs an IAM OIDC
// provider trusting the leased test domain, which Terraform would have to
// create before the nodes that serve the documents exist.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/internal/cloudidentity"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const identityTestRoleARN = "arn:aws:iam::123456789012:role/aerolvm-itest"

// identityTag is a role tag unique to this run, so concurrent scenarios on
// one deployment never share a tag.
func identityTag(t *testing.T, prefix string) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

// allowIdentityTag puts a tag on a team's allow list (team "" is the
// operator namespace) with the suite's admin credential, and removes it when
// the test ends.
func allowIdentityTag(t *testing.T, team, tag, minRole string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sdk := client(t).SDK()
	role, err := sdk.PutIdentityRole(ctx, tag, sdktypes.IdentityRoleOptions{MinRole: minRole, Team: team})
	if err != nil {
		t.Fatalf("put identity role %s for team %q: %v", tag, team, err)
	}
	if role.Tag != tag || role.MinRole != minRole {
		t.Fatalf("put identity role = %+v", role)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if err := sdk.DeleteIdentityRole(cctx, tag, team); err != nil {
			t.Logf("cleanup: delete identity role %s: %v", tag, err)
		}
	})
}

// publicGet fetches a path with no credential at all, as a cloud would.
func identityPublicGet(t *testing.T, ctx context.Context, base, path string) (int, []byte, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := harness.HTTPClient(30 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("GET %s%s: %v", base, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, resp.Header
}

func publicJWKS(t *testing.T, ctx context.Context, base string) []byte {
	t.Helper()
	st, body, _ := identityPublicGet(t, ctx, base, cloudidentity.JWKSPath)
	if st != http.StatusOK {
		t.Fatalf("JWKS from %s = %d %s", base, st, body)
	}
	return body
}

// identitySandbox creates a running sandbox with an identity for tag.
func identitySandbox(t *testing.T, tag string, mutate func(*sdktypes.CreateSandboxOptions)) *microvm.Sandbox {
	t.Helper()
	opts := sdktypes.CreateSandboxOptions{
		Name:     harness.UniqueName(sc, t),
		Identity: &sdktypes.IdentityOptions{RoleTag: tag, AWSRoleARN: identityTestRoleARN},
	}
	if mutate != nil {
		mutate(&opts)
	}
	sb := client(t).NewSandbox(t, opts)
	waitRunning(t, sb)
	return sb
}

// readIdentityToken waits until the sandbox's token file holds a token
// other than not, and returns it.
func readIdentityToken(t *testing.T, ctx context.Context, sb *microvm.Sandbox, not string, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		res, err := sb.ExecCommand(ctx, "cat "+cloudidentity.TokenFile+" 2>/dev/null")
		if err == nil {
			if tok := strings.TrimSpace(res.Stdout); tok != "" && tok != not {
				return tok
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s: no new identity token within %s (last exec error %v)", sb.ID, within, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func apiStatus(err error) int {
	var apiErr *microvm.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// UC-431 — the discovery document and the JWKS are public and read-only,
// and hold public keys only (security point 4).
func TestParityIdentityDocumentsArePublic(t *testing.T) {
	harness.Require(t, sc, "UC-431")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, body, hdr := identityPublicGet(t, ctx, sc.BaseURL, cloudidentity.DiscoveryPath)
	if st != http.StatusOK {
		t.Fatalf("discovery without a credential = %d %s", st, body)
	}
	var doc struct {
		Issuer  string   `json:"issuer"`
		JWKSURI string   `json:"jwks_uri"`
		Algs    []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("discovery body: %v (%s)", err, body)
	}
	want := strings.ToLower(strings.TrimRight(sc.BaseURL, "/"))
	if doc.Issuer != want || doc.JWKSURI != want+cloudidentity.JWKSPath || len(doc.Algs) != 1 || doc.Algs[0] != "RS256" {
		t.Fatalf("discovery = %+v, want issuer %s", doc, want)
	}
	if !strings.Contains(hdr.Get("Cache-Control"), "max-age") {
		t.Fatalf("discovery Cache-Control = %q", hdr.Get("Cache-Control"))
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(publicJWKS(t, ctx, sc.BaseURL), &jwks); err != nil || len(jwks.Keys) == 0 {
		t.Fatalf("JWKS = %+v %v", jwks, err)
	}
	for _, k := range jwks.Keys {
		if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" || k["kid"] == "" {
			t.Fatalf("JWKS key = %v", k)
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, ok := k[private]; ok {
				t.Fatalf("the public JWKS carries private member %q", private)
			}
		}
	}
	// Read-only: nothing else is served there.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(sc.BaseURL, "/")+cloudidentity.JWKSPath, strings.NewReader("{}"))
	resp, err := harness.HTTPClient(30 * time.Second).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST to the JWKS = %d, want 405", resp.StatusCode)
	}
}

// UC-432 — the first token lands soon after the create returns (D1.8 gap,
// logged), with the AWS env, and verifies with the public JWKS.
func TestParityIdentityTokenInSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-432")
	tag := identityTag(t, "uc432")
	allowIdentityTag(t, "", tag, "runner")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	sb := identitySandbox(t, tag, nil)
	created := time.Now()
	tok := readIdentityToken(t, ctx, sb, "", 60*time.Second)
	gap := time.Since(created)
	t.Logf("D1.8: first identity token readable %s after the create returned (includes exec round trips)", gap.Round(time.Millisecond))
	if gap > 30*time.Second {
		t.Fatalf("the first token took %s; D1.8 says to move the push onto the create path above 1 s at p99", gap)
	}
	claims, err := cloudidentity.Verify(tok, publicJWKS(t, ctx, sc.BaseURL), time.Now())
	if err != nil {
		t.Fatalf("token does not verify with the public JWKS: %v", err)
	}
	if err := sb.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if sb.Identity == nil {
		t.Fatal("the sandbox shows no identity")
	}
	issuer := strings.ToLower(strings.TrimRight(sc.BaseURL, "/"))
	if claims.Subject != sb.Identity.Subject || !strings.HasSuffix(claims.Subject, ":role:"+tag) || claims.Role != tag ||
		claims.Audience != cloudidentity.DefaultAudience || claims.Sandbox != sb.ID || claims.Issuer != issuer ||
		claims.Expiry-claims.IssuedAt != 3600 || claims.IssuedAt-claims.NotBefore != 60 {
		t.Fatalf("claims = %+v (sandbox shows subject %q)", claims, sb.Identity.Subject)
	}
	env := parityExec(t, ctx, sb, `printf '%s|%s|%s' "$AEROLVM_IDENTITY_TOKEN_FILE" "$AWS_WEB_IDENTITY_TOKEN_FILE" "$AWS_ROLE_ARN"`)
	if env != cloudidentity.TokenFile+"|"+cloudidentity.TokenFile+"|"+identityTestRoleARN {
		t.Fatalf("identity env = %q", env)
	}
	if mode := parityExec(t, ctx, sb, "stat -c %a "+cloudidentity.TokenFile); mode != "644" {
		t.Fatalf("token file mode = %s, want 644", mode)
	}
	// The server's own measurement of the same gap (D1.8).
	st, body := fcDo(t, ctx, http.MethodGet, "", "/v1/metrics", nil, nil)
	if st == http.StatusOK {
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "aerolvm_identity_first_token_seconds") {
				t.Logf("%s", line)
			}
		}
	}
}

// UC-433 — a stopped and started sandbox gets a fresh token at once.
func TestParityIdentityTokenAfterRestart(t *testing.T) {
	harness.Require(t, sc, "UC-433")
	tag := identityTag(t, "uc433")
	allowIdentityTag(t, "", tag, "runner")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sb := identitySandbox(t, tag, nil)
	first := readIdentityToken(t, ctx, sb, "", 60*time.Second)
	jwks := publicJWKS(t, ctx, sc.BaseURL)
	before, err := cloudidentity.Verify(first, jwks, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sdk := client(t).SDK()
	if _, err := sdk.Stop(ctx, sb.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	time.Sleep(time.Second) // a new token is at least a second later, so exp moves
	started, err := sdk.Start(ctx, sb.ID)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	waitRunning(t, started)
	second := readIdentityToken(t, ctx, started, first, 60*time.Second)
	after, err := cloudidentity.Verify(second, publicJWKS(t, ctx, sc.BaseURL), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if after.ID == before.ID || after.Expiry <= before.Expiry || after.Subject != before.Subject {
		t.Fatalf("after a restart: before %+v, after %+v", before, after)
	}
	if err := started.Refresh(ctx); err != nil || started.Identity == nil || started.Identity.TokenExpiresAt == nil {
		t.Fatalf("the sandbox does not show its token's expiry: %v %+v", err, started.Identity)
	}
}

// UC-434 — D1.5 live: a tag not on the team's list is 403, a runner asking
// for an admin-only tag is 403, and an allowed tag's subject names the
// caller's own team (security points 3 and 6).
func TestParityIdentityAllowList(t *testing.T) {
	harness.Require(t, sc, "UC-434")
	dev, prod := identityTag(t, "uc434-dev"), identityTag(t, "uc434-prod")
	allowIdentityTag(t, harness.TeamPayments, dev, "runner")
	allowIdentityTag(t, harness.TeamPayments, prod, "admin")
	tok := mintToken(t, "uc434", "runner", harness.TeamPayments)
	runner := sdkFor(t, tok.Secret)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	for _, tc := range []struct{ name, tag string }{
		{"a tag not on the list", identityTag(t, "uc434-none")},
		{"an admin-only tag", prod},
	} {
		sb, err := runner.Create(ctx, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Name: harness.UniqueName(sc, t),
			Identity: &sdktypes.IdentityOptions{RoleTag: tc.tag}})
		if err == nil {
			_ = runner.Destroy(context.Background(), sb.ID)
			t.Fatalf("%s: create succeeded", tc.name)
		}
		if apiStatus(err) != http.StatusForbidden {
			t.Fatalf("%s: create = %v, want 403", tc.name, err)
		}
	}
	sb, err := runner.Create(ctx, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Name: harness.UniqueName(sc, t),
		Identity: &sdktypes.IdentityOptions{RoleTag: dev}})
	if err != nil {
		t.Fatalf("allowed tag: %v", err)
	}
	t.Cleanup(func() { _ = runner.Destroy(context.Background(), sb.ID) })
	if sb.Identity == nil || sb.Identity.Subject != "team:"+harness.TeamPayments+":role:"+dev {
		t.Fatalf("subject = %+v, want the runner's own team", sb.Identity)
	}
}

// UC-435 — the push route is not reachable through the toolbox proxy
// (security point 5), and identity env a create sets differently is 400.
func TestParityIdentityPushRouteAndEnvConflict(t *testing.T) {
	harness.Require(t, sc, "UC-435")
	tag := identityTag(t, "uc435")
	allowIdentityTag(t, "", tag, "runner")
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	sb := identitySandbox(t, tag, nil)
	first := readIdentityToken(t, ctx, sb, "", 60*time.Second)
	forged := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.eA"
	st, body := fcDo(t, ctx, http.MethodPut, "", "/v1/sandboxes/"+sb.ID+"/toolbox/admin/identity/token", map[string]string{"token": forged}, nil)
	if st != http.StatusNotFound {
		t.Fatalf("PUT the push route through the proxy = %d %s, want 404", st, body)
	}
	if got := readIdentityToken(t, ctx, sb, "", 10*time.Second); got != first {
		t.Fatal("a push through the proxy changed the token file")
	}
	_, err := client(t).SDK().Create(ctx, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Name: harness.UniqueName(sc, t),
		Env:      map[string]string{cloudidentity.EnvAWSRoleARN: "arn:aws:iam::999999999999:role/other"},
		Identity: &sdktypes.IdentityOptions{RoleTag: tag, AWSRoleARN: identityTestRoleARN}})
	if apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a create whose env contradicts its identity = %v, want 400", err)
	}
}

// UC-436 — in a cluster a token signed on the sandbox's owner verifies with
// the JWKS every node serves (the cluster check of the design's section 5).
func TestParityIdentityTokenVerifiesOnEveryNode(t *testing.T) {
	harness.Require(t, sc, "UC-436")
	targets := identityTargets(t)
	if len(targets.Nodes) < 2 {
		t.Skip("needs two nodes")
	}
	tag := identityTag(t, "uc436")
	allowIdentityTag(t, "", tag, "runner")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sb := identitySandbox(t, tag, nil)
	tok := readIdentityToken(t, ctx, sb, "", 60*time.Second)
	for _, node := range targets.Nodes {
		base := nodeBase(t, node)
		claims, err := cloudidentity.Verify(tok, publicJWKS(t, ctx, base), time.Now())
		if err != nil || claims.Sandbox != sb.ID {
			t.Fatalf("node %s: the token does not verify with its JWKS: %v", node.Name, err)
		}
	}
	t.Logf("token from sandbox %s verified with the JWKS of %d nodes", sb.ID, len(targets.Nodes))
}

// UC-437 — taking a tag off the list stops new tokens (revocation, security
// point 8): a restarted sandbox that used it gets none and says why.
func TestParityIdentityRemovedTagStopsTokens(t *testing.T) {
	harness.Require(t, sc, "UC-437")
	tag := identityTag(t, "uc437")
	sdk := client(t).SDK()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if _, err := sdk.PutIdentityRole(ctx, tag, sdktypes.IdentityRoleOptions{MinRole: "runner"}); err != nil {
		t.Fatal(err)
	}
	sb := identitySandbox(t, tag, nil)
	first := readIdentityToken(t, ctx, sb, "", 60*time.Second)
	if err := sdk.DeleteIdentityRole(ctx, tag, ""); err != nil {
		t.Fatal(err)
	}
	// A worker reads the allow list through a 10 s cache.
	time.Sleep(12 * time.Second)
	if _, err := sdk.Stop(ctx, sb.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	started, err := sdk.Start(ctx, sb.ID)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	waitRunning(t, started)
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := started.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		if started.Identity != nil && strings.Contains(started.Identity.LastError, "removed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sandbox never said its tag was removed: %+v", started.Identity)
		}
		time.Sleep(2 * time.Second)
	}
	res, err := started.ExecCommand(ctx, "cat "+cloudidentity.TokenFile+" 2>/dev/null")
	if err == nil {
		if got := strings.TrimSpace(res.Stdout); got != "" && got != first {
			t.Fatal("a sandbox whose tag was removed got a new token")
		}
	}
}
