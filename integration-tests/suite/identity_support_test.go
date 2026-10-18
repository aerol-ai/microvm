//go:build integration

package suite

// Shared setup for the identity use cases (plans/identity-and-access.md
// T12, UC-268..UC-294): the in-harness test issuer and the identity file it
// installs on every node, team avm_ tokens minted with the operator
// credential, and per-node API addresses.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// tokenPropagation bounds how long a fresh token may take to work on a node:
// one mirror sync (~5 s) on a worker without Raft state, plus slack.
const tokenPropagation = 30 * time.Second

// operatorAPI is the scenario's own credential against the API domain: the
// PAT, or under SB_PAT_SCOPE=host the admin token run.sh minted with it.
func operatorAPI() *harness.APIClient { return harness.NewAPIClient(sc.BaseURL, sc.PAT) }

// mintedToken is an API token a case minted, with a client that presents it.
type mintedToken struct {
	ID     string
	Secret string
	API    *harness.APIClient
}

// mintToken creates an API token with the operator credential, revokes it
// when the test ends, and waits until every node that will authenticate it
// accepts it. This is the D4 replacement for the deleted static token file.
func mintToken(t *testing.T, prefix, role, team string) mintedToken {
	t.Helper()
	return mintTokenFor(t, operatorAPI(), prefix, role, team, "2h", true)
}

// mintTokenFor mints through admin (any address, any minting credential)
// with a chosen lifetime; await waits until the token is accepted wherever
// it will be used (awaitTokenWhereUsed), which a token meant to expire at
// once must not do.
func mintTokenFor(t *testing.T, admin *harness.APIClient, prefix, role, team, expiresIn string, await bool) mintedToken {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	created, err := admin.CreateToken(ctx, models.CreateAPITokenRequest{
		Name: harness.TokenName(prefix), Role: role, Team: team, ExpiresIn: expiresIn,
	})
	if err != nil {
		t.Fatalf("mint a %s token for team %s: %v", role, team, err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if err := operatorAPI().RevokeToken(cctx, created.ID); err != nil {
			t.Logf("cleanup: revoke token %s: %v", created.ID, err)
		}
	})
	tok := mintedToken{ID: created.ID, Secret: created.Token, API: harness.NewAPIClient(sc.BaseURL, created.Token)}
	if await {
		awaitTokenWhereUsed(ctx, t, tok, role)
	}
	return tok
}

// awaitTokenWhereUsed waits until a fresh token works on the API domain AND
// on every node that reads tokens from the mirror (harness.TokenMirrorNodes).
// A create the API domain places on a worker, or a read or exec forwarded to
// a sandbox's owner, is authenticated again on that node, which learns the
// token one mirror poll (~5 s) after the API domain does. Waiting on the API
// domain alone is how UC-268, UC-273, UC-284 and UC-287 failed on the
// hetero demo run: 401 unknown_or_revoked from the worker that owned the
// request. A node this machine cannot reach over SSH is logged and left
// out, so the case still runs, with the old, weaker wait for that node.
func awaitTokenWhereUsed(ctx context.Context, t *testing.T, tok mintedToken, role string) {
	t.Helper()
	if _, err := harness.AwaitAccepted(ctx, tok.API, tokenPropagation); err != nil {
		t.Fatalf("the fresh %s token never worked on the API domain: %v", role, err)
	}
	for _, node := range harness.TokenMirrorNodes(harness.LoadIntegrationTargets()) {
		if !harness.NodeSSHReachable(t, node) {
			t.Logf("no SSH to %s: not waiting for the fresh %s token there, so a request it answers may see one mirror poll of 401", node.Name, role)
			continue
		}
		if _, err := harness.AwaitAccepted(ctx, tok.API.At(tokenWaitBase(t, node)), tokenPropagation); err != nil {
			t.Fatalf("the fresh %s token never worked on %s, which authenticates the requests forwarded to it: %v", role, node.Name, err)
		}
	}
}

// tokenWaitBases holds one forwarded address per test and node, so a case
// that mints several tokens opens one SSH tunnel per node, not one per
// token. Each tunnel lives as long as the test that opened it.
var tokenWaitBases sync.Map

type tokenWaitKey struct {
	t    *testing.T
	node string
}

func tokenWaitBase(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	key := tokenWaitKey{t: t, node: node.Name}
	if base, ok := tokenWaitBases.Load(key); ok {
		return base.(string)
	}
	base := nodeBase(t, node)
	tokenWaitBases.Store(key, base)
	t.Cleanup(func() { tokenWaitBases.Delete(key) })
	return base
}

// sdkFor is the Go SDK presenting bearer: the suite doubles as SDK coverage,
// and an avm_ token goes in the SDK's token field like a PAT does.
func sdkFor(t *testing.T, bearer string) *microvm.Client {
	t.Helper()
	c, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: sc.BaseURL, PATToken: bearer})
	if err != nil {
		t.Fatalf("SDK client: %v", err)
	}
	return c
}

// sandboxAs creates a running sandbox with bearer's SDK and destroys it with
// the operator credential when the test ends, whatever the test did to the
// token in between.
func sandboxAs(t *testing.T, bearer string) *microvm.Sandbox {
	t.Helper()
	public := true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := sdkFor(t, bearer).Create(ctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Image: harness.DefaultImage, AllowPublicTraffic: &public,
	})
	if err != nil {
		t.Fatalf("create a sandbox with a named credential: %v", err)
	}
	destroySandbox(t, sb.ID)
	return sb
}

// execPath is the toolbox exec route the SDK calls.
func execPath(sandboxID string) string {
	return "/v1/sandboxes/" + sandboxID + "/toolbox/process/execute"
}

// sandboxAudit reads every record of a sandbox through the API as c, kind
// optional, scoped to an incarnation when one is given (a post-delete read).
func sandboxAudit(t *testing.T, c *harness.APIClient, sandboxID, kind, incarnation string) []auditlog.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var all []auditlog.Event
	cursor := ""
	for page := 0; page < 20; page++ {
		path := fmt.Sprintf("/v1/sandboxes/%s/audit?limit=200", sandboxID)
		if kind != "" {
			path += "&kind=" + kind
		}
		if incarnation != "" {
			path += "&incarnation_id=" + incarnation
		}
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		resp, err := c.Do(ctx, http.MethodGet, path, nil)
		if err != nil || resp.Status != http.StatusOK {
			t.Fatalf("read the audit of %s: %v %s", sandboxID, err, resp)
		}
		var p harness.AuditPage
		if err := resp.JSON(&p); err != nil {
			t.Fatal(err)
		}
		all = append(all, p.Events...)
		if p.NextCursor == "" || p.NextCursor == cursor {
			break
		}
		cursor = p.NextCursor
	}
	return all
}

// awaitSandboxAudit polls the sandbox's audit until pred holds: records are
// appended off the request path, so a read right after the call can miss
// the newest.
func awaitSandboxAudit(t *testing.T, c *harness.APIClient, sandboxID, kind, incarnation string, what string, pred func([]auditlog.Event) bool) []auditlog.Event {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		evs := sandboxAudit(t, c, sandboxID, kind, incarnation)
		if pred(evs) {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not in the audit of %s after 90 s; it holds:\n%s", what, sandboxID, describeEvents(evs))
		}
		time.Sleep(3 * time.Second)
	}
}

// describeEvents is a compact listing for failure messages.
func describeEvents(evs []auditlog.Event) string {
	var b strings.Builder
	for _, ev := range evs {
		fmt.Fprintf(&b, "  %s %s %s caller=%s via=%s owner=%s node=%s reason=%s\n",
			ev.Time.Format(time.RFC3339), ev.Kind, harness.RouteOf(ev), harness.CallerID(ev), callerVia(ev), ev.OwnerRef, ev.NodeID, ev.Reason)
	}
	if b.Len() == 0 {
		return "  (no records)"
	}
	return b.String()
}

func callerVia(ev auditlog.Event) string {
	if ev.Caller == nil {
		return ""
	}
	return ev.Caller.Via
}

// identityTargets returns the provisioned nodes, skipping when the run did
// not export them (a manual `go test` without run.sh).
func identityTargets(t *testing.T) *harness.IntegrationTargets {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) == 0 {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	return targets
}

// nodeBase is a local address that reaches node's sandboxd on its loopback
// listener for the rest of the test. sandboxd sees a loopback peer, so under
// SB_PAT_SCOPE=host the operator token works there.
func nodeBase(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	return "http://" + harness.SSHForward(t, node, "127.0.0.1:21212")
}

// nodeMetrics scrapes one node's /v1/metrics through base with the operator
// token.
func nodeMetrics(t *testing.T, base string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := harness.NewAPIClient(base, sc.OperatorPAT).Do(ctx, http.MethodGet, "/v1/metrics", nil)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("scrape %s/v1/metrics: %v %s", base, err, resp)
	}
	return string(resp.Body)
}

// nodeForOwner maps a placement owner id to the provisioned node.
func nodeForOwner(t *testing.T, targets *harness.IntegrationTargets, ownerID string) harness.IntegrationNode {
	t.Helper()
	node, ok := harness.IntegrationNodeForClusterID(targets, ownerID)
	if !ok {
		t.Fatalf("placement owner %q is not a provisioned node", ownerID)
	}
	return node
}

// --- the test issuer fixture ---------------------------------------------

// identityFixture is the test issuer, installed on every node.
type identityFixture struct {
	issuer  *harness.TestIssuer
	targets *harness.IntegrationTargets
	spec    harness.IdentityFileSpec
}

var (
	identityFixtureMu sync.Mutex
	identityFixtureV  *identityFixture
)

// mcpResource is the /mcp protected-resource URL on the leased domain.
func mcpResource() string {
	if sc.Domain == "" {
		return ""
	}
	return "https://" + sc.Domain + "/mcp"
}

// oidcFixture starts the test issuer and installs it on every node, once per
// run. A setup that fails or skips leaves nothing behind, so the next OIDC
// case tries again and reports its own failure rather than inheriting a
// half-installed issuer.
func oidcFixture(t *testing.T) *identityFixture {
	t.Helper()
	identityFixtureMu.Lock()
	defer identityFixtureMu.Unlock()
	if identityFixtureV != nil {
		return identityFixtureV
	}
	targets := identityTargets(t)
	issuer := harness.NewTestIssuer(t)
	fx := &identityFixture{
		issuer:  issuer,
		targets: targets,
		spec:    harness.IdentityFileSpec{IssuerURL: issuer.URL, MCPResource: mcpResource()},
	}
	ok := false
	defer func() {
		if !ok {
			issuer.Close()
		}
	}()
	if err := fx.install(t, fx.spec); err != nil {
		t.Fatal(err)
	}
	ok = true
	identityFixtureV = fx
	return fx
}

// install pushes both key sets and the identity file for spec to every
// node, reloads each with SIGHUP, and waits until a token from the issuer
// works on every node. It returns an error rather than failing the test so
// a cleanup can restore the file and report.
func (fx *identityFixture) install(t *testing.T, spec harness.IdentityFileSpec) error {
	t.Helper()
	raw, err := harness.RenderIdentityFile(spec)
	if err != nil {
		return err
	}
	nodes := sshNodes(t, fx.targets)
	for _, node := range nodes {
		for _, f := range []struct {
			path    string
			content []byte
		}{
			{harness.IssuerJWKSPath, fx.issuer.JWKS()},
			{harness.K8sJWKSPath, fx.issuer.K8sJWKS()},
			// The identity file last: a reload must never see a file naming
			// a key file that is not there yet.
			{harness.IdentityFilePath, raw},
		} {
			if err := harness.InstallNodeFile(t, node, f.path, f.content); err != nil {
				return err
			}
		}
		if err := harness.ReloadNodeIdentity(t, node); err != nil {
			return err
		}
	}
	fx.spec = spec
	probe := fx.issuer.Token(t, "itest-probe", harness.GroupFleetViewers)
	for _, node := range nodes {
		c := harness.NewAPIClient(nodeBase(t, node), probe)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		_, err := harness.AwaitAccepted(ctx, c, 90*time.Second)
		cancel()
		if err != nil {
			return fmt.Errorf("node %s never accepted a token from the test issuer after the identity file was installed (SB_IDENTITY_FILE must be %s; the node's journal names the load error): %w",
				node.Name, harness.IdentityFilePath, err)
		}
	}
	return nil
}

// pushJWKS installs the issuer's current key set on node, alone: what a
// provider's key rotation looks like from a node with a jwks_file.
func (fx *identityFixture) pushJWKS(t *testing.T, node harness.IntegrationNode) error {
	t.Helper()
	return harness.InstallNodeFile(t, node, harness.IssuerJWKSPath, fx.issuer.JWKS())
}

// sshNodes is every node the suite can reach over SSH; the identity file
// must reach all of them, so one it cannot reach fails the setup.
func sshNodes(t *testing.T, targets *harness.IntegrationTargets) []harness.IntegrationNode {
	t.Helper()
	var out []harness.IntegrationNode
	for _, node := range targets.Nodes {
		harness.RequireNodeSSH(t, node)
		out = append(out, node)
	}
	return out
}

// whoamiAs asks base who bearer is and requires a 200.
func whoamiAs(t *testing.T, base, bearer string) models.WhoAmI {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	who, resp, err := harness.NewAPIClient(base, bearer).WhoAmI(ctx)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("whoami at %s: %v %s", base, err, resp)
	}
	return who
}

// statusAs is one request's status and body as bearer.
func statusAs(t *testing.T, c *harness.APIClient, method, path string, body any) *harness.APIResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	resp, err := c.Do(ctx, method, path, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}
