//go:build integration

package suite

// Identity and access, API-token half (plans/identity-and-access.md §8):
// team avm_ tokens minted at setup with the operator credential (D4) and
// used against the live API.

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Routes an api record names (pkg/api/v1/routes.go patterns).
const (
	routeCreate  = "POST /v1/sandboxes"
	routeExec    = "POST /v1/sandboxes/{id}/toolbox/{path...}"
	routeDestroy = "DELETE /v1/sandboxes/{id}"
)

func byCallerRoute(evs []auditlog.Event, callerID, route string) []auditlog.Event {
	return harness.FilterAudit(evs, func(ev auditlog.Event) bool {
		return ev.Kind == auditlog.KindAPI && harness.CallerID(ev) == callerID && harness.RouteOf(ev) == route
	})
}

func firstIncarnation(evs []auditlog.Event) string {
	for _, ev := range evs {
		if ev.IncarnationID != "" {
			return ev.IncarnationID
		}
	}
	return ""
}

// UC-268 — a runner token for team payments creates, execs and deletes; the
// sandbox belongs to team:payments and three api records name the token.
func TestIdentityTeamTokenLifecycle(t *testing.T) {
	harness.Require(t, sc, "UC-268")
	tok := mintToken(t, "uc268", "runner", harness.TeamPayments)

	who := whoamiAs(t, sc.BaseURL, tok.Secret)
	if who.Principal.ID != tok.ID || who.Role != "runner" || who.Team != harness.TeamPayments {
		t.Fatalf("whoami for the payments runner token = %+v, want %s runner on payments", who, tok.ID)
	}

	sb := sandboxAs(t, tok.Secret)
	resp := statusAs(t, tok.API, http.MethodPost, execPath(sb.ID), models.ExecRequest{Command: "echo uc268"})
	var ex models.ExecResult
	if resp.Status != http.StatusOK || resp.JSON(&ex) != nil || strings.TrimSpace(ex.Stdout) != "uc268" {
		t.Fatalf("exec with the runner token = %s", resp)
	}

	// Read the incarnation before the delete: a post-delete read is scoped
	// to one, by design.
	before := awaitSandboxAudit(t, tok.API, sb.ID, auditlog.KindAPI, "", "the create and exec records", func(evs []auditlog.Event) bool {
		return len(byCallerRoute(evs, tok.ID, routeCreate)) > 0 && len(byCallerRoute(evs, tok.ID, routeExec)) > 0
	})
	incarnation := firstIncarnation(before)

	if resp := statusAs(t, tok.API, http.MethodDelete, "/v1/sandboxes/"+sb.ID, nil); resp.Status/100 != 2 {
		t.Fatalf("delete with the runner token = %s", resp)
	}
	if incarnation == "" {
		t.Fatalf("no record of %s carries an incarnation id, so the post-delete history cannot be read:\n%s", sb.ID, describeEvents(before))
	}

	evs := awaitSandboxAudit(t, operatorAPI(), sb.ID, auditlog.KindAPI, incarnation, "the delete record", func(evs []auditlog.Event) bool {
		return len(byCallerRoute(evs, tok.ID, routeDestroy)) > 0
	})
	for _, route := range []string{routeCreate, routeExec, routeDestroy} {
		got := byCallerRoute(evs, tok.ID, route)
		if len(got) != 1 {
			t.Errorf("%d %q records name %s, want exactly 1:\n%s", len(got), route, tok.ID, describeEvents(evs))
			continue
		}
		if got[0].OwnerRef != "team:"+harness.TeamPayments {
			t.Errorf("the %q record says owner %q, want team:%s", route, got[0].OwnerRef, harness.TeamPayments)
		}
		if got[0].Caller.Kind != "token" || got[0].Caller.Team != harness.TeamPayments {
			t.Errorf("the %q record's caller = %+v, want a token acting for payments", route, got[0].Caller)
		}
	}
}

// UC-269 — a team token reading another team's sandbox gets 404, not 403:
// a 403 would confirm the sandbox exists.
func TestIdentityCrossTeamReadIsNotFound(t *testing.T) {
	harness.Require(t, sc, "UC-269")
	payments := mintToken(t, "uc269-pay", "runner", harness.TeamPayments)
	checkout := mintToken(t, "uc269-chk", "runner", harness.TeamCheckout)
	sb := sandboxAs(t, checkout.Secret)

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/v1/sandboxes/" + sb.ID, nil},
		{http.MethodPost, execPath(sb.ID), models.ExecRequest{Command: "id"}},
		{http.MethodDelete, "/v1/sandboxes/" + sb.ID, nil},
	} {
		if resp := statusAs(t, payments.API, tc.method, tc.path, tc.body); resp.Status != http.StatusNotFound {
			t.Errorf("payments token %s %s on a checkout sandbox = %s, want 404", tc.method, tc.path, resp)
		}
	}
	resp := statusAs(t, payments.API, http.MethodGet, "/v1/sandboxes", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("list as payments = %s", resp)
	}
	if strings.Contains(string(resp.Body), sb.ID) {
		t.Fatalf("the payments token's list includes checkout's sandbox %s", sb.ID)
	}
	// The owner still has it: the 404 was scoping, not a lost sandbox.
	if resp := statusAs(t, checkout.API, http.MethodGet, "/v1/sandboxes/"+sb.ID, nil); resp.Status != http.StatusOK {
		t.Fatalf("checkout reading its own sandbox = %s", resp)
	}
}

// UC-270 — a viewer token's exec is a 403 naming sandbox.exec, and the
// refusal is a denied api record naming the token.
func TestIdentityViewerExecDenied(t *testing.T) {
	harness.Require(t, sc, "UC-270")
	runner := mintToken(t, "uc270-run", "runner", harness.TeamPayments)
	viewer := mintToken(t, "uc270-view", "viewer", harness.TeamPayments)
	sb := sandboxAs(t, runner.Secret)

	if resp := statusAs(t, viewer.API, http.MethodGet, "/v1/sandboxes/"+sb.ID, nil); resp.Status != http.StatusOK {
		t.Fatalf("a viewer on payments cannot read a payments sandbox: %s", resp)
	}
	resp := statusAs(t, viewer.API, http.MethodPost, execPath(sb.ID), models.ExecRequest{Command: "id"})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("viewer exec = %s, want 403", resp)
	}
	if e := resp.Err(); e.RequiredPermission != "sandbox.exec" || e.Role != "viewer" || !strings.Contains(e.Error, "sandbox.exec") {
		t.Fatalf("the 403 must name sandbox.exec and the caller's role (D9): %+v", e)
	}
	awaitSandboxAudit(t, operatorAPI(), sb.ID, auditlog.KindAPI, "", "a denied record naming the viewer token", func(evs []auditlog.Event) bool {
		for _, ev := range byCallerRoute(evs, viewer.ID, routeExec) {
			if ev.Result == auditlog.APIResultDenied {
				return true
			}
		}
		return false
	})
}

// UC-271 — a token revoked through node A is refused on another node within
// 15 s: a revoke is a Raft write that every voter applies, and a worker
// without Raft state sees it on its next mirror sync.
func TestIdentityRevokeReachesOtherNode(t *testing.T) {
	harness.Require(t, sc, "UC-271")
	targets := identityTargets(t)
	if len(targets.Nodes) < 2 {
		t.Skip("needs two nodes")
	}
	nodeA, nodeC := targets.Nodes[0], targets.Nodes[len(targets.Nodes)-1]
	baseA, baseC := nodeBase(t, nodeA), nodeBase(t, nodeC)
	tok := mintToken(t, "uc271", "runner", harness.TeamPayments)

	onC := tok.API.At(baseC)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := harness.AwaitAccepted(ctx, onC, tokenPropagation); err != nil {
		t.Fatalf("the token never worked on %s: %v", nodeC.Name, err)
	}
	if err := harness.NewAPIClient(baseA, sc.OperatorPAT).RevokeToken(ctx, tok.ID); err != nil {
		t.Fatalf("revoke through %s: %v", nodeA.Name, err)
	}
	took, resp, err := harness.AwaitRefused(ctx, onC, 15*time.Second)
	if err != nil {
		t.Fatalf("revoked through %s, still accepted on %s: %v", nodeA.Name, nodeC.Name, err)
	}
	if resp.Err().Reason != "unknown_or_revoked" {
		t.Fatalf("a revoked token's 401 reason = %q, want unknown_or_revoked (never disclosing which)", resp.Err().Reason)
	}
	t.Logf("revoke on %s reached %s in %s", nodeA.Name, nodeC.Name, took.Round(100*time.Millisecond))
}

// flipLastChar changes a token's last checksum character.
func flipLastChar(tok string) string {
	last := tok[len(tok)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return tok[:len(tok)-1] + string(repl)
}

// UC-272 — an expired token is a 401 expired; a token whose checksum does
// not match is a 401 malformed, refused before any lookup: the malformed
// counter moves and the unknown_or_revoked one (the lookup's) does not.
func TestIdentityExpiredAndMalformedTokens(t *testing.T) {
	harness.Require(t, sc, "UC-272")
	targets := identityTargets(t)
	node := targets.Nodes[0]
	base := nodeBase(t, node)

	expired := mintTokenFor(t, operatorAPI(), "uc272-exp", "runner", harness.TeamPayments, "3s", false)
	time.Sleep(6 * time.Second)
	_, resp, err := expired.API.At(base).WhoAmI(context.Background())
	if err != nil || resp.Status != http.StatusUnauthorized || resp.Err().Reason != "expired" {
		t.Fatalf("an expired token = %v %s, want 401 reason expired", err, resp)
	}

	good := mintToken(t, "uc272-ok", "runner", harness.TeamPayments)
	malformed := harness.NewAPIClient(base, flipLastChar(good.Secret))
	labels := func(reason string) map[string]string { return map[string]string{"key": "token", "key2": reason} }
	before := nodeMetrics(t, base)
	const n = 5
	for i := 0; i < n; i++ {
		_, resp, err := malformed.WhoAmI(context.Background())
		if err != nil || resp.Status != http.StatusUnauthorized || resp.Err().Reason != "malformed" {
			t.Fatalf("a token with a bad checksum = %v %s, want 401 reason malformed", err, resp)
		}
	}
	after := nodeMetrics(t, base)
	mal := harness.MetricValueOrZero(after, "aerolvm_auth_failures_total", labels("malformed")) -
		harness.MetricValueOrZero(before, "aerolvm_auth_failures_total", labels("malformed"))
	lookups := harness.MetricValueOrZero(after, "aerolvm_auth_failures_total", labels("unknown_or_revoked")) -
		harness.MetricValueOrZero(before, "aerolvm_auth_failures_total", labels("unknown_or_revoked"))
	if mal < n {
		t.Fatalf("aerolvm_auth_failures_total{token,malformed} rose by %v for %d malformed tokens", mal, n)
	}
	if lookups != 0 {
		t.Fatalf("aerolvm_auth_failures_total{token,unknown_or_revoked} rose by %v: a malformed token reached the lookup", lookups)
	}
}

// UC-273 — an exec through edge E for a sandbox owned by O: O records the
// call with via=E, and E writes no record of its own (the forward carries
// the edge's mark so the call is recorded once).
func TestIdentityForwardedExecRecordedOnceOnOwner(t *testing.T) {
	harness.Require(t, sc, "UC-273")
	targets := identityTargets(t)
	c := client(t)
	tok := mintToken(t, "uc273", "runner", harness.TeamPayments)
	sb := sandboxAs(t, tok.Secret)
	ownerID := resolvePlacementOwner(t, c, sb.ID)
	if ownerID == "" {
		t.Fatal("no placement owner for the sandbox")
	}
	owner := nodeForOwner(t, targets, ownerID)
	var edge harness.IntegrationNode
	for _, n := range targets.Nodes {
		if n.Name != owner.Name {
			edge = n
			break
		}
	}
	if edge.Name == "" {
		t.Skip("no node other than the owner")
	}
	edgeID := heteroNodeID(t, c, targets, edge.Name)
	harness.RequireNodeSSH(t, owner)

	marker := "uc273-" + harness.TokenName("x")
	resp := statusAs(t, tok.API.At(nodeBase(t, edge)), http.MethodPost, execPath(sb.ID), models.ExecRequest{Command: "echo " + marker})
	if resp.Status != http.StatusOK || !strings.Contains(string(resp.Body), marker) {
		t.Fatalf("exec through edge %s = %s", edge.Name, resp)
	}

	var onOwner []auditlog.Event
	deadline := time.Now().Add(90 * time.Second)
	for {
		all, err := harness.NodeAuditEvents(t, owner, tok.ID)
		if err != nil {
			t.Fatal(err)
		}
		onOwner = harness.FilterAudit(byCallerRoute(all, tok.ID, routeExec), func(ev auditlog.Event) bool { return ev.SandboxID == sb.ID })
		if len(onOwner) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if len(onOwner) != 1 {
		t.Fatalf("owner %s holds %d exec records for the forwarded call, want 1:\n%s", owner.Name, len(onOwner), describeEvents(onOwner))
	}
	if onOwner[0].Caller.Via != edgeID {
		t.Fatalf("the owner's record says via=%q, want the edge %q", onOwner[0].Caller.Via, edgeID)
	}
	onEdge, err := harness.NodeAuditEvents(t, edge, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := harness.FilterAudit(byCallerRoute(onEdge, tok.ID, routeExec), func(ev auditlog.Event) bool { return ev.SandboxID == sb.ID }); len(got) != 0 {
		t.Fatalf("the edge %s recorded the forwarded exec as well (%d records); it must leave the record to the owner:\n%s", edge.Name, len(got), describeEvents(got))
	}
}

// UC-274 — an include_env list by a team token: every owner's secret_open
// record names the token, and all of them carry the one correlation id the
// edge minted for the call.
func TestIdentityIncludeEnvFanOutNamesCaller(t *testing.T) {
	harness.Require(t, sc, "UC-274")
	c := client(t)
	tok := mintToken(t, "uc274", "runner", harness.TeamPayments)
	sdk := sdkFor(t, tok.Secret)

	owners := map[string]string{} // sandbox id → owner node
	distinct := map[string]bool{}
	for i := 0; i < 6 && (len(distinct) < 2 || len(owners) < 3); i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := sdk.Create(ctx, sdktypes.CreateSandboxOptions{
			Name: harness.UniqueName(sc, t), Image: harness.DefaultImage, Env: map[string]string{"UC274_SECRET": "s3cr3t-" + harness.TokenName("v")},
		})
		cancel()
		if err != nil {
			t.Fatalf("create a sandbox with env: %v", err)
		}
		destroySandbox(t, sb.ID)
		owner := resolvePlacementOwner(t, c, sb.ID)
		owners[sb.ID] = owner
		distinct[owner] = true
	}
	if len(distinct) < 2 {
		t.Skipf("every sandbox landed on one node (%v); the fan-out needs two owners", distinct)
	}

	if resp := statusAs(t, tok.API, http.MethodGet, "/v1/sandboxes?include_env=true", nil); resp.Status != http.StatusOK {
		t.Fatalf("include_env list as the runner token = %s", resp)
	}
	correlation := ""
	for id, owner := range owners {
		evs := awaitSandboxAudit(t, tok.API, id, "secret_open", "", "a secret_open naming the token", func(evs []auditlog.Event) bool {
			for _, ev := range evs {
				if harness.CallerID(ev) == tok.ID {
					return true
				}
			}
			return false
		})
		// The newest of the token's opens is the list call's; a page may be
		// ordered either way, so pick it by time.
		var latest auditlog.Event
		for _, ev := range evs {
			if harness.CallerID(ev) == tok.ID && !ev.Time.Before(latest.Time) {
				latest = ev
			}
		}
		if correlation == "" {
			correlation = latest.CorrelationID
		}
		if latest.CorrelationID == "" || latest.CorrelationID != correlation {
			t.Errorf("sandbox %s (owner %s): secret_open correlation %q, want the call's one id %q", id, owner, latest.CorrelationID, correlation)
		}
	}
}

// UC-278 — auditor, viewer on every team, and viewer on one team.
func TestIdentityReadOnlyRoles(t *testing.T) {
	harness.Require(t, sc, "UC-278")
	runner := mintToken(t, "uc278-run", "runner", harness.TeamPayments)
	auditor := mintToken(t, "uc278-aud", "auditor", "*")
	fleetViewer := mintToken(t, "uc278-vall", "viewer", "*")
	teamViewer := mintToken(t, "uc278-vpay", "viewer", harness.TeamPayments)
	sb := sandboxAs(t, runner.Secret)

	if resp := statusAs(t, auditor.API, http.MethodGet, "/v1/sandboxes/"+sb.ID+"/audit?limit=10", nil); resp.Status != http.StatusOK {
		t.Errorf("auditor reading a team's audit = %s, want 200", resp)
	}
	if resp := statusAs(t, auditor.API, http.MethodGet, "/v1/sandboxes", nil); resp.Status != http.StatusOK || !strings.Contains(string(resp.Body), sb.ID) {
		t.Errorf("auditor listing sandboxes = %s, want 200 including %s", resp, sb.ID)
	}
	for _, tc := range []struct {
		name, method, path string
		body               any
		perm               string
	}{
		{"exec", http.MethodPost, execPath(sb.ID), models.ExecRequest{Command: "id"}, "sandbox.exec"},
		{"env", http.MethodGet, "/v1/sandboxes/" + sb.ID + "?include_env=true", nil, "sandbox.secrets"},
		{"create", http.MethodPost, "/v1/sandboxes", map[string]any{"image": harness.DefaultImage}, "sandbox.write"},
	} {
		resp := statusAs(t, auditor.API, tc.method, tc.path, tc.body)
		if resp.Status != http.StatusForbidden || resp.Err().RequiredPermission != tc.perm {
			t.Errorf("auditor %s = %s, want 403 naming %s", tc.name, resp, tc.perm)
		}
	}
	if resp := statusAs(t, fleetViewer.API, http.MethodGet, "/v1/metrics", nil); resp.Status != http.StatusOK || !strings.Contains(string(resp.Body), "aerolvm_") {
		t.Errorf("viewer on * scraping /v1/metrics = %s, want 200", resp)
	}
	if resp := statusAs(t, teamViewer.API, http.MethodGet, "/v1/metrics", nil); resp.Status != http.StatusForbidden {
		t.Errorf("viewer on payments scraping /v1/metrics = %s, want 403 (metrics describe every team)", resp)
	}

	// /debug/vars is not on Caddy's API matcher, so ask a node directly.
	base := sc.BaseURL
	if targets := harness.LoadIntegrationTargets(); targets != nil && len(targets.Nodes) > 0 {
		base = nodeBase(t, targets.Nodes[0])
	}
	for name, tok := range map[string]mintedToken{"auditor": auditor, "viewer on *": fleetViewer, "viewer on payments": teamViewer} {
		if resp := statusAs(t, tok.API.At(base), http.MethodGet, "/debug/vars", nil); resp.Status != http.StatusForbidden {
			t.Errorf("%s on /debug/vars = %s, want 403 (fleet.admin only)", name, resp)
		}
	}
}

// UC-280 — the facades with a team token: the sandbox belongs to the team
// and its create record names the token.
func TestIdentityFacadesWithTeamToken(t *testing.T) {
	harness.Require(t, sc, "UC-280")
	payments := mintToken(t, "uc280-pay", "runner", harness.TeamPayments)
	checkout := mintToken(t, "uc280-chk", "runner", harness.TeamCheckout)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	type created struct{ facade, id string }
	var made []created
	// E2B's SDK sends X-API-KEY, not a bearer; the auth edge reads it as one.
	e2b := harness.NewAPIClient(sc.BaseURL, "")
	e2b.Headers = map[string]string{"X-API-KEY": payments.Secret}
	if resp := statusAs(t, e2b, http.MethodPost, "/e2b/sandboxes", map[string]any{"templateID": "base"}); resp.Status != http.StatusCreated {
		t.Errorf("E2B create with a team token = %s", resp)
	} else {
		var r struct {
			SandboxID string `json:"sandboxID"`
		}
		fcDecode(t, resp.Body, &r)
		made = append(made, created{"e2b", r.SandboxID})
	}
	if st, body := fcDo(t, ctx, http.MethodPost, "", "/daytona/sandbox", map[string]any{"snapshot": harness.DefaultImage},
		map[string]string{"Authorization": "Bearer " + payments.Secret}); st != http.StatusCreated {
		t.Errorf("Daytona create with a team token = %d %s", st, body)
	} else {
		var r idResponse
		fcDecode(t, body, &r)
		made = append(made, created{"daytona", r.ID})
	}
	if st, body := fcDo(t, ctx, http.MethodPost, "", "/runloop/v1/devboxes", map[string]any{"name": "uc280-" + harness.UniqueName(sc, t)},
		map[string]string{"Authorization": "Bearer " + payments.Secret}); st != http.StatusCreated && st != http.StatusOK {
		t.Errorf("Runloop create with a team token = %d %s", st, body)
	} else {
		var r idResponse
		fcDecode(t, body, &r)
		made = append(made, created{"runloop", r.ID})
	}

	for _, m := range made {
		if m.id == "" {
			t.Errorf("%s create returned no id", m.facade)
			continue
		}
		destroySandbox(t, m.id)
		if resp := statusAs(t, payments.API, http.MethodGet, "/v1/sandboxes/"+m.id, nil); resp.Status != http.StatusOK {
			t.Errorf("%s sandbox %s is not the payments team's: GET as payments = %s", m.facade, m.id, resp)
		}
		if resp := statusAs(t, checkout.API, http.MethodGet, "/v1/sandboxes/"+m.id, nil); resp.Status != http.StatusNotFound {
			t.Errorf("%s sandbox %s is visible to checkout: GET = %s", m.facade, m.id, resp)
		}
		awaitSandboxAudit(t, operatorAPI(), m.id, auditlog.KindAPI, "", m.facade+" create record naming the token as team:payments", func(evs []auditlog.Event) bool {
			for _, ev := range evs {
				if harness.CallerID(ev) == payments.ID && ev.OwnerRef == "team:"+harness.TeamPayments && ev.Request != nil && ev.Request.Method == http.MethodPost {
					return true
				}
			}
			return false
		})
	}
}

// UC-287 — an SSH session through the gateway writes one api record whose
// caller is the sandbox key, and the sandbox's create record names the
// token that made it. On a cluster the gateway that takes the connection is
// often not the owner's: it bridges the session through its own node's
// sessions API with the operator token, and the owner must still hold the
// ssh record and must not name the operator for the bridged calls (the
// sandbox key holder made them, via the gateway's node).
func TestIdentitySSHSessionRecord(t *testing.T) {
	harness.Require(t, sc, "UC-287")
	tok := mintToken(t, "uc287", "runner", harness.TeamPayments)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	sb, err := sdkFor(t, tok.Secret).Create(ctx, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Name: harness.UniqueName(sc, t)})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	destroySandbox(t, sb.ID)
	if sb.SSHPrivateKey == "" {
		t.Fatal("create response carried no SSH private key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(sb.SSHPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	port := os.Getenv("AEROL_SSH_PORT")
	if port == "" {
		port = "2220"
	}
	cfg := &ssh.ClientConfig{User: sb.ID, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 15 * time.Second}
	var out []byte
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, err = sshOnce(sc.Domain+":"+port, cfg, "echo uc287")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil || strings.TrimSpace(string(out)) != "uc287" {
		t.Fatalf("SSH session: %v %q", err, out)
	}

	evs := awaitSandboxAudit(t, operatorAPI(), sb.ID, auditlog.KindAPI, "", "the SSH session record", func(evs []auditlog.Event) bool {
		for _, ev := range evs {
			if ev.Ref == auditlog.RefSSH {
				return true
			}
		}
		return false
	})
	ssh := harness.FilterAudit(evs, func(ev auditlog.Event) bool { return ev.Ref == auditlog.RefSSH })
	if len(ssh) != 1 || ssh[0].Caller == nil || ssh[0].Caller.Kind != "sandbox_key" || ssh[0].Caller.ID != sb.ID {
		t.Fatalf("SSH session records = %d, want one with caller sandbox_key %s:\n%s", len(ssh), sb.ID, describeEvents(ssh))
	}
	if len(byCallerRoute(evs, tok.ID, routeCreate)) != 1 {
		t.Fatalf("the sandbox's create record does not name its creator %s:\n%s", tok.ID, describeEvents(evs))
	}
	// Single node: the gateway talks to the toolbox directly and there are
	// no bridged calls, so this holds trivially.
	bridged := harness.FilterAudit(evs, func(ev auditlog.Event) bool {
		return ev.Ref != auditlog.RefSSH && ev.Request != nil && strings.HasPrefix(ev.Request.Route, "/v1/sandboxes/{id}/sessions")
	})
	for _, ev := range bridged {
		if ev.Caller == nil || ev.Caller.Kind != "sandbox_key" || ev.Caller.ID != sb.ID {
			t.Fatalf("a call the SSH gateway bridged is not the sandbox key's:\n%s", describeEvents(bridged))
		}
	}
}

// sshOnce runs one command over a fresh SSH connection.
func sshOnce(addr string, cfg *ssh.ClientConfig, cmd string) ([]byte, error) {
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	sess, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.CombinedOutput(cmd)
}

// UC-294 — two teams register the same WASM module bytes with no id: each
// gets its own row under the digest id, neither sees, deletes or collides
// with the other's, and a boot by id resolves the caller's own row before an
// operator-published one.
func TestIdentityWasmModulePerTeam(t *testing.T) {
	harness.Require(t, sc, "UC-294")
	ref := os.Getenv("AEROL_WASM_REGISTER_REF")
	if ref == "" {
		t.Skip("AEROL_WASM_REGISTER_REF not set (allowlisted oci ref to register, as UC-51)")
	}
	payments := mintToken(t, "uc294-pay", "runner", harness.TeamPayments)
	checkout := mintToken(t, "uc294-chk", "runner", harness.TeamCheckout)

	register := func(tok mintedToken) models.WasmModule {
		t.Helper()
		resp := statusAs(t, tok.API, http.MethodPost, "/v1/wasm-modules", models.CreateWasmModuleRequest{ModuleRef: ref})
		var mod models.WasmModule
		if resp.Status/100 != 2 || resp.JSON(&mod) != nil || mod.ID == "" {
			t.Fatalf("register the module as %s = %s (a second owner must never get an id conflict)", tok.ID, resp)
		}
		t.Cleanup(func() {
			cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, _ = tok.API.Do(cctx, http.MethodDelete, "/v1/wasm-modules/"+mod.ID, nil)
		})
		return mod
	}
	pm := register(payments)
	cm := register(checkout)
	if pm.Digest != cm.Digest {
		t.Fatalf("the same bytes have two digests: %s vs %s", pm.Digest, cm.Digest)
	}

	countID := func(tok mintedToken, id string) int {
		resp := statusAs(t, tok.API, http.MethodGet, "/v1/wasm-modules", nil)
		var list []models.WasmModule
		if resp.Status != http.StatusOK || resp.JSON(&list) != nil {
			t.Fatalf("list modules as %s = %s", tok.ID, resp)
		}
		n := 0
		for _, m := range list {
			if m.ID == id {
				n++
			}
		}
		return n
	}
	if countID(payments, pm.ID) != 1 || countID(checkout, cm.ID) != 1 {
		t.Fatal("each team must see exactly one row under its module id: its own")
	}

	// payments deletes its row; checkout's is untouched.
	if resp := statusAs(t, payments.API, http.MethodDelete, "/v1/wasm-modules/"+pm.ID, nil); resp.Status/100 != 2 {
		t.Fatalf("payments deleting its own row = %s", resp)
	}
	if resp := statusAs(t, checkout.API, http.MethodGet, "/v1/wasm-modules/"+cm.ID, nil); resp.Status != http.StatusOK {
		t.Fatalf("payments' delete took checkout's row too: GET as checkout = %s", resp)
	}
	if resp := statusAs(t, payments.API, http.MethodGet, "/v1/wasm-modules/"+pm.ID, nil); resp.Status != http.StatusNotFound {
		t.Fatalf("after deleting its row, payments still reads one under %s (checkout's?): %s", pm.ID, resp)
	}

	// A boot by catalogue id resolves the caller's own row.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sb, err := sdkFor(t, checkout.Secret).Create(ctx, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: "wasm", Image: cm.ID, ModuleRef: cm.ID,
	})
	if err != nil {
		t.Fatalf("checkout booting its own module by id: %v", err)
	}
	destroySandbox(t, sb.ID)
}
