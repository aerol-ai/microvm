//go:build integration

package suite

// Identity and access, operator half (plans/identity-and-access.md §8): the
// auditor's tools over the S3 export, the host-scoped operator token, and
// the client address through Caddy.

import (
	"context"
	"encoding/csv"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// auditExportURL is s3://<bucket>/<prefix> of the scenario's audit export
// (run.sh exports both from Terraform's outputs).
func auditExportURL(t *testing.T) string {
	t.Helper()
	bucket, prefix := os.Getenv("AEROL_AUDIT_EXPORT_BUCKET"), os.Getenv("AEROL_AUDIT_EXPORT_PREFIX")
	if bucket == "" {
		t.Fatal("the scenario advertises audit-export-s3 but run.sh exported no AEROL_AUDIT_EXPORT_BUCKET (Terraform output audit_export_bucket)")
	}
	return "s3://" + bucket + "/" + strings.Trim(prefix, "/")
}

// awsRegionFlag passes the run's region to the CLI's S3 reads.
func awsRegionFlag() []string {
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := os.Getenv(k); v != "" {
			return []string{"--region", v}
		}
	}
	return nil
}

// UC-279 — the auditor's two tools over the S3 export: `aerolvm audit
// search` finds a runner token's create, exec and delete and verifies the
// chain; `aerolvm access review` lists that token with its last action,
// flags an expired token, and lists every admin.
func TestIdentityAuditSearchAndAccessReview(t *testing.T) {
	harness.Require(t, sc, "UC-279")
	export := auditExportURL(t)
	tok := mintToken(t, "uc279-run", "runner", harness.TeamPayments)
	expired := mintTokenFor(t, operatorAPI(), "uc279-exp", "runner", harness.TeamCheckout, "3s", false)

	sb := sandboxAs(t, tok.Secret)
	if resp := statusAs(t, tok.API, http.MethodPost, execPath(sb.ID), models.ExecRequest{Command: "echo uc279"}); resp.Status != http.StatusOK {
		t.Fatalf("exec = %s", resp)
	}
	if resp := statusAs(t, tok.API, http.MethodDelete, "/v1/sandboxes/"+sb.ID, nil); resp.Status/100 != 2 {
		t.Fatalf("delete = %s", resp)
	}
	time.Sleep(4 * time.Second) // let the 3 s token lapse

	// The exporter ships in batches, so poll until the three actions are in
	// the export.
	var report struct {
		Result  auditlog.Result `json:"result"`
		Matched int             `json:"matched"`
		Matches []struct {
			NodeID string         `json:"node_id"`
			Record auditlog.Event `json:"record"`
		} `json:"matches"`
	}
	deadline := time.Now().Add(6 * time.Minute)
	for {
		args := append([]string{"audit", "search", "--since", "2h", "--export", export, "--caller", tok.ID, "--json"}, awsRegionFlag()...)
		r := aerolvm(t, sc.BaseURL, nil, args...)
		if r.code == 0 {
			r.json(t, &report)
			routes := map[string]bool{}
			for _, m := range report.Matches {
				routes[harness.RouteOf(m.Record)] = true
			}
			if routes[routeCreate] && routes[routeExec] && routes[routeDestroy] {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit search never found the token's create, exec and delete in %s (exit %d): %s\n%s", export, r.code, r.stderr, r.stdout)
		}
		time.Sleep(15 * time.Second)
	}
	if report.Result != auditlog.ResultPass {
		t.Fatalf("audit search found the actions but the chain verdict is %q, want PASS", report.Result)
	}

	// A day, not two hours: the identity file went onto the nodes when the
	// first OIDC case ran, which on a full run can be well over an hour ago.
	args := append([]string{"access", "review", "--since", "24h", "--export", export, "--format", "csv"}, awsRegionFlag()...)
	// With the test issuer installed, the review also reads the identity
	// file in force: its bindings are admins and team grants too, and the
	// install that put it on the nodes is an identity_config change.
	withIdentity := sc.Has(harness.CapIdentityOIDC)
	if withIdentity {
		fx := oidcFixture(t)
		raw, err := harness.RenderIdentityFile(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "identity.yaml")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--identity-file", path)
	}
	r := aerolvm(t, sc.BaseURL, nil, args...)
	if r.code != 0 {
		t.Fatalf("aerolvm access review = %d: %s\n%s", r.code, r.stderr, r.stdout)
	}
	rows, err := csv.NewReader(strings.NewReader(r.stdout)).ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("access review CSV: %v\n%s", err, r.stdout)
	}
	col := map[string]int{}
	for i, name := range rows[0] {
		col[name] = i
	}
	field := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	byID := map[string][]string{}
	var flaggedAdmin, adminBinding, identityChange bool
	for _, row := range rows[1:] {
		if field(row, "row") == "token" {
			byID[field(row, "id")] = row
		}
		if field(row, "row") == "binding" && field(row, "role") == "admin" && strings.Contains(field(row, "detail"), harness.GroupAdmins) &&
			strings.Contains(field(row, "flags"), "admin") {
			adminBinding = true
		}
		if field(row, "row") == "identity_change" {
			identityChange = true
		}
		if strings.Contains(field(row, "flags"), "admin") {
			flaggedAdmin = true
		}
		if field(row, "row") == "review" && !strings.Contains(field(row, "detail"), "result=PASS") {
			t.Errorf("the review's verdict is not PASS: %s", field(row, "detail"))
		}
	}
	if row, ok := byID[tok.ID]; !ok || field(row, "last_action") == "" {
		t.Errorf("the review does not list %s with its last action: %v", tok.ID, row)
	}
	if row, ok := byID[expired.ID]; !ok || !strings.Contains(field(row, "flags"), "expired") {
		t.Errorf("the review does not flag the expired token %s: %v", expired.ID, row)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, err := operatorAPI().ListTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range list.Tokens {
		if tk.Role == "admin" && !tk.Expired {
			if row, ok := byID[tk.ID]; !ok || !strings.Contains(field(row, "flags"), "admin") {
				t.Errorf("admin token %s (%s) is not listed as an admin: %v", tk.ID, tk.Name, row)
			}
		}
	}
	if !flaggedAdmin {
		t.Error("the review flags no admin at all; the operator token at least has acted in the window")
	}
	if withIdentity {
		if !adminBinding {
			t.Errorf("the review does not list the identity file's %s -> admin binding as an admin", harness.GroupAdmins)
		}
		if !identityChange {
			t.Error("the review shows no identity-file change, although the suite installed the file within the window")
		}
	}
}

// nodeCurlStatus runs curl on from against rawURL and returns the HTTP
// status. The bearer goes on stdin (curl -H @-), never into argv.
func nodeCurlStatus(t *testing.T, from harness.IntegrationNode, rawURL, bearer string) int {
	t.Helper()
	target, ok := harness.SSHTarget(from)
	if !ok {
		t.Fatalf("node %s has no SSH address", from.Name)
	}
	stdin := ""
	if bearer != "" {
		stdin = "Authorization: Bearer " + bearer + "\n"
	}
	out, err := harness.SSHRunStdin(t, target, "curl -sS -m 20 -o /dev/null -w 'HTTP=%{http_code}' -H @- '"+rawURL+"'", stdin)
	i := strings.LastIndex(out, "HTTP=")
	if i < 0 {
		t.Fatalf("curl %s from %s: %v %s", rawURL, from.Name, err, out)
	}
	code, _ := strconv.Atoi(strings.TrimSpace(out[i+5:]))
	if code == 0 {
		t.Fatalf("curl %s from %s could not connect (is sandboxd listening on the private address?): %s", rawURL, from.Name, out)
	}
	return code
}

// UC-285 — SB_PAT_SCOPE=host: the PAT is refused through Caddy and from a
// remote peer on 21212, and works from a loopback peer, including for a
// sandbox another node owns; SSO and avm_ tokens work through Caddy and on
// 21212; a viewer on every team scrapes 21212's metrics.
func TestIdentityPATScopeHost(t *testing.T) {
	harness.Require(t, sc, "UC-285")
	targets := identityTargets(t)
	pat := sc.OperatorPAT
	if pat == sc.PAT {
		t.Fatal("under pat-scope-host run.sh must export an admin avm_ token as AEROL_PAT and the PAT as AEROL_OPERATOR_PAT; both are the same token here")
	}
	seed, _ := harness.PickSSHNode(targets)
	harness.RequireNodeSSH(t, seed)
	remote := seed
	for _, n := range targets.Nodes {
		if n.Name != seed.Name {
			remote = n // a different host where there is one
			break
		}
	}
	seedPrivate := "http://" + seed.PrivateIP + ":21212"

	resp := statusAs(t, harness.NewAPIClient(sc.BaseURL, pat), http.MethodGet, "/v1/sandboxes", nil)
	if resp.Status != http.StatusUnauthorized || !strings.Contains(resp.Err().Error, "aerolvm login --sso") {
		t.Fatalf("the PAT through Caddy = %s, want 401 with the sign-in hint", resp)
	}
	if code := nodeCurlStatus(t, remote, seedPrivate+"/v1/sandboxes", pat); code != http.StatusUnauthorized {
		t.Fatalf("the PAT from %s to %s = %d, want 401", remote.Name, seedPrivate, code)
	}

	// From a loopback peer the PAT works, and on a cluster reaches a sandbox
	// another node owns (the forward carries X-Cluster-PAT-Origin: host).
	sb := client(t).NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	via := seed
	if sc.Has(harness.CapCluster) {
		owner := nodeForOwner(t, targets, resolvePlacementOwner(t, client(t), sb.ID))
		for _, n := range targets.Nodes {
			if n.Name != owner.Name {
				via = n
				break
			}
		}
	}
	if resp := statusAs(t, harness.NewAPIClient(nodeBase(t, via), pat), http.MethodGet, "/v1/sandboxes/"+sb.ID, nil); resp.Status != http.StatusOK {
		t.Fatalf("the PAT from %s's loopback for sandbox %s = %s, want 200", via.Name, sb.ID, resp)
	}

	runner := mintToken(t, "uc285-run", "runner", harness.TeamPayments)
	viewer := mintToken(t, "uc285-view", "viewer", "*")
	creds := map[string]string{"an avm_ token": runner.Secret}
	if sc.Has(harness.CapIdentityOIDC) {
		creds["an SSO token"] = oidcFixture(t).issuer.Token(t, "uc285-sso", harness.GroupPaymentsEng)
	}
	for label, bearer := range creds {
		if who := whoamiAs(t, sc.BaseURL, bearer); who.Role != "runner" {
			t.Errorf("%s through Caddy: %+v", label, who)
		}
		if code := nodeCurlStatus(t, remote, seedPrivate+"/v1/whoami", bearer); code != http.StatusOK {
			t.Errorf("%s from %s to %s = %d, want 200", label, remote.Name, seedPrivate, code)
		}
	}
	if code := nodeCurlStatus(t, remote, seedPrivate+"/v1/metrics", viewer.Secret); code != http.StatusOK {
		t.Errorf("a viewer on * scraping %s/v1/metrics = %d, want 200 (the Prometheus credential under host scope)", seedPrivate, code)
	}
}

// UC-288 — PROXY protocol on caddy-l4's fallback: a bad token from this
// machine through Caddy leaves an auth_denied record naming this machine's
// address, not 127.0.0.1; good requests through Caddy count as origin
// public; and a preview site still serves through the same listener.
func TestIdentityClientAddressThroughCaddy(t *testing.T) {
	harness.Require(t, sc, "UC-288")
	targets := identityTargets(t)
	seed, _ := harness.PickSSHNode(targets)
	harness.RequireNodeSSH(t, seed)
	target, _ := harness.SSHTarget(seed)
	// This machine's address as AWS sees it: sshd's view of the session.
	out, err := harness.SSHRun(t, target, `echo "SSHCLIENT=${SSH_CLIENT%% *}"`)
	i := strings.Index(out, "SSHCLIENT=")
	if err != nil || i < 0 {
		t.Fatalf("read SSH_CLIENT on %s: %v %s", seed.Name, err, out)
	}
	fields := strings.Fields(out[i+len("SSHCLIENT="):])
	if len(fields) == 0 {
		t.Fatalf("sshd on %s reported no client address: %q", seed.Name, out)
	}
	myIP := fields[0]

	start := time.Now().Add(-5 * time.Second)
	bogus := "avm_" + strings.Repeat("A", 12) + "_" + strings.Repeat("B", 43) + "_" + strings.Repeat("C", 6)
	if _, resp, err := harness.NewAPIClient(sc.BaseURL, bogus).WhoAmI(context.Background()); err != nil || resp.Status != http.StatusUnauthorized {
		t.Fatalf("a bogus token through Caddy = %v %s, want 401", err, resp)
	}

	var sources []string
	deadline := time.Now().Add(90 * time.Second)
	for len(sources) == 0 && time.Now().Before(deadline) {
		for _, node := range targets.Nodes {
			evs, err := harness.NodeAuditEvents(t, node, `"kind":"auth_denied"`)
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range evs {
				if ev.Time.After(start) && ev.Request != nil && ev.Request.Route == "/v1/whoami" {
					sources = append(sources, ev.Request.Source)
				}
			}
		}
		if len(sources) == 0 {
			time.Sleep(3 * time.Second)
		}
	}
	if len(sources) == 0 {
		t.Fatal("no node wrote an auth_denied record for the bogus token")
	}
	for _, src := range sources {
		if src == "127.0.0.1" || src == "::1" || src == "" {
			t.Fatalf("the auth_denied record names %q: Caddy's hop, not the client (PROXY protocol not in effect)", src)
		}
	}
	if !slices.Contains(sources, myIP) {
		t.Fatalf("auth_denied sources %v do not include this machine's address %s", sources, myIP)
	}

	// Good requests through Caddy are public-origin.
	runner := mintToken(t, "uc288", "runner", harness.TeamPayments)
	bases := map[string]string{}
	for _, node := range targets.Nodes {
		bases[node.Name] = nodeBase(t, node)
	}
	label := map[string]string{"key": "token", "key2": "public"}
	sum := func() float64 {
		total := 0.0
		for _, base := range bases {
			total += harness.MetricValueOrZero(nodeMetrics(t, base), "aerolvm_auth_requests_total", label)
		}
		return total
	}
	before := sum()
	const n = 5
	for k := 0; k < n; k++ {
		whoamiAs(t, sc.BaseURL, runner.Secret)
	}
	if got := sum() - before; got < n {
		t.Fatalf("aerolvm_auth_requests_total{token,public} rose by %v across the fleet for %d requests through Caddy", got, n)
	}

	// The PROXY wrapper sits on the listener every preview site uses too.
	c := client(t)
	sb := privateHTTPServerSandbox(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExposePort(ctx, 8080)
	if err != nil || res.PublicURL == "" {
		t.Fatalf("expose port: %v", err)
	}
	fetchEventually(t, res.PublicURL)
}
