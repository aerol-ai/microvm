package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
)

// testdata/access-review is the access review's fixture: an export from
// three nodes and the token list GET /v1/tokens returned at the same time.
// accessReviewFixture below is its source; `go test -run
// 'TestAccessReviewFixtureIsCurrent|TestAccessReviewGolden' -update`
// rewrites the files and the golden reports from it (the -update flag is
// shared with sso_test.go's golden files, so name the tests), and without
// -update the test fails when they drift apart.
//
// What it holds, by what the report must show:
//   - tokens: ci-deploy (busy, part of it summarized by the flood budget),
//     platform-admin (admin, minted in the window by ana), auditor-q4
//     (minted in the window by platform-admin, used once to list tokens),
//     prom-scrape (expires in 12 days; its only call is before the window),
//     -legacy-ci (expired, and a name that starts a spreadsheet formula);
//   - principals besides listed tokens: ana (fleet admin by identity
//     provider), bob (refused, with a display name full of Markdown), eve
//     (refused, with a display name that is a spreadsheet formula), the
//     operator token, a node, two daemon subsystems, a sandbox SSH key, a
//     token revoked in the window and one the expiry sweep removed;
//   - refused credentials from two addresses, seen on both nodes;
//   - node-a runs with SB_AUDIT_API_RECORDS=mutations and lost 7 records to
//     a queue overflow; node-b records plain reads (all) and its exporter
//     re-sent a batch; node-c only has records from before the window;
//   - identity_config records: node-a and node-b move to identity.yaml
//     (an admin binding added, a binding removed, a deny subject and an
//     issuer added), then node-b reorders its bindings into a third file,
//     so with --identity-file node-a enforces it, node-b another file and
//     node-c is unknown.
const reviewFixture = "testdata/access-review"

const reviewSince = "2026-10-16T00:00:00Z"

var reviewNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

type fixtureBatch struct {
	node, day, name string
	evs             []auditlog.Event
}

func reviewTok(id, name, team string) *auditlog.Caller {
	return &auditlog.Caller{Kind: "token", ID: id, Name: name, Team: team}
}

func reviewPerson(id, name, team string) *auditlog.Caller {
	return &auditlog.Caller{Kind: "oidc", ID: id, Name: name, Team: team}
}

func reviewCall(method, route string, status int) *auditlog.Request {
	return &auditlog.Request{Method: method, Route: route, Status: status}
}

// accessReviewFixture builds the fixture export: each node's records linked
// into one chain across its batches, in the order given.
func accessReviewFixture() []fixtureBatch {
	at := func(day, clock string) time.Time {
		t, err := time.Parse(time.RFC3339, day+"T"+clock+"Z")
		if err != nil {
			panic(err)
		}
		return t
	}
	n := 0
	rec := func(node string, t time.Time, kind, result, ref, sandbox string, caller *auditlog.Caller, req *auditlog.Request) auditlog.Event {
		n++
		ev := auditlog.Event{Time: t, Actor: node, NodeID: node, EventID: fmt.Sprintf("ae-%s-%d", node, n), Kind: kind, Result: result, Ref: ref,
			SandboxID: sandbox, CorrelationID: fmt.Sprintf("corr-%d", n), Caller: caller, Request: req}
		if sandbox != "" {
			ev.IncarnationID, ev.OwnerRef = "inc-"+sandbox, "team:payments"
		}
		return ev
	}
	api := func(node string, t time.Time, result, sandbox string, caller *auditlog.Caller, req *auditlog.Request) auditlog.Event {
		return rec(node, t, auditlog.KindAPI, result, req.Method+" "+req.Route, sandbox, caller, req)
	}
	const (
		d15, d16 = "2026-10-15", "2026-10-16"
		exec     = "/v1/sandboxes/{id}/toolbox/{path...}"
	)
	ciDeploy := reviewTok("tok_7Hq2abcdEFGH", "ci-deploy", "payments")
	admin := reviewTok("tok_Adm1nQ4xYz00", "platform-admin", "*")
	auditor := reviewTok("tok_Aud1tQ4xYz00", "auditor-q4", "*")
	prom := reviewTok("tok_Prom5crape00", "prom-scrape", "*")
	gone := reviewTok("tok_Gone7Rv0ked0", "old-deploy", "payments")
	swept := reviewTok("tok_Swept0ld0000", "old-runner", "payments")
	ana := reviewPerson("oidc:okta:00u1ana", "ana@acme.com", "*")
	bob := reviewPerson("oidc:okta:00u2bob", "Bob | <b>*admin*</b> [click](https://evil.example) www.evil.example", "payments")
	eve := reviewPerson("oidc:okta:00u9eve", `=HYPERLINK("https://evil.example","report")`, "checkout")

	withTarget := func(r *auditlog.Request, target string) *auditlog.Request { r.Target = target; return r }
	grant := func(r *auditlog.Request, target, role, team string) *auditlog.Request {
		r.Target, r.Grant = target, &auditlog.Grant{Role: role, Team: team}
		return r
	}
	coalesced := withTarget(reviewCall("POST", exec, 200), "process/execute")
	coalesced.Digest, coalesced.Count = strings.Repeat("9b", 32), 3
	rateLimited := rec("node-a", at(d16, "09:30:00"), auditlog.KindAPI, auditlog.APIResultOK, "", "sb-1", ciDeploy, &auditlog.Request{Routes: []string{"POST " + exec}})
	rateLimited.Reason, rateLimited.Dropped = auditlog.ReasonRateLimited, 412
	refused := func(node string, t time.Time, source, reason string, folded int64) auditlog.Event {
		r := reviewCall("POST", "/v1/sandboxes", 401)
		r.Source = source
		ev := rec(node, t, auditlog.KindAuthDenied, auditlog.APIResultDenied, "POST /v1/sandboxes", "", nil, r)
		ev.Reason, ev.Dropped = reason, folded
		return ev
	}
	gap := rec("node-a", at(d16, "09:50:00"), auditKindGap, "gap", "", "", nil, nil)
	gap.Dropped = 7
	// The flood-mode record shares its second with the identity change before
	// it, as two records written at one daemon start do, so the re-sent batch
	// below starts in the same second as the batch it overlaps: the walk must
	// still start at the identity change.
	floodMode := rec("node-b", at(d16, "09:03:00"), auditlog.KindAPIFloodMode, auditlog.APIResultOK, "coalesce:coalesce", "", &auditlog.Caller{Kind: "system", ID: "system:audit"}, nil)
	floodMode.Reason = "single_owner"
	ssh := rec("node-b", at(d16, "09:12:00"), auditlog.KindAPI, auditlog.APIResultOK, auditlog.RefSSH, "sb-3", &auditlog.Caller{Kind: "sandbox_key", ID: "sb-3"},
		&auditlog.Request{Method: "SSH", Route: auditlog.RefSSH, Surface: auditlog.SurfaceSSH, Target: "default"})
	viaEdge := *ana
	viaEdge.Via = "node-a"
	// node-a and node-b move from identity file v1 to the fixture's
	// identity.yaml; node-b later reorders its bindings into a third file.
	identityChange := func(node string, t time.Time, change *auditlog.IdentityConfig) auditlog.Event {
		ev := rec(node, t, auditlog.KindIdentityConfig, "success", "", "", &auditlog.Caller{Kind: "system", ID: "system:identity-file"}, nil)
		ev.Reason, ev.IdentityConfig = "ok", change
		return ev
	}
	identityV2Change := &auditlog.IdentityConfig{
		OldHash: identityV1Hash, NewHash: reviewIdentityHash(),
		BindingsAdded:   []string{`okta group="platform-admins" -> admin/*`, `okta group="eng | <b>all</b> [x](https://evil.example)" -> viewer/*`},
		BindingsRemoved: []string{`okta group="platform-admins" -> runner/payments`},
		DenyAdded:       []string{"okta:00u9eve"},
		IssuersAdded:    []string{`github-actions url="https://token.actions.githubusercontent.com" audiences=["aerolvm"] kind=oidc claims=username:sub,groups:groups,roles:roles max_token_lifetime=24h0m0s`},
	}
	operator := &auditlog.Caller{Kind: "operator", ID: "operator"}
	anaRateLimited := rec("node-b", at(d16, "09:58:00"), auditlog.KindAPI, auditlog.APIResultOK, "", "sb-3", &viaEdge, &auditlog.Request{Routes: []string{"POST " + exec}})
	anaRateLimited.Reason, anaRateLimited.Dropped = auditlog.ReasonRateLimited, 20

	nodeA := [][]auditlog.Event{
		{api("node-a", at(d15, "23:50:00"), auditlog.APIResultOK, "sb-0", prom, reviewCall("POST", "/v1/sandboxes", 201))},
		{
			identityChange("node-a", at(d16, "08:30:00"), identityV2Change),
			api("node-a", at(d16, "09:00:00"), auditlog.APIResultOK, "sb-1", ciDeploy, reviewCall("POST", "/v1/sandboxes", 201)),
			rec("node-a", at(d16, "09:01:00"), "secret_open", "success", "env:sb-1", "sb-1", ciDeploy, nil),
			api("node-a", at(d16, "09:05:00"), auditlog.APIResultOK, "", ana, grant(reviewCall("POST", "/v1/tokens", 201), "tok_Adm1nQ4xYz00", "admin", "*")),
			api("node-a", at(d16, "09:10:00"), auditlog.APIResultOK, "sb-1", ana, coalesced),
			api("node-a", at(d16, "09:11:00"), auditlog.APIResultDenied, "sb-1", bob, withTarget(reviewCall("POST", exec, 403), "process/execute")),
		},
		{
			refused("node-a", at(d16, "09:20:00"), "203.0.113.9", "expired", 3),
			rateLimited,
			api("node-a", at(d16, "09:40:00"), auditlog.APIResultOK, "sb-2", &auditlog.Caller{Kind: "system", ID: "system:lifecycle"}, reviewCall("SYSTEM", "lifecycle.auto_stop", 200)),
			api("node-a", at(d16, "09:45:00"), auditlog.APIResultOK, "", admin, withTarget(reviewCall("DELETE", "/v1/tokens/{id}", 204), "tok_Gone7Rv0ked0")),
			gap,
			api("node-a", at(d16, "09:55:00"), auditlog.APIResultOK, "sb-1", ana, reviewCall("DELETE", "/v1/sandboxes/{id}", 204)),
			api("node-a", at(d16, "10:00:00"), auditlog.APIResultOK, "sb-2", &auditlog.Caller{Kind: "node", ID: "node:node-b"}, reviewCall("DELETE", "/v1/sandboxes/{id}", 204)),
		},
	}
	nodeB := [][]auditlog.Event{
		{
			identityChange("node-b", at(d16, "09:03:00"), identityV2Change),
			floodMode,
			api("node-b", at(d16, "09:05:00"), auditlog.APIResultOK, "", operator, grant(reviewCall("POST", "/v1/tokens", 201), "tok_CkOut0000000", "runner", "checkout")),
			ssh,
			api("node-b", at(d16, "09:15:00"), auditlog.APIResultOK, "", admin, grant(reviewCall("POST", "/v1/tokens", 201), "tok_Aud1tQ4xYz00", "auditor", "*")),
		},
		{
			api("node-b", at(d16, "09:25:00"), auditlog.APIResultOK, "", &viaEdge, reviewCall("GET", "/v1/sandboxes", 200)),
			api("node-b", at(d16, "09:30:00"), auditlog.APIResultOK, "", auditor, reviewCall("GET", "/v1/tokens", 200)),
			api("node-b", at(d16, "09:31:00"), auditlog.APIResultDenied, "sb-3", auditor, reviewCall("DELETE", "/v1/sandboxes/{id}", 403)),
			api("node-b", at(d16, "09:35:00"), auditlog.APIResultOK, "sb-3", gone, withTarget(reviewCall("POST", exec, 200), "process/execute")),
			api("node-b", at(d16, "09:40:00"), auditlog.APIResultDenied, "", eve, reviewCall("POST", "/v1/sandboxes", 403)),
			refused("node-b", at(d16, "09:45:00"), "203.0.113.9", "malformed", 0),
			refused("node-b", at(d16, "09:46:00"), "198.51.100.7", "expired", 1),
			api("node-b", at(d16, "09:50:00"), auditlog.APIResultOK, "sb-4", operator, reviewCall("POST", "/v1/sandboxes", 201)),
			api("node-b", at(d16, "09:55:00"), auditlog.APIResultOK, "sb-3", swept, withTarget(reviewCall("GET", exec, 200), "files/download")),
			identityChange("node-b", at(d16, "09:57:00"), &auditlog.IdentityConfig{OldHash: reviewIdentityHash(), NewHash: identityV3Hash, Reordered: true, DenyRemoved: []string{"okta:00u9eve"}}),
			anaRateLimited,
		},
	}
	nodeC := [][]auditlog.Event{
		{api("node-c", at("2026-09-01", "12:00:00"), auditlog.APIResultOK, "sb-9", ciDeploy, reviewCall("POST", "/v1/sandboxes", 201))},
	}

	var out []fixtureBatch
	link := func(node string, batches [][]auditlog.Event) {
		prev := auditlog.GenesisPrevHash
		for i, evs := range batches {
			for j := range evs {
				auditlog.LinkEvent(prev, &evs[j])
				prev = evs[j].EventHash
			}
			out = append(out, fixtureBatch{node: node, day: evs[0].Time.Format("2006/01/02"), name: fmt.Sprintf("%s_%d.jsonl", node, i), evs: evs})
		}
	}
	link("node-a", nodeA)
	link("node-b", nodeB)
	link("node-c", nodeC)
	// node-b's exporter re-sent the tail of its first batch under a name that
	// sorts before it, starting in the same second: verified as
	// already-checked records, never counted twice, never the walk's start.
	out = append(out, fixtureBatch{node: "node-b", day: "2026/10/16", name: "node-b_0-resent.jsonl", evs: nodeB[0][1:]})
	return out
}

// reviewIdentityYAML is the fixture's identity.yaml: the file node-a
// enforces at the end of the window. Bob's group carries Markdown and the
// ops team starts a spreadsheet formula, both of which sandboxd accepts.
const reviewIdentityYAML = `version: 1
issuers:
  - name: okta
    display_name: Acme Okta
    url: https://acme.okta.com/oauth2/default
    audiences: [0oa1cli]
    clients: { cli: 0oa1cli }
    claims: { username: email, groups: groups }
  - name: github-actions
    url: https://token.actions.githubusercontent.com
    audiences: [aerolvm]
    claims: { username: sub }
bindings:                              # first match wins, top to bottom
  - { issuer: okta, group: platform-admins, role: admin }
  - { issuer: okta, group: secops, role: auditor }
  - { issuer: okta, group: "eng | <b>all</b> [x](https://evil.example)", role: viewer, team: "*" }
  - { issuer: okta, group: payments-eng, role: runner, team: payments }
  - { issuer: okta, group: ops, role: runner, team: -ops }
  - { issuer: github-actions, claim: { repository: acme/payments, ref: refs/heads/main }, role: runner, team: payments }
deny_subjects: ["okta:00u9eve"]
`

// identityV1Hash and identityV3Hash stand for the files before and after
// identity.yaml; only identity.yaml exists as a file.
var (
	identityV1Hash = strings.Repeat("1a", 32)
	identityV3Hash = strings.Repeat("3c", 32)
)

// reviewIdentityHash is identity.yaml's SHA-256, as a node records it.
func reviewIdentityHash() string {
	sum := sha256.Sum256([]byte(reviewIdentityYAML))
	return hex.EncodeToString(sum[:])
}

// reviewFixtureTokens is the token list the fixture's GET /v1/tokens returns.
func reviewFixtureTokens() models.APITokenList {
	day := func(s string) time.Time {
		t, err := time.Parse("2006-01-02T15:04:05Z", s)
		if err != nil {
			panic(err)
		}
		return t
	}
	return models.APITokenList{Tokens: []models.APIToken{
		{ID: "tok_Prom5crape00", Name: "prom-scrape", Role: "viewer", Team: "*", CreatedBy: "operator", CreatedAt: day("2026-07-20T10:00:00Z"), ExpiresAt: day("2026-10-30T00:00:00Z")},
		{ID: "tok_7Hq2abcdEFGH", Name: "ci-deploy", Role: "runner", Team: "payments", CreatedBy: "operator", CreatedAt: day("2026-09-01T08:00:00Z"), ExpiresAt: day("2026-11-30T08:00:00Z")},
		{ID: "tok_Adm1nQ4xYz00", Name: "platform-admin", Role: "admin", Team: "*", CreatedBy: "oidc:okta:00u1ana", CreatedAt: day("2026-10-16T09:05:00Z"), ExpiresAt: day("2027-01-14T09:05:00Z")},
		{ID: "tok_Aud1tQ4xYz00", Name: "auditor-q4", Role: "auditor", Team: "*", CreatedBy: "tok_Adm1nQ4xYz00", CreatedAt: day("2026-10-16T09:15:00Z"), ExpiresAt: day("2026-12-31T00:00:00Z")},
		{ID: "tok_CkOut0000000", Name: "ci-deploy", Role: "runner", Team: "checkout", CreatedBy: "operator", CreatedAt: day("2026-10-16T09:05:00Z"), ExpiresAt: day("2027-01-14T09:05:00Z")},
		{ID: "tok_0ldC10000000", Name: "-legacy-ci", Role: "runner", Team: "checkout", CreatedBy: "operator", CreatedAt: day("2026-06-01T00:00:00Z"), ExpiresAt: day("2026-10-10T00:00:00Z"), Expired: true},
	}}
}

func fixtureBatchPath(root string, b fixtureBatch) string {
	return filepath.Join(root, "export", "node="+b.node, filepath.FromSlash(b.day), b.name)
}

// TestAccessReviewFixtureIsCurrent keeps testdata/access-review in step
// with its source above, and rewrites it with -update.
func TestAccessReviewFixtureIsCurrent(t *testing.T) {
	files := map[string][]byte{}
	for _, b := range accessReviewFixture() {
		files[fixtureBatchPath(reviewFixture, b)] = batchBody(b.evs)
	}
	raw, err := json.MarshalIndent(reviewFixtureTokens(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files[filepath.Join(reviewFixture, "tokens.json")] = append(raw, '\n')
	files[filepath.Join(reviewFixture, "identity.yaml")] = []byte(reviewIdentityYAML)
	for path, want := range files {
		if *updateGolden {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run with -update to write the fixture)", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from accessReviewFixture; run with -update", path)
		}
	}
}

// reviewTokenServer serves body as GET /v1/tokens, or refuses with status
// when it is set.
func reviewTokenServer(t *testing.T, body []byte, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Header.Get("Authorization") != "Bearer test-token":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		case status != 0:
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"token.read needs the auditor or admin role"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tokens":
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newReviewHarness runs the CLI against a sandboxd whose GET /v1/tokens
// answers with tokens (the fixture's tokens.json when nil), on the
// fixture's clock.
func newReviewHarness(t *testing.T, tokens *models.APITokenList, status int) *harness {
	t.Helper()
	var body []byte
	var err error
	if tokens == nil {
		body, err = os.ReadFile(filepath.Join(reviewFixture, "tokens.json"))
	} else {
		body, err = json.Marshal(tokens)
	}
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.env = map[string]string{"SB_API_URL": reviewTokenServer(t, body, status).URL, "SB_PAT_TOKEN": "test-token"}
	h.app.now = func() time.Time { return reviewNow }
	return h
}

func reviewArgs(extra ...string) []string {
	return append([]string{"access", "review", "--export-dir", filepath.Join(reviewFixture, "export"), "--since", reviewSince}, extra...)
}

func checkReviewGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(reviewFixture, name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the golden file (run with -update after checking the change):\n%s", name, got)
	}
}

// TestAccessReviewGolden is the report itself, in both file formats, over
// the fixture export and token list.
func TestAccessReviewGolden(t *testing.T) {
	identityFile := []string{"--identity-file", filepath.Join(reviewFixture, "identity.yaml")}
	for _, tc := range []struct {
		name, golden string
		args         []string
	}{
		{"md", "review.md", []string{"--format", "md"}},
		{"csv", "review.csv", []string{"--format", "csv"}},
		{"md with the identity file", "review-identity.md", append([]string{"--format", "md"}, identityFile...)},
		{"csv with the identity file", "review-identity.csv", append([]string{"--format", "csv"}, identityFile...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newReviewHarness(t, nil, 0)
			if code := h.run(reviewArgs(tc.args...)...); code != exitOK {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, h.stdout.String(), h.stderr.String())
			}
			if h.stderr.String() != "" {
				t.Fatalf("stderr is not empty: %s", h.stderr.String())
			}
			checkReviewGolden(t, tc.golden, []byte(h.stdout.String()))
		})
	}
}

// TestAccessReviewJSON pins the joins the golden files show, on the
// structure: every flag the row lists, and the counts behind them.
func TestAccessReviewJSON(t *testing.T) {
	h := newReviewHarness(t, nil, 0)
	if code := h.run(reviewArgs("--json", "--format", "csv")...); code != exitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	var rep accessReview
	h.jsonOut(&rep)
	if rep.Result != auditlog.ResultPass || rep.Witnessed || rep.ReadRecords != readRecordsMixed || !rep.GeneratedAt.Equal(reviewNow) {
		t.Fatalf("header: %+v", rep)
	}
	tokens := map[string]reviewToken{}
	var order []string
	for _, tok := range rep.Tokens {
		tokens[tok.ID] = tok
		order = append(order, tok.Name+"@"+tok.Team)
	}
	// Two tokens may share a name in different teams; the team orders them.
	if got := strings.Join(order, " "); got != "-legacy-ci@checkout auditor-q4@* ci-deploy@checkout ci-deploy@payments platform-admin@* prom-scrape@*" {
		t.Fatalf("token order: %s", got)
	}
	flags := func(fs []reviewFlag) string { return flagsText(fs, ",") }
	wantTokens := map[string]string{
		"tok_0ldC10000000": "expired,no_recorded_action",
		"tok_Aud1tQ4xYz00": "denied",
		"tok_CkOut0000000": "no_recorded_action",
		"tok_7Hq2abcdEFGH": "rate_limited",
		"tok_Adm1nQ4xYz00": "admin",
		"tok_Prom5crape00": "expiring,no_recorded_action",
	}
	for id, want := range wantTokens {
		if got := flags(tokens[id].Flags); got != want {
			t.Errorf("token %s flags %q, want %q", id, got, want)
		}
	}
	// ci-deploy: one create, 412 calls the budget summarized, and a secret
	// open; its node-c record is before the window and not counted.
	ci := tokens["tok_7Hq2abcdEFGH"]
	if ci.Calls["api"] != 413 || ci.Calls["secret_open"] != 1 || ci.RateLimited != 412 || ci.LastNode != "node-a" {
		t.Errorf("ci-deploy activity: %+v", ci.reviewActivity)
	}
	if pa := tokens["tok_Adm1nQ4xYz00"]; pa.Calls["api"] != 2 || pa.LastAction != "DELETE /v1/tokens/{id}" {
		t.Errorf("platform-admin activity merged across nodes: %+v", pa.reviewActivity)
	}
	// Two creates in the same second on two nodes are ordered by node.
	if len(rep.Changes) != 4 || rep.Changes[0].TokenID != "tok_Adm1nQ4xYz00" || flags(rep.Changes[0].Flags) != "admin_grant" ||
		rep.Changes[1].TokenID != "tok_CkOut0000000" || rep.Changes[1].By != "operator" ||
		rep.Changes[2].Role != "auditor" || len(rep.Changes[2].Flags) != 0 || rep.Changes[3].Change != changeRevoked || rep.Changes[3].By != "tok_Adm1nQ4xYz00" {
		t.Fatalf("token changes: %+v", rep.Changes)
	}
	principals := map[string]reviewPrincipal{}
	for _, p := range rep.Principals {
		principals[p.ID] = p
	}
	wantPrincipals := map[string]string{
		"oidc:okta:00u1ana":    "rate_limited",
		"oidc:okta:00u2bob":    "denied",
		"oidc:okta:00u9eve":    "denied",
		"operator":             "admin",
		"node:node-b":          "admin",
		"sb-3":                 "",
		"system:audit":         "",
		"system:identity-file": "",
		"system:lifecycle":     "",
		"tok_Gone7Rv0ked0":     "not_listed",
		"tok_Swept0ld0000":     "not_listed",
	}
	if len(principals) != len(wantPrincipals) {
		t.Fatalf("principals: %+v", rep.Principals)
	}
	for id, want := range wantPrincipals {
		if got := flags(principals[id].Flags); got != want {
			t.Errorf("principal %s flags %q, want %q", id, got, want)
		}
	}
	// ana: a create, a coalesced exec of 3, a delete and a read on node-a's
	// side and node-b's, plus 20 calls the budget summarized on node-b.
	if ana := principals["oidc:okta:00u1ana"]; ana.Calls["api"] != 26 || ana.RateLimited != 20 || ana.LastNode != "node-b" || strings.Join(ana.Teams, ",") != "*" {
		t.Errorf("ana, merged across nodes: %+v teams %v", ana.reviewActivity, ana.Teams)
	}
	if op := principals["operator"]; op.Calls["api"] != 2 {
		t.Errorf("operator: %+v", op.reviewActivity)
	}
	if len(rep.Refused) != 2 || rep.Refused[0].Source != "203.0.113.9" || rep.Refused[0].Count != 5 || rep.Refused[0].LastNode != "node-b" || rep.Refused[1].Count != 2 {
		t.Fatalf("refused: %+v", rep.Refused)
	}
	nodes := map[string]reviewNode{}
	for _, n := range rep.Nodes {
		nodes[n.NodeID] = n
	}
	if a := nodes["node-a"]; a.ReadRecords != readRecordsMutations || a.Lost != 7 || a.RecordsChecked != 14 || a.IdentityHash != reviewIdentityHash() {
		t.Errorf("node-a: %+v", a)
	}
	if b := nodes["node-b"]; b.ReadRecords != readRecordsAll || b.UnreachedBatches != 1 || b.RecordsChecked != 16 || b.IdentityHash != identityV3Hash {
		t.Errorf("node-b: %+v", b)
	}
	if c := nodes["node-c"]; c.ReadRecords != readRecordsNone || c.RecordsChecked != 0 || c.Result != auditlog.ResultPass {
		t.Errorf("node-c: %+v", c)
	}
}

// TestAccessReviewTamperedExportFails: a record rewritten to make a refused
// call look allowed breaks node-a's chain, so the review fails with audit
// verify's exit code and prints no report.
func TestAccessReviewTamperedExportFails(t *testing.T) {
	root := t.TempDir()
	copyTree(t, filepath.Join(reviewFixture, "export"), root)
	batch := filepath.Join(root, "node=node-a", "2026", "10", "16", "node-a_1.jsonl")
	raw, err := os.ReadFile(batch)
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(raw), `"result":"denied"`, `"result":"ok"`, 1)
	if forged == string(raw) {
		t.Fatal("fixture changed: nothing to forge")
	}
	if err := os.WriteFile(batch, []byte(forged), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"access", "review", "--export-dir", root, "--since", reviewSince}
	for _, format := range []string{"md", "csv"} {
		h := newReviewHarness(t, nil, 0)
		if code := h.run(append(args, "--format", format)...); code != exitError {
			t.Fatalf("%s: exit %d, want %d\n%s", format, code, exitError, h.stdout.String())
		}
		if h.stdout.String() != "" {
			t.Fatalf("%s: a failed review printed a report:\n%s", format, h.stdout.String())
		}
		errOut := h.stderr.String()
		for _, want := range []string{"FAIL  node node-a", "does not link", "PASS  node node-b", "no access review was produced"} {
			if !strings.Contains(errOut, want) {
				t.Fatalf("%s: stderr does not mention %q:\n%s", format, want, errOut)
			}
		}
	}
	h := newReviewHarness(t, nil, 0)
	if code := h.run(append(args, "--json")...); code != exitError || h.stdout.String() != "" {
		t.Fatalf("json: exit %d, stdout %q", code, h.stdout.String())
	}
	if e := h.errorEnvelope(); !strings.Contains(e.Message, "node node-a: export 2026-10-16/node-a_1.jsonl: record") {
		t.Fatalf("json error envelope: %+v", e)
	}
}

// TestAccessReviewEscaping: what the golden files show for the hostile
// names, checked on its own so a regeneration cannot quietly drop it.
func TestAccessReviewEscaping(t *testing.T) {
	identityFile := []string{"--identity-file", filepath.Join(reviewFixture, "identity.yaml")}
	h := newReviewHarness(t, nil, 0)
	if code := h.run(reviewArgs(identityFile...)...); code != exitOK {
		t.Fatalf("md exit %d: %s", code, h.stderr.String())
	}
	md := h.stdout.String()
	for _, want := range []string{
		`Bob \| \<b>\*admin\*\</b> \[click\](https\://evil.example) www\.evil.example`,
		`=HYPERLINK("https\://evil.example","report")`, // '=' is not Markdown; the link is broken
		`| tok\_0ldC10000000 | -legacy-ci |`,
		`| \* |`,
		// A group name from the identity file, in the bindings table and in
		// a binding line from an identity_config record.
		`| 3 | okta | group="eng \| \<b>all\</b> \[x\](https\://evil.example)" | viewer | \* | every\_team |`,
		`| binding\_added | okta group="eng \| \<b>all\</b> \[x\](https\://evil.example)" -> viewer/\* | every\_team |`,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown does not contain %q", want)
		}
	}
	if m := regexp.MustCompile(`(^|[^\\])(<|\[click\]\(|https://evil)`).FindString(md); m != "" {
		t.Errorf("Markdown carries unescaped %q", m)
	}
	h = newReviewHarness(t, nil, 0)
	if code := h.run(reviewArgs(append(identityFile, "--format", "csv")...)...); code != exitOK {
		t.Fatalf("csv exit %d: %s", code, h.stderr.String())
	}
	csvOut := h.stdout.String()
	for _, want := range []string{
		`"'=HYPERLINK(""https://evil.example"",""report"")"`,
		`token,tok_0ldC10000000,'-legacy-ci,`,
		`binding,5,okta,"group=""ops""",runner,'-ops,`,
	} {
		if !strings.Contains(csvOut, want) {
			t.Errorf("CSV does not contain %q:\n%s", want, csvOut)
		}
	}
	if strings.Contains(csvOut, ",=HYPERLINK") || strings.Contains(csvOut, `,"=HYPERLINK`) || strings.Contains(csvOut, ",-legacy-ci,") {
		t.Errorf("CSV carries a cell a spreadsheet would run:\n%s", csvOut)
	}
}

func TestAccessReviewUsageAndErrors(t *testing.T) {
	fake := auditFake(t)
	empty := t.TempDir()
	// An export whose only node has nothing since the window opened.
	oldOnly := t.TempDir()
	copyTree(t, filepath.Join(reviewFixture, "export", "node=node-c"), filepath.Join(oldOnly, "node=node-c"))
	// An export with a batch the CLI cannot read.
	unreadable := t.TempDir()
	copyTree(t, filepath.Join(reviewFixture, "export"), unreadable)
	locked := filepath.Join(unreadable, "node=node-b", "2026", "10", "16", "node-b_1.jsonl")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	s3 := []string{"--endpoint", fake.URL, "--region", "us-east-1", "--path-style"}
	cases := []struct {
		name   string
		args   []string
		status int
		code   int
		want   string
	}{
		{name: "no subcommand", args: []string{"access"}, code: exitUsage, want: "expected a subcommand: review"},
		{name: "unknown subcommand", args: []string{"access", "audit"}, code: exitUsage, want: `unknown subcommand "audit"`},
		{name: "no since", args: []string{"access", "review", "--export-dir", empty}, code: exitUsage, want: "--since is required"},
		{name: "no export", args: []string{"access", "review", "--since", "90d"}, code: exitUsage, want: "exactly one of --export or --export-dir"},
		{name: "both exports", args: []string{"access", "review", "--since", "90d", "--export", "s3://a", "--export-dir", empty}, code: exitUsage, want: "exactly one of"},
		{name: "bad format", args: []string{"access", "review", "--since", "90d", "--export-dir", empty, "--format", "xlsx"}, code: exitUsage, want: `--format must be md or csv, got "xlsx"`},
		{name: "negative lag", args: []string{"access", "review", "--since", "90d", "--export-dir", empty, "--max-lag", "-1m"}, code: exitUsage, want: "--max-lag"},
		{name: "bad since", args: []string{"access", "review", "--since", "last quarter", "--export-dir", empty}, code: exitUsage, want: "--since must be"},
		{name: "bad witness URL", args: []string{"access", "review", "--since", "90d", "--export-dir", empty, "--witness", "https://w"}, code: exitUsage, want: "--witness must be s3://"},
		{name: "bad export URL", args: []string{"access", "review", "--since", "90d", "--export", "s3:///x"}, code: exitUsage, want: "--export must be s3://"},
		{name: "unexpected argument", args: []string{"access", "review", "extra", "--since", "90d", "--export-dir", empty}, code: exitUsage, want: "unexpected argument"},
		{name: "unknown flag", args: []string{"access", "review", "--nope"}, code: exitUsage, want: "nope"},
		{name: "a caller who may not read tokens", args: reviewArgs(), status: http.StatusForbidden, code: exitError, want: "token.read needs the auditor or admin role"},
		// A broken identity file stops the review before any call: the
		// token server here would refuse, and that is not what is reported.
		{name: "a missing identity file", args: reviewArgs("--identity-file", filepath.Join(empty, "identity.yaml")), status: http.StatusForbidden, code: exitError, want: "--identity-file: open"},
		{name: "an identity file sandboxd would refuse", args: reviewArgs("--identity-file", filepath.Join(reviewFixture, "tokens.json")), status: http.StatusForbidden, code: exitError, want: "version 0, want 1"},
		{name: "an empty export is incomplete", args: []string{"access", "review", "--since", reviewSince, "--export-dir", empty}, code: exitIncomplete, want: "no export batches found"},
		{name: "nothing exported since the window opened", args: []string{"access", "review", "--since", reviewSince, "--export-dir", oldOnly}, code: exitIncomplete, want: "no export batches found"},
		{name: "a missing export dir", args: []string{"access", "review", "--since", reviewSince, "--export-dir", filepath.Join(empty, "nope")}, code: exitError, want: "no such file"},
		{name: "an unreadable batch", args: []string{"access", "review", "--since", reviewSince, "--export-dir", unreadable}, code: exitError, want: "node node-b: read export batch"},
		{name: "missing witness bucket", args: append([]string{"access", "review", "--since", reviewSince, "--export-dir", empty, "--witness", "s3://missing"}, s3...), code: exitError, want: "missing"},
		{name: "missing export bucket", args: append([]string{"access", "review", "--since", reviewSince, "--export", "s3://missing"}, s3...), code: exitError, want: "missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newReviewHarness(t, nil, c.status)
			if code := h.run(c.args...); code != c.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.code, h.stdout.String(), h.stderr.String())
			}
			if out := h.stdout.String() + h.stderr.String(); !strings.Contains(out, c.want) {
				t.Fatalf("output does not mention %q:\n%s", c.want, out)
			}
			if h.stdout.String() != "" {
				t.Fatalf("a failed review printed on stdout:\n%s", h.stdout.String())
			}
		})
	}
}

// TestAccessReviewWithWitnessAndS3: over an S3 export with a witness the
// review is a full verification and nodes come from the witness; an export
// that stopped makes it INCOMPLETE (exit 3), and the report says so first.
func TestAccessReviewWithWitnessAndS3(t *testing.T) {
	start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Minute)
	fake := auditFake(t)
	a := newAuditNode("node-a", start, 270)
	b := newAuditNode("node-b", start, 270)
	a.publish(fake, 0)
	b.publish(fake, 20)
	args := []string{"access", "review", "--witness", "s3://witness/witness/", "--export", "s3://audit/audit", "--endpoint", fake.URL,
		"--region", "us-east-1", "--path-style", "--since", start.Add(6 * time.Hour).Format(time.RFC3339)}
	empty := &models.APITokenList{}

	h := newReviewHarness(t, empty, 0)
	h.app.now = nil
	if code := h.run(args...); code != exitIncomplete {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, exitIncomplete, h.stdout.String(), h.stderr.String())
	}
	md := h.stdout.String()
	for _, want := range []string{"> **INCOMPLETE:**", "INCOMPLETE on 2 nodes", "every witnessed head in the window was checked", "| node-b | INCOMPLETE |", "waited longer than --max-lag"} {
		if !strings.Contains(md, want) {
			t.Fatalf("incomplete review is missing %q:\n%s", want, md)
		}
	}

	h = newReviewHarness(t, empty, 0)
	h.app.now = nil
	if code := h.run(append(args, "--json")...); code != exitIncomplete {
		t.Fatalf("json exit %d: %s", code, h.stderr.String())
	}
	var rep accessReview
	h.jsonOut(&rep)
	if !rep.Witnessed || len(rep.Nodes) != 2 || rep.Nodes[0].Result != auditlog.ResultPass || rep.Nodes[1].Result != auditlog.ResultIncomplete || rep.ReadRecords != readRecordsNone {
		t.Fatalf("witnessed report: %+v", rep)
	}
	if n := rep.Nodes[0]; n.HeadsInWindow == 0 || n.HeadsLinked != n.HeadsInWindow {
		t.Fatalf("node-a: %d of %d heads linked", n.HeadsLinked, n.HeadsInWindow)
	}
}

// TestAccessReviewSetupFailures: an AWS configuration that cannot load, or
// a spool directory that cannot be made, stops the review with exit 1 and
// no report.
func TestAccessReviewSetupFailures(t *testing.T) {
	fake := auditFake(t)
	newAuditNode("node-a", time.Now().UTC().Add(-2*time.Hour), 6).publish(fake, 0)
	s3 := []string{"--endpoint", fake.URL, "--region", "us-east-1", "--path-style", "--since", "1d"}
	cases := []struct {
		name string
		env  string
		val  string
		args []string
		want string
	}{
		{"witness client", "AWS_PROFILE", "no-such-profile", append([]string{"--witness", "s3://witness/witness/", "--export", "s3://audit/audit"}, s3...), "no-such-profile"},
		{"export client", "AWS_PROFILE", "no-such-profile", append([]string{"--export", "s3://audit/audit"}, s3...), "no-such-profile"},
		{"export spool", "TMPDIR", filepath.Join(t.TempDir(), "gone"), append([]string{"--export", "s3://audit/audit"}, s3...), "node node-a:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(c.env, c.val)
			h := newReviewHarness(t, &models.APITokenList{}, 0)
			if code := h.run(append([]string{"access", "review"}, c.args...)...); code != exitError || h.stdout.String() != "" {
				t.Fatalf("exit %d, stdout %q, stderr %s", code, h.stdout.String(), h.stderr.String())
			}
			if !strings.Contains(h.stderr.String(), c.want) {
				t.Fatalf("stderr does not mention %q: %s", c.want, h.stderr.String())
			}
		})
	}
}

// TestAccessReviewFirstFailingNodeStopsTheRest: with more nodes than run at
// once, a node that cannot be read is reported, and the nodes not yet
// started are skipped rather than read for a review that is already lost.
func TestAccessReviewFirstFailingNodeStopsTheRest(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"node-a", "node-b", "node-c", "node-d", "node-e", "node-f", "node-g"} {
		copyTree(t, filepath.Join(reviewFixture, "export", "node=node-b"), filepath.Join(root, "node="+id))
	}
	locked := filepath.Join(root, "node=node-a", "2026", "10", "16", "node-b_0.jsonl")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	var merged []string
	err := walkReviewEvidence(t.Context(), accessReviewOptions{auditVerifyOptions: auditVerifyOptions{exportDir: root, since: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)}},
		reviewNow, func(s *reviewShare) { merged = append(merged, s.node) })
	if err == nil || !strings.HasPrefix(err.Error(), "node node-a: read export batch") || len(merged) != 0 {
		t.Fatalf("err %v, merged %v", err, merged)
	}

	// Without the failure every node is merged, in node order.
	if err := os.Chmod(locked, 0o644); err != nil {
		t.Fatal(err)
	}
	merged = nil
	err = walkReviewEvidence(t.Context(), accessReviewOptions{auditVerifyOptions: auditVerifyOptions{exportDir: root, since: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)}},
		reviewNow, func(s *reviewShare) { merged = append(merged, s.node) })
	if err != nil || strings.Join(merged, " ") != "node-a node-b node-c node-d node-e node-f node-g" {
		t.Fatalf("err %v, merged %v", err, merged)
	}
}

// TestReviewShareFolding covers the folding rules on records the fixture
// does not carry: callers with no id, a later node winning the last action
// and the name, and the cap on refusing sources.
func TestReviewShareFolding(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	call := func(at time.Time, c *auditlog.Caller) auditlog.Event {
		return auditlog.Event{Time: at, Kind: auditlog.KindAPI, Result: auditlog.APIResultOK, Ref: "POST /v1/sandboxes", Caller: c,
			Request: reviewCall("POST", "/v1/sandboxes", 201)}
	}
	a, b := newReviewShare("node-a"), newReviewShare("node-b")
	a.observe(call(t0, &auditlog.Caller{Kind: "oidc", ID: "oidc:x", Name: "old@acme.com"}))
	a.observe(call(t0, nil))
	a.observe(call(t0, &auditlog.Caller{Kind: "oidc", ID: " "}))
	a.observe(auditlog.Event{Time: t0, Kind: "secret_open", Result: "success"})
	a.observe(auditlog.Event{Time: t0, Result: "success", Caller: &auditlog.Caller{Kind: "oidc", ID: "oidc:x"}})
	b.observe(call(t0.Add(time.Hour), &auditlog.Caller{Kind: "oidc", ID: "oidc:x", Name: "new@acme.com"}))
	// A revoke whose record names no caller still lists the revoke.
	b.observe(auditlog.Event{Time: t0, Kind: auditlog.KindAPI, Result: auditlog.APIResultOK, Request: &auditlog.Request{Method: "DELETE", Route: tokenItemRoute, Status: 204, Target: "tok_x"}})
	for i := 0; i < accessReviewMaxSources+2; i++ {
		ev := auditlog.Event{Time: t0.Add(time.Duration(i) * time.Second), Kind: auditlog.KindAuthDenied, Request: &auditlog.Request{Source: fmt.Sprintf("192.0.2.%d", i)}}
		if i == 0 {
			ev.Request.Source = ""
		}
		a.observe(ev)
		b.observe(ev)
	}
	if len(a.principals) != 1 || a.principals["oidc:x"].Calls["unknown"] != 1 {
		t.Fatalf("callers with no id are not principals; a record with no kind counts as unknown: %+v", a.principals)
	}
	if len(a.refused) != accessReviewMaxSources+1 || a.refused[otherSources].Count != 2 || a.refused["unknown"].Reasons["unknown"] != 1 {
		t.Fatalf("refused sources past the cap: %d rows, other %+v", len(a.refused), a.refused[otherSources])
	}
	r := buildAccessReview(nil, []*reviewShare{a, b}, t0.Add(-time.Hour), reviewNow, false)
	if len(r.Principals) != 1 {
		t.Fatalf("principals: %+v", r.Principals)
	}
	if p := r.Principals[0]; p.Name != "new@acme.com" || p.LastNode != "node-b" || p.Calls["api"] != 2 {
		t.Fatalf("the later node wins the name and the last action: %+v", p)
	}
	if len(r.Refused) != accessReviewMaxSources+1 || r.Refused[0].Source != otherSources || r.Refused[0].Count != 4 {
		t.Fatalf("merged refusals keep the cap: %d rows, first %+v", len(r.Refused), r.Refused[0])
	}
	if len(r.Changes) != 1 || who(r.Changes[0].By, r.Changes[0].ByName) != "an unrecorded caller" {
		t.Fatalf("changes: %+v", r.Changes)
	}
}

func TestFleetReadRecords(t *testing.T) {
	cases := []struct {
		nodes []string
		want  string
	}{
		{[]string{readRecordsAll, readRecordsAll}, readRecordsAll},
		{[]string{readRecordsAll, readRecordsNone}, readRecordsMixed},
		{[]string{readRecordsMutations, readRecordsNone}, readRecordsMutations},
		{[]string{readRecordsNone}, readRecordsNone},
		{nil, readRecordsNone},
	}
	for _, c := range cases {
		if got := fleetReadRecords(c.nodes); got != c.want {
			t.Errorf("fleetReadRecords(%v) = %s, want %s", c.nodes, got, c.want)
		}
	}
}

func TestReviewWords(t *testing.T) {
	cases := []struct{ got, want string }{
		{who("tok_x", ""), "tok_x"},
		{who("operator", "operator"), "operator"},
		{who("oidc:x", "ana@acme.com"), "ana@acme.com (oidc:x)"},
		{who("", ""), "an unrecorded caller"},
		{daysWords(5 * time.Hour), "less than a day"},
		{daysWords(36 * time.Hour), "1 day"},
		{daysWords(80 * time.Hour), "3 days"},
		{countsWords(map[string]int64{"b": 2, "a": 1}, " "), "a 1, b 2"},
		{countsWords(map[string]int64{"b": 2, "a": 1}, "="), "a=1; b=2"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
