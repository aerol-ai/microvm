package harness

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Shared helpers for the secrets, audit and enterprise use cases (plan §7.1).
//
// They exist so the assertions in those files stay declarative. The behaviours
// under test — seal, fan-out, failover, reseal, boot gates — are each several
// round trips of setup before anything can be asserted, and hand-rolling that
// setup per use case is how a suite ends up asserting on its own scaffolding
// instead of on the product.

// HASandboxTimeout bounds the create + min-ACK fan-out wait. A cluster create
// with failover.policy=recreate seals the credentials and waits for peer ACKs
// inside the create call, so it is legitimately slower than a plain create.
const HASandboxTimeout = 4 * time.Minute

// SecretHoldersView is GET /v1/cluster/sandboxes/{id}/secret-holders.
//
// Declared here rather than imported from internal/service so the suite stays
// a black-box client of the wire format — the same reason OwnerNodeID decodes
// its own placement shape. The server-side handler test pins the JSON field
// names; a rename there that missed this file shows up as a zero-valued
// Holders, which every caller below treats as a failure rather than a pass.
type SecretHoldersView struct {
	SandboxID      string   `json:"sandbox_id"`
	IncarnationID  string   `json:"incarnation_id"`
	Ref            string   `json:"ref"`
	Holders        []string `json:"holders"`
	SealGeneration int64    `json:"seal_generation"`
	Version        int      `json:"version"`
	PendingPut     []string `json:"pending_put"`
	PendingDelete  []string `json:"pending_delete"`
}

// Converged reports whether the fan-out has settled: every recipient holds a
// copy and nothing is owed. A holder-count assertion taken while PendingPut is
// non-empty is asserting against a moving target and will flake.
func (v SecretHoldersView) Converged() bool {
	return len(v.PendingPut) == 0 && len(v.PendingDelete) == 0
}

// SecretHoldersFor reads the recipient set for one sandbox. The error is
// returned rather than fatal so a caller can poll for convergence.
func (c *Client) SecretHoldersFor(ctx context.Context, sandboxID string) (SecretHoldersView, error) {
	var out SecretHoldersView
	err := c.GetJSON(ctx, "/v1/cluster/sandboxes/"+url.PathEscape(sandboxID)+"/secret-holders", &out)
	return out, err
}

// SecretHolders returns the recipient set, failing the test if it cannot be
// read. Sorted by the server, so two reads are directly comparable.
func SecretHolders(t *testing.T, c *Client, sandboxID string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v, err := c.SecretHoldersFor(ctx, sandboxID)
	if err != nil {
		t.Fatalf("read secret holders for %s: %v", sandboxID, err)
	}
	return v.Holders
}

// WaitSecretHolders polls until pred is satisfied by a CONVERGED holder view.
//
// Requiring convergence is the point: without it a test that wants "three
// holders" can observe a transient two-holder view mid-fan-out and either pass
// early or fail for the wrong reason. The last view (or error) is folded into
// the returned error, because "the predicate was never satisfied" on its own
// tells whoever reads the report nothing about what the cluster was doing.
func (c *Client) WaitSecretHolders(ctx context.Context, sandboxID string, timeout time.Duration, pred func(SecretHoldersView) bool) (SecretHoldersView, error) {
	deadline := time.Now().Add(timeout)
	var last SecretHoldersView
	var lastErr error
	for {
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		v, err := c.SecretHoldersFor(rctx, sandboxID)
		cancel()
		if err == nil {
			last, lastErr = v, nil
			if v.Converged() && pred(v) {
				return v, nil
			}
		} else {
			lastErr = err
		}
		if !time.Now().Add(holdersPollInterval).Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(holdersPollInterval):
		}
	}
	if lastErr != nil {
		return last, fmt.Errorf("secret holders for %s never satisfied the predicate within %s; last error: %w", sandboxID, timeout, lastErr)
	}
	return last, fmt.Errorf("secret holders for %s never satisfied the predicate within %s; last view: %+v", sandboxID, timeout, last)
}

// holdersPollInterval and readyPollInterval are package vars so the offline
// tests can drive the polling loops without sleeping for real seconds.
var (
	holdersPollInterval = 2 * time.Second
	readyPollInterval   = 2 * time.Second
)

// AwaitSecretHolders is the fatal wrapper around WaitSecretHolders.
func AwaitSecretHolders(t *testing.T, c *Client, sandboxID string, timeout time.Duration, pred func(SecretHoldersView) bool) SecretHoldersView {
	t.Helper()
	v, err := c.WaitSecretHolders(context.Background(), sandboxID, timeout, pred)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// HASandboxSpec is the input to CreateHASandbox.
//
// The plan sketched this as CreateHASandbox(t, c, creds, env) with creds as
// mount credentials. It is a struct instead because mount credentials are only
// sealed when they ride a real MountSpec, and a MountSpec needs a live backend
// (S3/NFS/SSHFS/rclone) to mount — so making them the default carrier would
// have coupled every secrets use case to external storage the scenario may not
// have. Env is the credential carrier that always works: secretsFromRequest
// (internal/service/cluster_secrets.go) seals req.Env exactly as it seals
// mount credentials, and env is readable from inside the sandbox, which is
// what UC-117 has to prove. A scenario that does have a backend adds Mounts.
type HASandboxSpec struct {
	// Env is sealed and replicated. Use it for the secret material a use case
	// then reads back from inside the sandbox.
	Env map[string]string
	// Mounts is for the scenarios that can satisfy a real external backend;
	// MountSpec.Credentials is sealed alongside Env.
	Mounts []models.MountSpec
	// Image defaults to DefaultImage.
	Image string
}

// CreateHASandbox creates a sandbox with failover.policy=recreate carrying the
// spec's sealed material, and waits for failover_ready.
//
// Cleanup is registered exactly as NewSandbox does, so an HA sandbox — which
// costs a sealed row on every recipient, not just its owner — is never left
// behind by a failing test.
func CreateHASandbox(t *testing.T, c *Client, spec HASandboxSpec) *microvm.Sandbox {
	t.Helper()
	public := true
	image := spec.Image
	if image == "" {
		image = DefaultImage
	}
	opts := sdktypes.CreateSandboxOptions{
		Name:               UniqueName(c.sc, t),
		Image:              image,
		AllowPublicTraffic: &public,
		Env:                spec.Env,
		Mounts:             spec.Mounts,
		Failover:           &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	}

	ctx, cancel := context.WithTimeout(context.Background(), HASandboxTimeout)
	defer cancel()
	sb, err := c.SDK().Create(ctx, opts)
	if err != nil {
		t.Fatalf("create HA sandbox: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if derr := c.SDK().Destroy(cctx, sb.ID); derr != nil {
			t.Logf("cleanup: destroy HA sandbox %s: %v", sb.ID, derr)
		}
	})
	AwaitFailoverReady(t, c, sb.ID, HASandboxTimeout)
	return sb
}

// WaitFailoverReady blocks until the sandbox reports failover_ready=true.
//
// A nil failover_ready means the server did not compute one (policy=none, or a
// single-node deployment), which is NOT readiness — treating it as ready would
// make every HA use case pass vacuously on a non-cluster scenario, which is
// the exact failure §6.2b warns about.
func (c *Client) WaitFailoverReady(ctx context.Context, sandboxID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	last := "never read"
	for {
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		sb, err := c.SDK().Get(rctx, sandboxID)
		cancel()
		switch {
		case err != nil:
			last = "get error: " + err.Error()
		case sb.FailoverReady == nil:
			last = "failover_ready absent (policy not recreate, or not a cluster)"
		case *sb.FailoverReady:
			return nil
		default:
			last = "failover_ready=false"
		}
		if !time.Now().Add(readyPollInterval).Before(deadline) {
			return fmt.Errorf("sandbox %s never became failover-ready within %s (%s)", sandboxID, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readyPollInterval):
		}
	}
}

// AwaitFailoverReady is the fatal wrapper around WaitFailoverReady.
func AwaitFailoverReady(t *testing.T, c *Client, sandboxID string, timeout time.Duration) {
	t.Helper()
	if err := c.WaitFailoverReady(context.Background(), sandboxID, timeout); err != nil {
		t.Fatal(err)
	}
}

// AuditQuery are the query parameters of GET /v1/sandboxes/{id}/audit, as
// parseSecretAuditQuery (pkg/api/v1/audit_handler.go) reads them. There is no
// "local" switch on the public route — the peer-local slice lives behind the
// mTLS-gated /v1/cluster/internal path, so UC-134's honesty check reads the
// coverage block of a fanned-out answer rather than asking for a local one.
type AuditQuery struct {
	Limit  int
	Cursor string
	Kind   string
	// IncarnationID scopes a post-delete read. Required for a retained-ACL
	// match: the server has no any-incarnation fallback, by design, so that a
	// recreated id cannot read the previous incarnation's events.
	IncarnationID string
}

func (q AuditQuery) encode() string {
	v := url.Values{}
	if q.Limit > 0 {
		v.Set("limit", fmt.Sprint(q.Limit))
	}
	if q.Cursor != "" {
		v.Set("cursor", q.Cursor)
	}
	if q.Kind != "" {
		v.Set("kind", q.Kind)
	}
	if q.IncarnationID != "" {
		v.Set("incarnation_id", q.IncarnationID)
	}
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

// AuditCoverage mirrors the coverage block of a SecretAuditPage.
type AuditCoverage struct {
	Answered []string `json:"answered"`
	Missing  []string `json:"missing"`
	Partial  bool     `json:"partial"`
}

// AuditPage is GET /v1/sandboxes/{id}/audit. The event type is imported from
// pkg/auditlog rather than redeclared: it is the on-the-wire record AND the
// hash-chained on-disk record, so a field added there must reach the suite or
// the export/witness use cases would silently stop checking it.
type AuditPage struct {
	Events     []auditlog.Event `json:"events"`
	Coverage   AuditCoverage    `json:"coverage"`
	NextCursor string           `json:"next_cursor"`
}

// AuditPageFor reads one page of a sandbox's audit history.
func (c *Client) AuditPageFor(ctx context.Context, sandboxID string, q AuditQuery) (AuditPage, error) {
	var page AuditPage
	path := "/v1/sandboxes/" + url.PathEscape(sandboxID) + "/audit" + q.encode()
	err := c.GetJSON(ctx, path, &page)
	return page, err
}

// AuditEvents is the fatal wrapper around AuditPageFor.
func AuditEvents(t *testing.T, c *Client, sandboxID string, q AuditQuery) AuditPage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	page, err := c.AuditPageFor(ctx, sandboxID, q)
	if err != nil {
		t.Fatalf("read audit events for %s: %v", sandboxID, err)
	}
	return page
}

// AllAuditPages walks every page via next_cursor and returns the flattened
// history.
//
// maxPages bounds a server that keeps handing back a cursor, and a cursor that
// repeats is an immediate error rather than a loop: both are pagination bugs
// that would otherwise hang the suite instead of failing one use case, and a
// hung run costs the whole fleet's uptime, not one red row.
func (c *Client) AllAuditPages(ctx context.Context, sandboxID string, pageSize, maxPages int) ([]auditlog.Event, error) {
	var all []auditlog.Event
	q := AuditQuery{Limit: pageSize}
	for i := 0; i < maxPages; i++ {
		page, err := c.AuditPageFor(ctx, sandboxID, q)
		if err != nil {
			return all, err
		}
		all = append(all, page.Events...)
		if page.NextCursor == "" {
			return all, nil
		}
		if page.NextCursor == q.Cursor {
			return all, fmt.Errorf("audit pagination for %s did not advance: cursor %q repeated", sandboxID, page.NextCursor)
		}
		q.Cursor = page.NextCursor
	}
	return all, fmt.Errorf("audit pagination for %s did not terminate within %d pages", sandboxID, maxPages)
}

// AllAuditEvents is the fatal wrapper around AllAuditPages.
func AllAuditEvents(t *testing.T, c *Client, sandboxID string, pageSize, maxPages int) []auditlog.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	events, err := c.AllAuditPages(ctx, sandboxID, pageSize, maxPages)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// CountAuditEvents counts events whose Kind matches.
func CountAuditEvents(events []auditlog.Event, kind string) int {
	n := 0
	for _, ev := range events {
		if ev.Kind == kind {
			n++
		}
	}
	return n
}

// AssertNoPlaintext fails the test if any secret appears in haystack under any
// encoding a leak plausibly takes.
//
// One place knows every shape, deliberately. A per-use-case `strings.Contains`
// check catches only the raw form, and the interesting leaks are the ones that
// went through a JSON encoder, a base64 envelope or a URL query on the way out
// — exactly the paths that make a value stop looking like itself. what names
// the haystack so a failure says where the leak was, not just that there was
// one.
func AssertNoPlaintext(t *testing.T, what string, haystack string, secrets ...string) {
	t.Helper()
	if form, ok := FindPlaintextLeak(haystack, secrets...); ok {
		// Never print the secret itself: this runs against live deployments
		// and the output lands in a CI log and a published report.
		t.Fatalf("%s leaked a secret in %s form (haystack %d bytes)", what, form, len(haystack))
	}
}

// FindPlaintextLeak returns the name of the first encoding under which a
// secret appears in haystack. Separated from the assertion so the encoding
// table itself is unit-testable offline — this is the one piece of the suite
// whose bugs are silent, because a form it fails to check is a leak that
// reports as a pass.
func FindPlaintextLeak(haystack string, secrets ...string) (string, bool) {
	for _, s := range secrets {
		if strings.TrimSpace(s) == "" {
			continue
		}
		forms := plaintextForms(s)
		// Deterministic order, so the reported form does not vary run to run.
		for _, form := range sortedKeys(forms) {
			if enc := forms[form]; enc != "" && strings.Contains(haystack, enc) {
				return form, true
			}
		}
	}
	return "", false
}

// plaintextForms returns the encodings a secret could survive into an output
// as. Keep this exhaustive rather than clever — a missing form is a leak the
// sweep will not see.
func plaintextForms(s string) map[string]string {
	forms := map[string]string{
		"raw":          s,
		"base64-std":   base64.StdEncoding.EncodeToString([]byte(s)),
		"base64-raw":   base64.RawStdEncoding.EncodeToString([]byte(s)),
		"base64-url":   base64.URLEncoding.EncodeToString([]byte(s)),
		"hex":          hex.EncodeToString([]byte(s)),
		"url-query":    url.QueryEscape(s),
		"url-path":     url.PathEscape(s),
		"json-escaped": jsonInner(s),
	}
	// A JSON-escaped value identical to the raw one adds nothing and would
	// report the same hit twice under two names.
	if forms["json-escaped"] == s {
		delete(forms, "json-escaped")
	}
	if forms["url-query"] == s {
		delete(forms, "url-query")
	}
	if forms["url-path"] == s {
		delete(forms, "url-path")
	}
	return forms
}

// jsonInner returns the JSON string encoding of s without its quotes, which is
// the form a secret takes when it is nested inside a larger serialized body.
func jsonInner(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return s
	}
	return string(b[1 : len(b)-1])
}

// SortedCopy returns a sorted copy, for comparing holder sets the server did
// not sort (e.g. one assembled from several reads).
func SortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// itestEnvOverrideFile and itestEnvDropIn are where WithNodeEnv puts its
// overrides.
//
// A separate drop-in, never an edit to cluster.env. systemd applies
// EnvironmentFile assignments in order and the last one wins, and drop-ins load
// in lexical filename order, so "zz-" lands after cluster-init's "cluster.conf"
// and after the base sandboxd.env. Restoring is then a file delete, which
// cannot half-succeed — whereas an in-place edit of cluster.env that is
// interrupted (a test timeout, a killed run) leaves a node holding a corrupted
// cluster identity that no later test can repair.
const (
	itestEnvOverrideFile = "/etc/sandboxd/itest-override.env"
	itestEnvDropIn       = "/etc/systemd/system/sandboxd.service.d/zz-itest-override.conf"
)

// NodeBootResult is what a node did when restarted under an env override.
//
// Started is false for the boot-gate cases (§I), which is a PASS there, not an
// infrastructure failure — so the restart itself must not be fatal and the
// refusal message has to be observable. Journal carries it.
type NodeBootResult struct {
	Started bool
	Status  string
	Journal string
}

// RefusedWith reports whether the node refused to start AND the journal names
// the given reason. Both halves matter: a node that failed to start for an
// unrelated reason (a bad binary, a full disk) would otherwise satisfy a
// boot-gate assertion that only checked Started==false.
func (r NodeBootResult) RefusedWith(substr string) bool {
	return !r.Started && strings.Contains(r.Journal, substr)
}

// WithNodeEnv sets env vars on one node, restarts sandboxd, runs fn with the
// boot outcome, and ALWAYS restores the original configuration.
//
// The restore is the whole point. §I deliberately boots nodes with configs the
// enterprise validator refuses, and a case that fails partway through — an
// assertion, a timeout, a panic — must not leave a node down: every later use
// case in the run would fail against a degraded fleet, and the reported cause
// would be whatever ran next rather than what actually broke. The restore runs
// from a defer, so it survives t.Fatal (which is a runtime.Goexit) and panics
// alike, and a restore that itself fails is reported loudly because a stranded
// node invalidates the rest of the run.
//
// Setting no variables is allowed and means "restart the node unchanged",
// which is how UC-159 checks that a node rejoins cleanly.
func WithNodeEnv(t *testing.T, node IntegrationNode, kv map[string]string, fn func(NodeBootResult)) {
	t.Helper()
	target, ok := SSHTarget(node)
	if !ok {
		t.Fatalf("node %s has no SSH address", node.Name)
	}

	// Restore first, defer second, apply third: registering the cleanup before
	// the mutation means a failure inside the apply itself is still cleaned up.
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		out, err := SSHRun(t, target, "sudo rm -f "+itestEnvDropIn+" "+itestEnvOverrideFile+
			" && sudo systemctl daemon-reload && sudo systemctl restart sandboxd")
		if err != nil {
			t.Errorf("RESTORE FAILED on %s — the node may be left down and the rest of this run is suspect: %v\n%s", node.Name, err, out)
			return
		}
		if !awaitUnitActive(t, target, "sandboxd", 3*time.Minute) {
			t.Errorf("RESTORE FAILED on %s — sandboxd did not come back active after the override was removed; the rest of this run is suspect", node.Name)
		}
	}
	defer restore()

	var b strings.Builder
	b.WriteString("# Written by the integration suite (harness.WithNodeEnv). Transient.\n")
	for _, k := range sortedKeys(kv) {
		// No quoting: systemd EnvironmentFile takes the rest of the line
		// verbatim, and quoting here would make the value arrive with quotes.
		fmt.Fprintf(&b, "%s=%s\n", k, kv[k])
	}
	script := fmt.Sprintf(`set -e
sudo install -d -m 0755 /etc/systemd/system/sandboxd.service.d
sudo install -d -m 0750 /etc/sandboxd
sudo tee %s >/dev/null <<'AEROL_ITEST_ENV'
%sAEROL_ITEST_ENV
sudo chmod 0600 %s
sudo tee %s >/dev/null <<'AEROL_ITEST_DROPIN'
[Service]
EnvironmentFile=%s
AEROL_ITEST_DROPIN
sudo systemctl daemon-reload`, itestEnvOverrideFile, b.String(), itestEnvOverrideFile, itestEnvDropIn, itestEnvOverrideFile)

	if out, err := SSHRun(t, target, script); err != nil {
		t.Fatalf("apply env override on %s: %v\n%s", node.Name, err, out)
	}

	// The restart is expected to fail for the boot-gate cases, so its exit
	// status is information, not an error. systemctl restart blocks until the
	// unit settles either way.
	_, _ = SSHRun(t, target, "sudo systemctl restart sandboxd")
	res := NodeBootResult{Started: awaitUnitActive(t, target, "sandboxd", 90*time.Second)}
	status, _ := SSHRun(t, target, "sudo systemctl is-active sandboxd || true")
	res.Status = strings.TrimSpace(status)
	journal, _ := SSHRun(t, target, "sudo journalctl -u sandboxd --no-pager -n 120 || true")
	res.Journal = journal

	fn(res)
}

// awaitUnitActive polls systemctl is-active. It returns false rather than
// failing so callers can treat "did not start" as either an assertion or an
// error, depending on which they are testing.
func awaitUnitActive(t *testing.T, target, unit string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := SSHRun(t, target, "sudo systemctl is-active "+unit+" || true")
		switch strings.TrimSpace(out) {
		case "active":
			return true
		case "failed":
			// Terminal: systemd has given up. Polling on would just burn the
			// remaining timeout for an answer that cannot change.
			return false
		}
		if err != nil {
			t.Logf("is-active %s on %s: %v", unit, target, err)
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
