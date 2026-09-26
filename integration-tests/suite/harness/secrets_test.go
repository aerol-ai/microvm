package harness

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The leak sweep is the one helper whose bugs are invisible in the field: a
// form it does not know about is a leak that reports as a clean pass. So the
// table is asserted form by form, against a value that survives each encoding
// as something that no longer looks like itself.
func TestFindPlaintextLeakCatchesEveryEncoding(t *testing.T) {
	const secret = "s3cr3t/value+with=chars & spaces"

	cases := map[string]string{
		"raw":          secret,
		"base64-std":   base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64-raw":   base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"base64-url":   base64.URLEncoding.EncodeToString([]byte(secret)),
		"hex":          hex.EncodeToString([]byte(secret)),
		"url-query":    url.QueryEscape(secret),
		"url-path":     url.PathEscape(secret),
		"json-escaped": mustJSONInner(t, secret),
	}

	for name, encoded := range cases {
		haystack := "prefix noise " + encoded + " trailing noise"
		form, found := FindPlaintextLeak(haystack, secret)
		if !found {
			t.Fatalf("%s encoding slipped through the sweep (encoded=%q)", name, encoded)
		}
		// The reported form need not be the one we injected — several
		// encodings coincide for some inputs — but it must be a real form.
		if _, ok := plaintextForms(secret)[form]; !ok {
			t.Fatalf("%s: reported form %q is not in the table", name, form)
		}
	}
}

func mustJSONInner(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[1 : len(b)-1])
}

// A clean haystack must not report a leak, and an empty secret must not make
// every haystack "leak" — strings.Contains(x, "") is true for all x, which
// would turn the whole sweep into an unconditional failure.
func TestFindPlaintextLeakNoFalsePositives(t *testing.T) {
	if form, found := FindPlaintextLeak("nothing to see here", "hunter2"); found {
		t.Fatalf("clean haystack reported a %s leak", form)
	}
	if form, found := FindPlaintextLeak("anything at all", "", "   "); found {
		t.Fatalf("empty secret reported a %s leak; the sweep would fail unconditionally", form)
	}
}

// The reported form must be stable: it is printed into a report a human reads
// when triaging a leak, and a map-iteration-order answer would make two runs
// of the same failure disagree about what happened.
func TestFindPlaintextLeakFormIsDeterministic(t *testing.T) {
	const secret = "abc"
	// "abc" appears raw AND hex-encoded in this haystack.
	haystack := secret + " " + hex.EncodeToString([]byte(secret))
	first, ok := FindPlaintextLeak(haystack, secret)
	if !ok {
		t.Fatal("no leak found in a haystack that plainly contains one")
	}
	for i := 0; i < 50; i++ {
		got, ok := FindPlaintextLeak(haystack, secret)
		if !ok || got != first {
			t.Fatalf("form varied between runs: %q then %q (ok=%v)", first, got, ok)
		}
	}
}

// AssertNoPlaintext must pass silently on clean input. Its failure path calls
// t.Fatalf, which cannot be captured; FindPlaintextLeak above covers it.
func TestAssertNoPlaintextPassesOnCleanInput(t *testing.T) {
	AssertNoPlaintext(t, "clean body", `{"env":{"TOKEN":"[redacted]"}}`, "hunter2")
}

func TestAuditQueryEncode(t *testing.T) {
	if got := (AuditQuery{}).encode(); got != "" {
		t.Fatalf("empty query encoded to %q, want no query string at all", got)
	}
	got := AuditQuery{Limit: 25, Cursor: "c1", Kind: "secret.seal", IncarnationID: "inc-1"}.encode()
	for _, want := range []string{"limit=25", "cursor=c1", "kind=secret.seal", "incarnation_id=inc-1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("encoded query %q is missing %q", got, want)
		}
	}
	// A zero limit means "server default", not limit=0 — which the server
	// would parse as a literal zero and could answer with an empty page.
	if strings.Contains(AuditQuery{Cursor: "c"}.encode(), "limit=") {
		t.Fatal("a zero limit was sent as limit=0")
	}
}

// Converged is what stops a holder-count assertion from reading a mid-fan-out
// view. Outstanding work of either kind must read as not-converged.
func TestSecretHoldersViewConverged(t *testing.T) {
	if !(SecretHoldersView{Holders: []string{"a", "b"}}).Converged() {
		t.Fatal("a view with no outstanding work reported not converged")
	}
	if (SecretHoldersView{PendingPut: []string{"b"}}).Converged() {
		t.Fatal("an unfinished fan-out reported converged")
	}
	if (SecretHoldersView{PendingDelete: []string{"b"}}).Converged() {
		t.Fatal("an unfinished teardown reported converged")
	}
}

// RefusedWith must require BOTH halves. A node that died of a bad binary or a
// full disk also fails to start, and accepting that as a boot-gate pass is how
// §I would go green having proven nothing.
func TestNodeBootResultRefusedWith(t *testing.T) {
	gate := NodeBootResult{Started: false, Journal: "fatal: SB_SECRET_AUDIT_STRICT_BOOT must be true under enterprise mode"}
	if !gate.RefusedWith("must be true under enterprise mode") {
		t.Fatal("a genuine boot-gate refusal was not recognised")
	}
	if gate.RefusedWith("no such file or directory") {
		t.Fatal("an unrelated failure satisfied a boot-gate assertion")
	}
	started := NodeBootResult{Started: true, Journal: "must be true under enterprise mode"}
	if started.RefusedWith("must be true under enterprise mode") {
		t.Fatal("a node that started was reported as having refused")
	}
}

func TestCountAuditEventsAndSortedCopy(t *testing.T) {
	events := []auditlog.Event{{Kind: "secret.seal"}, {Kind: "secret.open"}, {Kind: "secret.seal"}}
	if got := CountAuditEvents(events, "secret.seal"); got != 2 {
		t.Fatalf("secret.seal count = %d, want 2", got)
	}
	if got := CountAuditEvents(events, "secret.reseal"); got != 0 {
		t.Fatalf("absent kind counted %d, want 0", got)
	}

	in := []string{"c", "a", "b"}
	out := SortedCopy(in)
	if strings.Join(out, ",") != "a,b,c" {
		t.Fatalf("SortedCopy = %v", out)
	}
	if strings.Join(in, ",") != "c,a,b" {
		t.Fatalf("SortedCopy mutated its input: %v", in)
	}
}

// SecretHoldersFor must decode the wire shape the v1 handler emits. The field
// names here are the contract: this test is what catches a server-side rename
// that the black-box struct would otherwise absorb as a zero value.
func TestSecretHoldersForDecodesWireShape(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"sandbox_id": "sb-1",
			"incarnation_id": "inc-1",
			"ref": "secret://sb-1/inc-1",
			"holders": ["node-a","node-b"],
			"seal_generation": 3,
			"version": 2,
			"pending_put": ["node-c"]
		}`))
	}))
	defer srv.Close()

	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "pat-token"}}
	v, err := c.SecretHoldersFor(t.Context(), "sb-1")
	if err != nil {
		t.Fatalf("SecretHoldersFor: %v", err)
	}
	if gotPath != "/v1/cluster/sandboxes/sb-1/secret-holders" {
		t.Fatalf("requested %q", gotPath)
	}
	if gotAuth != "Bearer pat-token" {
		t.Fatalf("PAT was not attached: %q", gotAuth)
	}
	if v.SandboxID != "sb-1" || v.IncarnationID != "inc-1" || v.Ref != "secret://sb-1/inc-1" {
		t.Fatalf("identity fields did not decode: %+v", v)
	}
	if strings.Join(v.Holders, ",") != "node-a,node-b" {
		t.Fatalf("holders = %v", v.Holders)
	}
	if v.SealGeneration != 3 || v.Version != 2 {
		t.Fatalf("seal_generation/version did not decode: %+v", v)
	}
	if v.Converged() {
		t.Fatal("a view with pending_put reported converged")
	}
}

// A sandbox id with a slash or a space must not silently address a different
// path. The suite generates names from t.Name(), which is '/'-separated for
// subtests, so this is a live hazard rather than a theoretical one.
func TestSecretHoldersForEscapesSandboxID(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"holders":[]}`))
	}))
	defer srv.Close()

	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}
	if _, err := c.SecretHoldersFor(t.Context(), "sb/../evil"); err != nil {
		t.Fatalf("SecretHoldersFor: %v", err)
	}
	if strings.Contains(gotPath, "/../") {
		t.Fatalf("sandbox id escaped its path segment: %q", gotPath)
	}
}

// A non-2xx must surface as an error, not as an empty holder set — "no
// holders" is precisely the answer a cleanup assertion treats as success.
func TestSecretHoldersForReportsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"sandbox not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}
	v, err := c.SecretHoldersFor(t.Context(), "sb-missing")
	if err == nil {
		t.Fatalf("404 decoded as a holder view: %+v", v)
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error does not name the status: %v", err)
	}
}

// fastPolls shrinks the polling interval so the wait-loop tests assert on
// behaviour rather than on elapsed wall-clock.
func fastPolls(t *testing.T) {
	t.Helper()
	oh, or := holdersPollInterval, readyPollInterval
	holdersPollInterval, readyPollInterval = time.Millisecond, time.Millisecond
	t.Cleanup(func() { holdersPollInterval, readyPollInterval = oh, or })
}

func holdersServer(t *testing.T, bodies ...string) *Client {
	t.Helper()
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n
		if i >= len(bodies) {
			i = len(bodies) - 1
		}
		n++
		_, _ = w.Write([]byte(bodies[i]))
	}))
	t.Cleanup(srv.Close)
	return &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}
}

// The wait must not settle on a view that still owes fan-out work, even when
// the holder count already matches. This is the flake the Converged gate
// exists to prevent, and the one §6.2b calls out as a stub trap.
func TestWaitSecretHoldersIgnoresUnconvergedViews(t *testing.T) {
	fastPolls(t)
	c := holdersServer(t,
		`{"holders":["a","b","c"],"pending_put":["c"],"seal_generation":1}`,
		`{"holders":["a","b","c"],"pending_put":["c"],"seal_generation":1}`,
		`{"holders":["a","b","c"],"seal_generation":2}`,
	)
	v, err := c.WaitSecretHolders(context.Background(), "sb-1", 5*time.Second, func(v SecretHoldersView) bool {
		return len(v.Holders) == 3
	})
	if err != nil {
		t.Fatalf("WaitSecretHolders: %v", err)
	}
	if v.SealGeneration != 2 {
		t.Fatalf("settled on the unconverged view (generation %d, want 2)", v.SealGeneration)
	}
}

// A predicate that is never satisfied must time out with the last view in the
// message — a bare "timed out" tells a report reader nothing about what the
// cluster was actually doing.
func TestWaitSecretHoldersTimesOutWithContext(t *testing.T) {
	fastPolls(t)
	c := holdersServer(t, `{"holders":["a"],"seal_generation":7}`)
	_, err := c.WaitSecretHolders(context.Background(), "sb-1", 20*time.Millisecond, func(SecretHoldersView) bool { return false })
	if err == nil {
		t.Fatal("an unsatisfiable predicate returned success")
	}
	if !strings.Contains(err.Error(), "SealGeneration:7") {
		t.Fatalf("timeout error does not carry the last view: %v", err)
	}
}

func TestWaitSecretHoldersReportsPersistentReadFailure(t *testing.T) {
	fastPolls(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}
	_, err := c.WaitSecretHolders(context.Background(), "sb-1", 20*time.Millisecond, func(SecretHoldersView) bool { return true })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("a persistently failing read did not surface: %v", err)
	}
}

// failover_ready is a *bool and its absence is the vacuous-pass hazard: on a
// non-cluster scenario the server omits it entirely, and treating that as
// ready would make every HA use case green without a cluster.
func TestWaitFailoverReadyRejectsAbsentFlag(t *testing.T) {
	fastPolls(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"sb-1","name":"n","status":"running"}`))
	}))
	defer srv.Close()
	c := NewClient(t, &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"})
	err := c.WaitFailoverReady(context.Background(), "sb-1", 20*time.Millisecond)
	if err == nil {
		t.Fatal("an absent failover_ready was accepted as ready")
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Fatalf("error does not explain the absence: %v", err)
	}
}

func TestWaitFailoverReadyWaitsForTrue(t *testing.T) {
	fastPolls(t)
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ready := n > 1
		n++
		_, _ = w.Write([]byte(`{"id":"sb-1","name":"n","status":"running","failover_ready":` + boolLit(ready) + `}`))
	}))
	defer srv.Close()
	c := NewClient(t, &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"})
	if err := c.WaitFailoverReady(context.Background(), "sb-1", 5*time.Second); err != nil {
		t.Fatalf("WaitFailoverReady: %v", err)
	}
	if n < 3 {
		t.Fatalf("returned after %d polls; it did not actually wait for the flag to flip", n)
	}
}

func TestWaitFailoverReadyReportsFalse(t *testing.T) {
	fastPolls(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"sb-1","name":"n","status":"running","failover_ready":false}`))
	}))
	defer srv.Close()
	c := NewClient(t, &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"})
	err := c.WaitFailoverReady(context.Background(), "sb-1", 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "failover_ready=false") {
		t.Fatalf("a stuck-false flag was not reported as such: %v", err)
	}
}

func boolLit(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Pagination walks to the end and concatenates in order.
func TestAllAuditPagesWalksEveryPage(t *testing.T) {
	pages := []string{
		`{"events":[{"kind":"secret.seal"},{"kind":"secret.open"}],"next_cursor":"c2"}`,
		`{"events":[{"kind":"secret.open"}],"next_cursor":"c3"}`,
		`{"events":[{"kind":"secret.reseal"}]}`,
	}
	var seen []string
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Query().Get("cursor"))
		_, _ = w.Write([]byte(pages[n]))
		n++
	}))
	defer srv.Close()
	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}

	events, err := c.AllAuditPages(context.Background(), "sb-1", 2, 10)
	if err != nil {
		t.Fatalf("AllAuditPages: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("got %d events across 3 pages, want 4", len(events))
	}
	if CountAuditEvents(events, "secret.open") != 2 || CountAuditEvents(events, "secret.reseal") != 1 {
		t.Fatalf("pages were not concatenated faithfully: %+v", events)
	}
	if strings.Join(seen, ",") != ",c2,c3" {
		t.Fatalf("cursor sequence = %v", seen)
	}
}

// A server that keeps handing back the same cursor must fail the use case, not
// spin the suite forever.
func TestAllAuditPagesRejectsARepeatingCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"events":[{"kind":"secret.seal"}],"next_cursor":"stuck"}`))
	}))
	defer srv.Close()
	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}

	_, err := c.AllAuditPages(context.Background(), "sb-1", 1, 100)
	if err == nil {
		t.Fatal("a non-advancing cursor was walked to completion")
	}
	if !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("wrong diagnosis: %v", err)
	}
}

// An always-advancing cursor must stop at maxPages.
func TestAllAuditPagesBoundsTotalPages(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		_, _ = w.Write([]byte(`{"events":[{"kind":"secret.seal"}],"next_cursor":"c` + fmt.Sprint(n) + `"}`))
	}))
	defer srv.Close()
	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}

	events, err := c.AllAuditPages(context.Background(), "sb-1", 1, 4)
	if err == nil || !strings.Contains(err.Error(), "did not terminate") {
		t.Fatalf("an endless pagination was not bounded: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("collected %d events, want the 4 pages it did read", len(events))
	}
}

func TestAuditPageForReportsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "index incomplete", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := &Client{sc: &Scenario{Name: "unit", BaseURL: srv.URL, PAT: "p"}}
	if _, err := c.AuditPageFor(context.Background(), "sb-1", AuditQuery{}); err == nil {
		t.Fatal("a 503 decoded as an empty page; UC-137 would pass on a short answer")
	}
}

// fakeSSH records every script WithNodeEnv runs and lets a test decide what
// `systemctl is-active` answers.
type fakeSSH struct {
	mu     sync.Mutex
	runs   []string
	active string // what is-active reports; "" means alternate per activeSeq
}

func (f *fakeSSH) install(t *testing.T) {
	t.Helper()
	prev := sshRunner
	sshRunner = func(_ *testing.T, _, script string) (string, error) {
		// The reachability probe must answer, or RequireNodeSSH skips every
		// test that uses this fake — the fake stands in for a node we CAN
		// reach, and its unreachable counterpart is unreachableSSH below.
		if strings.Contains(script, "aerol-ssh-ok") {
			return "aerol-ssh-ok\n", nil
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.runs = append(f.runs, script)
		if strings.Contains(script, "is-active") {
			return f.active + "\n", nil
		}
		return "", nil
	}
	// The probe result is cached per target for the whole run, so a test that
	// installs a different fake would otherwise inherit the previous one's
	// answer.
	resetSSHReachability()
	t.Cleanup(func() {
		sshRunner = prev
		resetSSHReachability()
	})
}

// resetSSHReachability clears the per-run probe cache. Test-only.
func resetSSHReachability() {
	sshReachableMu.Lock()
	defer sshReachableMu.Unlock()
	sshReachable = map[string]bool{}
}

func (f *fakeSSH) ran(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.runs {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

func (f *fakeSSH) countRan(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.runs {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

func testNode() IntegrationNode {
	return IntegrationNode{Name: "node1", PublicIP: "203.0.113.10"}
}

// The override must be a drop-in, never an edit to cluster.env: a half-applied
// edit to cluster.env leaves a node holding a corrupted cluster identity that
// no later test can repair, whereas a drop-in is removed by deleting a file.
func TestWithNodeEnvWritesADropInAndNeverTouchesClusterEnv(t *testing.T) {
	fake := &fakeSSH{active: "active"}
	fake.install(t)

	WithNodeEnv(t, testNode(), map[string]string{
		"SB_SECRET_AUDIT_STRICT_BOOT": "false",
		"SB_CONTAINER_PRIVILEGED":     "true",
	}, func(res NodeBootResult) {
		if !res.Started {
			t.Fatal("a node reporting is-active=active was read as not started")
		}
	})

	if !fake.ran(itestEnvDropIn) || !fake.ran(itestEnvOverrideFile) {
		t.Fatalf("the override drop-in was not written: %v", fake.runs)
	}
	if !fake.ran("SB_CONTAINER_PRIVILEGED=true") || !fake.ran("SB_SECRET_AUDIT_STRICT_BOOT=false") {
		t.Fatalf("the requested env did not reach the node: %v", fake.runs)
	}
	for _, forbidden := range []string{"/etc/sandboxd/cluster.env", "/etc/sandboxd/sandboxd.env"} {
		if fake.ran(forbidden) {
			t.Fatalf("WithNodeEnv touched %s; a partial edit there strands the node's cluster identity", forbidden)
		}
	}
	// The drop-in must sort after cluster-init's cluster.conf, or systemd
	// applies it first and cluster.env silently wins every collision.
	if !strings.HasPrefix(path.Base(itestEnvDropIn), "zz-") {
		t.Fatalf("drop-in %q does not sort after cluster.conf", itestEnvDropIn)
	}
}

// The load-bearing property: a use case that fails partway through must not
// leave the node down. t.Fatal is a runtime.Goexit and a panic unwinds the
// stack; both run deferred functions, which is exactly why the restore is a
// defer and not a trailing statement.
func TestWithNodeEnvRestoresAfterAPanic(t *testing.T) {
	fake := &fakeSSH{active: "active"}
	fake.install(t)

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic did not propagate out of WithNodeEnv")
			}
		}()
		WithNodeEnv(t, testNode(), map[string]string{"SB_X": "1"}, func(NodeBootResult) {
			panic("the use case blew up mid-assertion")
		})
	}()

	assertRestored(t, fake)
}

func TestWithNodeEnvRestoresAfterGoexit(t *testing.T) {
	fake := &fakeSSH{active: "active"}
	fake.install(t)

	// runtime.Goexit is precisely what t.Fatal does. Running it on its own
	// goroutine is the only way to observe the unwind without failing this
	// test along with it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		WithNodeEnv(t, testNode(), map[string]string{"SB_X": "1"}, func(NodeBootResult) {
			runtime.Goexit()
		})
	}()
	<-done

	assertRestored(t, fake)
}

func assertRestored(t *testing.T, fake *fakeSSH) {
	t.Helper()
	if !fake.ran("rm -f "+itestEnvDropIn) || !fake.ran(itestEnvOverrideFile+" &&") {
		t.Fatalf("the override was not removed; the node is left in the test's configuration: %v", fake.runs)
	}
	if !fake.ran("systemctl restart sandboxd") {
		t.Fatal("sandboxd was never restarted after the override was removed; the node is left down")
	}
	// Exactly one restore — a double restore would mean the cleanup could run
	// again later and restart a node some other test is mid-way through.
	if n := fake.countRan("rm -f " + itestEnvDropIn); n != 1 {
		t.Fatalf("restore ran %d times, want exactly 1", n)
	}
}

// Setting nothing is how UC-159 checks that a node rejoins cleanly after the
// boot-gate matrix; it must still restart the node and still clean up.
func TestWithNodeEnvWithNoVarsStillRestartsAndRestores(t *testing.T) {
	fake := &fakeSSH{active: "active"}
	fake.install(t)

	called := false
	WithNodeEnv(t, testNode(), nil, func(res NodeBootResult) {
		called = true
		if !res.Started {
			t.Fatal("an unchanged node did not come back")
		}
	})
	if !called {
		t.Fatal("fn never ran")
	}
	assertRestored(t, fake)
}

// awaitUnitActive is what tells a boot-gate case whether the node refused to
// start. It cannot use t.Fatal — "did not start" is the PASS for §I — so its
// three outcomes are asserted directly. A t.Run wrapper cannot stand in here:
// a failing subtest fails its parent, so a negative path that calls t.Errorf
// is not observable from inside the same test binary.
func TestAwaitUnitActive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active string
		want   bool
	}{
		{"active", "active", true},
		{"failed is terminal", "failed", false},
		{"activating times out", "activating", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSSH{active: tc.active}
			fake.install(t)
			start := time.Now()
			if got := awaitUnitActive(t, "u@h", "sandboxd", 40*time.Millisecond); got != tc.want {
				t.Fatalf("awaitUnitActive = %v, want %v", got, tc.want)
			}
			// "failed" is terminal in systemd: polling on would burn the whole
			// timeout for an answer that cannot change, and §I restarts a node
			// per forbidden combination.
			if tc.active == "failed" && time.Since(start) > 30*time.Millisecond {
				t.Fatalf("a terminal 'failed' state was polled for %s instead of returning at once", time.Since(start))
			}
		})
	}
}

// A node with no reachable address must be an error, not a silent no-op that
// would make a boot-gate use case pass having done nothing. WithNodeEnv fails
// the test in that case; here we pin the guard it reads.
func TestSSHTargetRejectsAnAddresslessNode(t *testing.T) {
	if _, ok := SSHTarget(IntegrationNode{Name: "ghost"}); ok {
		t.Fatal("a node with neither a public nor a private IP produced an SSH target")
	}
	if target, ok := SSHTarget(IntegrationNode{Name: "n", PrivateIP: "10.0.0.4"}); !ok || !strings.HasSuffix(target, "@10.0.0.4") {
		t.Fatalf("private-IP fallback = %q, %v", target, ok)
	}
}

// KnownCapabilities must list every Capability constant. The guard it feeds
// only catches typos while it is complete: a constant missing from the map
// makes a correctly-spelled capability read as a typo (which is what happened
// when the six secrets capabilities landed), and the map is the only list.
func TestKnownCapabilitiesCoversEveryConstant(t *testing.T) {
	// Parsing the declarations is deliberate: a hand-written second list here
	// would go stale in exactly the same way the one it replaced did.
	src, err := os.ReadFile("usecases.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^\s*(Cap[A-Za-z0-9]+)\s+Capability\s*=\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 20 {
		t.Fatalf("only found %d capability constants; the pattern no longer matches the declarations", len(matches))
	}
	for _, m := range matches {
		if !KnownCapabilities[Capability(m[2])] {
			t.Fatalf("capability %s (%q) is declared but missing from KnownCapabilities, so any UC requiring it fails as a typo", m[1], m[2])
		}
	}
	if len(KnownCapabilities) != len(matches) {
		t.Fatalf("KnownCapabilities has %d entries but %d constants are declared", len(KnownCapabilities), len(matches))
	}
}

// A curl that could not connect must be an error, never a 0 status silently
// read as "this node does not hold a copy" — which would turn an unreachable
// peer into evidence that the fan-out was correctly scoped.
func TestPeerProbeFromOutput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		out        string
		err        error
		wantStatus int
		wantErr    bool
		present    bool
		absent     bool
	}{
		{name: "held", out: "200", wantStatus: 200, present: true},
		{name: "held no content", out: "204", wantStatus: 204, present: true},
		{name: "absent", out: "404", wantStatus: 404, absent: true},
		{name: "refused identity", out: "403", wantStatus: 403},
		{name: "could not connect", out: "000\n", wantErr: true},
		{name: "no output", out: "", err: errors.New("ssh exited 255"), wantErr: true},
		{name: "unparsable", out: "curl: (6) could not resolve host", wantErr: true},
		// curl exits non-zero for some statuses; a real status is the answer.
		{name: "status despite exit code", out: "503", err: errors.New("exit 22"), wantStatus: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := peerProbeFromOutput("node1", tc.out, tc.err)
			if (p.Err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", p.Err, tc.wantErr)
			}
			if !tc.wantErr && p.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", p.Status, tc.wantStatus)
			}
			if p.Present() != tc.present {
				t.Fatalf("Present() = %v, want %v", p.Present(), tc.present)
			}
			if p.Absent() != tc.absent {
				t.Fatalf("Absent() = %v, want %v", p.Absent(), tc.absent)
			}
		})
	}
}

// Present and Absent must not both be false-y in a way that lets a caller
// treat "refused" as "absent": a 403 is neither, and a UC that read it as
// absent would report a broken authz path as correct scoping.
func TestPeerSecretProbeRefusedIsNeitherPresentNorAbsent(t *testing.T) {
	p := PeerSecretProbe{Status: 403}
	if p.Present() || p.Absent() {
		t.Fatalf("403 classified as present=%v absent=%v", p.Present(), p.Absent())
	}
}

// Seed-first ordering is load-bearing: restarting all SWIM members with the
// seed last once split a live cluster 2+1, because the joiners came up with
// no rendezvous to gossip with.
func TestSeedFirstOrdersTheSeedAheadAndDropsUnreachableNodes(t *testing.T) {
	in := []IntegrationNode{
		{Name: "joiner-a", PublicIP: "203.0.113.11"},
		{Name: "ghost"}, // no address at all
		{Name: "seed", Seed: true, PublicIP: "203.0.113.10"},
		{Name: "joiner-b", PrivateIP: "10.0.0.5"},
	}
	got := seedFirst(in)
	if len(got) != 3 {
		t.Fatalf("got %d nodes, want the 3 reachable ones: %+v", len(got), got)
	}
	if got[0].Name != "seed" {
		t.Fatalf("seed is not first: %s", got[0].Name)
	}
	for _, n := range got {
		if n.Name == "ghost" {
			t.Fatal("an unreachable node was kept")
		}
	}
}

// Every node must be configured before fn runs, and every node must be
// restored afterwards — a partially-configured fleet would make the use case
// assert against a mix of two configurations.
func TestWithClusterEnvConfiguresEveryNodeThenRestoresAll(t *testing.T) {
	fake := &fakeSSH{active: "active"}
	fake.install(t)

	targets := &IntegrationTargets{Nodes: []IntegrationNode{
		{Name: "joiner-a", PublicIP: "203.0.113.11"},
		{Name: "seed", Seed: true, PublicIP: "203.0.113.10"},
	}}

	var saw map[string]NodeBootResult
	WithClusterEnv(t, targets, map[string]string{"SB_SECRET_RECIPIENT_BACKUP_COUNT": "1"}, func(res map[string]NodeBootResult) {
		saw = res
	})

	if len(saw) != 2 {
		t.Fatalf("fn saw %d nodes, want 2: %+v", len(saw), saw)
	}
	if n := fake.countRan("SB_SECRET_RECIPIENT_BACKUP_COUNT=1"); n != 2 {
		t.Fatalf("the override was written to %d nodes, want 2", n)
	}
	if n := fake.countRan("rm -f " + itestEnvDropIn); n != 2 {
		t.Fatalf("restore ran on %d nodes, want 2", n)
	}
}

// An unreachable node must SKIP the case, not fail it: whether this machine
// holds a key for the fleet is a fact about the operator's laptop, and a red
// row sends whoever reads the matrix looking for a defect that is not there.
// A silent pass would be worse still.
func TestRequireNodeSSHSkipsWhenUnreachable(t *testing.T) {
	prev := sshRunner
	sshRunner = func(*testing.T, string, string) (string, error) {
		return "Permission denied (publickey).", errors.New("exit status 255")
	}
	resetSSHReachability()
	t.Cleanup(func() { sshRunner = prev; resetSSHReachability() })

	// A skip is not observable from the parent, so assert the decision the
	// skip is made from instead: the probe must report the node unreachable,
	// and it must be cached rather than re-dialled.
	calls := 0
	sshRunner = func(*testing.T, string, string) (string, error) {
		calls++
		return "Permission denied (publickey).", errors.New("exit status 255")
	}
	node := IntegrationNode{Name: "node1", PublicIP: "203.0.113.10"}
	target, _ := SSHTarget(node)
	for i := 0; i < 3; i++ {
		probeNodeSSH(t, target)
	}
	if calls != 1 {
		t.Fatalf("the probe dialled %d times; it must be cached, or every SSH case pays the connect timeout again", calls)
	}
	sshReachableMu.Lock()
	reachable := sshReachable[target]
	sshReachableMu.Unlock()
	if reachable {
		t.Fatal("a node answering 'Permission denied' was recorded as reachable")
	}
}

// And a reachable node must not skip.
func TestRequireNodeSSHPassesWhenReachable(t *testing.T) {
	fake := &fakeSSH{active: "active"}
	fake.install(t)
	RequireNodeSSH(t, IntegrationNode{Name: "node1", PublicIP: "203.0.113.10"})
}
