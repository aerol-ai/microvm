//go:build integration

package suite

// Identity and access, the disruptive half (plans/identity-and-access.md
// §8 and CEO review D21): chaos (UC-291..UC-293), the token spray
// (UC-272b), PAT rotation (UC-277), the mixed-version gate (UC-281), the
// enterprise boot gates (UC-283) and flood control's mode switch (UC-289).
// Each one restarts, partitions or loads nodes, so the file sorts last and
// every case restores what it changed.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func requireDisruptive(t *testing.T, why string) {
	t.Helper()
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: " + why)
	}
}

// nodesByRole splits the fleet into workers (no Raft state, so they read
// tokens from the mirror) and the rest.
func nodesByRole(targets *harness.IntegrationTargets) (workers, others []harness.IntegrationNode) {
	for _, n := range targets.Nodes {
		if n.Role == "worker" {
			workers = append(workers, n)
		} else {
			others = append(others, n)
		}
	}
	return workers, others
}

// envInt reads a positive integer knob, falling back to def.
func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// UC-272b — the D21 token spray against a worker: malformed and unknown
// avm_ tokens at volume are all refused with 401 by the worker itself. No
// other node counts a single token refusal (no lookup was forwarded to the
// server tier), and the worker's mirror never resnapshots. The rate is
// AEROL_TOKEN_SPRAY_RPS (default 2000; the plan's 10k is the offline
// benchmark's figure, beyond what one operator machine sends over SSH).
func TestIdentityTokenSpray(t *testing.T) {
	harness.Require(t, sc, "UC-272b")
	targets := identityTargets(t)
	workers, others := nodesByRole(targets)
	if len(workers) == 0 {
		t.Skip("no worker without Raft state in this topology")
	}
	worker := workers[0]
	base := nodeBase(t, worker)
	otherBases := map[string]string{}
	for _, n := range others {
		otherBases[n.Name] = nodeBase(t, n)
	}

	tokenFailures := func(text string) float64 {
		return harness.MetricValueOrZero(text, "aerolvm_auth_failures_total", map[string]string{"key": "token", "key2": "malformed"}) +
			harness.MetricValueOrZero(text, "aerolvm_auth_failures_total", map[string]string{"key": "token", "key2": "unknown_or_revoked"})
	}
	const resnap = "aerolvm_identity_mirror_resnapshots_total"
	before := nodeMetrics(t, base)
	otherBefore := map[string]float64{}
	for name, b := range otherBases {
		otherBefore[name] = tokenFailures(nodeMetrics(t, b))
	}

	rps := envInt("AEROL_TOKEN_SPRAY_RPS", 2000)
	secs := envInt("AEROL_TOKEN_SPRAY_SECONDS", 10)
	var sent, refused, other atomic.Int64
	var mu sync.Mutex
	statuses := map[int]int{}
	tick := time.NewTicker(time.Second / time.Duration(rps))
	defer tick.Stop()
	jobs := make(chan string, 1024)
	var wg sync.WaitGroup
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 128}}
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bearer := range jobs {
				req, _ := http.NewRequest(http.MethodGet, base+"/v1/sandboxes", nil)
				req.Header.Set("Authorization", "Bearer "+bearer)
				resp, err := hc.Do(req)
				sent.Add(1)
				code := 0
				if err == nil {
					code = resp.StatusCode
					resp.Body.Close()
				}
				if code == http.StatusUnauthorized {
					refused.Add(1)
				} else {
					other.Add(1)
				}
				mu.Lock()
				statuses[code]++
				mu.Unlock()
			}
		}()
	}
	start := time.Now()
	for i := 0; time.Since(start) < time.Duration(secs)*time.Second; i++ {
		<-tick.C
		var bearer string
		if i%2 == 0 {
			// Unknown: well-formed, checksum and all, but never minted.
			tok, err := identitywire.NewAPIToken(nil)
			if err != nil {
				t.Fatal(err)
			}
			bearer = tok.Plaintext()
		} else {
			bearer = "avm_" + randomBase64(40) // malformed: wrong shape
		}
		jobs <- bearer
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start)
	t.Logf("spray: %d requests in %s (%.0f/s) at %s: %v", sent.Load(), elapsed.Round(time.Millisecond), float64(sent.Load())/elapsed.Seconds(), worker.Name, statuses)

	if other.Load() != 0 {
		t.Fatalf("%d of %d spray requests got something other than 401: %v (a 5xx means a refusal path did work it should not)", other.Load(), sent.Load(), statuses)
	}
	after := nodeMetrics(t, base)
	if got := tokenFailures(after) - tokenFailures(before); got < float64(refused.Load()) {
		t.Fatalf("the worker counted %v token refusals for %d refused requests", got, refused.Load())
	}
	if d := harness.MetricValueOrZero(after, resnap, nil) - harness.MetricValueOrZero(before, resnap, nil); d != 0 {
		t.Fatalf("the spray made the worker's mirror resnapshot %v times", d)
	}
	for name, b := range otherBases {
		if d := tokenFailures(nodeMetrics(t, b)) - otherBefore[name]; d != 0 {
			t.Errorf("%s counted %v token refusals during a spray aimed only at %s: a lookup left the worker", name, d, worker.Name)
		}
	}
}

func randomBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// partitionScript cuts node off from the given addresses (both directions)
// and arms a dead-man heal on the node itself, so a harness that dies
// mid-partition does not leave the node cut off.
func partitionScript(ips []string, heal string) string {
	var b strings.Builder
	b.WriteString("set -e; ")
	fmt.Fprintf(&b, "sudo systemd-run --unit aerolvm-itest-heal-$$ --on-active=600 /bin/sh -c %q >/dev/null 2>&1 || true; ", heal)
	for _, ip := range ips {
		fmt.Fprintf(&b, "sudo iptables -I INPUT -s %s -m comment --comment aerolvm-itest-partition -j DROP; ", ip)
		fmt.Fprintf(&b, "sudo iptables -I OUTPUT -d %s -m comment --comment aerolvm-itest-partition -j DROP; ", ip)
	}
	b.WriteString("echo PARTITIONED")
	return b.String()
}

// healScript removes every rule partitionScript added.
func healScript(ips []string) string {
	var b strings.Builder
	for _, ip := range ips {
		fmt.Fprintf(&b, "while iptables -D INPUT -s %s -m comment --comment aerolvm-itest-partition -j DROP 2>/dev/null; do :; done; ", ip)
		fmt.Fprintf(&b, "while iptables -D OUTPUT -d %s -m comment --comment aerolvm-itest-partition -j DROP 2>/dev/null; do :; done; ", ip)
	}
	return b.String()
}

// UC-291 — chaos: a worker partitioned from the server tier for 90 s. After
// SB_IDENTITY_MAX_STALE (60 s) its mirror is stale and avm_ tokens get 503
// "identity data is stale", but a metrics.read scrape keeps working (D16)
// and OIDC and the PAT, which need no server, are unaffected. After the
// heal the mirror resyncs within one poll.
func TestIdentityWorkerPartitionStaleMirror(t *testing.T) {
	harness.Require(t, sc, "UC-291")
	requireDisruptive(t, "this partitions a worker from the server tier for 90 s")
	fx := oidcFixture(t)
	workers, others := nodesByRole(fx.targets)
	if len(workers) == 0 || len(others) == 0 {
		t.Skip("needs a worker and a server tier")
	}
	worker := workers[0]
	harness.RequireNodeSSH(t, worker)
	target, _ := harness.SSHTarget(worker)
	base := nodeBase(t, worker)

	runner := mintToken(t, "uc291-run", "runner", harness.TeamPayments)
	scraper := mintToken(t, "uc291-scrape", "viewer", "*")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for _, tok := range []mintedToken{runner, scraper} {
		if _, err := harness.AwaitAccepted(ctx, tok.API.At(base), tokenPropagation); err != nil {
			t.Fatalf("the token never reached %s before the partition: %v", worker.Name, err)
		}
	}
	sso := fx.issuer.Token(t, "uc291-sso", harness.GroupPaymentsEng)

	// Only the server tier: the worker keeps its ingress, so what is under
	// test is the mirror losing its source, not the node going dark.
	var serverIPs []string
	for _, n := range others {
		if n.PrivateIP != "" && (n.Role == "server" || n.Role == "mixed" || n.Seed) {
			serverIPs = append(serverIPs, n.PrivateIP)
		}
	}
	if len(serverIPs) == 0 {
		t.Skip("no server-tier node with a private address")
	}
	heal := healScript(serverIPs)
	healed := false
	doHeal := func() {
		if healed {
			return
		}
		healed = true
		if out, err := harness.SSHRun(t, target, "sudo sh -c '"+strings.ReplaceAll(heal, "'", `'"'"'`)+"' && echo HEALED"); err != nil || !strings.Contains(out, "HEALED") {
			t.Errorf("RESTORE FAILED: %s may still be partitioned from the server tier (a dead-man heal fires within 10 minutes): %v %s", worker.Name, err, out)
		}
	}
	t.Cleanup(doHeal)
	if out, err := harness.SSHRun(t, target, partitionScript(serverIPs, heal)); err != nil || !strings.Contains(out, "PARTITIONED") {
		t.Fatalf("partition %s: %v %s", worker.Name, err, out)
	}
	cut := time.Now()

	time.Sleep(65 * time.Second)
	_, resp, err := runner.API.At(base).WhoAmI(ctx)
	if err != nil || resp.Status != http.StatusServiceUnavailable || !strings.Contains(resp.Err().Error, "stale") {
		t.Errorf("an avm_ token on the partitioned worker after %s = %v %s, want 503 identity data is stale", time.Since(cut).Round(time.Second), err, resp)
	}
	if r := statusAs(t, scraper.API.At(base), http.MethodGet, "/v1/metrics", nil); r.Status != http.StatusOK {
		t.Errorf("a metrics.read scrape on the stale worker = %s, want 200 (D16: keep metrics flowing)", r)
	}
	if who := whoamiAs(t, base, sso); who.Role != "runner" {
		t.Errorf("an SSO token on the partitioned worker: %+v", who)
	}
	if who := whoamiAs(t, base, sc.OperatorPAT); who.Principal.ID != "operator" {
		t.Errorf("the PAT on the partitioned worker's loopback: %+v", who)
	}

	if wait := 90*time.Second - time.Since(cut); wait > 0 {
		time.Sleep(wait)
	}
	doHeal()
	healedAt := time.Now()
	// One poll is SB_IDENTITY_SYNC_INTERVAL (5 s); give it three.
	if _, err := harness.AwaitAccepted(ctx, runner.API.At(base), 15*time.Second); err != nil {
		t.Fatalf("the worker's mirror did not resync within 15 s of the heal: %v", err)
	}
	t.Logf("mirror resynced %s after the heal", time.Since(healedAt).Round(100*time.Millisecond))
}

// leaderNode finds the current Raft leader's node.
func leaderNode(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := operatorAPI().Do(ctx, http.MethodGet, "/v1/cluster/leader", nil)
		cancel()
		if err == nil && resp.Status == http.StatusOK {
			if id := harness.ParseLeaderJSON(string(resp.Body)); id != "" {
				return nodeForOwner(t, targets, id)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Raft leader reported: %v %s", err, resp)
		}
		time.Sleep(3 * time.Second)
	}
}

// UC-292 — chaos: the Raft leader killed during a burst of 50 token creates
// (25 names, each sent twice at once). Afterwards no two live tokens share a
// name, every 201 handed out a secret for a token that exists and works,
// and every create that failed left its name either absent or listed: a
// retry gets 201 or 409, never a duplicate.
func TestIdentityLeaderKilledDuringTokenCreates(t *testing.T) {
	harness.Require(t, sc, "UC-292")
	requireDisruptive(t, "this kills the Raft leader")
	targets := identityTargets(t)
	leader := leaderNode(t, targets)
	// The case cannot choose its victim, it must kill whoever leads, and
	// killing the seed costs the cluster its rendezvous rather than one
	// member. On a fresh fleet the seed usually leads, so this runs once an
	// earlier case has moved leadership; the skip says which happened.
	requireNonSeedVictim(t, leader)
	prefix := harness.TokenName("uc292")
	const names = 25

	type result struct {
		name    string
		status  int
		created models.CreatedAPIToken
	}
	results := make(chan result, 2*names)
	var wg sync.WaitGroup
	api := operatorAPI()
	for i := 0; i < names; i++ {
		name := fmt.Sprintf("%s-%02d", prefix, i)
		for k := 0; k < 2; k++ {
			wg.Add(1)
			go func(delay time.Duration) {
				defer wg.Done()
				time.Sleep(delay)
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				resp, err := api.Do(ctx, http.MethodPost, "/v1/tokens", models.CreateAPITokenRequest{Name: name, Role: "viewer", Team: harness.TeamPayments, ExpiresIn: "1h"})
				r := result{name: name}
				if err == nil {
					r.status = resp.Status
					if resp.Status == http.StatusCreated {
						_ = resp.JSON(&r.created)
					}
				}
				results <- r
			}(time.Duration(i) * 120 * time.Millisecond)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if list, err := operatorAPI().ListTokens(ctx); err == nil {
			for _, tk := range list.Tokens {
				if strings.HasPrefix(tk.Name, prefix) {
					_ = operatorAPI().RevokeToken(ctx, tk.ID)
				}
			}
		}
	})

	time.Sleep(time.Second) // a few creates are committed, most are in flight
	restore := harness.KillNodeDaemon(t, leader)
	wg.Wait()
	close(results)
	restore()

	var all []result
	statuses := map[int]int{}
	for r := range results {
		all = append(all, r)
		statuses[r.status]++
	}
	t.Logf("creates with leader %s killed mid-burst: %v", leader.Name, statuses)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var list models.APITokenList
	deadline := time.Now().Add(3 * time.Minute)
	for {
		var err error
		if list, err = operatorAPI().ListTokens(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("list tokens after the leader came back: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
	live := map[string][]models.APIToken{}
	byID := map[string]models.APIToken{}
	for _, tk := range list.Tokens {
		if strings.HasPrefix(tk.Name, prefix) && !tk.Expired {
			live[tk.Name] = append(live[tk.Name], tk)
			byID[tk.ID] = tk
		}
	}
	for name, toks := range live {
		if len(toks) > 1 {
			t.Errorf("%d live tokens share the name %s", len(toks), name)
		}
	}
	got201 := map[string]bool{}
	for _, r := range all {
		if r.status != http.StatusCreated {
			continue
		}
		got201[r.name] = true
		if _, ok := byID[r.created.ID]; !ok {
			t.Errorf("a 201 for %s handed out a secret for token %s, which does not exist", r.name, r.created.ID)
			continue
		}
		if _, err := harness.AwaitAccepted(ctx, harness.NewAPIClient(sc.BaseURL, r.created.Token), tokenPropagation); err != nil {
			t.Errorf("the secret a 201 returned for %s does not work: %v", r.name, err)
		}
	}
	// Retry every name that never got a 201: 201 if the failed create left
	// nothing, 409 if it was applied after all, and then it must be listed.
	for i := 0; i < names; i++ {
		name := fmt.Sprintf("%s-%02d", prefix, i)
		if got201[name] {
			continue
		}
		resp := statusAs(t, api, http.MethodPost, "/v1/tokens", models.CreateAPITokenRequest{Name: name, Role: "viewer", Team: harness.TeamPayments, ExpiresIn: "1h"})
		switch resp.Status {
		case http.StatusCreated:
			if len(live[name]) != 0 {
				t.Errorf("retrying %s created a second live token next to %s", name, live[name][0].ID)
			}
		case http.StatusConflict:
			if len(live[name]) != 1 {
				t.Errorf("retrying %s says it exists, but it is not listed", name)
			}
		default:
			t.Errorf("retrying %s after the leader came back = %s", name, resp)
		}
	}
}

// UC-293 — chaos: the test issuer rotates its signing key under load
// (AEROL_IDENTITY_CHAOS_RPS, default the plan's 1000/s). Every node
// refetches at most once a minute, nothing answers 5xx, and tokens signed
// with the new key are accepted from the first refetch on.
func TestIdentityIssuerKeyRotationUnderLoad(t *testing.T) {
	harness.Require(t, sc, "UC-293")
	requireDisruptive(t, "this drives sustained load at the fleet")
	fx := oidcFixture(t)
	nodes := sshNodes(t, fx.targets)
	bases := map[string]string{}
	for _, n := range nodes {
		bases[n.Name] = nodeBase(t, n)
	}
	issuerLabel := map[string]string{"key": harness.IssuerName}
	fetches := func(text string) float64 {
		return harness.MetricValueOrZero(text, "aerolvm_identity_jwks_fetch_total", map[string]string{"key": harness.IssuerName, "key2": "ok"}) +
			harness.MetricValueOrZero(text, "aerolvm_identity_jwks_fetch_total", map[string]string{"key": harness.IssuerName, "key2": "error"})
	}
	// Start from a quiet minute on every node, so the first new-kid request
	// is allowed its refetch at once.
	deadline := time.Now().Add(3 * time.Minute)
	for name, base := range bases {
		for {
			last := harness.MetricValueOrZero(nodeMetrics(t, base), "aerolvm_identity_jwks_last_success_timestamp", issuerLabel)
			if last > 0 && time.Since(time.Unix(int64(last), 0)) > 65*time.Second {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s kept fetching keys for 3 minutes", name)
			}
			time.Sleep(5 * time.Second)
		}
	}
	before := map[string]float64{}
	for name, base := range bases {
		before[name] = fetches(nodeMetrics(t, base))
	}

	rps := envInt("AEROL_IDENTITY_CHAOS_RPS", 1000)
	oldTok := fx.issuer.Token(t, "uc293-old", harness.GroupPaymentsEng)
	var newTok atomic.Value // string, set after the rotation lands
	var oldOK, newOK, new401, fivexx, otherFail atomic.Int64
	hc := &http.Client{Timeout: 15 * time.Second, Transport: harness.NewTransport(func(tr *http.Transport) { tr.MaxIdleConnsPerHost = 256 })}
	jobs := make(chan bool, 4096) // true: use the new-key token
	var wg sync.WaitGroup
	for w := 0; w < 128; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for useNew := range jobs {
				bearer := oldTok
				if useNew {
					bearer, _ = newTok.Load().(string)
				}
				req, _ := http.NewRequest(http.MethodGet, sc.BaseURL+"/v1/whoami", nil)
				req.Header.Set("Authorization", "Bearer "+bearer)
				resp, err := hc.Do(req)
				switch {
				case err != nil:
					otherFail.Add(1)
				case resp.StatusCode >= 500:
					fivexx.Add(1)
				case resp.StatusCode == http.StatusOK && useNew:
					newOK.Add(1)
				case resp.StatusCode == http.StatusOK:
					oldOK.Add(1)
				case resp.StatusCode == http.StatusUnauthorized && useNew:
					new401.Add(1)
				default:
					otherFail.Add(1)
				}
				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	start := time.Now()
	tick := time.NewTicker(time.Second / time.Duration(rps))
	defer tick.Stop()
	rotated := false
	for time.Since(start) < 120*time.Second {
		<-tick.C
		if !rotated && time.Since(start) > 30*time.Second {
			fx.issuer.Rotate(t)
			for _, n := range nodes {
				if err := fx.pushJWKS(t, n); err != nil {
					t.Fatal(err)
				}
			}
			newTok.Store(fx.issuer.Token(t, "uc293-new", harness.GroupPaymentsEng))
			rotated = true
		}
		select {
		case jobs <- rotated && time.Now().UnixNano()%2 == 0:
		default: // the pool is saturated; count it as load we could not send
			otherFail.Add(1)
		}
	}
	close(jobs)
	wg.Wait()
	window := time.Since(start)
	t.Logf("rotation under load: old ok %d, new ok %d, new 401 %d, 5xx %d, other %d over %s",
		oldOK.Load(), newOK.Load(), new401.Load(), fivexx.Load(), otherFail.Load(), window.Round(time.Second))

	if fivexx.Load() != 0 {
		t.Errorf("%d requests answered 5xx during the rotation", fivexx.Load())
	}
	if newOK.Load() == 0 {
		t.Errorf("no request signed with the new key was accepted")
	}
	// The new JWKS reached every node before the first new-key token was
	// minted, so the one refetch each node allows finds the key: no new-key
	// token should be refused.
	if new401.Load() != 0 {
		t.Errorf("%d new-key tokens were refused although every node had the new key set before the first was sent", new401.Load())
	}
	allowed := math.Ceil(window.Minutes()) + 1
	for name, base := range bases {
		if d := fetches(nodeMetrics(t, base)) - before[name]; d > allowed {
			t.Errorf("%s fetched keys %v times in %s, want at most one a minute (%v)", name, d, window.Round(time.Second), allowed)
		}
	}
}

// UC-277 — PAT rotation with SB_PAT_TOKEN_PREVIOUS (runbook RotatePAT step
// 1): with the new PAT current and the old one previous on every node, both
// work on every node, the cluster stays whole and forwards between peers,
// and operator volumes written under the old PAT still mount.
func TestIdentityPATRotation(t *testing.T) {
	harness.Require(t, sc, "UC-277")
	requireDisruptive(t, "this rotates the PAT on every node, restarting each")
	targets := identityTargets(t)
	oldPAT := sc.OperatorPAT
	seed, _ := harness.PickSSHNode(targets)
	seedBase := nodeBase(t, seed)

	// A volume written under the old PAT, through a loopback peer (where the
	// PAT works under host scope too).
	vol := "uc277-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	sdkAt := func(base, pat string) *microvm.Client {
		c, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: base, PATToken: pat, HTTPClient: harness.HTTPClient(0)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if sc.Has(harness.CapPlatformVolumes) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := sdkAt(seedBase, oldPAT).Create(ctx, sdktypes.CreateSandboxOptions{
			Name: harness.UniqueName(sc, t), Image: harness.DefaultImage,
			PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
		})
		if err != nil {
			cancel()
			t.Fatalf("create with an operator volume: %v", err)
		}
		destroySandbox(t, sb.ID)
		if _, err := sb.ExecCommand(ctx, "echo uc277 > /vol/marker"); err != nil {
			cancel()
			t.Fatalf("write the volume: %v", err)
		}
		cancel()
	}

	newPAT := randomBase64(48)
	env := map[string]string{"SB_PAT_TOKEN": newPAT, "SB_PAT_TOKEN_PREVIOUS": oldPAT}
	if sc.Has(harness.CapPlatformVolumes) {
		// The scope operator volumes live under today, derived from the old
		// PAT; pinning it is runbook RotatePAT step 0.
		scope, err := volumes.OperatorScope("", oldPAT)
		if err != nil {
			t.Fatal(err)
		}
		env["SB_OPERATOR_VOLUME_SCOPE"] = scope
	}
	harness.WithClusterEnv(t, targets, env, func(res map[string]harness.NodeBootResult) {
		for name, r := range res {
			if !r.Started {
				t.Fatalf("%s did not start with the rotated PAT:\n%s", name, tailLines(r.Journal, 30))
			}
		}
		for _, node := range targets.Nodes {
			base := nodeBase(t, node)
			for label, pat := range map[string]string{"the new PAT": newPAT, "the previous PAT": oldPAT} {
				if who := whoamiAs(t, base, pat); who.Principal.ID != "operator" {
					t.Errorf("%s on %s: %+v", label, node.Name, who)
				}
			}
		}
		if sc.Has(harness.CapCluster) {
			sb := client(t).NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
			owner := nodeForOwner(t, targets, resolvePlacementOwner(t, client(t), sb.ID))
			for _, node := range targets.Nodes {
				if node.Name == owner.Name {
					continue
				}
				if r := statusAs(t, harness.NewAPIClient(nodeBase(t, node), newPAT), http.MethodPost, execPath(sb.ID), models.ExecRequest{Command: "echo fwd"}); r.Status != http.StatusOK {
					t.Errorf("an exec forwarded from %s to the owner %s with the new PAT = %s (peers must accept the new PAT)", node.Name, owner.Name, r)
				}
			}
		}
		if sc.Has(harness.CapPlatformVolumes) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			sb, err := sdkAt(seedBase, newPAT).Create(ctx, sdktypes.CreateSandboxOptions{
				Name: harness.UniqueName(sc, t), Image: harness.DefaultImage,
				PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/vol"}},
			})
			if err != nil {
				t.Fatalf("mount the operator volume under the new PAT: %v", err)
			}
			destroySandbox(t, sb.ID)
			res, err := sb.ExecCommand(ctx, "cat /vol/marker")
			if err != nil || strings.TrimSpace(res.Stdout) != "uc277" {
				t.Fatalf("the operator volume under the new PAT does not hold what the old PAT wrote: %v %q (SB_OPERATOR_VOLUME_SCOPE pins it)", err, res.Stdout)
			}
		}
	})
}

// UC-283 — enterprise mode needs identity on and SB_PAT_SCOPE=host; it
// refuses each missing piece by name, and boots with identity on, host
// scope and no identity file (tokens-only, the air-gapped shape), where
// avm_ tokens work and no SSO issuer is offered.
func TestIdentityEnterpriseBootGates(t *testing.T) {
	harness.Require(t, sc, "UC-283")
	requireDisruptive(t, "this refuses a node's boot on purpose")
	targets := identityTargets(t)
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	c := client(t)
	for _, g := range []enterpriseGate{
		{
			name: "identity off",
			// The file goes too: SB_IDENTITY_FILE without identity is its
			// own refusal, which would hide the one under test.
			env:  map[string]string{"SB_IDENTITY_ENABLED": "false", "SB_IDENTITY_FILE": ""},
			want: "SB_ENTERPRISE_MODE=true requires SB_IDENTITY_ENABLED=true",
		},
		{
			name: "PAT scope any",
			env:  map[string]string{"SB_PAT_SCOPE": "any"},
			want: "SB_ENTERPRISE_MODE=true requires SB_PAT_SCOPE=host",
		},
	} {
		t.Run(g.name, func(t *testing.T) {
			harness.WithNodeEnv(t, node, g.env, func(res harness.NodeBootResult) {
				if res.Started {
					t.Fatalf("the enterprise node STARTED with %s", g.name)
				}
				if !res.RefusedWith(g.want) {
					t.Fatalf("the node refused to start, but not with %q:\n%s", g.want, tailLines(res.Journal, 40))
				}
			})
			assertNodeBackInService(t, c, targets, node)
		})
	}
	t.Run("tokens-only boots", func(t *testing.T) {
		harness.WithNodeEnv(t, node, map[string]string{"SB_IDENTITY_FILE": ""}, func(res harness.NodeBootResult) {
			if !res.Started {
				t.Fatalf("enterprise with identity on, host scope and no identity file refused to boot:\n%s", tailLines(res.Journal, 40))
			}
			base := nodeBase(t, node)
			admin := harness.NewAPIClient(base, sc.OperatorPAT)
			tok := mintTokenFor(t, admin, "uc283", "runner", harness.TeamPayments, "1h", false)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if who, err := harness.AwaitAccepted(ctx, tok.API.At(base), tokenPropagation); err != nil || who.Role != "runner" {
				t.Fatalf("an avm_ token on the tokens-only node: %+v %v", who, err)
			}
			var disc identitywire.AuthDiscovery
			if r := statusAs(t, harness.NewAPIClient(base, ""), http.MethodGet, identitywire.AuthDiscoveryPath, nil); r.Status != http.StatusOK || r.JSON(&disc) != nil || len(disc.Issuers) != 0 || !disc.IdentityEnabled {
				t.Fatalf("discovery on a tokens-only node = %s, want identity on and no issuers", r)
			}
		})
		assertNodeBackInService(t, c, targets, node)
	})
}

// UC-289 — flood control in coalesce mode: a team alone on a node floods
// identical execs, which merge and are never capped; once a second team has
// a sandbox there the effective mode is both, the chain records the switch,
// the flood is capped with a rate_limited record naming the flooder, and the
// second team's records all land.
func TestIdentityFloodControlModeSwitch(t *testing.T) {
	harness.Require(t, sc, "UC-289")
	requireDisruptive(t, "this restarts sandboxd with SB_AUDIT_API_FLOOD_CONTROL=coalesce")
	if sc.Has(harness.CapCluster) {
		t.Skip("needs one node, so both teams' sandboxes share it; a cluster's placement cannot be steered")
	}
	targets := identityTargets(t)
	// One node (the case skips on a cluster), so this is the seed; the
	// picker says so on purpose rather than by list order. WithNodeEnv
	// restores the node and waits for it to rejoin (harness.NodeRejoinCheck).
	node, ok := harness.PickRestartableNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	harness.WithNodeEnv(t, node, map[string]string{"SB_AUDIT_API_FLOOD_CONTROL": "coalesce"}, func(res harness.NodeBootResult) {
		if !res.Started {
			t.Fatalf("the node did not start in coalesce mode:\n%s", tailLines(res.Journal, 30))
		}
		base := nodeBase(t, node)
		mode := func(effective string) float64 {
			return harness.MetricValueOrZero(nodeMetrics(t, base), "aerolvm_audit_api_flood_mode", map[string]string{"key": "coalesce", "key2": effective})
		}
		awaitMode := func(effective string) {
			t.Helper()
			deadline := time.Now().Add(75 * time.Second)
			for mode(effective) != 1 {
				if time.Now().After(deadline) {
					t.Fatalf("the effective flood mode never became %s", effective)
				}
				time.Sleep(3 * time.Second)
			}
		}

		payments := mintToken(t, "uc289-pay", "runner", harness.TeamPayments)
		sbA := sandboxAs(t, payments.Secret)
		if mode("both") == 1 {
			t.Skip("another owner already has a sandbox on the node, so it is not alone; rerun on a clean node")
		}
		awaitMode("coalesce")
		flood := func(tok mintedToken, sandboxID string, n int) {
			var wg sync.WaitGroup
			jobs := make(chan struct{}, n)
			for i := 0; i < n; i++ {
				jobs <- struct{}{}
			}
			close(jobs)
			for w := 0; w < 8; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range jobs {
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						_, _ = tok.API.Do(ctx, http.MethodPost, execPath(sandboxID), models.ExecRequest{Command: "true"})
						cancel()
					}
				}()
			}
			wg.Wait()
		}
		flood(payments, sbA.ID, 150)
		evs := awaitSandboxAudit(t, operatorAPI(), sbA.ID, auditlog.KindAPI, "", "coalesced exec records", func(evs []auditlog.Event) bool {
			for _, ev := range byCallerRoute(evs, payments.ID, routeExec) {
				if ev.Request.Count > 1 {
					return true
				}
			}
			return false
		})
		for _, ev := range evs {
			if ev.Reason == auditlog.ReasonRateLimited {
				t.Fatalf("a team alone on its node was capped in coalesce mode: %s", describeEvents([]auditlog.Event{ev}))
			}
		}

		switchedAfter := time.Now().Add(-5 * time.Second)
		checkout := mintToken(t, "uc289-chk", "runner", harness.TeamCheckout)
		sbB := sandboxAs(t, checkout.Secret)
		awaitMode("both")
		modeRecords, err := harness.NodeAuditEvents(t, node, `"kind":"`+auditlog.KindAPIFloodMode+`"`)
		if err != nil {
			t.Fatal(err)
		}
		if len(harness.FilterAudit(modeRecords, func(ev auditlog.Event) bool {
			return ev.Time.After(switchedAfter) && ev.Ref == "coalesce:both"
		})) == 0 {
			t.Errorf("the chain has no api_flood_mode record for the switch to both:\n%s", describeEvents(modeRecords))
		}

		const checkoutCalls = 5
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			flood(payments, sbA.ID, 300)
		}()
		for i := 0; i < checkoutCalls; i++ {
			resp := statusAs(t, checkout.API, http.MethodPost, execPath(sbB.ID), models.ExecRequest{Command: fmt.Sprintf("echo checkout-%d", i)})
			if resp.Status != http.StatusOK {
				t.Errorf("checkout exec %d during payments' flood = %s", i, resp)
			}
		}
		wg.Wait()
		awaitSandboxAudit(t, operatorAPI(), sbA.ID, "", "", "a rate_limited record naming the flooder", func(evs []auditlog.Event) bool {
			for _, ev := range evs {
				if ev.Reason == auditlog.ReasonRateLimited && harness.CallerID(ev) == payments.ID {
					return true
				}
			}
			return false
		})
		awaitSandboxAudit(t, operatorAPI(), sbB.ID, auditlog.KindAPI, "", "every one of checkout's exec records", func(evs []auditlog.Event) bool {
			n := int64(0)
			for _, ev := range byCallerRoute(evs, checkout.ID, routeExec) {
				if ev.Request.Count > 1 {
					n += ev.Request.Count
				} else {
					n++
				}
			}
			return n >= checkoutCalls
		})
	})
}

// auditLineCountScript prints how many lines the node's audit log holds.
const auditLineCountScript = `sudo bash -c 'set -a; . /etc/sandboxd/sandboxd.env 2>/dev/null || true; set +a; db="${SB_DB_PATH:-/var/lib/sandboxd/state.db}"; f="$(dirname "$db")/audit/secrets.jsonl"; [ -f "$f" ] && wc -l < "$f" || echo 0'`

// auditLinesSinceScript prints the log's lines after line N (stdin).
const auditLinesSinceScript = `sudo bash -c 'read -r n; set -a; . /etc/sandboxd/sandboxd.env 2>/dev/null || true; set +a; db="${SB_DB_PATH:-/var/lib/sandboxd/state.db}"; f="$(dirname "$db")/audit/secrets.jsonl"; [ -f "$f" ] && tail -n +$((n+1)) "$f"; echo __AUDIT_END__'`

// UC-281 — the rolling upgrade gate. The fleet runs a release from before
// the caller field (provision with --version <tag>); the case upgrades one
// node at a time to the build at AEROL_UPGRADE_SANDBOXD_URL. Until the last
// member advertises the new fv, no node writes a caller or request field or
// an api, auth_denied or identity_config record; after it, writes start;
// and every node's chain verifies throughout.
func TestIdentityRollingUpgradeGate(t *testing.T) {
	harness.Require(t, sc, "UC-281")
	requireDisruptive(t, "this replaces sandboxd on every node")
	url, sum := os.Getenv("AEROL_UPGRADE_SANDBOXD_URL"), os.Getenv("AEROL_UPGRADE_SANDBOXD_SHA256")
	if url == "" || sum == "" {
		t.Skip("set AEROL_UPGRADE_SANDBOXD_URL and AEROL_UPGRADE_SANDBOXD_SHA256 to the new build (make itest-publish prints a presigned URL) and provision the fleet from an older release with --version; see integration-tests/README.md")
	}
	targets := identityTargets(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if _, resp, err := operatorAPI().WhoAmI(ctx); err == nil && resp.Status == http.StatusOK {
		t.Skip("the fleet already answers /v1/whoami, so it already runs the identity build; provision from an older release with --version")
	}
	// upgradeScript replaces the sandboxd binary the unit runs with the
	// build at the URL on stdin, after checking its SHA-256, and restarts
	// the unit. It lives inside this function so the restart guards in
	// restart_node_test.go check the function that runs it.
	const upgradeScript = `set -e; read -r url; read -r sum; ` +
		`bin=$(systemctl show -p ExecStart --value sandboxd | sed -n 's/.*path=\([^ ;]*\).*/\1/p'); [ -n "$bin" ] || bin=/usr/local/bin/sandboxd; ` +
		`curl -fsSL "$url" -o /tmp/sandboxd.itest-upgrade; ` +
		`echo "$sum  /tmp/sandboxd.itest-upgrade" | sha256sum -c - >/dev/null; ` +
		`sudo install -m 0755 /tmp/sandboxd.itest-upgrade "$bin"; sudo systemctl restart sandboxd; echo UPGRADED`
	nodes := sshNodes(t, targets)
	// Joiners first, the seed last: the order an operator rolls a fleet.
	// The seed is upgraded on purpose, because the gate is about every
	// member; it goes last so the fleet keeps its rendezvous throughout.
	var order, seeds []harness.IntegrationNode
	for _, n := range nodes {
		if n.Seed {
			seeds = append(seeds, n)
		} else {
			order = append(order, n)
		}
	}
	order = append(order, seeds...)
	c := client(t)

	traffic := func() {
		t.Helper()
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
		_, _ = sb.ExecCommand(ctx, "true")
		_, _, _ = harness.NewAPIClient(sc.BaseURL, "avm_not-a-token").WhoAmI(ctx)
	}
	forbidden := func(line string) bool {
		return strings.Contains(line, `"caller":`) || strings.Contains(line, `"request":`) ||
			strings.Contains(line, `"kind":"api"`) || strings.Contains(line, `"kind":"auth_denied"`) || strings.Contains(line, `"kind":"identity_config"`)
	}
	marks := func() map[string]int {
		out := map[string]int{}
		for _, n := range nodes {
			target, _ := harness.SSHTarget(n)
			s, err := harness.SSHRun(t, target, auditLineCountScript)
			if err != nil {
				t.Fatalf("count %s's audit lines: %v %s", n.Name, err, s)
			}
			out[n.Name], _ = strconv.Atoi(strings.TrimSpace(lastNonEmptyLineSuite(s)))
		}
		return out
	}
	newLines := func(n harness.IntegrationNode, since int) []string {
		target, _ := harness.SSHTarget(n)
		s, err := harness.SSHRunStdin(t, target, auditLinesSinceScript, strconv.Itoa(since)+"\n")
		if err != nil || !strings.Contains(s, "__AUDIT_END__") {
			t.Fatalf("read %s's new audit lines: %v %s", n.Name, err, s)
		}
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "{") {
				out = append(out, l)
			}
		}
		return out
	}

	for i, node := range order {
		mark := marks()
		target, _ := harness.SSHTarget(node)
		if out, err := harness.SSHRunStdin(t, target, upgradeScript, url+"\n"+sum+"\n"); err != nil || !strings.Contains(out, "UPGRADED") {
			t.Fatalf("upgrade %s: %v %s", node.Name, err, out)
		}
		assertNodeBackInService(t, c, targets, node)
		// Back in the member list is not yet usable: the next node's
		// upgrade and the traffic below need a leader and the node's
		// InternalURL advertised again.
		if err := waitNodeRejoined(t, node); err != nil {
			t.Fatalf("after upgrading %s: %v", node.Name, err)
		}
		traffic()
		time.Sleep(20 * time.Second)
		last := i == len(order)-1
		for _, n := range nodes {
			lines := newLines(n, mark[n.Name])
			for _, l := range lines {
				if !last && forbidden(l) {
					t.Fatalf("with %d of %d members upgraded, %s wrote a record the older members cannot verify:\n%s", i+1, len(order), n.Name, l)
				}
			}
		}
	}

	// Every member is new: writes start.
	deadline := time.Now().Add(3 * time.Minute)
	mark := marks()
	for {
		traffic()
		started := false
		for _, n := range nodes {
			for _, l := range newLines(n, mark[n.Name]) {
				if strings.Contains(l, `"kind":"api"`) {
					started = true
				}
			}
		}
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("every member runs the new build, but no node writes api records 3 minutes later")
		}
		time.Sleep(15 * time.Second)
	}
	for _, n := range nodes {
		r := statusAs(t, harness.NewAPIClient(nodeBase(t, n), sc.OperatorPAT), http.MethodPost, "/v1/audit/verify", nil)
		if r.Status != http.StatusOK || strings.Contains(string(r.Body), `"FAIL"`) {
			t.Errorf("%s's chain after the rolling upgrade: %s", n.Name, r)
		}
	}
}
