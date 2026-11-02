package apihttp

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Per-tenant fairness for the list gate: one tenant's storm takes at most
// its share of a node's slots, the others are served in turn, and the
// refusal names whose fault it is (429 the tenant, 503 the node).

func newFairMetrics() GateMetrics {
	// expvar.Int values outside the registry: tests must not publish names.
	return GateMetrics{InFlight: new(expvar.Int), Admitted: new(expvar.Int), Shed: new(expvar.Int),
		RateLimited: new(expvar.Int), Queued: new(expvar.Int), Flows: new(expvar.Int)}
}

// waitFor polls cond (which reads the gate under its lock) until it holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func gateState(g *Gate) (inFlight, queued, flows int) {
	s := g.Snapshot(-1)
	return s.InFlight, s.Queued, s.Flows
}

// requireIdle: every slot back, nothing queued, no tenant state kept.
func requireIdle(t *testing.T, g *Gate, m GateMetrics) {
	t.Helper()
	if in, q, f := gateState(g); in != 0 || q != 0 || f != 0 {
		t.Fatalf("idle gate holds in_flight=%d queued=%d tenants=%d, want all 0", in, q, f)
	}
	if m.InFlight.Value() != 0 || m.Queued.Value() != 0 || m.Flows.Value() != 0 {
		t.Fatalf("idle gate metrics in_flight=%d queued=%d tenants=%d, want all 0", m.InFlight.Value(), m.Queued.Value(), m.Flows.Value())
	}
}

// The case this exists for: a noisy tenant with 100 lists at once and a
// quiet one with 3. Before, the noisy tenant took every slot and the quiet
// one waited, then got 503. Now the noisy tenant holds its share (4 of 16)
// and the rest of its lists are refused 429 after the queue wait, while the
// quiet tenant's lists are admitted at once and never refused.
func TestGateQuietTenantIsAdmittedWhileANoisyOneHoldsItsShare(t *testing.T) {
	const limit, share, noisy, quiet = 16, 4, 100, 3
	const wait = 300 * time.Millisecond
	m := newFairMetrics()
	g := NewGate(limit, share, wait, m)
	done := make(chan struct{})
	var wg sync.WaitGroup
	var noisyOK, noisy429, noisyOther atomic.Int64
	for range noisy {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.AcquireFlow(context.Background(), "owner:team:noisy")
			switch {
			case err == nil:
				noisyOK.Add(1)
				<-done
				release()
			case errors.Is(err, ErrRateLimited):
				noisy429.Add(1)
			default:
				noisyOther.Add(1)
			}
		}()
	}
	waitFor(t, "the noisy tenant to hold its share and queue the rest", func() bool {
		in, q, _ := gateState(g)
		return in == share && q == noisy-share
	})

	var quietHolds []func()
	for i := range quiet {
		start := time.Now()
		release, err := g.AcquireFlow(context.Background(), "owner:team:quiet")
		if err != nil {
			t.Fatalf("quiet list %d while the noisy tenant storms: %v, want admitted", i, err)
		}
		if took := time.Since(start); took > wait/2 {
			t.Fatalf("quiet list %d waited %v for a slot the noisy tenant could not take", i, took)
		}
		quietHolds = append(quietHolds, release)
	}

	// The noisy waiters time out on their own.
	waitFor(t, "every queued noisy list to be refused", func() bool { return noisy429.Load()+noisyOther.Load() == noisy-share })
	if noisyOther.Load() != 0 || noisy429.Load() != noisy-share || noisyOK.Load() != share {
		t.Fatalf("noisy: %d admitted, %d refused 429, %d other; want %d, %d, 0", noisyOK.Load(), noisy429.Load(), noisyOther.Load(), share, noisy-share)
	}
	if m.RateLimited.Value() != noisy-share || m.Shed.Value() != 0 || m.Admitted.Value() != share+quiet {
		t.Fatalf("metrics rate_limited=%d shed=%d admitted=%d, want %d/0/%d", m.RateLimited.Value(), m.Shed.Value(), m.Admitted.Value(), noisy-share, share+quiet)
	}
	if got := m.Flows.Value(); got != 2 {
		t.Fatalf("tenants gauge = %d, want 2 (noisy and quiet hold slots)", got)
	}
	close(done)
	wg.Wait()
	for _, release := range quietHolds {
		release()
	}
	requireIdle(t, g, m)
}

// When the node itself is full, a waiting quiet tenant gets its turn after
// a release or two, not after every list queued ahead of it: turns go
// round-robin across tenants, not first-come first-served across everyone.
func TestGateServesWaitersRoundRobinAcrossTenants(t *testing.T) {
	const limit, share = 4, 2
	m := newFairMetrics()
	g := NewGate(limit, share, 10*time.Second, m)
	// Tenants A and B fill the node (2 slots each) and queue 50 lists each.
	var holds []func()
	for _, flow := range []string{"A", "B"} {
		for range share {
			release, err := g.AcquireFlow(context.Background(), flow)
			if err != nil {
				t.Fatal(err)
			}
			holds = append(holds, release)
		}
	}
	type grant struct {
		flow    string
		release func()
	}
	granted := make(chan grant, 128)
	queue := func(flow string) {
		go func() {
			release, err := g.AcquireFlow(context.Background(), flow)
			if err != nil {
				t.Errorf("%s: %v", flow, err)
				return
			}
			granted <- grant{flow, release}
		}()
	}
	for i := range 50 {
		queue("A")
		queue("B")
		waitFor(t, "two more waiters", func() bool { _, q, _ := gateState(g); return q == 2*(i+1) })
	}
	queue("C")
	waitFor(t, "C to queue", func() bool { _, q, _ := gateState(g); return q == 101 })

	// Free slots one at a time, letting each grant run and end. C must get
	// a slot within one full turn of the ring (3 grants), not after the 100
	// lists that queued before it.
	holds[0]()
	received := 0
	for {
		got := <-granted
		received++
		got.release()
		if got.flow == "C" {
			break
		}
		if received >= 3 {
			t.Fatalf("C still waiting after %d grants (last to %s): turns are not round-robin", received, got.flow)
		}
	}
	for _, h := range holds[1:] {
		h()
	}
	// Drain: every queued list is still served.
	for ; received < 101; received++ {
		(<-granted).release()
	}
	waitFor(t, "the gate to go idle", func() bool { in, q, f := gateState(g); return in == 0 && q == 0 && f == 0 })
	requireIdle(t, g, m)
}

// The exact turn order with one slot: A queued three lists before B and C
// queued one each; FIFO would serve A, A, A, B, C. Round-robin serves A, B,
// C, A, A.
func TestGateTurnOrderIsRoundRobin(t *testing.T) {
	g := NewGate(1, 0, 10*time.Second, GateMetrics{})
	hold, err := g.AcquireFlow(context.Background(), "X")
	if err != nil {
		t.Fatal(err)
	}
	order := make(chan string, 5)
	for i, name := range []string{"A1", "A2", "A3", "B1", "C1"} {
		go func() {
			release, err := g.AcquireFlow(context.Background(), name[:1])
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			order <- name
			release()
		}()
		waitFor(t, name+" to queue", func() bool { _, q, _ := gateState(g); return q == i+1 })
	}
	hold()
	var got []string
	for range 5 {
		got = append(got, <-order)
	}
	if want := []string{"A1", "B1", "C1", "A2", "A3"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("turn order %v, want %v", got, want)
	}
	waitFor(t, "the gate to go idle", func() bool { in, q, f := gateState(g); return in == 0 && q == 0 && f == 0 })
}

// A tenant whose turn is next can leave the queue (its caller gone, or its
// wait over) before a slot frees: the turn passes to the tenant after it,
// not back to the start of the ring.
func TestGateTurnPassesOnWhenTheNextTenantLeaves(t *testing.T) {
	g := NewGate(1, 0, 10*time.Second, GateMetrics{})
	hold, err := g.AcquireFlow(context.Background(), "X")
	if err != nil {
		t.Fatal(err)
	}
	type grant struct {
		name    string
		release func()
	}
	granted := make(chan grant, 4)
	bCtx, bLeaves := context.WithCancel(context.Background())
	defer bLeaves()
	bDone := make(chan error, 1)
	for i, name := range []string{"A1", "A2", "B1", "C1"} {
		go func() {
			ctx := context.Background()
			if name == "B1" {
				ctx = bCtx
			}
			release, err := g.AcquireFlow(ctx, name[:1])
			if name == "B1" {
				bDone <- err
				return
			}
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			granted <- grant{name, release}
		}()
		waitFor(t, name+" to queue", func() bool { _, q, _ := gateState(g); return q == i+1 })
	}
	hold() // A1's turn; B is next
	first := <-granted
	bLeaves()
	if err := <-bDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("B1 left with %v", err)
	}
	first.release() // the turn after B's is C's
	second := <-granted
	second.release()
	third := <-granted
	third.release()
	if got := []string{first.name, second.name, third.name}; fmt.Sprint(got) != "[A1 C1 A2]" {
		t.Fatalf("turn order %v, want [A1 C1 A2]", got)
	}
	waitFor(t, "the gate to go idle", func() bool { in, q, f := gateState(g); return in == 0 && q == 0 && f == 0 })
}

// 429 when the caller's own tenant holds its share, 503 when the node is
// full and the caller's tenant is within its share; with no share in force,
// a full node is always 503.
func TestGateRefusalNamesWhoseFaultItIs(t *testing.T) {
	m := newFairMetrics()
	g := NewGate(2, 1, 0, m)
	if g.Limit() != 2 || g.PerFlowLimit() != 1 {
		t.Fatalf("limit %d share %d, want 2 and 1", g.Limit(), g.PerFlowLimit())
	}
	a, err := g.AcquireFlow(context.Background(), "A")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.AcquireFlow(context.Background(), "A"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("A over its share with a free slot = %v, want ErrRateLimited", err)
	}
	b, err := g.AcquireFlow(context.Background(), "B")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.AcquireFlow(context.Background(), "C"); !errors.Is(err, ErrOverloaded) || errors.Is(err, ErrRateLimited) {
		t.Fatalf("C within its share on a full node = %v, want ErrOverloaded", err)
	}
	if _, err := g.AcquireFlow(context.Background(), "A"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("A over its share on a full node = %v, want ErrRateLimited (its own share is the cause)", err)
	}
	a()
	c, err := g.AcquireFlow(context.Background(), "C")
	if err != nil {
		t.Fatalf("C after a slot freed = %v", err)
	}
	b()
	c()
	if m.RateLimited.Value() != 2 || m.Shed.Value() != 1 || m.Admitted.Value() != 3 {
		t.Fatalf("rate_limited=%d shed=%d admitted=%d, want 2/1/3", m.RateLimited.Value(), m.Shed.Value(), m.Admitted.Value())
	}
	requireIdle(t, g, m)

	// The refusal also waits out the queue wait first, for both kinds.
	g = NewGate(2, 1, 100*time.Millisecond, GateMetrics{})
	hold, _ := g.AcquireFlow(context.Background(), "A")
	start := time.Now()
	if _, err := g.AcquireFlow(context.Background(), "A"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("A over its share after the wait = %v", err)
	}
	if took := time.Since(start); took < 80*time.Millisecond {
		t.Fatalf("a 429 came after %v, before the 100ms queue wait", took)
	}
	hold()

	// No share in force (0, or more than the limit): one tenant may fill the
	// node, and a full node is 503 for it too.
	for _, perFlow := range []int{0, 3} {
		g := NewGate(2, perFlow, 0, GateMetrics{})
		if g.PerFlowLimit() != 2 {
			t.Fatalf("perFlow %d: share = %d, want the limit", perFlow, g.PerFlowLimit())
		}
		r1, _ := g.AcquireFlow(context.Background(), "A")
		r2, err := g.AcquireFlow(context.Background(), "A")
		if err != nil {
			t.Fatalf("perFlow %d: one tenant could not fill the node: %v", perFlow, err)
		}
		if _, err := g.AcquireFlow(context.Background(), "A"); !errors.Is(err, ErrOverloaded) || errors.Is(err, ErrRateLimited) {
			t.Fatalf("perFlow %d: full node = %v, want ErrOverloaded", perFlow, err)
		}
		r1()
		r2()
	}
}

// A tenant's state lives only while it has a list in flight or queued, so
// memory follows the requests being served, not every tenant ever seen.
func TestGateDropsIdleTenants(t *testing.T) {
	m := newFairMetrics()
	g := NewGate(4, 2, 20*time.Millisecond, m)
	for i := range 1000 {
		release, err := g.AcquireFlow(context.Background(), "owner:team:t"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	requireIdle(t, g, m)

	// A tenant whose lists all timed out, and one whose caller left while
	// queued, leave nothing behind either.
	h1, _ := g.AcquireFlow(context.Background(), "A")
	h2, _ := g.AcquireFlow(context.Background(), "A")
	if _, err := g.AcquireFlow(context.Background(), "A"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitFor(t, "a queued list", func() bool { _, q, _ := gateState(g); return q == 1 })
		cancel()
	}()
	rateLimited := m.RateLimited.Value()
	_, err := g.AcquireFlow(ctx, "A")
	if !errors.Is(err, ErrOverloaded) || !errors.Is(err, context.Canceled) {
		t.Fatalf("caller left while queued = %v, want ErrOverloaded wrapping context.Canceled", err)
	}
	if m.RateLimited.Value() != rateLimited {
		t.Fatal("a caller that left was counted as rate limited")
	}
	h1()
	h2()
	requireIdle(t, g, m)
}

// Every unscoped caller is the one operator tenant; a scoped caller is the
// owner its credential acts for, whatever token it presents.
func TestFlowOf(t *testing.T) {
	withAccess := func(a controlplane.Access) context.Context {
		return controlplane.ContextWithAccess(context.Background(), a)
	}
	team := func(id, team string) context.Context {
		return withAccess(controlplane.TokenAccess(id, "ci", controlplane.RoleRunner, team, time.Time{}))
	}
	managed := func(owner string) context.Context {
		a, err := controlplane.ControlPlaneAccess(controlplane.Identity{OwnerRef: owner, ExternalID: "user-1"})
		if err != nil {
			t.Fatal(err)
		}
		return withAccess(a)
	}
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"no Access (an internal call)", context.Background(), OperatorFlow},
		{"the operator PAT", withAccess(controlplane.OperatorAccess()), OperatorFlow},
		{"a peer node", withAccess(controlplane.NodeAccess("n2")), OperatorFlow},
		{"a fleet-wide token", team("tok_fleet", controlplane.FleetTeam), OperatorFlow},
		{"a scoped Access with no owner", withAccess(controlplane.Access{Role: controlplane.RoleViewer}), OperatorFlow},
		{"a team token", team("tok_1", "payments"), "owner:team:payments"},
		{"another token of the same team", team("tok_2", "payments"), "owner:team:payments"},
		{"another team", team("tok_3", "risk"), "owner:team:risk"},
		{"a managed account", managed("acct-1"), "owner:acct-1"},
		{"a managed account named operator", managed("operator"), "owner:operator"},
	}
	for _, tc := range cases {
		if got := FlowOf(tc.ctx); got != tc.want {
			t.Errorf("%s: FlowOf = %q, want %q", tc.name, got, tc.want)
		}
	}
	// Acquire takes the flow from the context.
	g := NewGate(2, 1, 0, GateMetrics{})
	r, err := g.Acquire(team("tok_1", "payments"))
	if err != nil {
		t.Fatal(err)
	}
	defer r()
	if _, err := g.Acquire(team("tok_2", "payments")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("a second token of the same team = %v, want ErrRateLimited (one share per tenant, not per token)", err)
	}
	r2, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("the operator beside a team at its share = %v", err)
	}
	r2()
}

// A release can hand a waiter its slot in the same instant the waiter's
// timer fires or its caller leaves. The waiter then owns the slot: it uses
// it (timer) or gives it back (caller left); a slot is never lost. The test
// holds the gate's lock across the instant to force both orders.
func TestGateGrantRacingTheWaitersEnd(t *testing.T) {
	for _, leave := range []bool{false, true} {
		t.Run(fmt.Sprintf("caller left %v", leave), func(t *testing.T) {
			// The caller-left case waits long, so only the cancellation
			// can end its wait.
			wait := 20 * time.Millisecond
			if leave {
				wait = time.Minute
			}
			g := NewGate(1, 0, wait, GateMetrics{})
			if _, err := g.AcquireFlow(context.Background(), "H"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				release func()
				err     error
			}
			res := make(chan result, 1)
			go func() {
				release, err := g.AcquireFlow(ctx, "W")
				res <- result{release, err}
			}()
			waitFor(t, "W to queue", func() bool { _, q, _ := gateState(g); return q == 1 })
			g.mu.Lock()
			if leave {
				cancel()
			}
			time.Sleep(100 * time.Millisecond) // W's timer (or ctx) fires; W blocks on the lock
			// H's release, by hand under the held lock: it grants W.
			h := g.flows["H"]
			h.inFlight--
			g.inFlight--
			g.dispatchLocked()
			g.dropIfIdleLocked(h)
			g.mu.Unlock()
			got := <-res
			if leave {
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("err = %v, want the caller's cancellation", got.err)
				}
			} else {
				if got.err != nil {
					t.Fatalf("a waiter granted as its timer fired was refused: %v", got.err)
				}
				got.release()
			}
			waitFor(t, "the slot to come back", func() bool { in, q, f := gateState(g); return in == 0 && q == 0 && f == 0 })
		})
	}
}

// Snapshot names the busiest tenants for /debug/vars: most refused first,
// then most queued, then most in flight.
func TestGateSnapshot(t *testing.T) {
	var nilGate *Gate
	if s := nilGate.Snapshot(5); s.Limit != 0 || s.Busiest != nil {
		t.Fatalf("nil gate snapshot = %+v", s)
	}
	g := NewGate(8, 2, 0, GateMetrics{})
	var holds []func()
	acquire := func(flow string, n int) {
		for range n {
			if r, err := g.AcquireFlow(context.Background(), flow); err == nil {
				holds = append(holds, r)
			}
		}
	}
	acquire("owner:team:noisy", 5) // 2 admitted, 3 refused
	acquire("owner:team:busy", 2)
	acquire("owner:team:quiet", 1)
	acquire(OperatorFlow, 1)
	s := g.Snapshot(3)
	if s.Limit != 8 || s.PerFlowLimit != 2 || s.InFlight != 6 || s.Queued != 0 || s.Flows != 4 || len(s.Busiest) != 3 {
		t.Fatalf("snapshot = %+v", s)
	}
	if s.Busiest[0].Flow != "owner:team:noisy" || s.Busiest[0].Refused != 3 || s.Busiest[0].InFlight != 2 || s.Busiest[1].Flow != "owner:team:busy" {
		t.Fatalf("busiest = %+v, want noisy (3 refused) then busy", s.Busiest)
	}
	raw, _ := json.Marshal(s)
	for _, key := range []string{`"per_tenant_limit":2`, `"tenants":4`, `"busiest":[`, `"refused":3`} {
		if !json.Valid(raw) || !strings.Contains(string(raw), key) {
			t.Fatalf("snapshot JSON %s lacks %s", raw, key)
		}
	}
	if all := g.Snapshot(-1); len(all.Busiest) != 4 {
		t.Fatalf("a negative top must list every tenant, got %d", len(all.Busiest))
	}
	for _, h := range holds {
		h()
	}
}

// The wire shape every surface writes through WriteStoreAwareError for a
// tenant over its share: 429, Retry-After, code rate_limited.
func TestWriteStoreAwareErrorRateLimited(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteStoreAwareError(nil, rec, ErrRateLimited)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(RateLimitedRetryAfterSeconds) {
		t.Fatalf("Retry-After = %q", got)
	}
	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != models.ErrorCodeRateLimited || body.Error == "" {
		t.Fatalf("body = %+v (%v)", body, err)
	}
}

// Many tenants, many goroutines, random holds, timeouts and callers that
// leave: a tenant never holds more than its share, the node never more than
// its limit, every attempt ends exactly one way, and the gate ends idle.
// Run under -race -count=20 (Part 4).
func TestGateFairnessStress(t *testing.T) {
	const limit, share, flows, perFlow, rounds = 8, 2, 12, 24, 15
	m := newFairMetrics()
	g := NewGate(limit, share, 2*time.Millisecond, m)
	var total atomic.Int64
	held := make([]atomic.Int64, flows)
	var admitted, refused, left atomic.Int64
	var wg sync.WaitGroup
	for f := range flows {
		flow := "owner:team:" + strconv.Itoa(f)
		for range perFlow {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range rounds {
					ctx, cancel := context.WithCancel(context.Background())
					if rand.IntN(8) == 0 {
						go func() {
							time.Sleep(time.Duration(rand.IntN(1500)) * time.Microsecond)
							cancel()
						}()
					}
					release, err := g.AcquireFlow(ctx, flow)
					switch {
					case err == nil:
						admitted.Add(1)
						if n := held[f].Add(1); n > share {
							t.Errorf("%s holds %d slots, over its share of %d", flow, n, share)
						}
						if n := total.Add(1); n > limit {
							t.Errorf("%d slots held, over the limit of %d", n, limit)
						}
						time.Sleep(time.Duration(rand.IntN(300)) * time.Microsecond)
						held[f].Add(-1)
						total.Add(-1)
						release()
						release() // idempotent
					case errors.Is(err, context.Canceled):
						left.Add(1)
					case errors.Is(err, ErrRateLimited), errors.Is(err, ErrOverloaded):
						refused.Add(1)
					default:
						t.Errorf("unexpected error %v", err)
					}
					cancel()
				}
			}()
		}
	}
	wg.Wait()
	if got := admitted.Load() + refused.Load() + left.Load(); got != flows*perFlow*rounds {
		t.Fatalf("%d attempts ended, want %d", got, flows*perFlow*rounds)
	}
	// A slot granted to a waiter whose caller had just left counts as
	// admitted, and is given straight back.
	if extra := m.Admitted.Value() - admitted.Load(); extra < 0 || extra > left.Load() || m.RateLimited.Value()+m.Shed.Value() != refused.Load() {
		t.Fatalf("metrics admitted=%d refused=%d, callers saw %d admitted, %d refused, %d left", m.Admitted.Value(), m.RateLimited.Value()+m.Shed.Value(), admitted.Load(), refused.Load(), left.Load())
	}
	if admitted.Load() == 0 || refused.Load() == 0 {
		t.Fatalf("the stress exercised nothing: %d admitted, %d refused", admitted.Load(), refused.Load())
	}
	requireIdle(t, g, m)
}
