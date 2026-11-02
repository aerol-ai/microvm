package docker

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Rules belong to an address (netrules ClearAddress): these tests check the
// Docker driver against that rule at every point where a pause container,
// the holder of a restricted sandbox's address, is created, handed to a
// workload or let go. An address that is free carries no rule, and a
// sandbox that gets an address next finds only its own rules there.

// ClearAddressRules makes dockerRuleSet a backend that can clear an address
// by listing (netrules addressRuleClearer): every rule whose source is ip,
// or with no source and ip as destination.
func (r *dockerRuleSet) ClearAddressRules(_ []string, ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = slices.DeleteFunc(r.rules, func(k string) bool { return ruleKeyedByAddress(k, ip) })
	return nil
}

func ruleKeyedByAddress(key, ip string) bool {
	f := strings.Fields(key)
	var src, dst string
	for i := 1; i+1 < len(f); i++ {
		switch f[i] {
		case "-s":
			src = f[i+1]
		case "-d":
			dst = f[i+1]
		}
	}
	if src != "" {
		return src == ip
	}
	return dst == ip
}

// rulesAt are the rules keyed by ip.
func (r *dockerRuleSet) rulesAt(ip string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, k := range r.rules {
		if ruleKeyedByAddress(k, ip) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// ownRules are the rules a create of req puts at ip, from a fresh firewall.
func ownRules(t *testing.T, req models.CreateSandboxRequest, ip string) []string {
	t.Helper()
	rs := &dockerRuleSet{}
	c := &Client{networkRules: netrules.NewWithBackend(rs)}
	if err := c.applyCreateNetRules(ip, req); err != nil {
		t.Fatal(err)
	}
	return rs.rulesAt(ip)
}

// leakRig is the own-pause rig with address reuse on and two more checks:
// a workload starts with exactly its own rules at its address (nothing a
// previous owner left), and no container that holds an address is removed
// with a rule still keyed by it.
type leakRig struct {
	*ownPauseRig
	t    *testing.T
	mu   sync.Mutex
	reqs map[string]models.CreateSandboxRequest
}

func newLeakRig(t *testing.T, pool bool) *leakRig {
	t.Helper()
	r := &leakRig{ownPauseRig: newOwnPauseRig(t, pool), t: t, reqs: map[string]models.CreateSandboxRequest{}}
	r.d.reuseIPs = true
	start, remove := r.d.onStart, r.d.onRemove
	r.d.onStart = func(c *netnsFakeContainer) {
		start(c)
		if c.labels[netnsPauseLabelKey] == "true" {
			return
		}
		ip, _ := r.addressOf(c)
		r.mu.Lock()
		req, ok := r.reqs[c.name]
		r.mu.Unlock()
		if !ok || ip == "" {
			return
		}
		if got, want := r.rs.rulesAt(ip), ownRules(t, req, ip); !slices.Equal(got, want) {
			r.violate("workload %s started at %s with rules %v, want only its own %v", c.name, ip, got, want)
		}
	}
	r.d.onRemove = func(c *netnsFakeContainer) {
		remove(c)
		if c.ip != "" && c.labels[netnsPauseLabelKey] != "true" && len(r.rs.rulesAt(c.ip)) > 0 {
			r.violate("container %s removed with rules still keyed by its address %s", c.name, c.ip)
		}
	}
	return r
}

func (r *leakRig) create(ctx context.Context, req models.CreateSandboxRequest, id string) (*SandboxRuntime, error) {
	r.mu.Lock()
	r.reqs[id] = req
	r.mu.Unlock()
	if !hasCreateNetRules(req) {
		// As the service: a create without rules has no early attach, so
		// no observer (a pool slot's address is still reported to one).
		return r.c.Create(ctx, req, id, "tok", nil)
	}
	return r.ownPauseRig.create(ctx, req, id)
}

// fillPool gives the rig's pool n free slots (the pool-slot path).
func (r *leakRig) fillPool(n int) {
	r.c.netnsPool = newTestNetnsPool(r.c, n)
	r.c.netnsPool.refill(context.Background())
}

var leakRequests = []struct {
	name string
	req  models.CreateSandboxRequest
}{
	{"block-all", models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}},
	{"allow-out", models.CreateSandboxRequest{Image: "img", NetworkAllowOut: []string{"1.1.1.0/24"}}},
}

// TestPauseAddressFreedWithoutRules: every way a restricted create can
// fail, on a pool slot and on its own pause, frees the address with no rule
// keyed by it; the next sandbox there, restricted or not, starts with only
// its own rules. The workload's create being rejected outright (Docker's
// "Minimum memory limit allowed is 6MB") is one of the points.
func TestPauseAddressFreedWithoutRules(t *testing.T) {
	isPause := func(c *netnsFakeContainer) bool { return c.labels[netnsPauseLabelKey] == "true" }
	failures := []struct {
		name string
		prep func(*leakRig, context.CancelFunc)
	}{
		{"workload create rejected", func(r *leakRig, _ context.CancelFunc) {
			r.d.createResp = func(name, _ string) *http.Response {
				if name == "sb-x" {
					return textResponse(http.StatusBadRequest, `{"message":"Minimum memory limit allowed is 6MB"}`)
				}
				return nil
			}
		}},
		{"rules fail to go on", func(r *leakRig, _ context.CancelFunc) {
			r.rs.failIns = fmt.Errorf("insert boom")
		}},
		{"workload start fails", func(r *leakRig, _ context.CancelFunc) {
			r.d.startResp = func(c *netnsFakeContainer) *http.Response {
				if !isPause(c) {
					return textResponse(http.StatusInternalServerError, "start boom")
				}
				return nil
			}
		}},
		{"toolbox never ready", func(r *leakRig, _ context.CancelFunc) {
			r.toolboxDown.Store(true)
			r.c.toolboxWaitTimeout = 100 * time.Millisecond
		}},
		{"context cancelled at the workload's start", func(r *leakRig, cancel context.CancelFunc) {
			r.d.startResp = func(c *netnsFakeContainer) *http.Response {
				if !isPause(c) {
					cancel()
					return textResponse(http.StatusInternalServerError, "cancelled")
				}
				return nil
			}
		}},
		{"context cancelled before the workload exists", func(r *leakRig, cancel context.CancelFunc) {
			r.d.createResp = func(name, _ string) *http.Response {
				if name == "sb-x" {
					cancel()
					return textResponse(http.StatusInternalServerError, "cancelled")
				}
				return nil
			}
		}},
	}
	for _, slot := range []string{"pool slot", "own pause"} {
		for _, f := range failures {
			for _, kind := range leakRequests {
				t.Run(slot+"/"+f.name+"/"+kind.name, func(t *testing.T) {
					r := newLeakRig(t, false)
					if slot == "pool slot" {
						r.fillPool(1)
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					f.prep(r, cancel)
					if _, err := r.create(ctx, kind.req, "sb-x"); err == nil {
						t.Fatal("create succeeded")
					}
					r.assertClean(t)
					r.assertNothingLeft(t)
					// Whatever address it held is free and clean: the next
					// sandboxes there get only their own rules.
					r.d.createResp, r.d.startResp, r.rs.failIns = nil, nil, nil
					r.toolboxDown.Store(false)
					r.c.toolboxWaitTimeout = 2 * time.Second
					for i, next := range []models.CreateSandboxRequest{{Image: "img"}, kind.req} {
						st, err := r.create(context.Background(), next, fmt.Sprintf("sb-next-%d", i))
						if err != nil {
							t.Fatal(err)
						}
						if i == 0 {
							err = r.c.Destroy(context.Background(), &models.Sandbox{ID: st.SandboxID, ContainerID: st.ContainerID, ContainerIP: st.ContainerIP})
						} else {
							err = r.destroy(st, next)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					r.assertClean(t)
					r.assertNothingLeft(t)
				})
			}
		}
	}
}

// TestPauseDestroyClearsWhatTheRowDoesNotName: an orphan's stub (no policy,
// maybe no address) and a row whose address is stale still leave the
// pause's address clean: the rules are cleared at the address the pause
// holds, not at the one the row says.
func TestPauseDestroyClearsWhatTheRowDoesNotName(t *testing.T) {
	for _, row := range []string{"orphan stub", "no address", "stale address"} {
		t.Run(row, func(t *testing.T) {
			r := newLeakRig(t, false)
			req := models.CreateSandboxRequest{Image: "img", NetworkAllowOut: []string{"1.1.1.0/24"}}
			st, err := r.create(context.Background(), req, "sb-o")
			if err != nil {
				t.Fatal(err)
			}
			sb := &models.Sandbox{ID: st.SandboxID, ContainerID: st.ContainerID, ContainerIP: st.ContainerIP}
			switch row {
			case "no address":
				sb.ContainerIP = ""
			case "stale address":
				sb.ContainerIP = "172.30.200.200"
			}
			if err := r.c.Destroy(context.Background(), sb); err != nil {
				t.Fatal(err)
			}
			if left := r.rs.rulesAt(st.ContainerIP); len(left) > 0 {
				t.Fatalf("rules left at the freed address %s: %v", st.ContainerIP, left)
			}
			if r.d.byRef("sb-o") != nil || r.d.byRef(netnsAdoptedName("sb-o")) != nil {
				t.Fatal("the workload or its pause left")
			}
		})
	}
}

// TestPauseSweepsClearADeadCreatesAddress: a sandboxd that died between a
// create's rules and its row leaves a pause holding a ruled address and no
// workload; the start-time sweep (pool off) and the pool's reconcile (pool
// on) remove the pause with its rules, and keep a pause whose workload the
// engine can't vouch for.
func TestPauseSweepsClearADeadCreatesAddress(t *testing.T) {
	for _, pool := range []bool{false, true} {
		t.Run(fmt.Sprintf("pool=%v", pool), func(t *testing.T) {
			r := newLeakRig(t, false)
			pause := map[string]string{netnsPauseLabelKey: "true"}
			r.d.add(&netnsFakeContainer{id: "dead", name: netnsAdoptedName("sb-dead"), labels: pause, running: true, ip: "172.30.7.7", created: 1})
			r.d.add(&netnsFakeContainer{id: "unsure", name: netnsAdoptedName("sb-unsure"), labels: pause, running: true, ip: "172.30.7.8", created: 1})
			for _, ip := range []string{"172.30.7.7", "172.30.7.8"} {
				if err := r.c.networkRules.BlockAllEgress(ip); err != nil {
					t.Fatal(err)
				}
				if err := r.c.networkRules.ApplyEgressPolicy(ip, []string{"1.1.1.0/24"}, nil); err != nil {
					t.Fatal(err)
				}
			}
			// The engine can't say whether sb-unsure's workload exists.
			r.d.mu.Lock()
			inner := r.d.transport()
			r.d.mu.Unlock()
			r.c.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/containers/sb-unsure/json") {
					return textResponse(http.StatusInternalServerError, "engine busy"), nil
				}
				return inner(req)
			})
			if pool {
				p := newTestNetnsPool(r.c, 0)
				p.reconcile(context.Background())
			} else {
				r.c.PrepareNetnsPause(context.Background(), time.Unix(10, 0))
			}
			if r.d.byRef("dead") != nil || len(r.rs.rulesAt("172.30.7.7")) != 0 {
				t.Fatalf("dead create's pause or rules left: %v", r.rs.rulesAt("172.30.7.7"))
			}
			if r.d.byRef("unsure") == nil || len(r.rs.rulesAt("172.30.7.8")) == 0 {
				t.Fatal("a pause whose workload may run was let go")
			}
		})
	}
}

// TestPauseRemovalKeepsAPauseItCannotRead: a pause whose address can't be
// read, or whose rules can't be cleared, stays (its rules stay with their
// owner); one already gone is fine.
func TestPauseRemovalKeepsAPauseItCannotRead(t *testing.T) {
	r := newLeakRig(t, false)
	if err := r.c.removePause(context.Background(), "nope", ""); err != nil {
		t.Fatalf("gone pause: %v", err)
	}
	r.d.add(&netnsFakeContainer{id: "p1", name: "p1", labels: map[string]string{netnsPauseLabelKey: "true"}, running: true, ip: "172.30.8.8"})
	inner := r.d.transport()
	r.c.httpClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/containers/p1/") {
			return textResponse(http.StatusInternalServerError, "engine busy"), nil
		}
		return inner(req)
	})
	if err := r.c.removePause(context.Background(), "p1", ""); err == nil || r.d.byRef("p1") == nil {
		t.Fatalf("unreadable pause removed (err=%v)", err)
	}
	r.c.httpClient.Transport = inner
	if err := r.c.removePause(context.Background(), "p1", "not-an-ip"); err == nil || r.d.byRef("p1") == nil {
		t.Fatalf("pause removed though its address couldn't be cleared (err=%v)", err)
	}
}

// TestPauseChurnWithFailuresLeavesNoRules: concurrent restricted and plain
// creates on reused addresses, some failing at random points, then their
// destroys: no workload ever starts next to another's rules, and nothing is
// left.
func TestPauseChurnWithFailuresLeavesNoRules(t *testing.T) {
	r := newLeakRig(t, false)
	r.fillPool(2)
	var n atomic.Int64
	r.d.startResp = func(c *netnsFakeContainer) *http.Response {
		if c.labels[netnsPauseLabelKey] != "true" && n.Add(1)%4 == 0 {
			return textResponse(http.StatusInternalServerError, "start boom")
		}
		return nil
	}
	r.d.createResp = func(name, _ string) *http.Response {
		if strings.HasSuffix(name, "-7") || strings.HasSuffix(name, "-13") {
			return textResponse(http.StatusBadRequest, `{"message":"Minimum memory limit allowed is 6MB"}`)
		}
		return nil
	}
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := leakRequests[i%len(leakRequests)].req
			if i%3 == 0 {
				req = models.CreateSandboxRequest{Image: "img"}
			}
			st, err := r.create(context.Background(), req, fmt.Sprintf("sb-churn-%d", i))
			if err != nil {
				return
			}
			if !hasCreateNetRules(req) {
				err = r.c.Destroy(context.Background(), &models.Sandbox{ID: st.SandboxID, ContainerID: st.ContainerID, ContainerIP: st.ContainerIP})
			} else {
				err = r.destroy(st, req)
			}
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	r.assertClean(t)
	r.assertNothingLeft(t)
}
