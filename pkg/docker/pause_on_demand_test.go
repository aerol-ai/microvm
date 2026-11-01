package docker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

const testPauseImage = "registry.k8s.io/pause:3.10"

// ownPauseRig is a Docker engine without a pause slot to give (pool off, or
// empty), the host firewall as a rule set, and a fail-closed checker over
// both, run at every transition rather than at the end:
//
//   - a workload container starts only with its request's rules already on
//     the address it will run at, in a namespace with IPv6 off (#855: the
//     pause that owns it was created with the sysctls), and a restricted
//     one never starts on Docker's own path (where its address exists only
//     once it runs);
//   - an address is reported to the create only once its rules are on, and
//     before the workload starts;
//   - a pause container, and with it the address, goes only once no
//     workload runs in its namespace, its rules are gone, and the create or
//     destroy that was told the address has let go of it.
type ownPauseRig struct {
	c  *Client
	d  *netnsFakeDaemon
	rs *dockerRuleSet
	// toolboxDown makes the toolbox health answer 503 (never ready).
	toolboxDown atomic.Bool

	mu         sync.Mutex
	restricted map[string]bool // sandbox ID -> its request carries rules
	known      map[string]int  // address -> times reported
	released   map[string]int  // address -> times let go
	violations []string
}

func newOwnPauseRig(t *testing.T, pool bool) *ownPauseRig {
	t.Helper()
	rig := &ownPauseRig{restricted: map[string]bool{}, known: map[string]int{}, released: map[string]int{}}
	d := newNetnsFakeDaemon()
	d.missing = map[string]bool{}
	_, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if rig.toolboxDown.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	t.Cleanup(closeFn)
	// Every sandbox address answers at the one local toolbox server.
	toolboxAt := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	rs := &dockerRuleSet{}
	c := &Client{
		logger:            slog.Default(),
		toolboxBinaryPath: writableToolbox(t),
		toolboxMountPath:  "/usr/local/bin/toolboxd",
		toolboxPort:       port,
		defaultRuntime:    models.RuntimeDocker,
		networkRules:      netrules.NewWithBackend(rs),
		httpClient:        &http.Client{Transport: d.transport()},
		streamClient:      &http.Client{Transport: d.transport()},
		toolboxClient: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, toolboxAt)
			},
		}},
		waitTimeout:        2 * time.Second,
		toolboxWaitTimeout: 2 * time.Second,
		pulls:              map[string]*imagePull{},
		pullFailures:       map[string]imagePullFailure{},
		pauseImage:         testPauseImage,
	}
	if pool {
		c.netnsPool = newTestNetnsPool(c, 1) // never refilled: every Adopt misses
	}
	rig.c, rig.d, rig.rs = c, d, rs
	d.onStart = rig.checkStart
	d.onRemove = rig.checkRemove
	return rig
}

func (rig *ownPauseRig) violate(format string, args ...any) {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	rig.violations = append(rig.violations, fmt.Sprintf(format, args...))
}

// addressOf is where a container runs: its pause's address when it joined
// one. Caller holds d.mu.
func (rig *ownPauseRig) addressOf(c *netnsFakeContainer) (ip string, onPause bool) {
	if ref, ok := strings.CutPrefix(c.netMode, "container:"); ok {
		if owner := rig.d.byRef(ref); owner != nil {
			return owner.ip, true
		}
		return "", true
	}
	return c.ip, false
}

// joinedLocked lists the containers in pause's namespace. Caller holds d.mu.
func (rig *ownPauseRig) joinedLocked(pause *netnsFakeContainer) []string {
	var out []string
	for _, c := range rig.d.containers {
		if c.netMode == "container:"+pause.id {
			out = append(out, c.name)
		}
	}
	return out
}

func (rig *ownPauseRig) checkStart(c *netnsFakeContainer) {
	if c.labels[netnsPauseLabelKey] == "true" {
		return
	}
	rig.mu.Lock()
	restricted := rig.restricted[c.name]
	rig.mu.Unlock()
	if !restricted {
		return
	}
	ip, onPause := rig.addressOf(c)
	if !onPause {
		rig.violate("restricted workload %s started on Docker's own path: its rules could go on only after it runs", c.name)
		return
	}
	if !rig.rs.on(ip) {
		rig.violate("workload %s started at %s before its rules were on", c.name, ip)
	}
	if owner := rig.d.byRef(strings.TrimPrefix(c.netMode, "container:")); owner == nil || !ipv6Off(owner.sysctls) {
		rig.violate("workload %s started in a namespace with IPv6 on", c.name)
	}
}

func (rig *ownPauseRig) checkRemove(c *netnsFakeContainer) {
	if c.labels[netnsPauseLabelKey] != "true" {
		return
	}
	if joined := rig.joinedLocked(c); len(joined) > 0 {
		rig.violate("pause %s removed while %v run in its namespace", c.name, joined)
	}
	if rig.rs.on(c.ip) {
		rig.violate("pause %s removed with rules still on %s (the next owner would inherit them)", c.name, c.ip)
	}
	rig.mu.Lock()
	known, released := rig.known[c.ip], rig.released[c.ip]
	rig.mu.Unlock()
	if known > released {
		rig.violate("pause %s removed before the create let go of %s", c.name, c.ip)
	}
}

// AddressKnown and ReleasingAddress make the rig the create's
// runtime.AddressObserver.
func (rig *ownPauseRig) AddressKnown(ip string) {
	if !rig.rs.on(ip) {
		rig.violate("address %s reported before its rules were on", ip)
	}
	rig.d.mu.Lock()
	for _, c := range rig.d.containers {
		if a, _ := rig.addressOf(c); a == ip && c.running && c.labels[netnsPauseLabelKey] != "true" {
			rig.violate("address %s reported after its workload %s started", ip, c.name)
		}
	}
	rig.d.mu.Unlock()
	rig.mu.Lock()
	rig.known[ip]++
	rig.mu.Unlock()
}

func (rig *ownPauseRig) ReleasingAddress(ip string) {
	rig.d.mu.Lock()
	for _, c := range rig.d.containers {
		if a, onPause := rig.addressOf(c); a == ip && onPause {
			rig.violate("address %s let go while workload %s is still there", ip, c.name)
		}
	}
	rig.d.mu.Unlock()
	if !rig.rs.on(ip) {
		rig.violate("address %s let go after its rules were already off", ip)
	}
	rig.mu.Lock()
	rig.released[ip]++
	rig.mu.Unlock()
}

func (rig *ownPauseRig) create(ctx context.Context, req models.CreateSandboxRequest, id string) (*SandboxRuntime, error) {
	rig.mu.Lock()
	rig.restricted[id] = hasCreateNetRules(req)
	rig.mu.Unlock()
	return rig.c.Create(sbruntime.WithAddressObserver(ctx, rig), req, id, "tok", nil)
}

func (rig *ownPauseRig) destroy(st *SandboxRuntime, req models.CreateSandboxRequest) error {
	sb := &models.Sandbox{ID: st.SandboxID, ContainerID: st.ContainerID, ContainerIP: st.ContainerIP,
		NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut}
	return rig.c.Destroy(sbruntime.WithAddressObserver(context.Background(), rig), sb)
}

func (rig *ownPauseRig) assertClean(t *testing.T) {
	t.Helper()
	rig.mu.Lock()
	defer rig.mu.Unlock()
	if len(rig.violations) > 0 {
		t.Fatalf("fail-closed contract broken:\n  %s", strings.Join(rig.violations, "\n  "))
	}
}

// assertNothingLeft: every reported address let go, no container but
// keep's, no rule.
func (rig *ownPauseRig) assertNothingLeft(t *testing.T, keep ...string) {
	t.Helper()
	rig.mu.Lock()
	for ip, n := range rig.known {
		if rig.released[ip] != n {
			t.Errorf("address %s reported %d times, let go %d", ip, n, rig.released[ip])
		}
	}
	rig.mu.Unlock()
	rig.d.mu.Lock()
	for _, c := range rig.d.containers {
		if !slices.Contains(keep, c.name) {
			t.Errorf("container %s (%s) left", c.name, c.id)
		}
	}
	rig.d.mu.Unlock()
	rig.rs.mu.Lock()
	defer rig.rs.mu.Unlock()
	if len(rig.rs.rules) > 0 {
		t.Errorf("rules left: %v", rig.rs.rules)
	}
}

func stage(timing *CreateTiming, name string) (desc string, ok bool) {
	for _, st := range timing.Stages() {
		if st.Name == name {
			return st.Desc, true
		}
	}
	return "", false
}

var restrictedRequests = []struct {
	name string
	req  models.CreateSandboxRequest
}{
	// A hostname allowlist reaches the driver as block-all.
	{"block-all", models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}},
	{"allow-out", models.CreateSandboxRequest{Image: "img", NetworkAllowOut: []string{"1.1.1.0/24"}}},
	{"deny-out", models.CreateSandboxRequest{Image: "img", NetworkDenyOut: []string{"10.0.0.0/8"}}},
}

// TestOwnPauseRestrictedCreateNeverRunsOpen: with no pool slot to give, a
// create with rules starts a pause of its own, puts its rules on the
// pause's address, reports it, and only then starts the workload in the
// pause's namespace; its destroy takes the workload, then the rules, then
// the pause. Fails on the base: the workload starts on Docker's own path.
func TestOwnPauseRestrictedCreateNeverRunsOpen(t *testing.T) {
	for _, pool := range []bool{false, true} {
		for _, tc := range restrictedRequests {
			t.Run(fmt.Sprintf("pool=%v/%s", pool, tc.name), func(t *testing.T) {
				rig := newOwnPauseRig(t, pool)
				ctx, timing := WithCreateTiming(context.Background())
				st, err := rig.create(ctx, tc.req, "sb-own")
				if err != nil {
					t.Fatal(err)
				}
				rig.assertClean(t)
				pause := rig.d.byRef(netnsAdoptedName("sb-own"))
				workload := rig.d.byRef("sb-own")
				if pause == nil || workload == nil {
					t.Fatalf("pause %v workload %v", pause, workload)
				}
				if workload.netMode != "container:"+pause.id || st.ContainerIP != pause.ip {
					t.Fatalf("workload netMode %q ip %q, pause %s at %s", workload.netMode, st.ContainerIP, pause.id, pause.ip)
				}
				if desc, ok := stage(timing, "docker_pause"); !ok || desc != "on_demand" {
					t.Fatalf("docker_pause stage %q (present %v)", desc, ok)
				}
				if rig.known[st.ContainerIP] != 1 || !rig.rs.on(st.ContainerIP) {
					t.Fatalf("known %v rules %v", rig.known, rig.rs.rules)
				}
				if err := rig.destroy(st, tc.req); err != nil {
					t.Fatal(err)
				}
				rig.assertClean(t)
				rig.assertNothingLeft(t)
				if rig.released[st.ContainerIP] != 1 {
					t.Fatalf("released %v", rig.released)
				}
			})
		}
	}
}

// TestOwnPauseOnlyForRestrictedRuncCreates: a create without rules, a
// create on a node whose host firewall is off, and a gVisor create keep
// Docker's own path: no pause, no report, no docker_pause stage.
func TestOwnPauseOnlyForRestrictedRuncCreates(t *testing.T) {
	cases := []struct {
		name string
		prep func(*ownPauseRig)
		req  models.CreateSandboxRequest
	}{
		{"no rules", nil, models.CreateSandboxRequest{Image: "img"}},
		{"host firewall off", func(r *ownPauseRig) { r.c.networkRules = disabledRules(t) }, models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}},
		{"gvisor", nil, models.CreateSandboxRequest{Image: "img", Runtime: models.RuntimeGvisor, NetworkBlockAll: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newOwnPauseRig(t, false)
			if tc.prep != nil {
				tc.prep(rig)
			}
			// Not judged by the start check: this path is the one that stays.
			ctx, timing := WithCreateTiming(sbruntime.WithAddressObserver(context.Background(), rig))
			st, err := rig.c.Create(ctx, tc.req, "sb-plain", "tok", nil)
			if err != nil {
				t.Fatal(err)
			}
			if rig.d.byRef(netnsAdoptedName("sb-plain")) != nil || rig.d.byRef("sb-plain").netMode != "" {
				t.Fatal("a pause was started")
			}
			if _, ok := stage(timing, "docker_pause"); ok {
				t.Fatal("docker_pause stage on Docker's own path")
			}
			if len(rig.known) != 0 {
				t.Fatalf("reported %v", rig.known)
			}
			if err := rig.destroy(st, tc.req); err != nil {
				t.Fatal(err)
			}
			rig.assertNothingLeft(t)
		})
	}
}

// TestOwnPauseFailuresLeaveNothing: whichever step of a restricted create
// fails, the workload never runs open, the create fails, and the engine
// and the host firewall hold nothing of it afterwards (a duplicate's pause
// excepted, which is not this create's).
func TestOwnPauseFailuresLeaveNothing(t *testing.T) {
	failName := func(name string) func(string, string) *http.Response {
		return func(n, _ string) *http.Response {
			if n == name {
				return textResponse(http.StatusInternalServerError, "create boom")
			}
			return nil
		}
	}
	failStart := func(match func(*netnsFakeContainer) bool) func(*netnsFakeContainer) *http.Response {
		return func(c *netnsFakeContainer) *http.Response {
			if match(c) {
				return textResponse(http.StatusInternalServerError, "start boom")
			}
			return nil
		}
	}
	isPause := func(c *netnsFakeContainer) bool { return c.labels[netnsPauseLabelKey] == "true" }
	cases := []struct {
		name    string
		prep    func(*ownPauseRig, context.CancelFunc)
		wantErr string
		is      error
		keep    []string
	}{
		{name: "pause create fails", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.d.createResp = failName(netnsAdoptedName("sb-f"))
		}, wantErr: "create pause container"},
		{name: "pause image pull fails", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.d.missing[testPauseImage] = true
			r.d.pullResp = func(image string) *http.Response {
				if image == testPauseImage {
					return textResponse(http.StatusInternalServerError, "pull boom")
				}
				return nil
			}
		}, wantErr: "pull pause image"},
		{name: "pause start fails", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.d.startResp = failStart(isPause)
		}, wantErr: "start pause container"},
		{name: "pause has no address", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.d.noIP = true
		}, wantErr: "has no IP"},
		{name: "a duplicate create holds the pause", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.d.add(&netnsFakeContainer{id: "dup", name: netnsAdoptedName("sb-f"), running: true, ip: "172.30.9.1", labels: map[string]string{netnsPauseLabelKey: "true"}})
		}, is: ErrSandboxContainerExists, keep: []string{netnsAdoptedName("sb-f")}},
		{name: "workload create fails", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.d.createResp = failName("sb-f")
		}, wantErr: "create container"},
		{name: "rules fail to go on", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.rs.failIns = errors.New("insert boom")
		}, wantErr: "apply network block"},
		{name: "workload start fails", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.d.startResp = failStart(func(c *netnsFakeContainer) bool { return !isPause(c) })
		}, wantErr: "start container"},
		{name: "workload comes up at another address", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			// A driver bug or an engine surprise: its rules are on the
			// pause's address, so it must not be left running.
			r.d.onStart = func(c *netnsFakeContainer) {
				if !isPause(c) {
					c.ip = "172.30.99.99"
				}
			}
		}, wantErr: "not at its pause slot's address"},
		{name: "toolbox never ready", prep: func(r *ownPauseRig, _ context.CancelFunc) {
			r.toolboxDown.Store(true)
			r.c.toolboxWaitTimeout = 100 * time.Millisecond
		}, wantErr: "toolbox"},
		{name: "context cancelled once reported", prep: func(r *ownPauseRig, cancel context.CancelFunc) {
			r.d.startResp = func(c *netnsFakeContainer) *http.Response {
				if !isPause(c) {
					cancel()
					return textResponse(http.StatusInternalServerError, "cancelled")
				}
				return nil
			}
		}, wantErr: "start container"},
	}
	for _, pool := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("pool=%v/%s", pool, tc.name), func(t *testing.T) {
				rig := newOwnPauseRig(t, pool)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				tc.prep(rig, cancel)
				_, err := rig.create(ctx, models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-f")
				switch {
				case err == nil:
					t.Fatal("create succeeded")
				case tc.is != nil && !errors.Is(err, tc.is):
					t.Fatalf("err = %v, want %v", err, tc.is)
				case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				rig.assertClean(t)
				rig.assertNothingLeft(t, tc.keep...)
			})
		}
	}
}

// TestOwnPausePullsAMissingImage: a node that never pulled the pause image
// (or whose image GC removed it) pulls it once on the create path, and the
// stage says so.
func TestOwnPausePullsAMissingImage(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	rig.d.missing[testPauseImage] = true
	ctx, timing := WithCreateTiming(context.Background())
	if _, err := rig.create(ctx, models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-pull"); err != nil {
		t.Fatal(err)
	}
	rig.assertClean(t)
	if desc, _ := stage(timing, "docker_pause"); desc != "on_demand_pulled" || rig.d.pullCalls != 1 {
		t.Fatalf("stage %q pulls %d", desc, rig.d.pullCalls)
	}
}

// TestOwnPauseRefusals: a restricted create that can't have a pause fails
// closed rather than run on Docker's own path.
func TestOwnPauseRefusals(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	rig.c.toolboxLoopback = true
	req := models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}
	if _, err := rig.create(context.Background(), req, "sb-lo"); !errors.Is(err, errLoopbackRestricted) {
		t.Fatalf("loopback: err = %v", err)
	}
	rig.assertNothingLeft(t)

	rig = newOwnPauseRig(t, false)
	rig.c.SetNetnsPauseImage("  ")
	if _, err := rig.create(context.Background(), req, "sb-noimg"); err == nil || !strings.Contains(err.Error(), "SB_DOCKER_NETNS_POOL_PAUSE_IMAGE") {
		t.Fatalf("no image: err = %v", err)
	}
	rig.assertNothingLeft(t)
}

// TestOwnPauseDuplicateCreatesConverge: two creates of one sandbox race;
// one wins, the other fails as a duplicate without touching the winner's
// pause, rules or workload.
func TestOwnPauseDuplicateCreatesConverge(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	req := models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}
	var wg sync.WaitGroup
	results := make([]*SandboxRuntime, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = rig.create(context.Background(), req, "sb-dup")
		}()
	}
	wg.Wait()
	won := slices.IndexFunc(errs, func(err error) bool { return err == nil })
	if won < 0 || errs[1-won] == nil {
		t.Fatalf("errs %v: want exactly one winner", errs)
	}
	if !errors.Is(errs[1-won], ErrSandboxContainerExists) && !strings.Contains(errs[1-won].Error(), "409") {
		t.Fatalf("loser err = %v", errs[1-won])
	}
	rig.assertClean(t)
	st := results[won]
	if pause := rig.d.byRef(netnsAdoptedName("sb-dup")); pause == nil || pause.ip != st.ContainerIP || !rig.rs.on(st.ContainerIP) {
		t.Fatalf("the winner lost its pause or rules: %+v %v", pause, rig.rs.rules)
	}
	if err := rig.destroy(st, req); err != nil {
		t.Fatal(err)
	}
	rig.assertClean(t)
	rig.assertNothingLeft(t)
}

// TestOwnPauseChurnLeavesNothing: creates and destroys, some failing at a
// random step, leave the engine and the host firewall as they were.
func TestOwnPauseChurnLeavesNothing(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	var n atomic.Int64
	rig.d.startResp = func(c *netnsFakeContainer) *http.Response {
		if c.labels[netnsPauseLabelKey] != "true" && n.Add(1)%3 == 0 {
			return textResponse(http.StatusInternalServerError, "start boom")
		}
		return nil
	}
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := restrictedRequests[i%len(restrictedRequests)].req
			st, err := rig.create(context.Background(), req, fmt.Sprintf("sb-churn-%d", i))
			if err != nil {
				return
			}
			if err := rig.destroy(st, req); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rig.assertClean(t)
	rig.assertNothingLeft(t)
}

// TestPrepareNetnsPause: on a node without the pool, the boot work pulls a
// missing pause image and removes only the pauses an earlier run left for
// sandboxes that are gone.
func TestPrepareNetnsPause(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	d := rig.d
	d.missing[testPauseImage] = true
	boot := time.Unix(1_000, 0)
	pause := map[string]string{netnsPauseLabelKey: "true"}
	d.add(&netnsFakeContainer{id: "orphan", name: netnsAdoptedName("sb-gone"), labels: pause, created: 900})
	d.add(&netnsFakeContainer{id: "kept", name: netnsAdoptedName("sb-live"), labels: pause, created: 900})
	d.add(&netnsFakeContainer{id: "live", name: "sb-live"})
	d.add(&netnsFakeContainer{id: "young", name: netnsAdoptedName("sb-creating"), labels: pause, created: 1_000})
	d.add(&netnsFakeContainer{id: "free", name: netnsFreePrefix + "abc", labels: pause, created: 900})
	before := netnsPoolOrphansReaped.Value()
	rig.c.PrepareNetnsPause(context.Background(), boot)
	if d.pullCalls != 1 {
		t.Fatalf("pulls %d", d.pullCalls)
	}
	for _, id := range []string{"kept", "live", "young", "free"} {
		if d.byRef(id) == nil {
			t.Fatalf("%s removed", id)
		}
	}
	if d.byRef("orphan") != nil || netnsPoolOrphansReaped.Value() != before+1 {
		t.Fatal("orphan kept")
	}

	// A failing engine: the list fails, the pull fails; nothing is removed.
	d.listErr = true
	d.missing[testPauseImage] = true
	d.pullResp = func(string) *http.Response { return textResponse(http.StatusInternalServerError, "pull boom") }
	rig.c.PrepareNetnsPause(context.Background(), boot)
	if d.byRef("kept") == nil {
		t.Fatal("removed on a failing engine")
	}
}

// TestOwnPauseWorkloadThatWontGoKeepsItShut: a failed create whose
// workload container can't be removed (it may run) keeps its rules and its
// pause and doesn't let go of the address; the orphan sweep's later Destroy
// takes it down in order.
func TestOwnPauseWorkloadThatWontGoKeepsItShut(t *testing.T) {
	for _, pool := range []bool{false, true} {
		t.Run(fmt.Sprintf("pool=%v", pool), func(t *testing.T) {
			rig := newOwnPauseRig(t, pool)
			var stuck atomic.Bool
			stuck.Store(true)
			rig.d.startResp = func(c *netnsFakeContainer) *http.Response {
				if c.name == "sb-stuck" {
					c.running = true // it ran, then the engine reported a failure
					return textResponse(http.StatusInternalServerError, "start boom")
				}
				return nil
			}
			rig.d.removeResp = func(c *netnsFakeContainer) *http.Response {
				if c.name == "sb-stuck" && stuck.Load() {
					return textResponse(http.StatusInternalServerError, "remove boom")
				}
				return nil
			}
			req := models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}
			if _, err := rig.create(context.Background(), req, "sb-stuck"); err == nil {
				t.Fatal("create succeeded")
			}
			rig.assertClean(t)
			pause := rig.d.byRef(netnsAdoptedName("sb-stuck"))
			workload := rig.d.byRef("sb-stuck")
			if pause == nil || workload == nil || !rig.rs.on(pause.ip) || rig.released[pause.ip] != 0 {
				t.Fatalf("pause %v workload %v rules %v released %v: all must stay", pause, workload, rig.rs.rules, rig.released)
			}
			stuck.Store(false)
			if err := rig.destroy(&SandboxRuntime{SandboxID: "sb-stuck", ContainerID: workload.id, ContainerIP: pause.ip}, req); err != nil {
				t.Fatal(err)
			}
			rig.assertClean(t)
			rig.assertNothingLeft(t)
		})
	}
}

// TestOwnPauseThatWontGoIsLeftForTheSweep: a failed create whose pause
// can't be removed still takes its workload, then its rules, then lets go
// of the address; the pause is logged and left for the boot sweep.
func TestOwnPauseThatWontGoIsLeftForTheSweep(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	pauseName := netnsAdoptedName("sb-pw")
	rig.d.startResp = func(c *netnsFakeContainer) *http.Response {
		if c.name == "sb-pw" {
			return textResponse(http.StatusInternalServerError, "start boom")
		}
		return nil
	}
	rig.d.removeResp = func(c *netnsFakeContainer) *http.Response {
		if c.name == pauseName {
			return textResponse(http.StatusInternalServerError, "remove boom")
		}
		return nil
	}
	if _, err := rig.create(context.Background(), models.CreateSandboxRequest{Image: "img", NetworkBlockAll: true}, "sb-pw"); err == nil {
		t.Fatal("create succeeded")
	}
	rig.assertClean(t)
	rig.assertNothingLeft(t, pauseName)
}

// TestPrepareNetnsPauseKeepsWhatItCannotRemove: a sweep whose remove fails
// logs it and goes on.
func TestPrepareNetnsPauseKeepsWhatItCannotRemove(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	pause := map[string]string{netnsPauseLabelKey: "true"}
	rig.d.add(&netnsFakeContainer{id: "stuck", name: netnsAdoptedName("sb-a"), labels: pause, created: 1})
	rig.d.add(&netnsFakeContainer{id: "gone", name: netnsAdoptedName("sb-b"), labels: pause, created: 1})
	rig.d.removeResp = func(c *netnsFakeContainer) *http.Response {
		if c.id == "stuck" {
			return textResponse(http.StatusInternalServerError, "remove boom")
		}
		return nil
	}
	rig.c.PrepareNetnsPause(context.Background(), time.Unix(10, 0))
	if rig.d.byRef("stuck") == nil || rig.d.byRef("gone") != nil {
		t.Fatal("want the stuck pause kept and the other removed")
	}
}

// TestPoolRefillCreateFailure: the pool's refill shares startNetnsPause; a
// create the engine refuses fails the spawn and leaves nothing.
func TestPoolRefillCreateFailure(t *testing.T) {
	rig := newOwnPauseRig(t, false)
	rig.d.createResp = func(string, string) *http.Response {
		return textResponse(http.StatusInternalServerError, "create boom")
	}
	pool := newTestNetnsPool(rig.c, 1)
	if _, err := pool.spawnPause(context.Background()); err == nil || !strings.Contains(err.Error(), "create pause container") {
		t.Fatalf("err = %v", err)
	}
	rig.assertNothingLeft(t)
}
