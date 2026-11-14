//go:build integration

package suite

// Live checks for placement rules (plan item P1, plans/placement-rules.md)
// and per-team quotas (P2). The cluster cases read each node's zone from
// GET /v1/cluster/members, so they run on any cluster whose nodes set
// SB_NODE_ZONE (cluster-3-mixed does, through per-node sandboxd_env) and
// skip with a reason on one that does not.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// placementMember is the slice of /v1/cluster/members the placement cases
// assert on.
type placementMember struct {
	NodeID string            `json:"node_id"`
	Alive  bool              `json:"alive"`
	Role   string            `json:"role"`
	Zone   string            `json:"zone"`
	Labels map[string]string `json:"labels"`
}

// zonedWorkers returns the live members that report a zone, keyed by zone.
// A zone shared by two nodes keeps both.
func zonedWorkers(t *testing.T, c *harness.Client) map[string][]placementMember {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var mr struct {
		Members []placementMember `json:"members"`
	}
	if err := c.GetJSON(ctx, "/v1/cluster/members", &mr); err != nil {
		t.Fatalf("get cluster members: %v", err)
	}
	out := map[string][]placementMember{}
	for _, m := range mr.Members {
		if m.Alive && m.Zone != "" {
			out[m.Zone] = append(out[m.Zone], m)
		}
	}
	return out
}

// requireTwoZones skips a case on a cluster whose nodes do not declare at
// least two zones: the case has nothing to tell apart there.
func requireTwoZones(t *testing.T, zones map[string][]placementMember) []string {
	t.Helper()
	if len(zones) < 2 {
		t.Skipf("needs nodes in at least two zones (SB_NODE_ZONE); members report %d", len(zones))
	}
	names := make([]string, 0, len(zones))
	for z := range zones {
		names = append(names, z)
	}
	sort.Strings(names)
	return names
}

// UC-438 — the members view shows each node's zone and labels from its
// capacity heartbeat (P1.7), and the zone is also the "zone" label.
func TestPlacementMembersShowZoneAndLabels(t *testing.T) {
	harness.Require(t, sc, "UC-438")
	zones := zonedWorkers(t, client(t))
	requireTwoZones(t, zones)
	for zone, members := range zones {
		for _, m := range members {
			if m.Labels["zone"] != zone {
				t.Fatalf("node %s: zone %q but labels %v (the zone must be the zone label)", m.NodeID, zone, m.Labels)
			}
		}
	}
}

// UC-439 — a create with a zone lands on a node in that zone every time, and
// a create with a node's zone and labels lands on that node: the label filter
// runs before power-of-two-choices, so no create escapes the rule.
func TestPlacementZoneRuleLandsInZone(t *testing.T) {
	harness.Require(t, sc, "UC-439")
	c := client(t)
	zones := zonedWorkers(t, c)
	names := requireTwoZones(t, zones)
	for _, zone := range names {
		allowed := map[string]bool{}
		for _, m := range zones[zone] {
			allowed[m.NodeID] = true
		}
		for i := range 3 {
			sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
				Name:      harness.UniqueName(sc, t),
				Placement: &sdktypes.PlacementRule{Zone: zone},
			})
			owner := resolvePlacementOwner(t, c, sb.ID)
			if !allowed[owner] {
				t.Fatalf("create %d with zone %q landed on %q, want one of %v", i, zone, owner, allowed)
			}
		}
	}
	// Every label of one node, the zone included: it must land there.
	target := zones[names[0]][0]
	labels := map[string]string{}
	for k, v := range target.Labels {
		if k != "zone" {
			labels[k] = v
		}
	}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:      harness.UniqueName(sc, t),
		Placement: &sdktypes.PlacementRule{Zone: target.Zone, Labels: labels},
	})
	if owner := resolvePlacementOwner(t, c, sb.ID); len(zones[names[0]]) == 1 && owner != target.NodeID {
		t.Fatalf("create with node %s's labels landed on %s", target.NodeID, owner)
	}
}

// UC-440 — a rule no node satisfies is refused with 409
// placement_unsatisfiable naming the rule, never a fallback, and nothing is
// created. On a single node the node's own labels decide, with the same
// answer (P1.6).
func TestPlacementUnsatisfiableIs409(t *testing.T) {
	harness.Require(t, sc, "UC-440")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	name := harness.UniqueName(sc, t)
	_, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:     harness.DefaultImage,
		Name:      name,
		Placement: &sdktypes.PlacementRule{Zone: "uc440-no-such-zone", Labels: map[string]string{"uc440": "missing"}},
	})
	var apiErr *microvm.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != "placement_unsatisfiable" {
		t.Fatalf("create = %v, want 409 placement_unsatisfiable", err)
	}
	if !strings.Contains(apiErr.Message, "uc440=missing") || !strings.Contains(apiErr.Message, "zone=uc440-no-such-zone") {
		t.Fatalf("message %q does not name the rule", apiErr.Message)
	}
	if apiErr.RetryAfter != 0 {
		t.Fatalf("Retry-After %v on a refusal no retry can fix", apiErr.RetryAfter)
	}
	// A malformed rule is a 400, not a 409.
	_, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:     harness.DefaultImage,
		Placement: &sdktypes.PlacementRule{Labels: map[string]string{"bad key": "v"}},
	})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed rule = %v, want 400", err)
	}
	list, err := c.SDK().List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, sb := range list {
		if sb.Name == name {
			t.Fatalf("refused create left sandbox %s behind", sb.ID)
		}
	}
}

// --- Per-team quotas (plan item P2) ---

// quotaTeam is a team name of its own per case, so cases never share a quota.
func quotaTeam(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

// putQuota sets a team's quota with the operator credential and removes it
// when the test ends.
func putQuota(t *testing.T, ctx context.Context, team string, limits sdktypes.TeamQuotaOptions) sdktypes.TeamQuota {
	t.Helper()
	q, err := client(t).SDK().PutTeamQuota(ctx, team, limits)
	if err != nil {
		t.Fatalf("PutTeamQuota(%s): %v", team, err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = client(t).SDK().DeleteTeamQuota(cctx, team)
	})
	return q
}

// createAs creates a sandbox with a team's SDK and destroys it at the end;
// the error is the caller's to judge.
func createAs(t *testing.T, ctx context.Context, sdk *microvm.Client, opts sdktypes.CreateSandboxOptions) (*microvm.Sandbox, error) {
	t.Helper()
	if opts.Image == "" {
		opts.Image = harness.DefaultImage
	}
	sb, err := sdk.Create(ctx, opts)
	if err == nil {
		destroySandbox(t, sb.ID)
	}
	return sb, err
}

func isQuotaRefusal(err error) bool {
	var apiErr *microvm.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests && apiErr.Code == "team_quota_exceeded"
}

// UC-441 — the admin quota API is idempotent and admin-only: the same PUT
// twice keeps generation 1, GET shows usage, DELETE twice is 204 then 404 on
// GET, and a team runner token cannot set its own quota.
func TestTeamQuotaAdminAPI(t *testing.T) {
	harness.Require(t, sc, "UC-441")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	team := quotaTeam("uc441")
	admin := client(t).SDK()
	limits := sdktypes.TeamQuotaOptions{MaxSandboxes: 2, MaxCPU: 4, MaxMemoryMB: 8192}
	for i := range 2 {
		q := putQuota(t, ctx, team, limits)
		if q.Generation != 1 || q.MaxSandboxes != 2 || q.Usage == nil {
			t.Fatalf("PUT %d = %+v, want generation 1 with usage", i+1, q)
		}
	}
	runner := mintToken(t, "uc441", "runner", team)
	if _, err := sdkFor(t, runner.Secret).PutTeamQuota(ctx, team, sdktypes.TeamQuotaOptions{MaxSandboxes: 100}); err == nil {
		t.Fatal("a team runner raised its own quota")
	}
	if _, err := createAs(t, ctx, sdkFor(t, runner.Secret), sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)}); err != nil {
		t.Fatalf("create within the quota: %v", err)
	}
	q, err := admin.GetTeamQuota(ctx, team)
	if err != nil || q.Usage == nil || q.Usage.Sandboxes != 1 {
		t.Fatalf("GET = %+v %v, want usage 1", q, err)
	}
	for range 2 {
		if err := admin.DeleteTeamQuota(ctx, team); err != nil {
			t.Fatalf("DELETE: %v", err)
		}
	}
	var apiErr *microvm.APIError
	if _, err := admin.GetTeamQuota(ctx, team); !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after DELETE = %v, want 404", err)
	}
}

// UC-442 — a team at its quota is refused with 429 team_quota_exceeded
// naming the limit, with no Retry-After; deleting a sandbox makes room.
func TestTeamQuotaRefusesCreatePastLimit(t *testing.T) {
	harness.Require(t, sc, "UC-442")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	team := quotaTeam("uc442")
	putQuota(t, ctx, team, sdktypes.TeamQuotaOptions{MaxSandboxes: 1})
	sdk := sdkFor(t, mintToken(t, "uc442", "runner", team).Secret)
	first, err := createAs(t, ctx, sdk, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err = createAs(t, ctx, sdk, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	var apiErr *microvm.APIError
	if !isQuotaRefusal(err) || !errors.As(err, &apiErr) || !strings.Contains(apiErr.Message, team) || apiErr.RetryAfter != 0 {
		t.Fatalf("second create = %v, want 429 team_quota_exceeded naming %s and no Retry-After", err, team)
	}
	if err := sdk.Destroy(ctx, first.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	// The slot comes back once the delete is recorded.
	deadline := time.Now().Add(time.Minute)
	for {
		_, err = createAs(t, ctx, sdk, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
		if err == nil {
			break
		}
		if !isQuotaRefusal(err) || time.Now().After(deadline) {
			t.Fatalf("create after delete = %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// UC-443 — the race the plan names: N creates at once for a team with K
// free slots; exactly K succeed and the rest get 429. On a cluster the
// leader decides for every node, so the count is exact cluster-wide.
func TestTeamQuotaConcurrentCreatesAreExact(t *testing.T) {
	harness.Require(t, sc, "UC-443")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	const slots, n = 3, 10
	team := quotaTeam("uc443")
	putQuota(t, ctx, team, sdktypes.TeamQuotaOptions{MaxSandboxes: slots})
	sdk := sdkFor(t, mintToken(t, "uc443", "runner", team).Secret)
	var mu sync.Mutex
	var granted, refused int
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := createAs(t, ctx, sdk, sdktypes.CreateSandboxOptions{Name: fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i)})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				granted++
			case isQuotaRefusal(err):
				refused++
			default:
				t.Errorf("create %d: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if granted != slots || refused != n-slots {
		t.Fatalf("granted %d refused %d, want exactly %d and %d", granted, refused, slots, n-slots)
	}
	q, err := client(t).SDK().GetTeamQuota(ctx, team)
	if err != nil || q.Usage == nil || q.Usage.Sandboxes != slots {
		t.Fatalf("usage = %+v %v, want %d", q, err, slots)
	}
}

// UC-444 — resize counts: growing a sandbox past the team's CPU quota is
// refused with 429 and changes nothing; shrinking always works.
func TestTeamQuotaRefusesResizePastLimit(t *testing.T) {
	harness.Require(t, sc, "UC-444")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	team := quotaTeam("uc444")
	putQuota(t, ctx, team, sdktypes.TeamQuotaOptions{MaxCPU: 2})
	sdk := sdkFor(t, mintToken(t, "uc444", "runner", team).Secret)
	sb, err := createAs(t, ctx, sdk, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), CPU: 1})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := sb.Resize(ctx, sdktypes.ResizeSandboxOptions{CPU: 3}); !isQuotaRefusal(err) {
		t.Fatalf("resize to 3 CPU = %v, want 429 team_quota_exceeded", err)
	}
	if err := sb.Resize(ctx, sdktypes.ResizeSandboxOptions{CPU: 0.5}); err != nil {
		t.Fatalf("shrinking resize: %v", err)
	}
	q, err := client(t).SDK().GetTeamQuota(ctx, team)
	if err != nil || q.Usage == nil || q.Usage.CPU != 0.5 {
		t.Fatalf("usage after shrink = %+v %v, want 0.5 CPU", q, err)
	}
}

// UC-445 — lowering a quota removes nothing but stops the team growing: a
// stopped sandbox of a team over its lowered quota cannot start (429), and
// starts again once the quota is lifted.
func TestTeamQuotaLoweredBlocksStart(t *testing.T) {
	harness.Require(t, sc, "UC-445")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	team := quotaTeam("uc445")
	putQuota(t, ctx, team, sdktypes.TeamQuotaOptions{MaxSandboxes: 2})
	sdk := sdkFor(t, mintToken(t, "uc445", "runner", team).Secret)
	var sbs []*microvm.Sandbox
	for range 2 {
		sb, err := createAs(t, ctx, sdk, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		sbs = append(sbs, sb)
	}
	if err := sbs[0].Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	putQuota(t, ctx, team, sdktypes.TeamQuotaOptions{MaxSandboxes: 1})
	// The read a worker's start check uses may lag a few seconds.
	deadline := time.Now().Add(30 * time.Second)
	var err error
	for {
		err = sbs[0].Start(ctx)
		if isQuotaRefusal(err) || time.Now().After(deadline) {
			break
		}
		if err == nil {
			_ = sbs[0].Stop(ctx)
		}
		time.Sleep(3 * time.Second)
	}
	if !isQuotaRefusal(err) {
		t.Fatalf("start over a lowered quota = %v, want 429 team_quota_exceeded", err)
	}
	if err := client(t).SDK().DeleteTeamQuota(ctx, team); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		err = sbs[0].Start(ctx)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		t.Fatalf("start with no quota: %v", err)
	}
}
