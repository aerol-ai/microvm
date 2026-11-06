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
	"net/http"
	"sort"
	"strings"
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
