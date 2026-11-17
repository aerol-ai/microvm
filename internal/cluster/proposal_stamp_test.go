package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// stampLeader is a single-node leader whose cluster lives under
// sb.example.com with its API at api.example.com, and which knows the
// workers in members.
func stampLeader(t *testing.T, name string, members ...Member) *Cluster {
	t.Helper()
	c, cleanup := newTestClusterWithCfg(t, name, true, nil, func(cfg *config.Config) {
		cfg.Domain = "sb.example.com"
		cfg.PublicHost = "api.example.com"
	})
	t.Cleanup(cleanup)
	waitForLeader(t, c, 10*time.Second)
	seedGossipView(t, c, members)
	return c
}

func workerMember(id, dataPlaneHost string) Member {
	m := recreateCandidate(id, config.NodeRoleWorker, 100)
	m.DataPlaneHost = dataPlaneHost
	return m
}

// A worker or gateway binds no new hostname, whatever team it records as
// its sandbox's owner: the owner writes that record itself, so its word on
// whose name a hostname is proves nothing. A server binds a new name after
// the caller's DNS proof; the owner then re-adds it (the owner's half of an
// attach, a replay), and may remove it.
func TestWorkerBindsNoNewHostname(t *testing.T) {
	c := stampLeader(t, "ldr-names", workerMember("wkr-9", "10.0.0.9"))
	// A recreator that would prove any name: the leader asks it nothing.
	dns := &anyProofRecreator{recordingRecreator: recordingRecreator{calls: map[string]recordedRecreate{}}}
	c.AttachRecreator(dns)
	w := workerApplyCtx("wkr-9")
	public := true
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-w", OwnerNodeID: "wkr-9", IncarnationID: "inc-w",
		OwnerRef: "team:payments", Spec: &models.CreateSandboxRequest{Image: "alpine", AllowPublicTraffic: &public}})
	if err := c.ApplyEncoded(w, place); err != nil {
		t.Fatalf("place: %v", err)
	}
	add := func(ctx context.Context, host string) error {
		raw, _ := encodeCommand(command{Op: opAddCustomDomain, SandboxID: "sb-w", Hostname: host, ExpectedIncarnationID: "inc-w"})
		return c.ApplyEncoded(ctx, raw)
	}
	for _, host := range []string{"app.payments.example", "api.sb.example.com", "sb-other.sb.example.com", "sb.example.com", "api.example.com"} {
		if err := add(w, host); !errors.Is(err, ErrPeerProposalRefused) {
			t.Errorf("worker binds %s = %v, want ErrPeerProposalRefused", host, err)
		}
	}
	if p, _ := c.fsm.get("sb-w"); len(p.CustomHostnames) != 0 {
		t.Fatalf("custom hostnames after the worker's adds: %v", p.CustomHostnames)
	}
	if len(dns.asked) != 0 {
		t.Fatalf("the leader looked up proofs for a worker: %v", dns.asked)
	}
	// A server binds it; the worker's re-add and its removal then pass.
	if err := add(ContextWithApplyPeer(context.Background(), c.nodeID, nil), "app.payments.example"); err != nil {
		t.Fatalf("server binds: %v", err)
	}
	if err := add(w, "app.payments.example"); err != nil {
		t.Fatalf("worker re-adds a held name: %v", err)
	}
	if p, _ := c.fsm.get("sb-w"); len(p.CustomHostnames) != 1 || p.CustomHostnames[0] != "app.payments.example" {
		t.Fatalf("custom hostnames %v", p.CustomHostnames)
	}
	remove, _ := encodeCommand(command{Op: opRemoveCustomDomain, SandboxID: "sb-w", Hostname: "app.payments.example", ExpectedIncarnationID: "inc-w"})
	if err := c.ApplyEncoded(w, remove); err != nil {
		t.Fatalf("worker removes its sandbox's name: %v", err)
	}
	if err := add(w, "app.payments.example"); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("worker binds a released name again = %v", err)
	}
}

// anyProofRecreator is a recreator that would prove any custom hostname,
// and records each one it is asked about.
type anyProofRecreator struct {
	recordingRecreator
	asked []string
}

func (a *anyProofRecreator) ProveCustomDomain(_ context.Context, host, owner string) error {
	a.asked = append(a.asked, host+"@"+owner)
	return nil
}

func TestLeaderStampsWorkerProposals(t *testing.T) {
	thin := workerMember("wkr-thin", "")
	thin.APIURL = ""
	c := stampLeader(t, "ldr-stamp", workerMember("wkr-9", "10.0.0.9"), workerMember("wkr-b", "10.0.0.11"), workerMember("wkr-3", "10.0.0.3"), thin)
	ctx := context.Background()
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-p", OwnerNodeID: "wkr-9", IncarnationID: "inc-p",
		OwnerAPIURL: "http://elsewhere.example", OwnerDataPlaneHost: "203.0.113.7", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), place); err != nil {
		t.Fatalf("place: %v", err)
	}
	if p, _ := c.fsm.get("sb-p"); p.OwnerAPIURL != "http://wkr-9" || p.OwnerDataPlaneHost != "10.0.0.9" {
		t.Fatalf("placed at %q / %q, want the member record's", p.OwnerAPIURL, p.OwnerDataPlaneHost)
	}
	// A node the leader has no member record for names no address.
	ghost, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-g", OwnerNodeID: "wkr-ghost", IncarnationID: "inc-g",
		OwnerAPIURL: "http://wkr-ghost", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-ghost"), ghost); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("place by a node with no member record = %v", err)
	}

	// A member whose gossip record lost its addresses (a cut meta tier)
	// places its own sandbox at the addresses it sends; another node cannot
	// name it as the target of a reservation.
	own, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-thin", OwnerNodeID: "wkr-thin", IncarnationID: "inc-t",
		OwnerAPIURL: "http://wkr-thin", OwnerDataPlaneHost: "10.0.0.20", Spec: &models.CreateSandboxRequest{Image: "alpine"}})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-thin"), own); err != nil {
		t.Fatalf("thin record, own place: %v", err)
	}
	if p, _ := c.fsm.get("sb-thin"); p.OwnerAPIURL != "http://wkr-thin" || p.OwnerDataPlaneHost != "10.0.0.20" {
		t.Fatalf("thin record placed at %q / %q", p.OwnerAPIURL, p.OwnerDataPlaneHost)
	}
	toThin, _ := encodeCommand(command{Op: opReserve, SandboxID: "sb-rt", OwnerNodeID: "wkr-thin", IncarnationID: "inc-rt",
		OwnerAPIURL: "http://elsewhere.example", Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64},
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix()})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), toThin); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("reserve on a node with no API URL on record = %v", err)
	}

	reserve, _ := encodeCommand(command{Op: opReserve, SandboxID: "sb-r", OwnerNodeID: "wkr-b", IncarnationID: "inc-r",
		OwnerAPIURL: "http://elsewhere.example", ReservedBy: "wkr-3",
		Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64}, ExpiresUnix: time.Now().Add(2 * time.Minute).Unix()})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), reserve); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	p, _ := c.fsm.get("sb-r")
	if p.ReservedBy != "wkr-9" || p.OwnerAPIURL != "http://wkr-b" || p.OwnerDataPlaneHost != "10.0.0.11" {
		t.Fatalf("reservation = by %q at %q / %q", p.ReservedBy, p.OwnerAPIURL, p.OwnerDataPlaneHost)
	}
	cancel, _ := encodeCommand(command{Op: opCancelReserve, SandboxID: "sb-r", ExpectedIncarnationID: "inc-r"})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-3"), cancel); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("cancel by a third node = %v", err)
	}
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), cancel); err != nil {
		t.Fatalf("cancel by the node that reserved it: %v", err)
	}
	if _, ok := c.fsm.get("sb-r"); ok {
		t.Fatal("reservation not cancelled")
	}

	// The leader's own proposals keep their addresses and name it.
	if err := c.applyCommand(ctx, command{Op: opReserve, SandboxID: "sb-l", OwnerNodeID: "wkr-b", OwnerAPIURL: "http://as-given",
		IncarnationID: "inc-l", Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64},
		ExpiresUnix: time.Now().Add(2 * time.Minute).Unix()}); err != nil {
		t.Fatalf("leader reserve: %v", err)
	}
	if p, _ := c.fsm.get("sb-l"); p.ReservedBy != c.nodeID || p.OwnerAPIURL != "http://as-given" {
		t.Fatalf("leader reservation = by %q at %q", p.ReservedBy, p.OwnerAPIURL)
	}
}

// A worker claims another node's reclaim entry only when the listing would
// offer it: not from a live node that drains its own.
func TestWorkerClaimsOnlyAdoptableReclaims(t *testing.T) {
	c := stampLeader(t, "ldr-reclaim", workerMember("wkr-9", ""), workerMember("wkr-live", ""))
	now := time.Now()
	held := VolumeReclaim{Tenant: "t-1", VolumeID: "vol-held", NodeID: "wkr-live", RecordedUnixNano: now.Add(-time.Hour).UnixNano()}
	dead := VolumeReclaim{Tenant: "t-1", VolumeID: "vol-dead", NodeID: "wkr-gone", RecordedUnixNano: now.Add(-time.Hour).UnixNano()}
	fresh := VolumeReclaim{Tenant: "t-1", VolumeID: "vol-fresh", NodeID: "wkr-gone", RecordedUnixNano: now.UnixNano()}
	c.fsm.mu.Lock()
	for _, r := range []VolumeReclaim{held, dead, fresh} {
		c.fsm.putVolumeReclaimLocked(r)
	}
	c.fsm.mu.Unlock()
	claim := func(r VolumeReclaim) error {
		cmd, err := claimVolumeReclaimCommand(r, "wkr-9")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := encodeCommand(cmd)
		return c.ApplyEncoded(workerApplyCtx("wkr-9"), raw)
	}
	if err := claim(held); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("claim from a live node that drains = %v", err)
	}
	if err := claim(fresh); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("claim of a dead node's entry before it may move = %v", err)
	}
	// Two sweepers, three adopters an entry: wkr-9 is one of them.
	if err := claim(dead); err != nil {
		t.Fatalf("claim of a dead node's old entry: %v", err)
	}
}

// The names a server never binds for a caller: its own base domain and
// API host, and, for a server with no domain of its own (a Kubernetes
// server: only the gateways serve the edge), each member's public host and
// every name under it.
func TestClusterHostnames(t *testing.T) {
	gw := workerMember("gw-1", "")
	gw.Role = config.NodeRoleIngress
	gw.PublicHost = "edge.example.net:443"
	c := stampLeader(t, "ldr-members-names", workerMember("wkr-9", ""), gw)
	for host, ours := range map[string]bool{
		"sb.example.com": true, "sb-x.sb.example.com": true, "api.example.com": true,
		"edge.example.net": true, "sb-x.edge.example.net": true,
		"App.Customer.com": true, "app.customer.com": false,
	} {
		if got := c.IsClusterHostname(host); got != ours {
			t.Errorf("IsClusterHostname(%s) = %v, want %v", host, got, ours)
		}
	}
	if !(*Cluster)(nil).IsClusterHostname("app.customer.com") {
		t.Error("a nil cluster must treat every name as its own")
	}
}
